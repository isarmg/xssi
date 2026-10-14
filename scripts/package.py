#!/usr/bin/env python3
"""Create/verify exact SHA256 payloads. No product SQL or password algorithms."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import re
import sys

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))

PRODUCTS = {'xcos', 'xczs', 'xocs', 'xscs', 'xsos', 'xszs'}
MANIFEST = 'share/package.json'
CHECKSUM = 'share/package.sha256'
MAX_FILES = 4096
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
VERSION_PATTERN = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'


class MachineParser(argparse.ArgumentParser):
    def error(self, message):
        if '--json' in sys.argv:
            print(json.dumps({'error': {'code': 'INVALID_ARGUMENT',
                                      'message': 'Invalid tool arguments; see --help.', 'retryable': False}}))
            raise SystemExit(1)
        super().error(message)

def loads(value):
    def unique(pairs):
        result={}
        for key,item in pairs:
            if key in result:raise ValueError('duplicate JSON object field')
            result[key]=item
        return result
    return json.loads(value,object_pairs_hook=unique)

def relative(value):
    if not isinstance(value, str): raise ValueError('payload path must be a string')
    p = PurePosixPath(value)
    if p.is_absolute() or str(p) != value or any(part in ('', '.', '..') for part in p.parts):
        raise ValueError('payload path must be canonical and relative')
    if len(value.encode('utf-8'))>4096 or any(ord(character)<32 or ord(character)==127 for character in value):
        raise ValueError('payload path exceeds its bound or contains control characters')
    if value in ('install.sh', 'upgrade.sh', 'maintenance.sh'):
        return value
    if not p.parts or p.parts[0] not in ('bin', 'libexec', 'share'):
        raise ValueError('payload path is outside the immutable package directories')
    if value in (MANIFEST, CHECKSUM): raise ValueError('manifest cannot hash itself')
    return value

def private_chain(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('physical absolute path required')
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError('package directory path must not use symbolic links')
    return path

def bytes_regular(path, maximum=1024 * 1024, expected=None):
    path = Path(path)
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(opened) != identity(before) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ValueError('single-link regular file required')
        if opened.st_size > maximum: raise ValueError('file exceeds its byte bound')
        if expected is not None:
            mode, owner = expected
            if stat.S_IMODE(opened.st_mode) != mode or opened.st_uid != owner:
                raise ValueError('payload ownership or exact mode mismatch')
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk: break
            total += len(chunk)
            if total > maximum: raise ValueError('file exceeds its byte bound')
            chunks.append(chunk)
        if identity(os.fstat(descriptor)) != identity(opened) or identity(path.lstat()) != identity(opened):
            raise ValueError('file changed while inspecting verified payload')
        return b''.join(chunks)
    finally: os.close(descriptor)

def digest(path):
    return hashlib.sha256(bytes_regular(path, MAX_FILE_BYTES)).hexdigest()

def verify_checksum(package):
    manifest = bytes_regular(package / MANIFEST)
    checksum = bytes_regular(package / CHECKSUM, 65)
    if checksum != (hashlib.sha256(manifest).hexdigest()+'\n').encode('ascii'):
        raise ValueError('package manifest SHA256 differs')
    if bytes_regular(package / MANIFEST) != manifest or bytes_regular(package / CHECKSUM, 65) != checksum:
        raise ValueError('package authority changed during verification')
    return manifest

def verify(package, *, installed=False):
    package = private_chain(Path(package).absolute())
    raw = verify_checksum(package)
    manifest = loads(raw)
    required = {'manifest_version', 'identity', 'schema_identity', 'server', 'setup', 'services', 'files'}
    if set(manifest) != required or type(manifest['manifest_version']) is not int or manifest['manifest_version'] != 1:
        raise ValueError('unsupported package manifest contract')
    identity = manifest['identity']
    if set(identity) != {'product', 'version', 'source_revision', 'target', 'state_contract_sha256'}:
        raise ValueError('invalid release identity fields')
    product = identity['product']
    if product not in PRODUCTS or identity['target'] != 'x86_64-unknown-linux-gnu':
        raise ValueError('unsupported product or target')
    if not re.fullmatch(VERSION_PATTERN,identity['version']) or not re.fullmatch(r'[0-9a-f]{40}',identity['source_revision']) or not re.fullmatch(r'[0-9a-f]{64}',identity['state_contract_sha256']):
        raise ValueError('release identity is not canonical')
    schema=manifest['schema_identity']
    if set(schema)!={'application','application_version','schema_revision','schema_sha256'} or schema['application']!=product or type(schema['schema_revision']) is not int or not 1<=schema['schema_revision']<=2**53-1 or not re.fullmatch(r'[0-9a-f]{64}',schema['schema_sha256']):
        raise ValueError('schema identity is not canonical')
    if not isinstance(schema['application_version'],str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',schema['application_version']):
        raise ValueError('schema format name is not canonical')
    if manifest['server'] != 'bin/'+product or manifest['setup'] != 'libexec/setup':
        raise ValueError('package entry points differ from the controlled layout')
    owner = package.lstat().st_uid
    files = manifest['files']
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('invalid payload count')
    declared = {}
    total = 0
    for entry in files:
        if set(entry) != {'path', 'mode', 'size', 'sha256'}: raise ValueError('invalid payload record')
        name = relative(entry['path'])
        if name in declared: raise ValueError('duplicate payload path')
        if entry['mode'] not in ('0755', '0644'): raise ValueError('unsupported payload mode')
        if type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_FILE_BYTES:
            raise ValueError('invalid payload size')
        total += entry['size']
        if total > MAX_TOTAL_BYTES: raise ValueError('package exceeds its total byte bound')
        parent = package / name
        private_chain(parent.parent)
        data = bytes_regular(parent, MAX_FILE_BYTES, (int(entry['mode'], 8), owner))
        if len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise ValueError('verified payload bytes differ')
        declared[name] = entry
    actual = set()
    inspected=0
    for current, directories, filenames in os.walk(package,followlinks=False):
        if installed and Path(current)==package:
            # Business data may use another declared ROOT directory, such as
            # files/media. Only these three directories contain executable
            # package material; their inventory remains exact and complete.
            directories[:]=[name for name in directories if name in ('bin','libexec','share')]
            filenames[:]=[name for name in filenames if name in ('install.sh','upgrade.sh','maintenance.sh')]
        for name in directories+filenames:
            inspected+=1
            if inspected>MAX_FILES+256:raise ValueError('payload tree exceeds its entry bound')
            path=Path(current)/name;relative_path=path.relative_to(package)
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o755:
                    raise ValueError('payload directory ownership or mode mismatch')
            elif stat.S_ISREG(info.st_mode): actual.add(relative_path.as_posix())
            else: raise ValueError('unsupported package entry type')
    if actual != set(declared) | {MANIFEST, CHECKSUM}:
        raise ValueError('package contains undeclared or missing files')
    for entrypoint in (manifest['server'], manifest['setup']):
        if declared.get(entrypoint, {}).get('mode') != '0755': raise ValueError('entrypoint must be executable')
    services = manifest['services']
    if not isinstance(services, list) or not 1 <= len(services) <= 2:
        raise ValueError('invalid service writer coverage')
    names = set()
    for service in services:
        if set(service) != {'name', 'path', 'role'}: raise ValueError('invalid service record')
        allowed = {f'{product}.service': 'server'}
        if product == 'xcos': allowed['xcos-mediamtx.service'] = 'media'
        if allowed.get(service['name']) != service['role'] or service['name'] in names:
            raise ValueError('uncontrolled service writer')
        names.add(service['name'])
        if service['path'] != f"share/systemd/{service['name']}" or service['path'] not in declared:
            raise ValueError('service unit template is not verified payload')
    if f'{product}.service' not in names: raise ValueError('main writer service is missing')
    return manifest

def finalize(stage, identity_path, schema_path):
    stage = private_chain(Path(stage).absolute())
    identity = loads(bytes_regular(identity_path))
    schema = loads(bytes_regular(schema_path))
    product = identity['product']
    if product not in PRODUCTS: raise ValueError('unsupported product')
    if (stage / MANIFEST).exists() or (stage / CHECKSUM).exists():
        raise ValueError('refusing to replace existing immutable release metadata')
    files = []
    for path in sorted(stage.rglob('*')):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode): path.chmod(0o755); continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('payload must contain only single-link regular files')
        name = relative(path.relative_to(stage).as_posix())
        mode = 0o755 if name.startswith('bin/') or name == 'libexec/setup' or name.endswith('.sh') else 0o644
        path.chmod(mode)
        files.append({'path': name, 'mode': f'{mode:04o}', 'size': info.st_size, 'sha256': digest(path)})
    services = [{'name': f'{product}.service', 'path': f'share/systemd/{product}.service', 'role': 'server'}]
    if product == 'xcos': services.append({'name':'xcos-mediamtx.service','path':'share/systemd/xcos-mediamtx.service','role':'media'})
    manifest = {'manifest_version':1, 'identity':identity, 'schema_identity':schema,
                'server':f'bin/{product}', 'setup':'libexec/setup', 'services':services, 'files':files}
    (stage / 'share').mkdir(exist_ok=True)
    with (stage / MANIFEST).open('xb') as stream:
        stream.write((json.dumps(manifest,sort_keys=True,separators=(',', ':'))+'\n').encode())
    with (stage / CHECKSUM).open('xb') as stream:
        stream.write((hashlib.sha256(bytes_regular(stage / MANIFEST)).hexdigest()+'\n').encode('ascii'))
    (stage / MANIFEST).chmod(0o644)
    (stage / CHECKSUM).chmod(0o644)

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('finalize')
    create.add_argument('stage', type=Path)
    create.add_argument('--identity', type=Path, required=True)
    create.add_argument('--schema', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('package', type=Path)
    args = parser.parse_args()
    if args.command == 'finalize': finalize(args.stage,args.identity,args.schema)
    else: print(json.dumps(verify(args.package),separators=(',', ':')))

if __name__ == '__main__': main()
