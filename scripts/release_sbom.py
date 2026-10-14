#!/usr/bin/env python3
"""Bind resolved runtime graphs and third-party receipts to final release files."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import tempfile
import zipfile

MAX_FILES = 16384
MAX_BYTES = 2 * 1024 * 1024 * 1024
MAX_JSON = 32 * 1024 * 1024
OUTPUT = 'share/release-sbom.cdx.json'
# Checksum manifests must hash the SBOM. A SBOM cannot recursively hash itself
# or that manifest; their own checksum/inventory provides this last edge.
CONTROL_FILES = {OUTPUT, 'share/package.json', 'share/package.sha256'}
FONT_SUFFIXES = {'.ttf', '.otf', '.woff', '.woff2'}
PACKAGE_ARCHIVES = {'.apk', '.aab', '.ipa', '.zip'}
INSTALLER_SCRIPTS = {'installer-scripts/postinstall.sh', 'installer-scripts/preremove.sh', 'installer-scripts/postremove.sh'}


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate inventory field')
            result[key] = value
        return result
    return json.loads(bounded(path, MAX_JSON), object_pairs_hook=unique)


def fields(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError('inventory fields do not match their current contract')


def text(value, maximum=4096):
    if not isinstance(value, str) or not value or len(value.encode()) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('inventory text is invalid')
    return value


def relative(value):
    text(value)
    path = PurePosixPath(value)
    if path.is_absolute() or PureWindowsPath(value).drive or str(path) != value or any(part in ('', '.', '..') for part in path.parts) or '\\' in value or ':' in value:
        raise ValueError('inventory path must be canonical and relative')
    return value


def sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('inventory SHA-256 is invalid')
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def bounded(path, maximum):
    path = Path(path)
    physical_directory(path.absolute().parent)
    named = path.lstat()
    if not stat.S_ISREG(named.st_mode) or getattr(named, 'st_file_attributes', 0) & 0x400:
        raise ValueError('inventory authority cannot follow a link or Windows reparse point')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        before = os.fstat(descriptor)
        if identity(before) != identity(named) or before.st_nlink != 1 or before.st_size > maximum:
            raise ValueError('inventory authority requires a bounded single-link regular file')
        chunks = []
        size = 0
        while chunk := os.read(descriptor, min(65536, maximum + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise ValueError('inventory authority exceeds its bound')
        if size != before.st_size or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(path.lstat()):
            raise ValueError('inventory authority changed during verification')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def digest(path):
    named=Path(path).lstat()
    if not stat.S_ISREG(named.st_mode) or getattr(named,'st_file_attributes',0)&0x400:
        raise ValueError('inventory cannot follow a link or Windows reparse point')
    descriptor = os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0) | getattr(os,'O_BINARY',0))
    try:
        before = os.fstat(descriptor)
        if identity(before)!=identity(named) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_BYTES:
            raise ValueError('inventory requires a bounded single-link regular file')
        result = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > MAX_BYTES:
                raise ValueError('inventory file exceeds its bound')
            result.update(chunk)
        if total != before.st_size or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(Path(path).lstat()):
            raise ValueError('release file changed while computing its inventory')
        return result.hexdigest()
    finally:
        os.close(descriptor)


def package_link_target(stage, name):
    pending = list(PurePosixPath(name).parts)
    resolved = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if not resolved:
                raise ValueError('package link escapes the delivered tree')
            resolved.pop()
            continue
        path = stage.joinpath(*resolved, part)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 32:
                raise ValueError('package link is cyclic or exceeds its bound')
            target = os.readlink(path)
            text(target)
            if '\\' in target or ':' in target:
                raise ValueError('package link uses an ambiguous separator')
            parts = list(PurePosixPath(target).parts)
            if target.startswith('/'):
                resolved = []
                parts = parts[1:]
            pending = parts + pending
        else:
            if pending and not stat.S_ISDIR(info.st_mode):
                raise ValueError('package link traverses an undelivered directory')
            resolved.append(part)
    if not resolved:
        raise ValueError('package link cannot alias the installation root')
    path = stage.joinpath(*resolved)
    if not (stat.S_ISREG(path.lstat().st_mode) or stat.S_ISDIR(path.lstat().st_mode)):
        raise ValueError('package link does not resolve to a delivered object')
    return '/'.join(resolved)


def physical_directory(path):
    path=Path(path).absolute()
    current=Path(path.anchor)
    for part in path.parts[1:]:
        current/=part
        info=current.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('inventory root must use physical directories')
    return path


def files(stage, package_symlinks=False, output_relative=OUTPUT):
    stage=physical_directory(stage)
    result = {}
    total = 0
    def walk_error(error):raise error
    for directory, subdirectories, names in os.walk(stage, followlinks=False,onerror=walk_error):
        for name in subdirectories:
            info=(Path(directory)/name).lstat()
            if getattr(info,'st_file_attributes',0)&0x400:
                raise ValueError('release tree contains a Windows reparse directory')
        symbolic_directories = [name for name in subdirectories if (Path(directory) / name).is_symlink()]
        subdirectories[:] = [name for name in subdirectories if name not in symbolic_directories]
        names = [*names, *symbolic_directories]
        for name in sorted(names):
            path = Path(directory) / name
            name = relative(path.relative_to(stage).as_posix())
            info = path.lstat()
            if getattr(info,'st_file_attributes',0)&0x400:
                raise ValueError('release tree contains a Windows reparse file')
            if name in {output_relative, 'share/package.json', 'share/package.sha256'}:
                continue
            total += path.lstat().st_size
            if len(result) >= MAX_FILES or total > MAX_BYTES:
                raise ValueError('release inventory exceeds its bound')
            if stat.S_ISLNK(info.st_mode):
                if not package_symlinks:
                    raise ValueError('release tree does not permit package symbolic links')
                target = os.readlink(path)
                package_link_target(stage, name)
                if identity(path.lstat()) != identity(info):
                    raise ValueError('package link changed while inspecting its target')
                result[name] = hashlib.sha256(target.encode()).hexdigest()
            else:
                result[name] = digest(path)
    return dict(sorted(result.items()))


def verify_file(item, stage, inventory):
    fields(item, ['path', 'sha256', 'archive_entry'])
    path = relative(item['path'])
    expected = sha(item['sha256'])
    if path not in inventory:
        raise ValueError('component file is absent from the final release')
    entry = item['archive_entry']
    if (stage / path).is_symlink():
        raise ValueError('component binding must identify the actual delivered regular file, not its installation alias')
    if entry is None:
        if inventory[path] != expected:
            raise ValueError('component digest differs from the final release file')
        return path, None
    relative(entry)
    with zipfile.ZipFile(stage / path) as archive:
        records = archive.infolist()
        if len(records) > MAX_FILES or len({info.filename for info in records}) != len(records):
            raise ValueError('component archive has ambiguous entries')
        info = archive.getinfo(entry)
        if info.is_dir() or info.file_size > MAX_BYTES or stat.S_ISLNK(info.external_attr >> 16):
            raise ValueError('component archive entry is not a bounded regular file')
        checksum = hashlib.sha256()
        total = 0
        with archive.open(info) as source:
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise ValueError('component archive entry exceeds its bound')
                checksum.update(chunk)
        if total != info.file_size or checksum.hexdigest() != expected or digest(stage / path) != inventory[path]:
            raise ValueError('embedded component differs from its release receipt')
    return path, entry


def source(value, platform=False):
    from urllib.parse import urlsplit
    fields(value, ['url', 'sha256'])
    url = text(value['url'])
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('third-party source must be a public HTTPS origin')
    if value['sha256'] is None and platform:
        return url
    sha(value['sha256'])
    return url


def dependencies(boms):
    components = {}
    edges = {}
    roots = set()
    for path in boms:
        bom = load(path)
        if bom.get('bomFormat') != 'CycloneDX' or bom.get('specVersion') not in ('1.5', '1.6'):
            raise ValueError('runtime graph is not a supported CycloneDX document')
        root = bom['metadata']['component']
        roots.add(text(root['bom-ref']))
        queue = [root, *bom.get('components', [])]
        local = set()
        while queue:
            item = dict(queue.pop())
            queue.extend(item.pop('components', []))
            ref = text(item['bom-ref'])
            if ref in local:
                raise ValueError('runtime graph repeats a component')
            local.add(ref)
            if item.get('scope') == 'excluded':
                raise ValueError('runtime graph contains excluded build or development material')
            if ref in components:
                for key in ('type', 'name', 'version', 'purl'):
                    if components[ref].get(key) != item.get(key):
                        raise ValueError('runtime graphs disagree about a shared dependency')
            else:
                components[ref] = item
        graph = {}
        for node in bom.get('dependencies', []):
            ref = text(node['ref'])
            children = node.get('dependsOn', [])
            if ref in graph or ref not in local or len(children) != len(set(children)) or not set(children) <= local:
                raise ValueError('runtime graph is not closed and unique')
            graph[ref] = set(children)
            edges.setdefault(ref, set()).update(children)
        if root['bom-ref'] not in graph:
            raise ValueError('runtime graph has no dependency root')
        seen = {root['bom-ref']}
        pending = list(seen)
        while pending:
            for child in graph.get(pending.pop(), set()):
                if child not in seen:
                    seen.add(child)
                    pending.append(child)
        # Cargo's per-target identity children are descriptive, never dependencies.
        if any(ref not in seen and not ref.startswith(root['bom-ref'] + ' ') for ref in local):
            raise ValueError('runtime graph includes disconnected material')
    return components, edges, roots


def import_requirements(path):
    if path.suffix.lower() == '.class':
        return None
    with path.open('rb') as stream:
        magic = stream.read(4)
    if magic == b'\x7fELF':
        command = ['readelf', '--dynamic', '--program-headers', '--version-info', str(path)]
        kind = 'ELF'
    elif magic[:2] == b'MZ':
        command = ['llvm-readobj', '--coff-imports', str(path)]
        kind = 'PE'
    elif magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
        command = ['otool', '-L', str(path)]
        kind = 'Mach-O'
    else:
        return None
    inspector = shutil.which(command[0])
    if inspector is None:
        raise ValueError('native import inspector is unavailable for the actual release format')
    command[0] = inspector
    # Native inspection is a build operation. Use the same live output bound
    # and complete process-tree ownership as every other build producer.
    from sbom import run
    environment={key:value for key,value in os.environ.items() if key in ('SYSTEMROOT','WINDIR','TMP','TEMP','SystemRoot')} | {
        'PATH':'/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin','LANG':'C','TZ':'UTC'}
    output = run(command,path.parent,environment,maximum=MAX_JSON,timeout=30).decode('utf-8',errors='strict')
    if kind == 'ELF':
        names = sorted(set(re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', output)))
        interpreters = re.findall(r'Requesting program interpreter: ([^\]]+)\]', output)
        versions = sorted(set(re.findall(r'Name: ([A-Za-z0-9_.+-]+)', output)))
        return {'format': kind, 'imports': names, 'interpreters': interpreters, 'symbol_versions': versions}
    if kind == 'PE':
        return {'format': kind, 'imports': sorted(set(re.findall(r'^\s*Name: ([^\r\n]+)', output, re.M)))}
    return {'format': kind, 'imports': sorted(set(re.findall(r'^\s+(\S+) \(compatibility version', output, re.M)))}


def archived_import_requirements(stage, path, covered, checksum):
    result = []
    with zipfile.ZipFile(stage / path) as archive:
        records = archive.infolist()
        if len(records) > MAX_FILES or len({item.filename for item in records}) != len(records):
            raise ValueError('release archive has ambiguous entries')
        for item in records:
            if item.is_dir() or PurePosixPath(item.filename).suffix.lower() == '.class':
                continue
            with archive.open(item) as source:
                magic = source.read(4)
                native = magic == b'\x7fELF' or magic[:2] == b'MZ' or magic in (
                    b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')
                if not native:
                    continue
                relative(item.filename)
                if (path, item.filename) not in covered or item.file_size > MAX_BYTES:
                    raise ValueError('embedded native binary is not bound to its actual runtime graph or component')
                with tempfile.TemporaryDirectory(prefix='xssi-native-inventory-') as temporary:
                    binary = Path(temporary) / 'binary'
                    total = len(magic)
                    with binary.open('wb') as output:
                        output.write(magic)
                        while chunk := source.read(1024 * 1024):
                            total += len(chunk)
                            if total > MAX_BYTES:
                                raise ValueError('embedded native binary exceeds its bound')
                            output.write(chunk)
                    if total != item.file_size:
                        raise ValueError('embedded native binary size differs')
                    imports = import_requirements(binary)
                    result.append({'path':path,'archive_entry':item.filename,**imports})
    if digest(stage / path) != checksum:
        raise ValueError('archive changed during native dependency inspection')
    return result


def native_graphs(stage, paths, inventory, product, version, revision, target):
    graphs=[];bindings=[];evidence=[]
    for path in paths:
        path=Path(path).resolve(strict=True)
        if not path.is_relative_to(stage):
            raise ValueError('native package receipt is outside the final release')
        name=relative(path.relative_to(stage).as_posix())
        if inventory.get(name)!=digest(path):
            raise ValueError('native package receipt changed before finalization')
        receipt=load(path)
        fields(receipt,['format_version','artifact','inner_bom','installed_files','installed_symlinks','embedded_files'],['package_metadata'])
        if type(receipt['format_version'])is not int or receipt['format_version']!=1:
            raise ValueError('native package receipt version is unsupported')
        artifact=receipt['artifact'];fields(artifact,['path','sha256','size','format'])
        binary=relative(artifact['path']);checksum=sha(artifact['sha256'])
        if artifact['format'] not in ('deb','rpm','pkg','msi') or inventory.get(binary)!=checksum or type(artifact['size'])is not int or (stage/binary).stat().st_size!=artifact['size']:
            raise ValueError('native package differs from its extraction receipt')
        inner=receipt['inner_bom'];fields(inner,['path','sha256'])
        inner_path=relative(inner['path'])
        if inventory.get(inner_path)!=sha(inner['sha256']):
            raise ValueError('native package inner inventory differs from its receipt')
        bom=load(stage/inner_path)
        if bom.get('bomFormat')!='CycloneDX' or bom.get('specVersion')!='1.5':
            raise ValueError('native package has no supported inner inventory')
        root=bom['metadata']['component'];properties=bom['metadata'].get('properties',[])
        props={item['name']:item['value'] for item in properties}
        if len(props)!=len(properties) or root['name']!=product or root['version']!=version or props.get('source_revision')!=revision or props.get('target')!=target:
            raise ValueError('native package source or target differs from this release')
        exclusions=json.loads(props['inventory-self-exclusion'])
        own=[value for value in exclusions if value.endswith('/release-sbom.cdx.json')]
        if len(own)!=1:
            raise ValueError('native inner inventory must identify its exact own output')
        observed={}
        for collection,keys in [('installed_files',['path','sha256','size','mode']),
                                ('installed_symlinks',['path','sha256','target']),
                                ('embedded_files',['path','sha256','size','mode'])]:
            for item in receipt[collection]:
                fields(item,keys);location=relative(item['path']);sha(item['sha256'])
                if location in observed:
                    raise ValueError('native receipt repeats an installed object')
                if 'mode' in item:
                    mode=item['mode']
                    header_script=(collection=='embedded_files' and artifact['format']=='rpm' and location in INSTALLER_SCRIPTS and mode is None)
                    if type(item['size'])is not int or not 0<=item['size']<=MAX_BYTES or (not header_script and (type(mode)is not int or not 0<=mode<=0o7777)):
                        raise ValueError('native receipt has an invalid size or mode')
                if 'target' in item and hashlib.sha256(text(item['target']).encode()).hexdigest()!=item['sha256']:
                    raise ValueError('native receipt link target differs from its digest')
                observed[location]=item
        expected={};file_refs=set()
        for item in bom.get('components',[]):
            if item.get('type')!='file':continue
            location=relative(item['name']);hashes=[value['content'] for value in item.get('hashes',[]) if value['alg']=='SHA-256']
            properties=item.get('properties',[]);values={value['name']:value['value'] for value in properties}
            if len(hashes)!=1 or location in expected or len(values)!=len(properties):
                raise ValueError('native inner inventory file metadata is ambiguous')
            actual=observed.get(location)
            if actual is None or actual['sha256']!=sha(hashes[0]):
                raise ValueError('extracted native payload differs from its inner inventory')
            if values.get('file-kind')=='symbolic-link':
                if actual.get('target')!=values.get('link-target'):
                    raise ValueError('extracted native alias differs from its inner inventory')
            else:
                if actual.get('size')!=int(values['file-size']):
                    raise ValueError('native file size differs from its inner inventory')
                scope=values['file-mode-scope']
                required_scope='installer-script' if location in INSTALLER_SCRIPTS else ('build-host' if 'windows' in target else 'installed-posix')
                if scope!=required_scope:
                    raise ValueError('native file permission scope differs from its target')
                if scope in ('installed-posix','installer-script') and actual.get('mode')!=int(values['file-mode']) and not (scope=='installer-script' and artifact['format']=='rpm' and actual.get('mode') is None):
                    raise ValueError('native file mode differs from its inner inventory')
            expected[location]=item;file_refs.add(item['bom-ref'])
        if observed.get(own[0],{}).get('sha256')!=inner['sha256'] or set(observed)!=set(expected)|{own[0]}:
            raise ValueError('native extraction does not match the complete inner file inventory')
        passive=set()
        for item in receipt.get('package_metadata',[]):
            fields(item,['path','sha256','size','mode']);location=relative(item['path']);sha(item['sha256'])
            if artifact['format']!='deb' or location not in ('DEBIAN/control','DEBIAN/md5sums','DEBIAN/conffiles') or location in observed or location in passive:
                raise ValueError('native package contains an undeclared installation action or ambiguous metadata')
            if type(item['size'])is not int or not 0<=item['size']<=MAX_BYTES or type(item['mode'])is not int or not 0<=item['mode']<=0o7777:
                raise ValueError('passive package metadata size or mode is invalid')
            passive.add(location)
        inner_root=root['bom-ref'];outer_root='urn:native-payload:'+checksum
        kept={inner_root,*[item['bom-ref'] for item in bom.get('components',[]) if item.get('type')!='file']}
        graph={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
               'metadata':{'component':{**root,'bom-ref':outer_root}},
               'components':[item for item in bom.get('components',[]) if item.get('type')!='file'],
               'dependencies':[{'ref':outer_root if item['ref']==inner_root else item['ref'],
                  'dependsOn':[outer_root if child==inner_root else child for child in item.get('dependsOn',[]) if child in kept]}
                  for item in bom.get('dependencies',[]) if item['ref'] in kept]}
        graphs.append(graph)
        bindings.append({'ref':outer_root,'files':[{'path':binary,'sha256':checksum,'archive_entry':None}]})
        evidence.append({'path':name,'sha256':inventory[name],'receipt':receipt,
                         'runtime_prerequisites':props.get('runtime-prerequisites','[]')})
    return graphs,bindings,evidence


def finalize(stage, dependency_boms, receipt, product, version, revision, target, build_input_root=None, package_symlinks=False, output_relative=OUTPUT, *, native_packages=()):
    stage = physical_directory(stage)
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('release source is not bound to an immutable Git revision')
    text(product, 128); text(version, 128); text(target, 128)
    relative(output_relative)
    if not output_relative.endswith('.cdx.json'):
        raise ValueError('release inventory output must be an explicit CycloneDX JSON path')
    data = load(receipt)
    fields(data, ['format_version', 'runtime_roots', 'components'])
    if type(data['format_version']) is not int or data['format_version'] != 1:
        raise ValueError('unsupported external inventory contract')
    inventory = files(stage, package_symlinks, output_relative)
    native_boms,native_bindings,native_evidence=native_graphs(stage,native_packages,inventory,product,version,revision,target)
    # Temporary normalized graphs never become extra shipped payload files.
    with tempfile.TemporaryDirectory(prefix='xssi-native-runtime-') as temporary:
        graph_paths=[]
        for index,bom in enumerate(native_boms):
            path=Path(temporary)/f'{index}.json';path.write_text(json.dumps(bom));graph_paths.append(path)
        components, edges, roots = dependencies([*dependency_boms,*graph_paths])
    covered = set()
    bindings = set()
    for binding in [*data['runtime_roots'],*native_bindings]:
        fields(binding, ['ref', 'files'])
        ref = binding['ref']
        if ref not in roots or ref in bindings or not binding['files']:
            raise ValueError('runtime graph must have one actual release-file binding')
        bindings.add(ref)
        for item in binding['files']:
            covered.add(verify_file(item, stage, inventory))
        components[ref]['properties'] = [*components[ref].get('properties', []),
            {'name': 'release-file-bindings', 'value': json.dumps(binding['files'], sort_keys=True)}]
    if bindings != roots:
        raise ValueError('a resolved runtime graph is not bound to the final release')
    platform = []
    external_refs = set()
    for item in data['components']:
        fields(item, ['ref', 'type', 'name', 'version', 'source', 'licenses', 'delivery', 'files', 'dependencies'], ['embedding'])
        ref = text(item['ref'])
        delivery = item['delivery']
        if ref in components or ref in external_refs or delivery not in ('file', 'embedded', 'platform'):
            raise ValueError('third-party component identity or delivery is invalid')
        external_refs.add(ref)
        url = source(item['source'], delivery == 'platform')
        if delivery == 'platform':
            if item['files'] or 'embedding' in item:
                raise ValueError('platform prerequisite cannot claim a shipped file')
            platform.append(item)
            continue
        text(item['name']); text(item['version'])
        if item['type'] not in ('application', 'library', 'data') or not item['licenses'] or not item['files']:
            raise ValueError('shipped component is missing its identity, license or actual files')
        licenses = []
        for license_ in item['licenses']:
            fields(license_, ['name', 'path', 'sha256'])
            name = text(license_['name'])
            license_path = relative(license_['path'])
            if inventory.get(license_path) != sha(license_['sha256']) or (stage / license_path).stat().st_size == 0:
                raise ValueError('upstream license text is missing or differs from its receipt')
            licenses.append({'license': {'name': name, 'properties': [
                {'name': 'license-file', 'value': license_path},
                {'name': 'license-sha256', 'value': license_['sha256']}]}})
        for file in item['files']:
            covered.add(verify_file(file, stage, inventory))
        if 'embedding' in item and delivery != 'embedded':
            raise ValueError('build-input evidence requires an embedded component')
        if 'embedding' in item or (delivery == 'embedded' and any(file['archive_entry'] is None for file in item['files'])):
            embed = item.get('embedding')
            fields(embed, ['kind', 'source_files', 'target_files'], ['input_root'])
            if embed['kind'] not in ('static-link', 'compiled-resource') or not embed['source_files']:
                raise ValueError('embedded component has no actual build-input evidence')
            location=embed.get('input_root','build' if build_input_root else 'stage')
            if location not in ('stage','build') or (location=='build' and build_input_root is None):
                raise ValueError('embedding has no declared actual build-input root')
            inputs = Path(stage if location=='stage' else build_input_root).resolve(strict=True)
            for file in embed['source_files']:
                fields(file, ['path', 'sha256'])
                path = inputs / relative(file['path'])
                if not path.resolve(strict=True).is_relative_to(inputs) or digest(path) != sha(file['sha256']):
                    raise ValueError('embedded source differs from its actual build input')
            if embed['target_files'] != item['files']:
                raise ValueError('embedding receipt does not identify its final target files')
        children = item['dependencies']
        if not isinstance(children, list) or len(children) != len(set(children)):
            raise ValueError('external component dependency graph is ambiguous')
        components[ref] = {'type': item['type'], 'bom-ref': ref, 'name': item['name'],
            'version': item['version'], 'licenses': licenses,
            'externalReferences': [{'type': 'distribution', 'url': url,
                                    'hashes': [{'alg': 'SHA-256', 'content': item['source']['sha256']}]}],
            'properties': [{'name': 'delivery', 'value': delivery},
                {'name': 'release-file-bindings', 'value': json.dumps(item['files'], sort_keys=True)}]}
        if 'embedding' in item:
            components[ref]['properties'].append({'name': 'actual-build-inputs', 'value': json.dumps(item['embedding'], sort_keys=True)})
        edges[ref] = set(children)
    for children in edges.values():
        if not children <= components.keys():
            raise ValueError('third-party dependency graph refers to an absent component')
    for path in inventory:
        if (stage / path).is_symlink():
            continue
        if PurePosixPath(path).suffix.lower() in FONT_SUFFIXES and (path, None) not in covered:
            raise ValueError('shipped font has no upstream component and license receipt')
        if PurePosixPath(path).suffix.lower() in PACKAGE_ARCHIVES:
            with zipfile.ZipFile(stage / path) as archive:
                for item in archive.infolist():
                    if PurePosixPath(item.filename).suffix.lower() in FONT_SUFFIXES and (path, item.filename) not in covered:
                        raise ValueError('embedded font has no upstream component and license receipt')
    prerequisites = []
    for path in inventory:
        if (stage / path).is_symlink():
            continue
        native = import_requirements(stage / path)
        if native is not None:
            if (path, None) not in covered:
                raise ValueError('native executable or library has no resolved component binding')
            prerequisites.append({'path': path, **native})
        if PurePosixPath(path).suffix.lower() in PACKAGE_ARCHIVES:
            prerequisites.extend(archived_import_requirements(stage,path,covered,inventory[path]))
    release_ref = f'urn:release:{product}:{version}:{revision}:{target}'
    file_refs = {}
    for path, checksum in inventory.items():
        ref = f'urn:release-file:{path}'
        file_refs[path] = ref
        if ref in components:
            raise ValueError('file component collides with a dependency identity')
        components[ref] = {'type': 'file', 'bom-ref': ref, 'name': path,
                           'hashes': [{'alg': 'SHA-256', 'content': checksum}],
                           'properties': [
                               {'name':'file-size','value':str((stage/path).lstat().st_size)},
                               {'name':'file-mode','value':str(stat.S_IMODE((stage/path).lstat().st_mode))},
                               {'name':'file-mode-scope','value':'installer-script' if path in INSTALLER_SCRIPTS else ('build-host' if 'windows' in target else 'installed-posix')}]}
        if (stage / path).is_symlink():
            components[ref]['properties'].extend([
                {'name': 'file-kind', 'value': 'symbolic-link'},
                {'name': 'link-target', 'value': os.readlink(stage / path)},
                {'name': 'delivered-referent', 'value': package_link_target(stage, path)},
                {'name': 'hash-input', 'value': 'UTF-8 bytes of the symbolic link target'}])
        edges[ref] = set()
    edges[release_ref] = roots | external_refs.difference(item['ref'] for item in platform) | set(file_refs.values())
    document = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'metadata': {'component': {'type': 'application', 'bom-ref': release_ref, 'name': product, 'version': version},
            'properties': [{'name': 'source_revision', 'value': revision}, {'name': 'target', 'value': target},
                {'name': 'runtime-prerequisites', 'value': json.dumps(prerequisites, sort_keys=True)},
                {'name': 'platform-provided-components', 'value': json.dumps(platform, sort_keys=True)},
                {'name': 'verified-native-packages', 'value': json.dumps(native_evidence,sort_keys=True)},
                {'name': 'inventory-self-exclusion', 'value': json.dumps(sorted({output_relative, 'share/package.json', 'share/package.sha256'}))}]},
        'components': [components[key] for key in sorted(components)],
        'dependencies': [{'ref': key, 'dependsOn': sorted(value)} for key, value in sorted(edges.items())]}
    if files(stage, package_symlinks, output_relative) != inventory:
        raise ValueError('release content changed before final inventory publication')
    encoded=(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode('utf-8')
    if len(encoded)>MAX_JSON:
        raise ValueError('final inventory document exceeds its byte bound')
    destination = stage / output_relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.release-sbom-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--dependency-bom', type=Path, action='append', default=[])
    parser.add_argument('--external-components', type=Path, required=True)
    parser.add_argument('--product', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--build-input-root', type=Path)
    parser.add_argument('--package-symlinks', action='store_true', help='verify native package installation aliases within the delivered tree')
    parser.add_argument('--output-relative', default=OUTPUT, help='actual metadata location in the final package layout')
    parser.add_argument('--native-package-receipt',type=Path,action='append',default=[])
    args = parser.parse_args()
    finalize(args.stage, args.dependency_bom, args.external_components, args.product,
             args.version, args.source_revision, args.target, args.build_input_root, args.package_symlinks,args.output_relative,
             native_packages=args.native_package_receipt)


if __name__ == '__main__':
    main()
