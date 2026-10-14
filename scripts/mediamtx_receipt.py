#!/usr/bin/env python3
"""Recover the shipped MediaMTX program's Go graph and original source notices.

Go's own build-info reader identifies linked modules. The same exact Go
toolchain resolves non-test packages from the authenticated, immutable source;
both module sets must agree before any receipt is delivered.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import urllib.error
import zipfile
import io
import time

import release_sbom as sbom

GO_VERSION = 'go1.26.5'
GO_URL = 'https://go.dev/dl/go1.26.5.linux-amd64.tar.gz'
GO_SHA256 = '5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053'
GO_SIZE = 66879095
MAX_MODULES = 2048
MAX_JSON = 32 * 1024 * 1024
MAX_INPUT = 256 * 1024 * 1024
NOTICE = re.compile(r'^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)(?:[._-].*)?$', re.I)


def documents(raw):
    if len(raw) > MAX_JSON:
        raise ValueError('Go metadata exceeds its bound')
    text = raw.decode('utf-8')
    decoder = json.JSONDecoder(object_pairs_hook=unique)
    result = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        result.append(value)
        if len(result) > 16384:
            raise ValueError('Go package metadata exceeds its bound')
        text = text.lstrip()[end:]
    return result


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Go metadata contains duplicate fields')
        value[key] = item
    return value


def module_identity(value):
    path = sbom.text(value['Path'])
    version = sbom.text(value['Version'])
    if not re.fullmatch(r'[A-Za-z0-9._~!/-]+', path) or path.startswith(('/', '-')) or any(part in ('', '.', '..') for part in path.split('/')):
        raise ValueError('Go module path is not canonical')
    if not re.fullmatch(r'v[0-9][A-Za-z0-9.+-]*', version):
        raise ValueError('Go module has no immutable version')
    return path, version


def validate_info(info, version):
    if info.get('GoVersion') != GO_VERSION or info.get('Path') != 'github.com/bluenviron/mediamtx':
        raise ValueError('MediaMTX has unsupported actual Go build identity')
    if module_identity(info['Main']) != ('github.com/bluenviron/mediamtx', version):
        raise ValueError('MediaMTX module does not match the product artifact contract')
    settings = unique((item['Key'], item['Value']) for item in info['Settings'])
    supported = {'-buildmode', '-compiler', 'CGO_ENABLED', 'GOARCH', 'GOOS', 'GOAMD64',
                 'vcs', 'vcs.revision', 'vcs.time', 'vcs.modified'}
    if set(settings) - supported or any(settings.get(key) != value for key, value in {
            '-buildmode': 'exe', '-compiler': 'gc', 'CGO_ENABLED': '0',
            'GOARCH': 'amd64', 'GOOS': 'linux', 'GOAMD64': 'v1',
            'vcs': 'git', 'vcs.modified': 'false'}.items()):
        raise ValueError('MediaMTX build settings cannot be reproduced for graph resolution')
    if not re.fullmatch('[0-9a-f]{40}', settings.get('vcs.revision', '')):
        raise ValueError('MediaMTX source revision is unbound')
    deps = info['Deps']
    if not isinstance(deps, list) or not 1 <= len(deps) <= MAX_MODULES:
        raise ValueError('MediaMTX linked module count is invalid')
    result = {}
    for item in deps:
        identity = module_identity(item)
        if identity[0] in result:
            raise ValueError('MediaMTX linked module identity is ambiguous')
        effective = item.get('Replace', item)
        module_identity(effective)
        if not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', effective.get('Sum', '')):
            raise ValueError('MediaMTX linked source has no authenticated module checksum')
        result[identity[0]] = item
    return settings, result


def archive_license(archive, binary, expected):
    if sbom.digest(binary) != expected:
        raise ValueError('Shipped MediaMTX binary differs from the owned contract')
    with tarfile.open(archive) as package:
        members = package.getmembers()
        if {item.name for item in members} != {'mediamtx', 'mediamtx.yml', 'LICENSE'} or len(members) != 3:
            raise ValueError('MediaMTX release archive has an unexpected payload')
        if any(not item.isfile() or item.size > MAX_INPUT for item in members):
            raise ValueError('MediaMTX release archive contains an unsafe object')
        stream = package.extractfile('mediamtx')
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
            raise ValueError('MediaMTX archive and shipped program differ')
        notice = package.extractfile('LICENSE').read(MAX_INPUT + 1)
        if not notice.strip() or len(notice) > MAX_INPUT:
            raise ValueError('MediaMTX original release license is unavailable')
        return notice


def run(go, arguments, environment, cwd):
    result = subprocess.run([str(go), *arguments], cwd=cwd, env=environment,
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=300)
    if result.returncode:
        diagnostic = result.stderr.decode('utf-8', errors='replace')[-4096:]
        raise ValueError('Exact public Go source resolution failed: ' + diagnostic)
    return documents(result.stdout)


def tool(work, provided, cached_archive):
    archive = Path(cached_archive).resolve(strict=True) if cached_archive else work / 'go.tar.gz'
    if cached_archive is None:
        with urllib.request.urlopen(GO_URL, timeout=60) as response, archive.open('xb') as output:
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > GO_SIZE:
                    raise ValueError('Go toolchain download exceeds its exact size')
                output.write(chunk)
    if archive.stat().st_size != GO_SIZE or sbom.digest(archive) != GO_SHA256:
        raise ValueError('Go build-info toolchain checksum differs')
    with tarfile.open(archive) as package:
        package.extractall(work, filter='data')
    original = work / 'go/bin/go'
    executable = Path(provided).resolve(strict=True) if provided else original
    if sbom.digest(executable) != sbom.digest(original):
        raise ValueError('Go reader differs from the exact original verified toolchain')
    return executable, work / 'go'


def environment(work):
    network = ('PATH', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'HTTP_PROXY', 'HTTPS_PROXY',
               'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
               'no_proxy', 'GIT_SSL_CAINFO', 'CURL_CA_BUNDLE', 'REQUESTS_CA_BUNDLE')
    env = {key: os.environ[key] for key in network if key in os.environ}
    env.update({'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off', 'GOFLAGS': '',
                'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
                'GONOSUMDB': '', 'GONOPROXY': '', 'GOPRIVATE': '',
                'GOOS': 'linux', 'GOARCH': 'amd64', 'GOAMD64': 'v1', 'CGO_ENABLED': '0',
                'GOMAXPROCS': '2', 'GOMODCACHE': str(work / 'mod'),
                'GOCACHE': str(work / 'build'), 'GOPATH': str(work / 'path'),
                'HOME': str(work), 'GIT_TERMINAL_PROMPT': '0'})
    return env


def source_record(go, identity, env, cwd):
    values = run(go, ['mod', 'download', '-json', '@'.join(identity)], env, cwd)
    if len(values) != 1 or 'Error' in values[0] or module_identity(values[0]) != identity:
        raise ValueError('Authenticated Go source resolution failed')
    value = values[0]
    base = Path(env['GOMODCACHE']).resolve(strict=True)
    for key in ('Dir', 'Zip', 'GoMod'):
        if not Path(value[key]).resolve(strict=True).is_relative_to(base):
            raise ValueError('Go source resolution escaped its private module cache')
    return value


def ref(identity):
    return 'urn:golang:' + '@'.join(identity)


def fetch(url, maximum):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(maximum + 1)
            break
        except urllib.error.HTTPError as error:
            error.close()
            if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)
    if len(data) > maximum:
        raise ValueError('Original runtime resource exceeds its bound')
    return data


def generated_resources(root, binary, version):
    # The immutable Go source owns the HLS generator's version and checksum.
    owner = root / 'internal/servers/hls/hlsjsdownloader'
    hls_version = (owner / 'VERSION').read_text().strip()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', hls_version):
        raise ValueError('Original HLS.js version is unbound')
    expected = sbom.sha((owner / 'HASH').read_text().strip())
    url = f'https://github.com/video-dev/hls.js/releases/download/{hls_version}/release.zip'
    archive = fetch(url, 10 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != expected:
        raise ValueError('HLS.js original archive differs from the MediaMTX-owned checksum')
    with zipfile.ZipFile(io.BytesIO(archive)) as package:
        if package.namelist().count('dist/hls.min.js') != 1:
            raise ValueError('Original HLS.js resource is missing or ambiguous')
        info = package.getinfo('dist/hls.min.js')
        if info.file_size > 10 * 1024 * 1024:
            raise ValueError('Original HLS.js resource exceeds its bound')
        code = package.read(info)
    shipped = binary.read_bytes()
    if not code or code not in shipped or version.encode() not in shipped:
        raise ValueError('Original generated resources are absent from the actual MediaMTX ELF')
    tag_name = 'refs/tags/' + hls_version
    # Public Git ref resolution avoids a required API token or anonymous REST
    # quota. A peeled annotated tag and a lightweight tag bind exact commits.
    refs = subprocess.run(['git', 'ls-remote', '--exit-code',
                           'https://github.com/video-dev/hls.js.git', tag_name, tag_name + '^{}'],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=60, check=True).stdout.decode().splitlines()
    resolved = {}
    for line in refs:
        revision, name = line.split('\t')
        if name not in (tag_name, tag_name + '^{}') or name in resolved or not re.fullmatch('[0-9a-f]{40}', revision):
            raise ValueError('HLS.js original source revision is ambiguous or unbound')
        resolved[name] = revision
    if tag_name not in resolved:
        raise ValueError('HLS.js original source tag is unavailable')
    revision = resolved.get(tag_name + '^{}', resolved[tag_name])
    license_url = f'https://raw.githubusercontent.com/video-dev/hls.js/{revision}/LICENSE'
    license_ = fetch(license_url, 1024 * 1024)
    if not license_.strip():
        raise ValueError('HLS.js original license is empty')
    (root / 'internal/core/VERSION').write_text(version)
    (root / 'internal/servers/hls/hls.min.js').write_bytes(code)
    return {'version': hls_version, 'archive_url': url, 'archive_sha256': expected,
            'source_revision': revision, 'license_url': license_url, 'license': license_, 'code': code}


def original_notices(root, directories, source_files=()):
    root = root.resolve(strict=True)
    result = {}
    for directory in {root, *directories}:
        directory = directory.resolve(strict=True)
        if not directory.is_relative_to(root):
            raise ValueError('Compiled Go package escaped its authenticated source')
        while True:
            for path in directory.iterdir():
                if NOTICE.fullmatch(path.name):
                    if path.is_dir() and not path.is_symlink():
                        continue
                    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_INPUT:
                        raise ValueError('Original Go license is not a bounded regular file')
                    content = path.read_bytes()
                    if not content.strip():
                        raise ValueError('Original Go license is empty')
                    result[path.relative_to(root).as_posix()] = content
            if directory == root:
                break
            directory = directory.parent
    has_license = any(re.match('LICENSE|LICENCE|COPYING|COPYRIGHT', Path(name).name, re.I) for name in result)
    headers = []
    for name in sorted(source_files):
        path = root / sbom.relative(name)
        if not path.resolve(strict=True).is_relative_to(root):
            raise ValueError('Original source notice escaped its authenticated module')
        with path.open('rb') as source:
            start = source.read(64 * 1024)
        if start.startswith(b'/*'):
            end = start.find(b'*/')
            if end < 0:
                raise ValueError('Original leading notice exceeds its bound')
            header = start[:end + 2]
        else:
            lines = []
            for line in start.splitlines(keepends=True):
                if not line.lstrip().startswith(b'//'):
                    break
                lines.append(line)
            header = b''.join(lines)
        lower = header.lower()
        if b'copyright' not in lower:
            continue
        headers.append(name.encode() + b'\n\n' + header + b'\n')
        # Some actual compiled sources carry the full original license inline
        # instead of a separate file. Preserve those exact source bytes.
        if ((b'redistribution and use' in lower and b'this software is provided' in lower)
                or (b'permission is hereby granted' in lower and b'the software is provided' in lower)):
            has_license = True
    if headers:
        result['SOURCE-NOTICES.txt'] = b'\n'.join(headers)
    if not has_license:
        raise ValueError('Compiled Go source has no original license text')
    return result


def write(stage, name, content):
    path = stage / sbom.relative(name)
    parent = stage
    for part in Path(name).parts[:-1]:
        parent = parent / part
        if parent.exists() or parent.is_symlink():
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError('MediaMTX evidence directory is not physical')
        else:
            parent.mkdir()
    if path.exists():
        if path.is_symlink() or path.read_bytes() != content:
            raise ValueError('MediaMTX evidence conflicts with a delivered file')
    else:
        with path.open('xb') as output:
            output.write(content)
        path.chmod(0o644)
    return {'path': name, 'sha256': sbom.digest(path)}


def record(source_root, stage, archive, *, go=None, go_archive=None):
    source_root = Path(source_root).resolve(strict=True)
    stage = Path(stage).resolve(strict=True)
    archive = Path(archive).resolve(strict=True)
    contract = {}
    for line in (source_root / 'config/mediamtx.lock').read_text().splitlines():
        if line and not line.startswith('#'):
            key, value = line.split('=', 1)
            if key in contract:
                raise ValueError('MediaMTX artifact contract contains duplicate fields')
            contract[key] = value
    if set(contract) != {'version', 'platform', 'sha256'} or contract['platform'] != 'linux_amd64':
        raise ValueError('Unsupported MediaMTX artifact contract')
    binary = stage / 'bin/mediamtx'
    archive_sha256 = sbom.digest(archive)
    notice = archive_license(archive, binary, sbom.sha(contract['sha256']))
    if sbom.digest(archive) != archive_sha256:
        raise ValueError('MediaMTX source archive changed during verification')
    target = {'path': 'bin/mediamtx', 'sha256': sbom.digest(binary), 'archive_entry': None}
    with tempfile.TemporaryDirectory(prefix='xssi-mediamtx-') as temporary:
        work = Path(temporary)
        executable, standard_source = tool(work, go, go_archive)
        env = environment(work)
        env['GOROOT'] = str(standard_source)
        values = run(executable, ['version', '-m', '-json', str(binary)], env, work)
        if len(values) != 1:
            raise ValueError('MediaMTX build information is ambiguous')
        info = values[0]
        settings, linked = validate_info(info, contract['version'])
        main = source_record(executable, module_identity(info['Main']), env, work)
        if main.get('Origin', {}).get('Hash') != settings['vcs.revision']:
            raise ValueError('MediaMTX original source does not match its built revision')
        original_root = Path(main['Dir'])
        if (original_root / 'LICENSE').read_bytes() != notice:
            raise ValueError('MediaMTX archive license differs from its actual original source')
        root = work / 'source'
        shutil.copytree(original_root, root, copy_function=shutil.copyfile)
        for directory, _, _ in os.walk(root):
            Path(directory).chmod(0o700)
        hls = generated_resources(root, binary, contract['version'])
        packages = run(executable, ['list', '-deps', '-json', '-mod=readonly', info['Path']], env, root)
        records = {info['Main']['Path']: main}
        for name, item in linked.items():
            effective = item.get('Replace', item)
            value = source_record(executable, module_identity(effective), env, root)
            if value['Sum'] != effective['Sum']:
                raise ValueError('Go module source differs from the linked binary checksum')
            records[name] = value
        roots = {name: Path(value['Dir']) for name, value in records.items()}
        roots[info['Main']['Path']] = root
        roots['stdlib'] = standard_source
        identities = {name: ref(module_identity(value)) for name, value in records.items()}
        identities['stdlib'] = 'urn:golang:standard-library@' + GO_VERSION
        owners, sources, directories = {}, {}, {}
        for item in packages:
            if item.get('Error') or item.get('DepsErrors') or item.get('ForTest') or item.get('CgoFiles'):
                raise ValueError('Go runtime package graph cannot be resolved exactly')
            owner = 'stdlib' if item.get('Standard') else item.get('Module', {}).get('Path')
            if owner not in roots:
                raise ValueError('Go runtime package has no linked source identity')
            if owner not in ('stdlib', info['Main']['Path']):
                effective = item['Module'].get('Replace', item['Module'])
                if module_identity(effective) != module_identity(records[owner]):
                    raise ValueError('Resolved Go runtime package differs from the linked version')
            owners[item['ImportPath']] = owner
            directory = Path(item['Dir'])
            directories.setdefault(owner, set()).add(directory)
            selected = sources.setdefault(owner, {})
            for key in ('GoFiles', 'SFiles', 'HFiles', 'EmbedFiles', 'SysoFiles'):
                for name in item.get(key, []):
                    path = directory / sbom.relative(name)
                    if not path.resolve(strict=True).is_relative_to(roots[owner]):
                        raise ValueError('Actual compiled Go source escaped its module')
                    name = path.relative_to(roots[owner]).as_posix()
                    selected[name] = sbom.digest(path)
        if set(sources) != set(roots):
            raise ValueError('Source package graph and actual linked module graph differ')
        edges = {name: set() for name in roots}
        for item in packages:
            owner = owners[item['ImportPath']]
            for child in item.get('Imports', []):
                if child not in owners:
                    raise ValueError('Actual Go runtime import has no resolved package')
                if owners[child] != owner:
                    edges[owner].add(identities[owners[child]])
        hls_ref = 'urn:npm:hls.js@' + hls['version'][1:]
        edges[info['Main']['Path']].add(hls_ref)
        prepared = {}
        for name, root in roots.items():
            try:
                notices = original_notices(root, directories[name], sources[name])
            except ValueError as error:
                raise ValueError(f'Original runtime notices are invalid for {name}') from error
            candidates = sorted(path for path in sources[name] if path.endswith('.go') and Path(path).name != 'doc.go')
            if not candidates:
                raise ValueError('Linked Go module has no actual runtime source evidence')
            selected = 'src/runtime/proc.go' if name == 'stdlib' else candidates[0]
            if selected not in sources[name]:
                raise ValueError('Go runtime source is unavailable')
            prepared[name] = (notices, selected, (root / selected).read_bytes())
        if sbom.digest(binary) != target['sha256'] or sbom.digest(archive) != archive_sha256:
            raise ValueError('MediaMTX program or source archive changed during graph recovery')
        components = []
        for name, root in roots.items():
            identity = (name, GO_VERSION) if name == 'stdlib' else module_identity(records[name])
            slug = hashlib.sha256('@'.join(identity).encode()).hexdigest()[:24]
            notices, selected, code = prepared[name]
            licenses = []
            for path, content in sorted(notices.items()):
                file = write(stage, f'share/licenses/mediamtx/{slug}/{path}', content)
                licenses.append({'name': 'Original upstream ' + Path(path).name, **file})
            evidence = {'go_version': GO_VERSION, 'module': {'path': identity[0], 'version': identity[1]},
                        'compiled_sources': sources[name], 'dependencies': sorted(edges[name]),
                        'program_sha256': target['sha256'], 'selected_source': selected}
            if name != 'stdlib':
                evidence['sum'] = records[name]['Sum']
            inputs = [write(stage, f'share/build-inputs/mediamtx/{slug}/source.go', code),
                      write(stage, f'share/build-inputs/mediamtx/{slug}/source.json',
                            (json.dumps(evidence, sort_keys=True, indent=2) + '\n').encode())]
            if name == info['Main']['Path']:
                source = {'url': f'https://github.com/bluenviron/mediamtx/releases/download/{contract["version"]}/mediamtx_{contract["version"]}_linux_amd64.tar.gz', 'sha256': archive_sha256}
            elif name == 'stdlib':
                source = {'url': GO_URL, 'sha256': GO_SHA256}
            else:
                value = records[name]
                cache_path = Path(value['Zip']).relative_to(Path(env['GOMODCACHE']) / 'cache/download').as_posix()
                source = {'url': 'https://proxy.golang.org/' + cache_path, 'sha256': sbom.digest(value['Zip'])}
            component = {'ref': identities[name], 'type': 'application' if name == info['Main']['Path'] else 'library',
                'name': identity[0], 'version': identity[1], 'source': source, 'licenses': licenses,
                'delivery': 'file' if name == info['Main']['Path'] else 'embedded', 'files': [target],
                'dependencies': sorted(edges[name])}
            if name != info['Main']['Path']:
                component['embedding'] = {'kind': 'static-link', 'input_root': 'stage', 'source_files': inputs, 'target_files': [target]}
            components.append(component)
        license_ = write(stage, 'share/licenses/mediamtx/hls.js/LICENSE', hls['license'])
        code = write(stage, 'share/build-inputs/mediamtx/hls.js/hls.min.js', hls['code'])
        provenance = {key: value for key, value in hls.items() if key not in ('license', 'code')}
        evidence = write(stage, 'share/build-inputs/mediamtx/hls.js/source.json',
                         (json.dumps(provenance, sort_keys=True, indent=2) + '\n').encode())
        components.append({'ref': hls_ref, 'type': 'library', 'name': 'hls.js', 'version': hls['version'][1:],
            'source': {'url': hls['archive_url'], 'sha256': hls['archive_sha256']},
            'licenses': [{'name': 'Original upstream LICENSE', **license_}],
            'delivery': 'embedded', 'files': [target], 'dependencies': [],
            'embedding': {'kind': 'compiled-resource', 'input_root': 'stage',
                          'source_files': [code, evidence], 'target_files': [target]}})
        return components


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--go', type=Path)
    parser.add_argument('--go-archive', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = record(args.source_root, args.stage, args.archive, go=args.go, go_archive=args.go_archive)
    with args.output.open('x') as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write('\n')


if __name__ == '__main__':
    main()
