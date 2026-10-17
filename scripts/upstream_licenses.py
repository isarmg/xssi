"""Retain reviewed missing license texts from their actual upstream authority."""
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.request
from urllib.parse import urlsplit

from frontend_receipt import retain
import release_sbom as authority

ROOT = Path(__file__).resolve().parent
MAX_LICENSE = 64 * 1024
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
FILE = re.compile(r'^(?:licen[cs]e|copying|notice|unlicense)(?:[._-].*)?$', re.I)


def reviewed():
    result = authority.load(ROOT / 'upstream-licenses.json')
    authority.fields(result, ['format_version', 'registry'])
    if type(result['format_version']) is not int or result['format_version'] != 1:
        raise ValueError('unsupported reviewed upstream license definitions')
    if not isinstance(result['registry'], list):
        raise ValueError('reviewed upstream license definitions require package lists')
    return result


def _public(url):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in ('raw.githubusercontent.com', 'www.apache.org', 'spdx.org')
            or parsed.username or parsed.password or parsed.port is not None
            or parsed.query or parsed.fragment or not parsed.path.startswith('/')):
        raise ValueError('upstream license source is not its reviewed public HTTPS endpoint')
    if parsed.hostname == 'spdx.org' and parsed.path not in ('/licenses/MIT.txt', '/licenses/Apache-2.0.txt'):
        raise ValueError('standard license source is not an explicitly supported SPDX text')


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        _public(url)
        return super().redirect_request(request, response, code, message, headers, url)


def _fetch(url):
    _public(url)
    with urllib.request.build_opener(_Redirects()).open(url, timeout=20) as response:
        _public(response.geturl())
        data = response.read(MAX_LICENSE + 1)
    if len(data) > MAX_LICENSE:
        raise ValueError('upstream license text exceeds its bound')
    return data


def _download(url, environment):
    # The shared runner bounds wall time, output and the entire process tree.
    # urllib's socket timeout alone cannot bound a peer trickling bytes forever.
    from sbom import run
    # A fresh interpreter does not inherit the parent's dont_write_bytecode.
    # Its imports must not create ignored caches in the immutable tool source.
    return run([sys.executable, '-B', str(Path(__file__).resolve()), '--download', url],
               ROOT, environment, maximum=MAX_LICENSE, timeout=90)


def _directory(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('upstream license paths require canonical physical directories')
    return authority.physical_directory(path)


def _file(path):
    if '..' in Path(path).parts:
        raise ValueError('upstream license file escapes its physical directory')
    _directory(path.parent)
    return authority.bounded(path, 1024 * 1024)


def _present(package, source):
    candidates = []
    if package.get('license_file'):
        candidate = source / package['license_file']
        try:
            candidate.absolute().relative_to(source)
        except ValueError:
            raise ValueError('declared license file escapes its own dependency') from None
        candidates.append(candidate)
    for entry in source.iterdir():
        if FILE.fullmatch(entry.name):
            candidates.append(entry)
        elif entry.name == 'LICENSES':
            # Node owns validation of the approved SPDX filenames in this exact
            # current layout; it rejects links, nested and unknown directory entries.
            _directory(entry)
            children = list(entry.iterdir())
            if not children:
                raise ValueError('dependency LICENSES directory is empty')
            candidates.extend(children)
    for path in candidates:
        try:
            path.absolute().relative_to(source)
        except ValueError:
            raise ValueError('license file escapes its own dependency') from None
        _file(path)
    return bool(candidates)


def _registry(package, directory, definition):
    authority.fields(definition, ['name', 'version', 'package_checksum', 'repository', 'revision',
                     'vcs_path', 'manifest_sha256', 'vcs_sha256', 'license', 'licenses'], ['selected_license', 'standard_license'])
    if package['source'] != REGISTRY or package.get('repository') != definition['repository'] or package.get('license') != definition['license']:
        raise ValueError('registry package differs from its reviewed license authority')
    checksum = authority.load(directory / '.cargo-checksum.json')
    if checksum.get('package') != definition['package_checksum'] or not isinstance(checksum.get('files'), dict):
        raise ValueError('registry package archive differs from its reviewed SHA-256')
    for name, expected in [('Cargo.toml.orig', definition['manifest_sha256']),
                           ('.cargo_vcs_info.json', definition['vcs_sha256'])]:
        authority.sha(expected)
        if checksum['files'].get(name) != expected or hashlib.sha256(_file(directory / name)).hexdigest() != expected:
            raise ValueError('registry package provenance differs from its reviewed source')
    vcs = authority.load(directory / '.cargo_vcs_info.json')
    if vcs.get('git', {}).get('sha1') != definition['revision'] or vcs.get('path_in_vcs') != definition['vcs_path']:
        raise ValueError('registry package upstream revision differs')
    authority.sha(definition['package_checksum'])
    if not re.fullmatch('[0-9a-f]{40}', definition['revision']):
        raise ValueError('registry upstream revision is not immutable')
    repository = urlsplit(definition['repository'])
    if repository.scheme != 'https' or repository.netloc != 'github.com' or repository.query or repository.fragment:
        raise ValueError('registry source has no reviewed owning repository')
    parts = repository.path.strip('/').split('/')
    if (len(parts) < 2 or not all(re.fullmatch(r'[A-Za-z0-9_.-]+', part) for part in parts[:2])
            or (len(parts) != 2 and (len(parts) < 5 or parts[2] != 'tree'
                or '/'.join(parts[4:]) != definition['vcs_path']))):
        raise ValueError('registry repository subtree differs from the exact archive VCS path')
    # Cargo accepts a repository link to a monorepo crate subtree or a .git URL.
    # Original license authority is still the owning repository's exact commit,
    # never a branch named by the display link.
    owning = '/' + parts[0] + '/' + parts[1].removesuffix('.git')
    prefix = 'https://raw.githubusercontent.com' + owning + '/' + definition['revision'] + '/'
    standard = definition.get('standard_license')
    if standard is not None:
        declaration = tomllib.loads(_file(directory / 'Cargo.toml.orig').decode('utf-8'))
        if (standard not in ('MIT', 'Apache-2.0') or definition.get('selected_license') != standard
                or declaration.get('package', {}).get('license') != definition['license']
                or definition['license'] not in ('MIT', 'Apache-2.0', 'MIT OR Apache-2.0')
                or standard not in definition['license'].split(' OR ')
                or len(definition['licenses']) != 1
                or definition['licenses'][0]['name'] != 'SPDX-' + standard + '.txt'
                or definition['licenses'][0]['source'] != 'https://spdx.org/licenses/' + standard + '.txt'):
            raise ValueError('standard text is not bound to an explicit publisher SPDX declaration')
    for item in definition['licenses']:
        url = item['source']
        if url.startswith(prefix):
            authority.relative(url[len(prefix):])
        elif standard is not None and url == 'https://spdx.org/licenses/' + standard + '.txt':
            pass
        elif not (package['name'] in ('objc2-core-foundation', 'objc2-io-kit')
                  and package['version'] == '0.3.2' and definition.get('selected_license') == 'Apache-2.0'
                  and item['name'] == 'APACHE-2.0.txt' and url == 'https://www.apache.org/licenses/LICENSE-2.0'):
            raise ValueError('upstream license is not its owning immutable source or approved direct reference')
    return definition['revision'], definition['licenses']


def prepare(source_root, metadata, selected_ids, environment):
    """Create one current receipt for only the selected actual runtime packages.

    Unknown missing texts and existing output are refused. No generic project
    license substitutes for a dependency's actual upstream copyright or grant.
    """
    source_root = _directory(source_root)
    vendor = _directory(source_root / 'xssi-vendor')
    if not isinstance(selected_ids, set) or not all(isinstance(item, str) for item in selected_ids) or len(selected_ids) > 4096:
        raise ValueError('invalid selected runtime package identifiers')
    if not isinstance(metadata.get('packages'), list):
        raise ValueError('runtime metadata has no packages')
    packages = {item['id']: item for item in metadata['packages']}
    if len(packages) != len(metadata['packages']) or not selected_ids <= packages.keys():
        raise ValueError('runtime selection differs from the unique metadata packages')
    definitions = reviewed()
    registry = {(item['name'], item['version']): item for item in definitions['registry']}
    if len(registry) != len(definitions['registry']):
        raise ValueError('reviewed upstream package definitions repeat an identity')
    output = source_root / 'xssi-upstream-licenses'
    if output.exists() or output.is_symlink():
        raise ValueError('upstream license receipt output already exists')
    pending = []
    for identifier in sorted(selected_ids):
        package = packages[identifier]
        if package['source'] is None:
            continue
        directory = _directory(Path(package['manifest_path']).parent)
        if not directory.is_relative_to(vendor):
            raise ValueError('runtime dependency is outside its private vendor root')
        if _present(package, directory):
            continue
        key = (package['name'], package['version'])
        if package['source'] == REGISTRY and key in registry:
            definition = registry[key]
            revision, licenses = _registry(package, directory, definition)
        else:
            raise ValueError('dependency has no reviewed original license authority: ' + ' '.join(key))
        pending.append((package, definition, revision, licenses))
    receipts = []
    material = {}
    for package, definition, revision, licenses in pending:
        record = {key: package[key] for key in ('name', 'version', 'source')}
        repository = urlsplit(definition['repository'])
        owning = 'https://github.com/' + '/'.join(repository.path.strip('/').split('/')[:2]).removesuffix('.git')
        record.update(repository=owning, revision=revision, licenses=[])
        record['package_checksum'] = definition['package_checksum']
        if 'selected_license' in definition:
            record['selected_license'] = definition['selected_license']
        if 'standard_license' in definition:
            record['standard_license'] = definition['standard_license']
            original = _file(Path(package['manifest_path']).parent / 'Cargo.toml.orig')
            path = package['name'] + '-' + package['version'] + '/PUBLISHER-LICENSE-DECLARATION.toml'
            material[path] = original
            record['licenses'].append({'name': 'PUBLISHER-LICENSE-DECLARATION.toml', 'path': path,
                'sha256': definition['manifest_sha256'], 'kind': 'publisher-declaration',
                'source': 'https://static.crates.io/crates/' + package['name'] + '/' + package['name'] + '-' + package['version'] + '.crate#Cargo.toml.orig'})
        if not re.fullmatch('[A-Za-z0-9_-]+', package['name']) or not re.fullmatch('[A-Za-z0-9.+-]+', package['version']):
            raise ValueError('upstream license output has an invalid package name or version')
        for item in licenses:
            authority.fields(item, ['name', 'source', 'sha256'])
            if not re.fullmatch('[A-Za-z0-9._-]+', item['name']) or item['name'] in ('.', '..'):
                raise ValueError('upstream license has an invalid resource name')
            _public(item['source'])
            expected = authority.sha(item['sha256'])
            data = _download(item['source'], environment)
            if not data or len(data) > MAX_LICENSE or b'\0' in data or hashlib.sha256(data).hexdigest() != expected:
                raise ValueError('upstream original license SHA-256 or text differs')
            data.decode('utf-8', errors='strict')
            path = package['name'] + '-' + package['version'] + '/' + item['name']
            if path in material:
                raise ValueError('upstream original license repeats an output')
            material[path] = data
            retained = {'name': item['name'], 'path': path, 'sha256': expected, 'source': item['source']}
            if 'standard_license' in definition:
                retained['kind'] = 'standard-spdx'
            record['licenses'].append(retained)
        if not record['licenses']:
            raise ValueError('upstream original license receipt is empty')
        receipts.append(record)
    output.mkdir(mode=0o700)
    _directory(output)
    for path, contents in sorted(material.items()):
        retain(output, path, contents)
    retain(output, 'receipt.json', (json.dumps({'format_version': 1, 'packages': receipts}, sort_keys=True, indent=2) + '\n').encode())


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--download':
        raise SystemExit('only the bounded upstream download subprocess is supported')
    sys.stdout.buffer.write(_fetch(sys.argv[2]))
