"""Verify the actual browser Cargo runtime and bind it to its embedded payload."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib

import release_sbom as authority
from release_manifest import bounded
from cargo_selection import selection_from_tree
from frontend_receipt import retain
import sbom

TARGET = 'wasm32-unknown-unknown'
MANIFEST = 'web/xcss-web/Cargo.toml'


def portable_graph(metadata, selection, root, lock):
    packages = {item['id']: item for item in metadata['packages']}
    ids = {}
    manifests = {}
    for identifier in selection['ids']:
        item = packages[identifier]
        manifest = None
        source = item['source']
        if source is None:
            manifest = Path(item['manifest_path']).relative_to(root).as_posix()
            authority.relative(manifest)
        manifests[identifier] = manifest
        ids[identifier] = item['name'] + '@' + item['version'] + ' ' + (source or 'path:' + manifest)
    records = []
    for identifier in selection['ids']:
        item = packages[identifier]
        matches = [value for value in lock['package']
                   if (value['name'], value['version'], value.get('source'))
                   == (item['name'], item['version'], item['source'])]
        if len(matches) != 1:
            raise ValueError('browser runtime package lacks one exact Cargo lock identity')
        records.append({'id': ids[identifier], 'name': item['name'], 'version': item['version'],
                        'source': item['source'], 'manifest': manifests[identifier],
                        'checksum': matches[0].get('checksum'),
                        'dependencies': sorted(ids[child] for child in selection['edges'][identifier])})
    return {'root': ids[selection['root']], 'packages': sorted(records, key=lambda item: item['id'])}


def validate(receipt, source, outputs):
    authority.fields(receipt, ['target', 'mode', 'package', 'manifest', 'default_features',
                              'features', 'profile', 'toolchain', 'lock_sha256', 'source_inputs', 'graph', 'outputs'])
    if (receipt['target'] != TARGET or receipt['mode'] != 'csr' or receipt['manifest'] != MANIFEST
            or receipt['default_features'] is not True or receipt['features'] != []
            or receipt['profile'] != 'release'
            or receipt['toolchain'] != {'rust': '1.99.0', 'wasm_bindgen': '0.2.129'}
            or not isinstance(receipt['package'], str)
            or not re.fullmatch(r'[A-Za-z0-9_-]+', receipt['package'])):
        raise ValueError('browser runtime receipt differs from the sole production CSR build')
    expected = {path: digest for path, digest in outputs.items() if path.endswith('.wasm')}
    recorded = {}
    if not isinstance(receipt['outputs'], list):
        raise ValueError('browser runtime outputs are unavailable')
    for item in receipt['outputs']:
        authority.fields(item, ['path', 'sha256'])
        path = authority.relative(item['path'])
        if path in recorded:
            raise ValueError('browser runtime repeats a WASM output')
        recorded[path] = authority.sha(item['sha256'])
    if not expected or recorded != expected:
        raise ValueError('browser runtime is not bound to every actual WASM output')
    inputs = receipt['source_inputs']
    if not isinstance(inputs, dict) or not 1 <= len(inputs) <= 16384:
        raise ValueError('browser runtime source inventory is unavailable or exceeds its bound')
    if MANIFEST not in inputs or 'web/xcss-web/Cargo.lock' not in inputs:
        raise ValueError('browser runtime must bind its manifest and Cargo lock')
    total = 0
    for name, checksum in inputs.items():
        authority.relative(name)
        if not name.startswith('web/xcss-web/'):
            raise ValueError('browser runtime source escapes its standalone workspace')
        raw = bounded(source / name, 32 * 1024 * 1024)
        total += len(raw)
        if total > 256 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != authority.sha(checksum):
            raise ValueError('browser runtime source changed after compilation')
    if authority.sha(receipt['lock_sha256']) != inputs['web/xcss-web/Cargo.lock']:
        raise ValueError('browser runtime lock differs from its compiled input')
    authority.fields(receipt['graph'], ['root', 'packages'])
    return inputs


def generate(receipt, source, stage, outputs, binary):
    """Re-resolve and inventory only a checked private copy of compiled inputs."""
    source = Path(source).resolve(strict=True)
    inputs = validate(receipt, source, outputs)
    contract = authority.load(stage / 'share/contracts/install.json')
    identity = contract['identity']
    revision = identity['source_revision']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('browser runtime requires the exact product source revision')
    env = {key: value for key, value in os.environ.items()
           if not any(part in key.upper() for part in ('TOKEN', 'PASSWORD', 'SECRET', 'SIGNING', 'PRIVATE_KEY'))}
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER'):
        env.pop(key, None)
    env['TZ'] = 'UTC'
    env['RUSTUP_TOOLCHAIN'] = receipt['toolchain']['rust']
    with tempfile.TemporaryDirectory(prefix='xssi-wasm-inventory-') as temporary:
        workspace = Path(temporary).resolve(strict=True) / 'source'
        workspace.mkdir(mode=0o700)
        for name, checksum in inputs.items():
            raw = bounded(source / name, 32 * 1024 * 1024)
            if hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError('browser runtime source changed while exporting')
            destination = workspace / Path(name).relative_to('web/xcss-web')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        bom = sbom.produce_runtime_cargo_bom(workspace, workspace / 'Cargo.toml', receipt['package'],
            stage, 'wasm', [(workspace, revision)], target=TARGET, features=receipt['features'],
            default_features=receipt['default_features'], environment=env)
        metadata = authority.load(workspace / 'xssi-cargo-full-metadata.json')
        selection = selection_from_tree(metadata, (workspace / 'xssi-cargo-tree.txt').read_text(), receipt['package'])
        lock = tomllib.loads(bounded(workspace / 'Cargo.lock', 8 * 1024 * 1024).decode())
        if portable_graph(metadata, selection, workspace, lock) != receipt['graph']:
            raise ValueError('browser runtime Cargo graph differs from the actual compiled selection')
        # Original notices of integrated local dependencies remain package owned;
        # registry notices are retained by the common mature Cargo producer.
        for item in receipt['graph']['packages']:
            if item['source'] is not None:
                continue
            directory = workspace / Path(item['manifest']).parent
            for path in sorted(directory.iterdir()):
                if path.is_file() and re.fullmatch(r'(LICENSE|LICENCE|COPYING|NOTICE)([._-].*)?', path.name, re.I):
                    retain(stage, 'share/licenses/wasm/' + item['name'] + '/' + path.name,
                           bounded(path, 1024 * 1024))
        graph = authority.load(bom)
        root = graph['metadata']['component']['bom-ref']
    # Retained evidence binds the producer graph, actual compiled source and
    # WASM hashes; the final runtime root also binds the embedding Server bytes.
    retain(stage, 'share/build-inputs/wasm/runtime.json',
           (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode())
    retain(stage, 'share/wasm-Cargo.lock', bounded(source / 'web/xcss-web/Cargo.lock', 8 * 1024 * 1024))
    external = stage / 'share/external-components.json'
    data = authority.load(external)
    if any(item['ref'] == root for item in data['runtime_roots']):
        raise ValueError('browser runtime graph already has a release binding')
    data['runtime_roots'].append({'ref': root, 'files': [{'path': binary,
        'sha256': authority.digest(stage / binary), 'archive_entry': None}]})
    external.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')
    external.chmod(0o644)
    return bom
