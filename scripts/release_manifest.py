#!/usr/bin/env python3
"""Create and verify the complete final delivery with SHA-256 checksums."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_sbom

MANIFEST = 'share/package.json'
CHECKSUM = 'share/package.sha256'
PRODUCTS = {'xsoc', 'xscc', 'xcoc', 'xszc', 'xssc', 'xssi', 'taken-my'}


def bounded(path, maximum):
    return release_sbom.bounded(path, maximum)


def physical_stage(stage):
    stage = Path(stage).absolute()
    current = Path(stage.anchor)
    for part in stage.parts[1:]:
        current /= part
        info=current.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('delivery root must use physical directories')
    return stage


def identity(product, version, revision, target):
    if product not in PRODUCTS or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?', version) or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('client release identity is invalid')
    release_sbom.text(target, 128)
    if not re.fullmatch('[A-Za-z0-9_-]+', target):
        raise ValueError('client target is invalid')
    return {'product': product, 'version': version, 'source_revision': revision, 'target': target}


def inventory(stage):
    # SBOM excludes itself; the complete file manifest must include it.
    checksums = release_sbom.files(stage, output_relative=MANIFEST)
    entries = []
    for name, checksum in checksums.items():
        info = (stage / name).lstat()
        mode = stat.S_IMODE(info.st_mode)
        if mode & (0o7000 if os.name=='nt' else 0o7022):
            raise ValueError('client delivery has a special or publicly writable file mode')
        entries.append({'path': name, 'sha256': checksum, 'size': info.st_size, 'mode': mode})
    return entries


def validate_sbom(stage, expected):
    document = release_sbom.load(stage / release_sbom.OUTPUT)
    if document.get('bomFormat') != 'CycloneDX' or document.get('specVersion') != '1.5':
        raise ValueError('final client SBOM is missing or unsupported')
    component = document['metadata']['component']
    properties = document['metadata'].get('properties', [])
    names = [item['name'] for item in properties]
    if len(names) != len(set(names)):
        raise ValueError('final SBOM metadata is ambiguous')
    values = {item['name']: item['value'] for item in properties}
    if component.get('name') != expected['product'] or component.get('version') != expected['version'] or values.get('source_revision') != expected['source_revision'] or values.get('target') != expected['target']:
        raise ValueError('final SBOM and release identity differ')
    actual = release_sbom.files(stage)
    recorded = {}
    for item in document.get('components', []):
        if item.get('type') != 'file':
            continue
        name = release_sbom.relative(item['name'])
        hashes = [value['content'] for value in item.get('hashes', []) if value['alg'] == 'SHA-256']
        if name in recorded or len(hashes) != 1:
            raise ValueError('final SBOM file inventory is ambiguous')
        recorded[name] = release_sbom.sha(hashes[0])
    if recorded != actual:
        raise ValueError('final SBOM does not cover the actual final delivery')


def seal(path, contents):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_BINARY',0), 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())


def finalize(stage, product, version, revision, target):
    stage = physical_stage(stage)
    expected = identity(product, version, revision, target)
    validate_sbom(stage, expected)
    if (stage / MANIFEST).exists() or (stage / CHECKSUM).exists():
        raise ValueError('release finalization requires a delivery without existing checksum authority')
    entries = inventory(stage)
    document = {'manifest_version': 1, 'kind': 'release-inventory', 'identity': expected, 'files': entries}
    raw = (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
    checksum = (hashlib.sha256(raw).hexdigest() + '\n').encode()
    if inventory(stage) != entries:
        raise ValueError('client delivery changed before checksum publication')
    seal(stage / MANIFEST, raw)
    os.chmod(stage / MANIFEST, 0o644)
    seal(stage / CHECKSUM, checksum)
    os.chmod(stage / CHECKSUM, 0o644)
    return document


def verify(stage):
    stage = physical_stage(stage)
    raw = bounded(stage / MANIFEST, release_sbom.MAX_JSON)
    checksum = bounded(stage / CHECKSUM, 65)
    if checksum != (hashlib.sha256(raw).hexdigest() + '\n').encode():
        raise ValueError('client release manifest SHA-256 mismatch')
    def unique(pairs):
        value = {}
        for name, item in pairs:
            if name in value:
                raise ValueError('release manifest has duplicate fields')
            value[name] = item
        return value
    document = json.loads(raw, object_pairs_hook=unique)
    release_sbom.fields(document, ['manifest_version', 'kind', 'identity', 'files'])
    if type(document['manifest_version']) is not int or document['manifest_version'] != 1 or document['kind'] != 'release-inventory':
        raise ValueError('unsupported client release manifest')
    release_sbom.fields(document['identity'], ['product', 'version', 'source_revision', 'target'])
    expected = identity(document['identity']['product'], document['identity']['version'], document['identity']['source_revision'], document['identity']['target'])
    if inventory(stage) != document['files']:
        raise ValueError('client file inventory differs from the final delivery')
    validate_sbom(stage, expected)
    if bounded(stage / MANIFEST, release_sbom.MAX_JSON) != raw or bounded(stage / CHECKSUM, 65) != checksum:
        raise ValueError('client release checksum authority changed during verification')
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='command', required=True)
    create = actions.add_parser('finalize')
    create.add_argument('stage', type=Path)
    for argument in ('product', 'version', 'source-revision', 'target'):
        create.add_argument('--' + argument, required=True)
    check = actions.add_parser('verify')
    check.add_argument('stage', type=Path)
    args = parser.parse_args()
    if args.command == 'finalize':
        finalize(args.stage, args.product, args.version, args.source_revision, args.target)
    else:
        verify(args.stage)


if __name__ == '__main__':
    main()
