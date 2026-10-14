#!/usr/bin/env python3
"""Package an already-built Server through the normal pinned release pipeline.

This candidate gate never builds a replacement Server, creates a tag, or
publishes a release. Product staging and XSSI's producer/verifier own the
package contract; this entry point binds their inputs to the exact CI build.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import package

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'x86_64-unknown-linux-gnu'
# Enable another product only after reviewing its staging/notices/companions.
PRODUCTS = {'xscs'}


def environment():
    value = {key: item for key, item in os.environ.items()
             if not any(part in key.upper() for part in ('TOKEN', 'PASSWORD', 'SECRET', 'SIGNING', 'PRIVATE_KEY'))}
    value.update(GIT_NO_REPLACE_OBJECTS='1', PYTHONDONTWRITEBYTECODE='1')
    for key in ('XSSI_BUILD_METADATA_DIR', 'XSSI_BUILD_RECEIPT_DIR', 'XSSI_BUILD_SOURCE_REVISION',
                'XSSI_IDENTITY_FILE', 'XSSI_SCHEMA_FILE', 'XSSI_FRONTEND_METADATA_FILE'):
        value.pop(key, None)
    return value


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], env=environment(),
                                   stdin=subprocess.DEVNULL, text=True).strip()


def verify_checkout(source, revision):
    if (re.fullmatch(r'[0-9a-f]{40}', revision) is None
            or git(source, 'rev-parse', 'HEAD') != revision
            or git(source, 'status', '--porcelain=v1', '--untracked-files=all')):
        raise ValueError('candidate requires the exact clean source revision')


def installer_pin(source):
    raw = package.bytes_regular(source / 'config/xssi.lock', 128).decode('ascii')
    match = re.fullmatch(r'git_rev=([0-9a-f]{40})\n', raw)
    if match is None or match[1] == '0' * 40:
        raise ValueError('candidate requires one immutable reviewed XSSI pin')
    return match[1]


def verify_installer(source, installer):
    pin = installer_pin(source)
    if git(installer, 'rev-parse', 'HEAD') != pin:
        raise ValueError('candidate installer differs from the reviewed XSSI pin')
    verify_checkout(installer, pin)
    return pin


def read_metadata(metadata):
    package.private_chain(metadata)
    result = {}
    for path in sorted(metadata.rglob('*')):
        if path.is_dir() and not path.is_symlink():
            package.private_chain(path)
            continue
        package.private_chain(path.parent)
        result[path.relative_to(metadata).as_posix()] = package.bytes_regular(path, 16 * 1024 * 1024)
    return result


def binary_digest(binary):
    # Cargo's named executable is normally hardlinked to its deps artifact.
    # The product stager makes an exclusive copy and verifies this hash again.
    if not stat.S_ISREG(binary.lstat().st_mode):
        raise ValueError('candidate Server must be a regular file')
    with binary.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_build(binary, materials, product, version, revision):
    for name in (f'{product}-identity.json', f'{product}-schema.json', f'{product}-state-contract.json',
                 f'{product}-web-assets.json', 'contracts/install.json', 'frontend.json'):
        if name not in materials:
            raise ValueError('candidate is missing exact build metadata: ' + name)
    receipt = package.loads(package.bytes_regular(Path(str(binary) + '.xssi-web-build.json'), 16 * 1024 * 1024))
    identity = package.loads(materials[f'{product}-identity.json'])
    expected = {'product': product, 'version': version, 'source_revision': revision, 'target': TARGET}
    if (receipt.get('format') != 'xssi-web-build-receipt-v1'
            or not isinstance(receipt.get('identity'), dict) or not isinstance(identity, dict)
            or any(receipt['identity'].get(key) != value or identity.get(key) != value for key, value in expected.items())):
        raise ValueError('candidate build and package identities differ from the source product/version/revision/target')
    if binary_digest(binary) != receipt.get('binary_sha256'):
        raise ValueError('candidate Server differs from its exact build receipt')
    return receipt['binary_sha256'], identity


def write(path, value, mode=0o644):
    missing = []
    directory = path.parent
    while not directory.exists():
        missing.append(directory)
        directory = directory.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    with path.open('xb') as stream:
        stream.write(value)
    path.chmod(mode)


def build_candidate(product, source, binary, metadata, output, *, installer=ROOT):
    if product not in PRODUCTS:
        raise ValueError('unsupported candidate product or companion requirement')
    for directory in (source, installer, binary.parent, metadata, output.parent):
        package.private_chain(directory)
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or any(output == root or root in output.parents for root in (source, installer, metadata))):
        raise ValueError('candidate output must be a fresh absolute directory outside its inputs')
    revision = git(source, 'rev-parse', 'HEAD')
    verify_checkout(source, revision)
    pin = verify_installer(source, installer)
    version = tomllib.loads((source / 'Cargo.toml').read_text())['workspace']['package']['version']
    materials = read_metadata(metadata)
    digest, identity = validate_build(binary, materials, product, version, revision)
    # Load only from the already-verified clean product source. These are the
    # exact staging functions used by its annotated-tag-only formal packager.
    spec = importlib.util.spec_from_file_location('product_release', source / 'scripts/package-release.py')
    product_release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product_release)
    epoch = int(git(source, 'show', '-s', '--format=%ct', revision))
    name = f'{product}-{version}-linux-x86_64'
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix='.candidate-', dir=output) as temporary:
        work = Path(temporary)
        stage = work / name
        for directory in (stage, stage / 'bin', stage / 'share'):
            directory.mkdir(mode=0o755)
            directory.chmod(0o755)
        product_release.stage_verified_server(binary, stage / 'bin' / product, revision)
        product_release.stage_original_notices(stage / 'share', source=source)
        inputs = work / 'metadata'
        for relative, value in materials.items():
            write(inputs / relative, value)
            if relative.startswith('contracts/'):
                write(stage / 'share' / relative, value)
        for suffix in ('state-contract', 'web-assets'):
            write(stage / 'share' / f'{suffix}.json', materials[f'{product}-{suffix}.json'])
        write(stage / 'config/config.json.example', package.bytes_regular(source / 'config/config.json.example'))
        write(stage / 'share/README.md', package.bytes_regular(source / 'docs/server-release-readme.md'))
        env = environment()
        env.update({'XSSI_SOURCE_REVISION': revision,
                    'XSSI_IDENTITY_FILE': str(inputs / f'{product}-identity.json'),
                    'XSSI_SCHEMA_FILE': str(inputs / f'{product}-schema.json'),
                    'XSSI_FRONTEND_METADATA_FILE': str(inputs / 'frontend.json')})
        subprocess.run(['bash', str(installer / 'scripts/build-package.sh'), product, str(source), str(stage)],
                       cwd=installer, env=env, stdin=subprocess.DEVNULL, check=True)
        verified = package.verify(stage)
        if verified['identity'] != identity or package.digest(stage / 'bin' / product) != digest:
            raise ValueError('normal package producer changed the candidate Server or identity')
        verify_checkout(source, revision)
        verify_checkout(installer, pin)
        archive = output / f'{name}.tar.gz'
        with archive.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for path in [stage, *sorted(stage.rglob('*'))]:
                    entry = tar.gettarinfo(str(path), arcname=str(path.relative_to(work)))
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ''
                    entry.mtime = epoch
                    if entry.isfile():
                        with path.open('rb') as stream:
                            tar.addfile(entry, stream)
                    else:
                        tar.addfile(entry)
        write(output / 'SHA256SUMS', f'{binary_digest(archive)}  {archive.name}\n'.encode('ascii'))
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('product', choices=sorted(PRODUCTS))
    for name in ('source', 'binary', 'metadata', 'output'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    print(build_candidate(args.product, args.source, args.binary, args.metadata, args.output))


if __name__ == '__main__':
    main()
