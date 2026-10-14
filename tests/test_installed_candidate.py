"""Candidate boundaries with real filesystem/hash/Git checks, no fake install run.

Opaque ELF-prefixed bytes exercise the receipt boundary only. These tests never
claim that those fixtures are compiled products or run an installer with them.
"""
import copy
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/package-installed-candidate.py'
spec = importlib.util.spec_from_file_location('installed_candidate', SCRIPT)
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class CandidateBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='xssi-candidate-boundary-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / 'server'
        self.payload = b'\x7fELF-opaque-test-boundary-bytes-never-executed\n'
        self.binary.write_bytes(self.payload)
        self.product = 'xscs'
        self.version = '1.0.1'
        self.revision = 'a' * 40
        self.schema = {'application': self.product, 'application_version': 'current',
                       'schema_revision': 1, 'schema_sha256': 'c' * 64}
        self.state = {'contract_version': 1, 'application': self.product,
                      'application_version': self.version, 'source_revision': self.revision,
                      'schema': {'revision': 1, 'sha256': 'c' * 64}}
        self.identity = {'product': self.product, 'version': self.version, 'source_revision': self.revision,
                         'target': candidate.TARGET, 'state_contract_sha256': sha(encoded(self.state))}
        self.web = {'format': 'web-assets-v1', 'files': [{'path': 'index.html', 'content_type': 'text/html',
                    'size': 12, 'sha256': 'd' * 64}]}
        self.frontend = {'format_version': 1, 'distribution': 'dist', 'modules': [],
                         'outputs': [{'path': 'index.html', 'sha256': 'd' * 64}]}
        self.materials = {
            'xscs-identity.json': encoded(self.identity),
            'xscs-schema.json': encoded(self.schema),
            'xscs-state-contract.json': encoded(self.state),
            'xscs-web-assets.json': encoded(self.web),
            'contracts/install.json': encoded({'contract_version': 1, 'identity': self.identity,
                                                         'schema_identity': self.schema}),
            'frontend.json': encoded(self.frontend),
        }
        compiled = {'format': 'xssi-build-v1', 'product': self.product, 'version': self.version,
                    'source_revision': self.revision, 'target': candidate.TARGET,
                    'web_assets_sha256': sha(encoded(self.web))}
        self.receipt = {'format': 'xssi-web-build-receipt-v1', 'binary_sha256': sha(self.payload),
                        'identity_sha256': sha(encoded(compiled)),
                        'inventory_sha256': sha(encoded(self.web)),
                        'identity': compiled, 'inventory': self.web}
        self.receipt_path = Path(str(self.binary) + '.xssi-web-build.json')
        self.save_receipt()

    def save_receipt(self):
        self.receipt_path.write_bytes(encoded(self.receipt))

    def validate(self):
        return candidate.validate_build(self.binary, self.materials, self.product, self.version, self.revision)

    def init_git(self, root):
        root.mkdir()
        subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
        (root / 'tracked').write_text('owned immutable fixture\n')
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=Fixture', '-c',
                        'user.email=fixture@example.invalid', 'commit', '--quiet', '-m', 'Owned fixture'], check=True)
        return candidate.git(root, 'rev-parse', 'HEAD')

    def test_exact_payload_and_all_matching_receipts_are_preserved(self):
        digest, identity = self.validate()
        self.assertEqual(digest, sha(self.payload))
        self.assertEqual(identity, self.identity)

    def test_receipt_required_and_never_executes_the_server(self):
        with patch.object(candidate.subprocess, 'run') as run:
            self.validate()
            run.assert_not_called()
        self.receipt_path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.validate()

    def test_binary_replacement_is_rejected(self):
        self.binary.write_bytes(self.payload + b'replaced')
        with self.assertRaisesRegex(ValueError, 'exact build receipt'):
            self.validate()

    def test_all_four_identity_fields_must_match_both_receipts(self):
        for side in ('compiled', 'package'):
            for key, wrong in [('product', 'xsos'), ('version', '9.9.9'),
                               ('source_revision', 'b' * 40), ('target', 'aarch64-unknown-linux-gnu')]:
                with self.subTest(side=side, key=key):
                    original = copy.deepcopy(self.receipt)
                    materials = copy.deepcopy(self.materials)
                    if side == 'compiled':
                        self.receipt['identity'][key] = wrong
                        self.receipt['identity_sha256'] = sha(encoded(self.receipt['identity']))
                        self.save_receipt()
                    else:
                        changed = copy.deepcopy(self.identity)
                        changed[key] = wrong
                        self.materials['xscs-identity.json'] = encoded(changed)
                    with self.assertRaisesRegex(ValueError, 'product/version/revision/target'):
                        self.validate()
                    self.receipt, self.materials = original, materials
                    self.save_receipt()

    def test_duplicate_or_missing_build_receipt_fields_are_rejected(self):
        self.receipt_path.write_bytes(self.receipt_path.read_bytes()[:-1] + b',"format":"replacement"}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.validate()
        self.receipt.pop('binary_sha256')
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'exact build receipt'):
            self.validate()

    def test_all_metadata_outputs_are_mandatory(self):
        for field in list(self.materials):
            with self.subTest(field=field):
                materials = dict(self.materials)
                self.materials.pop(field)
                with self.assertRaisesRegex(ValueError, 'missing exact build metadata'):
                    self.validate()
                self.materials = materials

    def test_cargo_hardlinked_binary_is_accepted_but_linked_metadata_is_rejected(self):
        linked = self.root / 'linked'
        os.link(self.binary, linked)
        self.assertEqual(self.binary.stat().st_nlink, 2)
        self.assertEqual(self.validate()[0], sha(self.payload))
        linked.write_bytes(self.payload + b'changed via deps hardlink')
        with self.assertRaisesRegex(ValueError, 'exact build receipt'):
            self.validate()
        self.binary.write_bytes(self.payload)
        linked.unlink()
        self.binary.rename(linked)
        self.binary.symlink_to(linked)
        with self.assertRaises((ValueError, OSError)):
            self.validate()
        metadata = self.root / 'metadata'
        metadata.mkdir()
        os.link(self.receipt_path, metadata / 'identity.json')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            candidate.read_metadata(metadata)
        (metadata / 'identity.json').unlink()
        (metadata / 'identity.json').symlink_to(self.receipt_path)
        with self.assertRaises((ValueError, OSError)):
            candidate.read_metadata(metadata)

    def test_metadata_snapshot_preserves_exact_bytes(self):
        metadata = self.root / 'metadata'
        metadata.mkdir()
        for relative, content in self.materials.items():
            destination = metadata / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        self.assertEqual(candidate.read_metadata(metadata), self.materials)

    def test_source_must_be_exact_and_clean_including_untracked_files(self):
        source = self.root / 'source'
        revision = self.init_git(source)
        candidate.verify_checkout(source, revision)
        with self.assertRaisesRegex(ValueError, 'exact clean'):
            candidate.verify_checkout(source, 'b' * 40)
        (source / 'untracked').write_text('not part of the reviewed source\n')
        with self.assertRaisesRegex(ValueError, 'exact clean'):
            candidate.verify_checkout(source, revision)
        (source / 'untracked').unlink()
        (source / 'tracked').write_text('modified\n')
        with self.assertRaisesRegex(ValueError, 'exact clean'):
            candidate.verify_checkout(source, revision)

    def test_pinned_installer_must_match_and_be_clean(self):
        source = self.root / 'source'
        (source / 'config').mkdir(parents=True)
        installer = self.root / 'installer'
        pin = self.init_git(installer)
        lock = source / 'config/xssi.lock'
        lock.write_text(f'git_rev={pin}\n')
        self.assertEqual(candidate.verify_installer(source, installer), pin)
        lock.write_text('git_rev=' + 'b' * 40 + '\n')
        with self.assertRaisesRegex(ValueError, 'reviewed XSSI pin'):
            candidate.verify_installer(source, installer)
        lock.write_text(f'git_rev={pin}\n')
        (installer / 'tracked').write_text('modified producer\n')
        with self.assertRaisesRegex(ValueError, 'exact clean'):
            candidate.verify_installer(source, installer)

    def test_installer_pin_rejects_mutable_ambiguous_or_zero_revisions(self):
        source = self.root / 'source'
        (source / 'config').mkdir(parents=True)
        lock = source / 'config/xssi.lock'
        for value in ['main', '0' * 40, 'a' * 40 + '\ngit_rev=' + 'b' * 40, 'a' * 40 + '\n']:
            lock.write_text('git_rev=' + value + '\n')
            with self.subTest(value=value), self.assertRaises(ValueError):
                candidate.installer_pin(source)

    def test_candidate_uses_normal_package_and_verify_without_tags_or_server_rebuild(self):
        text = SCRIPT.read_text()
        self.assertIn("installer / 'scripts/build-package.sh'", text)
        self.assertIn('verified = package.verify(stage)', text)
        self.assertIn('product_release.stage_verified_server(', text)
        self.assertIn('product_release.stage_original_notices(', text)
        self.assertNotIn("['cargo', 'build'", text)
        self.assertNotIn("'refs/tags/", text)
        self.assertNotIn('product_release.main(', text)

    def test_only_the_product_with_reviewed_payload_staging_is_enabled(self):
        self.assertEqual(candidate.PRODUCTS, {'xscs'})

    def test_new_owned_staging_directories_have_exact_modes_with_private_umask(self):
        old = os.umask(0o077)
        try:
            destination = self.root / 'stage/share/contracts/install.json'
            candidate.write(destination, b'owned fixture')
        finally:
            os.umask(old)
        for directory in [destination.parent, destination.parent.parent, self.root / 'stage']:
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o644)
        with self.assertRaises(FileExistsError):
            candidate.write(destination, b'replacement')
        self.assertEqual(destination.read_bytes(), b'owned fixture')

    def test_children_have_no_signing_or_repository_credentials(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'redacted', 'XSSI_SIGNING_KEY': 'redacted',
                                    'HTTPS_PROXY': 'http://proxy.invalid', 'XSSI_BUILD_METADATA_DIR': '/old'}, clear=True):
            env = candidate.environment()
        self.assertNotIn('GH_TOKEN', env)
        self.assertNotIn('XSSI_SIGNING_KEY', env)
        self.assertNotIn('XSSI_BUILD_METADATA_DIR', env)
        self.assertEqual(env['HTTPS_PROXY'], 'http://proxy.invalid')
        self.assertEqual(env['GIT_NO_REPLACE_OBJECTS'], '1')
        self.assertEqual(env['PYTHONDONTWRITEBYTECODE'], '1')


if __name__ == '__main__':
    unittest.main()
