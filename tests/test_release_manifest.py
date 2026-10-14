import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_manifest as manifest
import release_sbom as sbom


class ClientChecksumTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xssi-client-checksum-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / 'delivery'
        self.stage.mkdir()
        (self.stage / 'xszc.ipa').write_bytes(b'final mobile package test content')
        # No archive suffix in this test: archive/native entry binding is
        # separately exercised by the actual release-inventory tests.
        (self.stage / 'xszc.ipa').rename(self.stage / 'mobile.pkg')
        bom = self.root / 'runtime.json'
        bom.write_text(json.dumps({'bomFormat': 'CycloneDX', 'specVersion': '1.5',
            'metadata': {'component': {'type': 'application', 'name': 'xszc-mobile',
                'version': '1.0.0', 'bom-ref': 'mobile-runtime'}},
            'components': [], 'dependencies': [{'ref': 'mobile-runtime', 'dependsOn': []}]}))
        receipt = self.root / 'external.json'
        receipt.write_text(json.dumps({'format_version': 1, 'runtime_roots': [
            {'ref': 'mobile-runtime', 'files': [{'path': 'mobile.pkg',
                'sha256': sbom.digest(self.stage / 'mobile.pkg'), 'archive_entry': None}]}],
            'components': []}))
        sbom.finalize(self.stage, [bom], receipt, 'xszc', '1.0.0', '1' * 40, 'aarch64-apple-ios')
    def finalize(self):
        return manifest.finalize(self.stage, 'xszc', '1.0.0', '1' * 40, 'aarch64-apple-ios')

    def verify(self):
        return manifest.verify(self.stage)

    def test_checksum_covers_payload_and_inventory(self):
        signed = self.finalize()
        self.assertEqual(self.verify(), signed)
        files = {item['path'] for item in signed['files']}
        self.assertEqual(files, {'mobile.pkg', sbom.OUTPUT})
        self.assertEqual((self.stage / manifest.CHECKSUM).stat().st_size, 65)
        with self.assertRaises(ValueError):
            self.finalize()

    def test_changed_added_removed_file_mode_and_checksum_reject(self):
        self.finalize()
        package = self.stage / 'mobile.pkg'
        original = package.read_bytes()
        package.write_bytes(original + b'changed')
        with self.assertRaises(ValueError):
            self.verify()
        package.write_bytes(original)
        (self.stage / 'unexpected').write_text('not signed')
        with self.assertRaises(ValueError):
            self.verify()
        (self.stage / 'unexpected').unlink()
        package.chmod(0o600)
        with self.assertRaises(ValueError):
            self.verify()
        package.chmod(0o644)
        package.unlink()
        with self.assertRaises(ValueError):
            self.verify()
        package.write_bytes(original)
        checksum = self.stage / manifest.CHECKSUM
        checksum.write_bytes(b'0' * 64 + b'\n')
        with self.assertRaises(ValueError):
            self.verify()

    def test_wrong_identity_and_stale_sbom_reject_before_publication(self):
        with self.assertRaises(ValueError):
            manifest.finalize(self.stage, 'xcoc', '1.0.0', '1' * 40, 'aarch64-apple-ios')
        (self.stage / 'mobile.pkg').write_bytes(b'changed after SBOM')
        with self.assertRaises(ValueError):
            self.finalize()
        self.assertFalse((self.stage / manifest.MANIFEST).exists())
        self.assertFalse((self.stage / manifest.CHECKSUM).exists())

    def test_changed_manifest_and_missing_checksum_reject(self):
        self.finalize()
        path = self.stage / manifest.MANIFEST
        original = path.read_bytes()
        path.write_bytes(original + b' ')
        with self.assertRaises(ValueError):
            self.verify()
        path.write_bytes(original)
        (self.stage / manifest.CHECKSUM).unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()


if __name__ == '__main__':
    unittest.main()
