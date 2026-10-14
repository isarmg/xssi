"""Exercise the Server producer order with real archive, hash and graph readers.

Payload and upstream source bytes are explicit opaque fixtures. Only network
requests are replaced; SQLite source retention, frontend archive verification,
receipt merging and final release inventory use their production functions.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

TESTS = Path(__file__).resolve().parent
SCRIPTS = TESTS.parent / 'scripts'
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(SCRIPTS))
import frontend_receipt
import release_sbom
import sqlite_receipt
import test_frontend_receipt as frontend_fixtures
import test_sqlite_receipt as sqlite_fixtures

spec = importlib.util.spec_from_file_location('helper_receipt_producer', SCRIPTS / 'build-helper.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class HelperReceiptOrderTests(unittest.TestCase):
    def setUp(self):
        self.frontend = frontend_fixtures.FrontendReceiptTests()
        self.frontend.setUp()
        self.addCleanup(self.frontend.doCleanups)
        # These temporary fixture roots are internally created, never caller
        # path aliases accepted by the production physical-path readers.
        self.root = self.frontend.root.resolve(strict=True)
        self.source = self.root / 'source'
        self.stage = self.root / 'stage'
        self.frontend.root = self.root
        self.frontend.source = self.source
        self.frontend.web = self.source / 'web'
        self.frontend.stage = self.stage
        self.frontend.metadata = self.root / 'frontend.json'
        native = sqlite_fixtures.SQLiteReceiptTests()
        native.setUp()
        self.addCleanup(native.doCleanups)
        self.helper_source = native.source.resolve(strict=True)
        vendor_name = native.vendor.name
        shutil.copytree(native.vendor, self.source / 'xssi-vendor' / vendor_name)
        shutil.copyfile(native.source / 'Cargo.lock', self.source / 'Cargo.lock')
        metadata = json.loads((native.source / 'xssi-cargo-metadata.json').read_text())
        for source in (self.helper_source, self.source):
            value = copy.deepcopy(metadata)
            value['packages'][0]['manifest_path'] = str(source / 'xssi-vendor' / vendor_name / 'Cargo.toml')
            (source / 'xssi-cargo-metadata.json').write_text(json.dumps(value))
        (self.stage / 'libexec').mkdir()
        (self.stage / 'libexec/setup').write_bytes(b'opaque Setup payload fixture\n')
        self.path = self.stage / 'share/external-components.json'
        self.boms = []
        for label, target in (('setup', 'libexec/setup'), ('server', 'bin/server')):
            path = self.stage / 'share' / (label + '-sbom.cdx.json')
            ref = 'fixture-' + label
            path.write_text(json.dumps({
                'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                'metadata': {'component': {'type': 'application', 'name': label,
                    'version': '1.0.0', 'bom-ref': ref}},
                'components': [], 'dependencies': [{'ref': ref, 'dependsOn': []}],
            }))
            self.boms.append((path, target))
        (self.frontend.web / 'package-lock.json').write_text(json.dumps(self.frontend.lock))
        self.frontend.metadata.write_text(json.dumps(self.frontend.receipt))
        (self.stage / 'share/web-assets.json').write_text(json.dumps(self.frontend.compiled))

    def frontend_components(self):
        with patch.object(frontend_receipt, 'download', side_effect=self.frontend.fetch):
            return frontend_receipt.generate(self.source, self.stage, self.frontend.metadata, 'bin/server')

    def merge_sqlite(self):
        components = [
            sqlite_receipt.record(self.helper_source, self.stage, 'setup', 'libexec/setup'),
            sqlite_receipt.record(self.source, self.stage, 'server', 'bin/server'),
        ]
        sqlite_receipt.merge(self.stage, components, self.boms)
        return components

    def verify_complete_inventory(self, original_components):
        data = json.loads(self.path.read_text())
        by_ref = {item['ref']: item for item in data['components']}
        self.assertEqual(len(by_ref), len(data['components']))
        for item in original_components:
            self.assertEqual(by_ref[item['ref']], item)
        native = next(item for item in data['components'] if item['name'] == 'SQLite')
        self.assertEqual({item['path'] for item in native['files']}, {'libexec/setup', 'bin/server'})
        self.assertEqual(native['embedding']['target_files'], native['files'])
        self.assertEqual(len(native['embedding']['source_files']), 6)
        bindings = {item['ref']: item['files'] for item in data['runtime_roots']}
        self.assertEqual(set(bindings), {'fixture-setup', 'fixture-server'})
        for ref, path in (('fixture-setup', 'libexec/setup'), ('fixture-server', 'bin/server')):
            self.assertEqual(bindings[ref], [{'path': path,
                'sha256': release_sbom.digest(self.stage / path), 'archive_entry': None}])
        output = release_sbom.finalize(self.stage, [item[0] for item in self.boms], self.path,
            'fixture-server', '1.0.0', '1' * 40, 'x86_64-unknown-linux-gnu', self.source)
        document = json.loads(output.read_text())
        refs = {item['bom-ref'] for item in document['components']}
        self.assertTrue(set(by_ref).issubset(refs))
        self.assertIn('fixture-setup', refs)
        self.assertIn('fixture-server', refs)
        for target in ('bin/server', 'libexec/setup'):
            delivered = next(item for item in document['components'] if item['type'] == 'file' and item['name'] == target)
            self.assertEqual(delivered['hashes'], [{'alg': 'SHA-256', 'content': release_sbom.digest(self.stage / target)}])

    def test_fresh_stage_sqlite_then_frontend_preserves_both_runtime_roots(self):
        self.assertFalse(self.path.exists())
        self.assertEqual(helper.ensure_external_receipt(self.stage), self.path)
        self.assertEqual(json.loads(self.path.read_text()), {'format_version': 1, 'runtime_roots': [], 'components': []})
        self.merge_sqlite()
        native = copy.deepcopy(json.loads(self.path.read_text())['components'])
        rendered = self.frontend_components()
        self.verify_complete_inventory([*native, *rendered])

    def test_frontend_first_initialization_preserves_existing_bytes_and_components(self):
        # Model the frontend producer's already contributed inventory before
        # the helper producer enters this stage for the first time.
        self.path.write_text(json.dumps({'format_version': 1, 'runtime_roots': [], 'components': []}))
        rendered = self.frontend_components()
        before = self.path.read_bytes()
        identity = self.path.stat()
        helper.ensure_external_receipt(self.stage)
        after = self.path.stat()
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual((after.st_dev, after.st_ino, after.st_mtime_ns),
                         (identity.st_dev, identity.st_ino, identity.st_mtime_ns))
        self.merge_sqlite()
        self.verify_complete_inventory(rendered)

    def test_malformed_existing_receipt_is_preserved_and_never_reset(self):
        for malformed in (b'{', b'null', b'[]', b'{"format_version":true,"runtime_roots":[],"components":[]}',
                          b'{"format_version":1,"runtime_roots":{},"components":[]}',
                          b'{"format_version":1,"runtime_roots":[],"components":[],"unknown":true}',
                          b'{"format_version":1,"format_version":1,"runtime_roots":[],"components":[]}'):
            with self.subTest(malformed=malformed):
                self.path.write_bytes(malformed)
                with self.assertRaises((ValueError, TypeError)):
                    helper.ensure_external_receipt(self.stage)
                self.assertEqual(self.path.read_bytes(), malformed)

    def test_duplicate_existing_component_or_runtime_refs_are_preserved_and_rejected(self):
        helper.ensure_external_receipt(self.stage)
        self.merge_sqlite()
        original = json.loads(self.path.read_text())
        for field in ('components', 'runtime_roots'):
            with self.subTest(field=field):
                changed = copy.deepcopy(original)
                changed[field].append(copy.deepcopy(changed[field][0]))
                before = json.dumps(changed).encode()
                self.path.write_bytes(before)
                with self.assertRaises(ValueError):
                    helper.ensure_external_receipt(self.stage)
                self.assertEqual(self.path.read_bytes(), before)

    def test_existing_symlink_receipt_preserves_its_referent(self):
        outside = self.root / 'outside-receipt.json'
        contents = b'{"format_version":1,"runtime_roots":[],"components":[]}'
        outside.write_bytes(contents)
        try:
            self.path.symlink_to(outside)
        except OSError as error:
            self.skipTest('platform cannot create the negative symlink fixture: ' + str(error))
        with self.assertRaises(ValueError):
            helper.ensure_external_receipt(self.stage)
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(outside.read_bytes(), contents)

    def test_share_directory_alias_cannot_create_a_receipt_in_its_referent(self):
        directory = self.stage / 'share'
        outside = self.root / 'outside-share'
        directory.rename(outside)
        try:
            directory.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest('platform cannot create the negative directory alias: ' + str(error))
        with self.assertRaises(ValueError):
            helper.ensure_external_receipt(self.stage)
        self.assertTrue(directory.is_symlink())
        self.assertFalse((outside / 'external-components.json').exists())

    def test_changed_existing_payload_or_original_license_rejects_without_rewriting_receipt(self):
        helper.ensure_external_receipt(self.stage)
        rendered = self.frontend_components()
        before = self.path.read_bytes()
        identity = self.path.stat()
        original_license = self.stage / rendered[0]['licenses'][0]['path']
        for target in (self.stage / 'bin/server', original_license):
            with self.subTest(target=target.relative_to(self.stage).as_posix()):
                original = target.read_bytes()
                target.write_bytes(original + b' changed after receipt contribution')
                with self.assertRaises(ValueError):
                    helper.ensure_external_receipt(self.stage)
                self.assertEqual(self.path.read_bytes(), before)
                after = self.path.stat()
                self.assertEqual((after.st_dev, after.st_ino, after.st_mtime_ns),
                                 (identity.st_dev, identity.st_ino, identity.st_mtime_ns))
                target.write_bytes(original)

    def test_existing_hardlinked_receipt_preserves_both_links(self):
        helper.ensure_external_receipt(self.stage)
        before = self.path.read_bytes()
        other = self.root / 'receipt-hardlink.json'
        try:
            os.link(self.path, other)
        except OSError as error:
            self.skipTest('platform cannot create the negative hardlink fixture: ' + str(error))
        with self.assertRaises(ValueError):
            helper.ensure_external_receipt(self.stage)
        self.assertTrue(os.path.samefile(self.path, other))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(other.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
