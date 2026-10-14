import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import upstream_licenses as upstream


class UpstreamLicenses(unittest.TestCase):
    def fixture(self, root):
        root = Path(root).resolve(strict=True)
        directory = root / 'xssi-vendor' / 'fixture-1.0.0'
        directory.mkdir(parents=True)
        manifest = b'[package]\nname="fixture"\nversion="1.0.0"\nlicense="Apache-2.0"\n'
        vcs = json.dumps({'git': {'sha1': 'b' * 40}, 'path_in_vcs': 'crates/fixture'}).encode()
        (directory / 'Cargo.toml').write_bytes(manifest)
        (directory / 'Cargo.toml.orig').write_bytes(manifest)
        (directory / '.cargo_vcs_info.json').write_bytes(vcs)
        hashes = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                  for name in ('Cargo.toml.orig', '.cargo_vcs_info.json')}
        (directory / '.cargo-checksum.json').write_text(json.dumps({'package': 'a' * 64, 'files': hashes}))
        text = b'Copyright fixture authors\nOriginal upstream license terms.\n'
        url = 'https://raw.githubusercontent.com/example/fixture/' + 'b' * 40 + '/LICENSE'
        record = {'name': 'fixture', 'version': '1.0.0', 'package_checksum': 'a' * 64,
                  'repository': 'https://github.com/example/fixture', 'revision': 'b' * 40,
                  'vcs_path': 'crates/fixture', 'manifest_sha256': hashes['Cargo.toml.orig'],
                  'vcs_sha256': hashes['.cargo_vcs_info.json'], 'license': 'Apache-2.0',
                  'licenses': [{'name': 'LICENSE', 'source': url, 'sha256': hashlib.sha256(text).hexdigest()}]}
        package = {'id': 'registry-fixture', 'name': 'fixture', 'version': '1.0.0',
                   'source': upstream.REGISTRY, 'repository': record['repository'],
                   'license': record['license'], 'license_file': None,
                   'manifest_path': str(directory / 'Cargo.toml')}
        definitions = {'format_version': 1, 'registry': [record]}
        return root, directory, package, definitions, text

    def invoke(self, root, package, definitions, text):
        with patch.object(upstream, 'reviewed', return_value=definitions), patch.object(upstream, '_download', return_value=text) as download:
            upstream.prepare(root, {'packages': [package]}, {package['id']}, {})
        return download

    def test_original_bytes_identity_and_public_source_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            self.invoke(root, package, definitions, text)
            output = root / 'xssi-upstream-licenses'
            receipt = json.loads((output / 'receipt.json').read_text())
            self.assertEqual(receipt['format_version'], 1)
            record = receipt['packages'][0]
            self.assertEqual(record['package_checksum'], 'a' * 64)
            self.assertEqual(record['source'], upstream.REGISTRY)
            self.assertEqual(record['revision'], 'b' * 40)
            retained = record['licenses'][0]
            self.assertEqual(retained['source'], definitions['registry'][0]['licenses'][0]['source'])
            self.assertEqual((output / retained['path']).read_bytes(), text)

    def test_only_selected_missing_packages_are_downloaded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            with patch.object(upstream, 'reviewed', return_value=definitions), patch.object(upstream, '_download') as download:
                upstream.prepare(root, {'packages': [package]}, set(), {})
            download.assert_not_called()
            self.assertEqual(json.loads((root / 'xssi-upstream-licenses/receipt.json').read_text())['packages'], [])

    def test_existing_original_package_license_needs_no_upstream_substitute(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            (directory / 'LICENSE').write_bytes(text)
            download = self.invoke(root, package, definitions, text)
            download.assert_not_called()

    def test_unknown_missing_license_is_rejected_before_fetch_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            definitions['registry'] = []
            with self.assertRaisesRegex(ValueError, 'no reviewed original'), patch.object(upstream, '_download') as download:
                with patch.object(upstream, 'reviewed', return_value=definitions):
                    upstream.prepare(root, {'packages': [package]}, {package['id']}, {})
            download.assert_not_called()
            self.assertFalse((root / 'xssi-upstream-licenses').exists())

    def test_archive_vcs_manifest_and_declared_license_changes_are_rejected(self):
        for change in ('archive', 'vcs', 'manifest', 'license', 'repository'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root, directory, package, definitions, text = self.fixture(temporary)
                if change == 'archive':
                    p = directory / '.cargo-checksum.json'
                    altered = json.loads(p.read_text()); altered['package'] = 'c' * 64
                    p.write_text(json.dumps(altered))
                elif change == 'vcs':
                    (directory / '.cargo_vcs_info.json').write_bytes(b'{}')
                elif change == 'manifest':
                    (directory / 'Cargo.toml.orig').write_bytes(b'[package]\n')
                elif change == 'license':
                    package['license'] = 'MIT'
                else:
                    package['repository'] = 'https://github.com/unknown/project'
                with self.assertRaises(ValueError):
                    self.invoke(root, package, definitions, text)
                self.assertFalse((root / 'xssi-upstream-licenses').exists())

    def test_upstream_declaration_and_referenced_terms_tampering_are_rejected(self):
        for changed in (0, 1):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root, directory, package, definitions, text = self.fixture(temporary)
                definition = definitions['registry'][0]
                package.update(name='objc2-core-foundation', version='0.3.2')
                definition.update(name=package['name'], version=package['version'])
                definition['selected_license'] = 'Apache-2.0'
                original = [b'Immutable upstream licensing declaration.\n', b'Complete directly referenced official terms.\n']
                definition['licenses'] = [{'name': name, 'source': url, 'sha256': hashlib.sha256(data).hexdigest()}
                    for name, url, data in [('LICENSE.md', definition['licenses'][0]['source'], original[0]),
                                          ('APACHE-2.0.txt', 'https://www.apache.org/licenses/LICENSE-2.0', original[1])]]
                altered = original[:]; altered[changed] += b'changed'
                with self.assertRaisesRegex(ValueError, 'SHA-256'), patch.object(upstream, 'reviewed', return_value=definitions), patch.object(upstream, '_download', side_effect=altered):
                    upstream.prepare(root, {'packages': [package]}, {package['id']}, {})
                self.assertFalse((root / 'xssi-upstream-licenses').exists())

    def test_existing_output_and_escaped_metadata_preserve_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            existing = root / 'xssi-upstream-licenses'
            existing.mkdir(); (existing / 'keep').write_bytes(text)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                self.invoke(root, package, definitions, text)
            self.assertEqual((existing / 'keep').read_bytes(), text)
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            package['manifest_path'] = str(directory / '..' / '..' / 'outside' / 'Cargo.toml')
            with self.assertRaises(ValueError):
                self.invoke(root, package, definitions, text)
            self.assertFalse((root / 'xssi-upstream-licenses').exists())

    def test_linked_or_escaping_declared_license_is_rejected(self):
        for linked in (False, True):
            with self.subTest(linked=linked), tempfile.TemporaryDirectory() as temporary:
                root, directory, package, definitions, text = self.fixture(temporary)
                outside = root / 'outside'; outside.write_bytes(text)
                if linked:
                    try:
                        (directory / 'LICENSE').symlink_to(outside)
                    except OSError:
                        self.skipTest('native symlink creation requires platform privileges')
                else:
                    package['license_file'] = '../../outside'
                with self.assertRaises(ValueError):
                    self.invoke(root, package, definitions, text)
                self.assertEqual(outside.read_bytes(), text)

    def test_missing_git_package_license_has_no_old_source_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, directory, package, definitions, text = self.fixture(temporary)
            package.update(name='xszs-protocol', repository=None,
                           source='git+https://github.com/isarmg/xszs.git?rev=' + 'b' * 40 + '#' + 'b' * 40)
            with self.assertRaisesRegex(ValueError, 'no reviewed original'):
                self.invoke(root, package, definitions, text)
            self.assertFalse((root / 'xssi-upstream-licenses').exists())

    def test_changed_license_reference_cannot_fetch_another_repository_or_version(self):
        for url in ('https://raw.githubusercontent.com/another/repo/' + 'b' * 40 + '/LICENSE',
                    'https://www.apache.org/licenses/LICENSE-1.1'):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as temporary:
                root, directory, package, definitions, text = self.fixture(temporary)
                definitions['registry'][0]['licenses'][0]['source'] = url
                with self.assertRaisesRegex(ValueError, 'owning immutable'):
                    self.invoke(root, package, definitions, text)
                self.assertFalse((root / 'xssi-upstream-licenses').exists())

    def test_reviewed_real_data_has_only_exact_sources_and_original_hashes(self):
        definitions = upstream.reviewed()
        self.assertEqual({r['name'] for r in definitions['registry']},
                         {'jni', 'objc2-core-foundation', 'objc2-io-kit', 'rustls-platform-verifier-android'})
        for r in definitions['registry']:
            self.assertRegex(r['revision'], '^[0-9a-f]{40}$')
            for key in ('package_checksum', 'manifest_sha256', 'vcs_sha256'):
                self.assertRegex(r[key], '^[0-9a-f]{64}$')
            for item in r['licenses']:
                upstream._public(item['source'])
                self.assertRegex(item['sha256'], '^[0-9a-f]{64}$')
                if item['source'].startswith('https://raw.githubusercontent.com/'):
                    self.assertIn('/' + r['revision'] + '/', item['source'])
            if r['name'].startswith('objc2-'):
                self.assertEqual(r['selected_license'], 'Apache-2.0')
                self.assertEqual({item['name'] for item in r['licenses']}, {'LICENSE.md', 'APACHE-2.0.txt'})


if __name__ == '__main__':
    unittest.main()
