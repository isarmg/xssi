import copy
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import mediamtx_receipt as receipt


def build_info():
    return {'GoVersion': receipt.GO_VERSION, 'Path': 'github.com/bluenviron/mediamtx',
            'Main': {'Path': 'github.com/bluenviron/mediamtx', 'Version': 'v1.20.0'},
            'Deps': [{'Path': 'example.org/library', 'Version': 'v1.0.0', 'Sum': 'h1:' + 'A' * 43 + '='}],
            'Settings': [{'Key': key, 'Value': value} for key, value in {
                '-buildmode': 'exe', '-compiler': 'gc', 'CGO_ENABLED': '0', 'GOARCH': 'amd64',
                'GOOS': 'linux', 'GOAMD64': 'v1', 'vcs': 'git', 'vcs.modified': 'false',
                'vcs.revision': 'a' * 40}.items()]}


class MediaMTXReceiptTests(unittest.TestCase):
    def test_replacement_is_an_authenticated_actual_source(self):
        info = build_info()
        item = info['Deps'][0]
        item['Replace'] = {'Path': 'example.org/fork', 'Version': 'v1.2.3', 'Sum': item.pop('Sum')}
        _, linked = receipt.validate_info(info, 'v1.20.0')
        self.assertEqual(receipt.module_identity(linked['example.org/library']['Replace']),
                         ('example.org/fork', 'v1.2.3'))
        del item['Replace']['Sum']
        with self.assertRaisesRegex(ValueError, 'authenticated'):
            receipt.validate_info(info, 'v1.20.0')

    def test_unsupported_binary_inputs_are_refused(self):
        original = build_info()
        variants = []
        version = copy.deepcopy(original); version['GoVersion'] = 'go1.27.0'; variants.append(version)
        cgo = copy.deepcopy(original); cgo['Settings'][2]['Value'] = '1'; variants.append(cgo)
        duplicate = copy.deepcopy(original); duplicate['Settings'].append(duplicate['Settings'][0]); variants.append(duplicate)
        overlay = copy.deepcopy(original); overlay['Settings'].append({'Key': '-overlay', 'Value': 'private.json'}); variants.append(overlay)
        dirty = copy.deepcopy(original); dirty['Settings'][7]['Value'] = 'true'; variants.append(dirty)
        duplicate_module = copy.deepcopy(original); duplicate_module['Deps'] *= 2; variants.append(duplicate_module)
        for info in variants:
            with self.subTest(info=info):
                with self.assertRaises(ValueError):
                    receipt.validate_info(info, 'v1.20.0')

    def test_local_and_ambiguous_module_sources_are_refused(self):
        for path, version in [('example.org//library', 'v1.0.0'),
                              ('../private', 'v1.0.0'), ('example.org/library', '(devel)'),
                              ('-option', 'v1.0.0'), ('example.org/./library', 'v1.0.0')]:
            with self.assertRaises(ValueError):
                receipt.module_identity({'Path': path, 'Version': version})

    def test_json_stream_is_bounded_and_rejects_duplicate_fields(self):
        self.assertEqual(receipt.documents(b'{"one":1}\n {"two":2}'), [{'one': 1}, {'two': 2}])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            receipt.documents(b'{"one":1,"one":2}')
        with self.assertRaises(ValueError):
            receipt.documents(b'{} trailing data')

    def test_archive_program_and_original_license_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'program'; binary.write_bytes(b'actual shipped program fixture')
            expected = hashlib.sha256(binary.read_bytes()).hexdigest()
            archive = root / 'program.tar.gz'
            def package(program, extra=None):
                with tarfile.open(archive, 'w:gz') as tar:
                    entries = [('mediamtx', program), ('mediamtx.yml', b'fixture config'), ('LICENSE', b'Original license\n')]
                    if extra:
                        entries.append(extra)
                    for name, content in entries:
                        info = tarfile.TarInfo(name); info.size = len(content)
                        tar.addfile(info, io.BytesIO(content))
            package(binary.read_bytes())
            self.assertEqual(receipt.archive_license(archive, binary, expected), b'Original license\n')
            package(b'different released program')
            with self.assertRaisesRegex(ValueError, 'archive and shipped'):
                receipt.archive_license(archive, binary, expected)
            package(binary.read_bytes(), ('LICENSE', b'second license'))
            with self.assertRaisesRegex(ValueError, 'unexpected payload'):
                receipt.archive_license(archive, binary, expected)
            binary.write_bytes(b'tampered delivered program')
            with self.assertRaisesRegex(ValueError, 'owned contract'):
                receipt.archive_license(archive, binary, expected)

    def test_original_notices_preserve_nested_copyright_and_refuse_missing_license(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); package = root / 'package'; package.mkdir()
            (root / 'LICENSE').write_bytes(b'Original license including copyright\n')
            (root / 'copyright').mkdir()
            (package / 'NOTICE').write_bytes(b'Original package notice\n')
            notices = receipt.original_notices(root, {package})
            self.assertEqual(notices['LICENSE'], b'Original license including copyright\n')
            self.assertEqual(notices['package/NOTICE'], b'Original package notice\n')
            (root / 'LICENSE').unlink()
            with self.assertRaisesRegex(ValueError, 'no original license'):
                receipt.original_notices(root, {package})

    def test_evidence_never_follows_directory_links_or_overwrites_conflicting_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stage = root / 'stage'; stage.mkdir()
            outside = root / 'outside'; outside.mkdir()
            (stage / 'share').symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'physical'):
                receipt.write(stage, 'share/source.json', b'fixture')
            self.assertEqual(list(outside.iterdir()), [])
            (stage / 'share').unlink()
            receipt.write(stage, 'share/source.json', b'actual evidence')
            with self.assertRaisesRegex(ValueError, 'conflicts'):
                receipt.write(stage, 'share/source.json', b'changed evidence')
            self.assertEqual((stage / 'share/source.json').read_bytes(), b'actual evidence')

    def test_complete_inline_source_license_is_preserved_without_guessing_from_the_module_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = (b'// Copyright original author\n'
                      b'// Redistribution and use in source and binary forms are permitted.\n'
                      b'// THIS SOFTWARE IS PROVIDED AS IS.\n')
            (root / 'source.go').write_bytes(header + b'\npackage fixture\n')
            notices = receipt.original_notices(root, {root}, ['source.go'])
            self.assertIn(header, notices['SOURCE-NOTICES.txt'])
            (root / 'source.go').write_bytes(b'// Copyright original author\n// See missing LICENSE file.\n\npackage fixture\n')
            with self.assertRaisesRegex(ValueError, 'no original license'):
                receipt.original_notices(root, {root}, ['source.go'])

    def test_public_download_retries_transport_failure_with_a_fixed_bound(self):
        failure = urllib.error.URLError('temporary public transport failure')
        with patch.object(receipt.urllib.request, 'urlopen', side_effect=[failure, failure, io.BytesIO(b'actual bytes')]) as request, patch.object(receipt.time, 'sleep'):
            self.assertEqual(receipt.fetch('https://example.org/source', 32), b'actual bytes')
            self.assertEqual(request.call_count, 3)
        with patch.object(receipt.urllib.request, 'urlopen', return_value=io.BytesIO(b'too many bytes')):
            with self.assertRaisesRegex(ValueError, 'bound'):
                receipt.fetch('https://example.org/source', 2)
        body = io.BytesIO(b'bounded original failure response')
        error = urllib.error.HTTPError('https://example.org/source', 403, 'denied', {}, body)
        with patch.object(receipt.urllib.request, 'urlopen', side_effect=error) as request:
            with self.assertRaises(urllib.error.HTTPError):
                receipt.fetch('https://example.org/source', 32)
            self.assertEqual(request.call_count, 1)
        self.assertTrue(body.closed)

    def test_go_source_resolution_preserves_proxy_and_trust_without_inheriting_release_secrets(self):
        network = {'HTTPS_PROXY': 'http://proxy.example.invalid',
                   'NO_PROXY': 'localhost', 'SSL_CERT_FILE': '/fixture/trust.pem',
                   'GIT_SSL_CAINFO': '/fixture/trust.pem'}
        with patch.dict(receipt.os.environ, {**network, 'GH_TOKEN': 'fixture-secret'}, clear=True):
            child = receipt.environment(Path('/tmp/isolated-go'))
        self.assertEqual({key: child[key] for key in network}, network)
        self.assertNotIn('GH_TOKEN', child)
        self.assertEqual(child['GOPROXY'], 'https://proxy.golang.org')


if __name__ == '__main__':
    unittest.main()
