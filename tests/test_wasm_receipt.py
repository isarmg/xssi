"""Bind WASM outputs to checked source, target-selected Cargo edges and release bytes.

Cargo's inventory subprocess is replaced in these boundary fixtures; the shared
Cargo producer and real product builds are verified separately.
"""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import frontend_receipt
import wasm_receipt
from cargo_selection import selection_from_tree
import test_frontend_receipt as frontend_fixtures

digest = frontend_fixtures.digest


class WasmReceiptTests(unittest.TestCase):
    def setUp(self):
        self.frontend = frontend_fixtures.FrontendReceiptTests()
        self.frontend.setUp()
        self.addCleanup(self.frontend.doCleanups)
        self.root = self.frontend.source / 'web/xcss-web'
        self.root.mkdir()
        files = {'Cargo.toml': b'[package]\nname="browser"\nversion="1.0.0"\n',
                 'Cargo.lock': b'version = 4\n[[package]]\nname="browser"\nversion="1.0.0"\n[[package]]\nname="runtime"\nversion="1.0.0"\n',
                 'runtime/Cargo.toml': b'[package]\nname="runtime"\nversion="1.0.0"\n',
                 'runtime/LICENSE': b'Original runtime MIT copyright fixture.\n'}
        for name, raw in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.files = files
        wasm = b'\x00asm\x01\x00\x00\x00'
        (self.frontend.web / 'dist/assets/browser.wasm').write_bytes(wasm)
        self.output = {'path': 'assets/browser.wasm', 'sha256': digest(wasm)}
        self.frontend.receipt['outputs'].append(copy.deepcopy(self.output))
        self.frontend.compiled['files'].append(copy.deepcopy(self.output))
        metadata, selection, graph = self.graph(self.root)
        self.frontend.receipt['rust'] = {
            'target': wasm_receipt.TARGET, 'mode': 'csr', 'package': 'browser',
            'manifest': wasm_receipt.MANIFEST, 'default_features': True, 'features': [], 'profile': 'release',
            'toolchain': {'rust': '1.99.0', 'wasm_bindgen': '0.2.129'},
            'lock_sha256': digest(files['Cargo.lock']),
            'source_inputs': {'web/xcss-web/' + name: digest(raw) for name, raw in files.items()},
            'graph': graph, 'outputs': [copy.deepcopy(self.output)]}
        provenance = (json.dumps({'rust_runtime': {key: value for key, value in self.frontend.receipt['rust'].items() if key != 'outputs'}}) + '\n').encode()
        (self.frontend.web / 'dist/assets/xcss-web-build.json').write_bytes(provenance)
        record = {'path': 'assets/xcss-web-build.json', 'sha256': digest(provenance)}
        self.frontend.receipt['outputs'].append(copy.deepcopy(record))
        self.frontend.compiled['files'].append(copy.deepcopy(record))
        contracts = self.frontend.stage / 'share/contracts'
        contracts.mkdir()
        (contracts / 'install.json').write_text(json.dumps({'identity': {'source_revision': 'a' * 40}}))

    def graph(self, root):
        packages = [{'id': name, 'name': name, 'version': '1.0.0', 'source': None,
                     'manifest_path': str(root / ('' if name == 'browser' else name) / 'Cargo.toml'),
                     'targets': [{'kind': ['lib']}]} for name in ('browser', 'runtime')]
        metadata = {'packages': packages, 'resolve': {'root': 'browser', 'nodes': [
            {'id': 'browser', 'deps': [{'pkg': 'runtime', 'dep_kinds': [{'kind': None}]}]},
            {'id': 'runtime', 'deps': []}]}}
        tree = '0\tbrowser v1.0.0 (' + str(root) + ')\n1\truntime v1.0.0 (' + str(root / 'runtime') + ')\n'
        selection = selection_from_tree(metadata, tree, 'browser')
        lock = {'package': [{'name': name, 'version': '1.0.0'} for name in ('browser', 'runtime')]}
        return metadata, selection, wasm_receipt.portable_graph(metadata, selection, root, lock)

    def producer(self, workspace, manifest, package, stage, label, local_sources, **options):
        self.assertEqual(options['target'], wasm_receipt.TARGET)
        self.assertEqual(options['features'], [])
        self.assertTrue(options['default_features'])
        metadata, selection, graph = self.graph(workspace)
        (workspace / 'xssi-cargo-full-metadata.json').write_text(json.dumps(metadata))
        (workspace / 'xssi-cargo-tree.txt').write_text('0\tbrowser v1.0.0 (' + str(workspace) + ')\n1\truntime v1.0.0 (' + str(workspace / 'runtime') + ')\n')
        path = stage / 'share/wasm-sbom.cdx.json'
        path.write_text(json.dumps({'metadata': {'component': {'bom-ref': 'wasm-root'}}}))
        return path

    def generate(self):
        with patch.object(wasm_receipt.sbom, 'produce_runtime_cargo_bom', side_effect=self.producer):
            return self.frontend.generate()

    def test_real_hash_and_source_binding_adds_runtime_root_and_original_local_license(self):
        self.generate()
        root = json.loads((self.frontend.stage / 'share/external-components.json').read_text())['runtime_roots']
        self.assertEqual(root, [{'ref': 'wasm-root', 'files': [{'path': 'bin/server',
            'sha256': digest((self.frontend.stage / 'bin/server').read_bytes()), 'archive_entry': None}]}])
        self.assertEqual((self.frontend.stage / 'share/wasm-Cargo.lock').read_bytes(), self.files['Cargo.lock'])
        self.assertEqual((self.frontend.stage / 'share/licenses/wasm/runtime/LICENSE').read_bytes(), self.files['runtime/LICENSE'])
        self.assertTrue((self.frontend.stage / 'share/build-inputs/wasm/runtime.json').is_file())

    def test_wasm_without_rust_graph_is_rejected(self):
        del self.frontend.receipt['rust']
        with self.assertRaisesRegex(ValueError, 'no actual Rust runtime'):
            self.generate()

    def test_changed_wasm_or_missing_output_binding_is_rejected(self):
        for field, value in [('outputs', []), ('outputs', [{'path': self.output['path'], 'sha256': 'b' * 64}])]:
            with self.subTest(value=value):
                self.frontend.receipt['rust'][field] = value
                with self.assertRaisesRegex(ValueError, 'actual WASM output'):
                    self.generate()

    def test_source_change_and_lock_substitution_are_rejected(self):
        (self.root / 'runtime/Cargo.toml').write_text('changed source')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.generate()
        (self.root / 'runtime/Cargo.toml').write_bytes(self.files['runtime/Cargo.toml'])
        self.frontend.receipt['rust']['lock_sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'compiled Server provenance'):
            self.generate()

    def test_changed_target_features_profile_and_runtime_edges_are_rejected(self):
        original = copy.deepcopy(self.frontend.receipt['rust'])
        for field, value in [('target', 'x86_64-unknown-linux-gnu'), ('features', ['ssr']),
                             ('profile', 'debug'), ('graph', {'root': 'wrong', 'packages': []})]:
            with self.subTest(field=field):
                self.frontend.receipt['rust'] = copy.deepcopy(original)
                self.frontend.receipt['rust'][field] = value
                with self.assertRaises(ValueError):
                    self.generate()


if __name__ == '__main__':
    unittest.main()
