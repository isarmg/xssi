"""Selected Cargo runtime graph identity and feature-union regressions."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from cargo_selection import CRATES_IO, selection_from_tree, tree_command


def package(name, source=CRATES_IO, *, kind='lib', version='1.0.0', identifier=None):
    return {'id': identifier or name, 'name': name, 'version': version, 'source': source,
            'manifest_path': '/tmp/selected/' + name + '/Cargo.toml',
            'targets': [{'kind': [kind]}]}


def node(identifier, *dependencies):
    return {'id': identifier, 'deps': [{'pkg': child, 'dep_kinds': [{'kind': kind, 'target': None}]}
                                      for child, kind in dependencies]}


class CargoSelectionTests(unittest.TestCase):
    def fixture(self):
        packages = [package('app', None), package('core'), package('leaf'), package('union-only'),
                    package('dev-only'), package('build-only'), package('derive', kind='proc-macro')]
        nodes = [node('app', ('core', None), ('union-only', None), ('dev-only', 'dev'),
                      ('build-only', 'build'), ('derive', None)),
                 node('core', ('leaf', None)), node('leaf'), node('union-only'),
                 node('dev-only'), node('build-only'), node('derive')]
        return {'packages': packages, 'resolve': {'nodes': nodes}}

    def test_selected_tree_excludes_workspace_feature_union(self):
        result = selection_from_tree(self.fixture(),
            '0\tapp v1.0.0 (/tmp/selected/app)\n1\tcore v1.0.0\n2\tleaf v1.0.0\n', 'app')
        self.assertEqual(result, {'root': 'app', 'ids': ['app', 'core', 'leaf'],
                                 'edges': {'app': ['core'], 'core': ['leaf'], 'leaf': []}})

    def test_shared_dependency_repeats_preserve_each_direct_edge(self):
        metadata = self.fixture()
        metadata['resolve']['nodes'][0]['deps'].append({'pkg': 'leaf', 'dep_kinds': [{'kind': None}]})
        result = selection_from_tree(metadata,
            '0\tapp v1.0.0 (/tmp/selected/app)\n1\tcore v1.0.0\n2\tleaf v1.0.0\n1\tleaf v1.0.0\n', 'app')
        self.assertEqual(result['edges']['app'], ['core', 'leaf'])
        self.assertEqual(result['edges']['core'], ['leaf'])

    def test_same_name_version_sources_never_match_by_name_alone(self):
        metadata = self.fixture()
        revision = '1234567890abcdef1234567890abcdef12345678'
        source = 'git+https://example.org/library.git?rev=' + revision + '#' + revision
        metadata['packages'].append(package('core', source, identifier='git-core'))
        metadata['resolve']['nodes'].append(node('git-core'))
        metadata['resolve']['nodes'][0]['deps'].append({'pkg': 'git-core', 'dep_kinds': [{'kind': None}]})
        result = selection_from_tree(metadata,
            '0\tapp v1.0.0 (/tmp/selected/app)\n1\tcore v1.0.0 (https://example.org/library.git?rev='
            + revision + '#12345678)\n', 'app')
        self.assertEqual(result['ids'], ['app', 'git-core'])
        duplicate = package('core', identifier='another-registry-core')
        metadata['packages'].append(duplicate)
        with self.assertRaisesRegex(ValueError, 'unique metadata source identity'):
            selection_from_tree(metadata, '0\tapp v1.0.0 (/tmp/selected/app)\n1\tcore v1.0.0\n', 'app')

    def test_invalid_tree_depth_identity_kind_and_edges_are_rejected(self):
        root = '0\tapp v1.0.0 (/tmp/selected/app)\n'
        cases = [root + '2\tcore v1.0.0\n', root + '0\tcore v1.0.0\n',
                 root + '1\tunknown v1.0.0\n', root + '1\tcore v2.0.0\n',
                 root + '1\tdev-only v1.0.0\n', root + '1\tbuild-only v1.0.0\n',
                 root + '1\tderive v1.0.0\n', root + '1\tleaf v1.0.0\n',
                 root + '1\tcore v1.0.0 (*)\n', root.replace('\t', '')]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                selection_from_tree(self.fixture(), text, 'app')

    def test_actual_query_binds_features_target_package_and_normal_edges(self):
        command = tree_command('/tmp/project/Cargo.toml', 'app', 'aarch64-linux-android',
                               ('ffi', 'storage'), default_features=False)
        for value in ('--locked', '--offline', '--no-dedupe', '--no-default-features', '--color'):
            self.assertIn(value, command)
        self.assertEqual(command[command.index('--edges') + 1], 'normal,no-proc-macro')
        self.assertEqual(command[command.index('--format') + 1], '\t{p}')
        self.assertEqual(command[command.index('--features') + 1], 'ffi,storage')
        self.assertEqual(command[command.index('--target') + 1], 'aarch64-linux-android')
        self.assertEqual(command[command.index('--package') + 1], 'app')
        with self.assertRaises(ValueError):
            tree_command('/tmp/project/Cargo.toml', 'app', 'target', ('ffi',), all_features=True)

    @unittest.skipUnless(shutil.which('cargo'), 'actual Cargo feature-selection fixture requires Cargo')
    def test_actual_workspace_metadata_feature_union_is_not_runtime_selection(self):
        with tempfile.TemporaryDirectory(prefix='xssi-cargo-selection-') as temporary:
            root = Path(temporary)
            names = ('app', 'other', 'common', 'android-only')
            (root / 'Cargo.toml').write_text(
                '[workspace]\nresolver="2"\nmembers=["app","other","common","android-only"]\n')
            for name in names:
                crate = root / name
                (crate / 'src').mkdir(parents=True)
                (crate / 'src/lib.rs').write_text('pub fn fixture() {}\n')
                manifest = '[package]\nname="' + name + '"\nversion="1.0.0"\nedition="2021"\n'
                if name in ('app', 'other'):
                    manifest += '[dependencies]\ncommon={path="../common",default-features=false'
                    manifest += ',features=["android"]' if name == 'other' else ''
                    manifest += '}\n'
                if name == 'common':
                    manifest += ('[features]\nandroid=["dep:android-only"]\n[dependencies]\n'
                                 'android-only={path="../android-only",optional=true}\n')
                (crate / 'Cargo.toml').write_text(manifest)
            metadata = json.loads(subprocess.check_output(
                ['cargo', 'metadata', '--offline', '--format-version', '1',
                 '--filter-platform', 'x86_64-unknown-linux-gnu'], cwd=root, timeout=30))
            packages = {package['name']: package for package in metadata['packages']}
            nodes = {node['id']: node for node in metadata['resolve']['nodes']}
            self.assertIn(packages['android-only']['id'],
                          [dependency['pkg'] for dependency in nodes[packages['common']['id']]['deps']])
            lock = (root / 'Cargo.lock').read_bytes()
            text = subprocess.check_output(tree_command(root / 'Cargo.toml', 'app',
                'x86_64-unknown-linux-gnu'), cwd=root, text=True, timeout=30)
            result = selection_from_tree(metadata, text, 'app')
            self.assertEqual(set(result['ids']), {packages[name]['id'] for name in ('app', 'common')})
            self.assertEqual((root / 'Cargo.lock').read_bytes(), lock)
            self.assertFalse((root / 'target').exists())


if __name__ == '__main__':
    unittest.main()
