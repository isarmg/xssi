"""Bind Cargo's selected normal runtime tree to exact metadata package IDs."""
from pathlib import Path
import re

MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_TREE_LINES = 200000
CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index'


def tree_command(manifest, root_name, target, features=(), *, default_features=True,
                 all_features=False):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', root_name):
        raise ValueError('invalid selected Cargo package')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', target):
        raise ValueError('invalid selected Cargo target')
    result = ['cargo', 'tree', '--locked', '--offline', '--manifest-path', str(manifest),
              '--package', root_name, '--target', target, '--edges', 'normal,no-proc-macro',
              '--no-dedupe', '--prefix', 'depth', '--format', '\t{p}', '--color', 'never']
    if not default_features:
        result.append('--no-default-features')
    if all_features:
        if features:
            raise ValueError('selected Cargo features cannot also request all features')
        result.append('--all-features')
    elif features:
        if isinstance(features, str):
            features = features.split(',')
        if any(not isinstance(value, str) or not value or '\x00' in value
               or any(character.isspace() for character in value) for value in features):
            raise ValueError('invalid selected Cargo feature list')
        result.extend(['--features', ','.join(features)])
    return result


def _matches(package, display):
    prefix = package['name'] + ' v' + package['version']
    source = package['source']
    if source is None:
        return display == prefix + ' (' + str(Path(package['manifest_path']).parent) + ')'
    if source == CRATES_IO:
        return display == prefix
    if source.startswith('registry+'):
        return display == prefix + ' (registry `' + source[len('registry+'):] + '`)'
    if source.startswith('git+'):
        url, separator, revision = source[len('git+'):].rpartition('#')
        if not separator or not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('selected Cargo Git source lacks its immutable resolved revision')
        start = prefix + ' (' + url + '#'
        if not display.startswith(start) or not display.endswith(')'):
            return False
        abbreviated = display[len(start):-1]
        return (bool(re.fullmatch(r'[0-9a-f]{7,40}', abbreviated))
                and revision.startswith(abbreviated))
    raise ValueError('unsupported selected Cargo source identity')


def selection_from_tree(metadata, text, root_name):
    """Use the target/feature-selected Cargo tree; metadata is identity authority.

    Cargo metadata may unite features across workspace members. Traversing its
    normal edges alone therefore invents runtime dependencies of another member.
    The mature Cargo tree query supplies actual selection; every displayed ID
    and direct edge must still match the full metadata name/version/source.
    """
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_TREE_BYTES:
        raise ValueError('selected Cargo tree exceeds its byte bound')
    packages_list = metadata.get('packages', [])
    if not isinstance(packages_list, list) or not 0 < len(packages_list) <= 4096:
        raise ValueError('invalid selected Cargo metadata package count')
    packages = {package['id']: package for package in packages_list}
    if len(packages) != len(packages_list):
        raise ValueError('duplicate Cargo metadata package identity')
    by_name_version = {}
    for package in packages_list:
        by_name_version.setdefault((package['name'], package['version']), []).append(package)
    nodes_list = metadata.get('resolve', {}).get('nodes', [])
    nodes = {node['id']: node for node in nodes_list}
    if len(nodes) != len(nodes_list):
        raise ValueError('duplicate Cargo metadata resolve identity')
    roots = [package['id'] for package in packages_list
             if package['name'] == root_name and package['source'] is None]
    if len(roots) != 1:
        raise ValueError('Cargo metadata has no unique selected local root')
    root = roots[0]
    lines = text.splitlines()
    if not lines or len(lines) > MAX_TREE_LINES:
        raise ValueError('invalid selected Cargo tree line count')
    selected = set()
    edges = {}
    stack = []
    for number, line in enumerate(lines):
        match = re.fullmatch(r'(0|[1-9][0-9]*)\t([^\x00-\x1f\x7f]+)', line)
        if not match:
            raise ValueError('selected Cargo tree lacks an exact depth and package record')
        depth = int(match[1])
        if depth > 256 or depth > len(stack) or (number > 0 and depth == 0):
            raise ValueError('selected Cargo tree has an invalid depth or another root')
        display = match[2]
        parts = display.split(' ', 2)
        if len(parts) < 2 or not parts[1].startswith('v'):
            raise ValueError('selected Cargo tree has an invalid package version')
        candidates = [package['id'] for package in by_name_version.get((parts[0], parts[1][1:]), [])
                      if _matches(package, display)]
        if len(candidates) != 1:
            raise ValueError('selected Cargo tree package has no unique metadata source identity')
        identifier = candidates[0]
        package = packages[identifier]
        if any('proc-macro' in target['kind'] for target in package.get('targets', [])):
            raise ValueError('selected runtime Cargo tree contains a procedural macro')
        if identifier not in nodes:
            raise ValueError('selected Cargo package has no resolve node')
        if number == 0 and identifier != root:
            raise ValueError('selected Cargo tree starts with another package')
        if depth:
            parent = stack[depth - 1]
            if identifier in stack[:depth]:
                raise ValueError('selected Cargo tree contains a dependency cycle')
            allowed = [dependency for dependency in nodes[parent]['deps']
                       if dependency['pkg'] == identifier
                       and (not dependency['dep_kinds']
                            or any(kind['kind'] is None for kind in dependency['dep_kinds']))]
            if not allowed:
                raise ValueError('selected Cargo tree edge is absent from normal metadata dependencies')
            edges.setdefault(parent, set()).add(identifier)
        selected.add(identifier)
        edges.setdefault(identifier, set())
        stack[depth:] = [identifier]
    return {'root': root, 'ids': sorted(selected),
            'edges': {identifier: sorted(children) for identifier, children in sorted(edges.items())}}
