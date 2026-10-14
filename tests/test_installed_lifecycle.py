#!/usr/bin/env python3
"""Archive/guard regression tests only; these do not count as installation tests."""
import importlib.util
import io
import os
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('installed_lifecycle.py')
spec = importlib.util.spec_from_file_location('installed_lifecycle', SCRIPT)
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)
lifecycle.PRODUCT = 'xczs'
lifecycle.SERVICES = ('xczs.service',)
lifecycle.ACCOUNT = 'isarmg-xczs'
SHA = 'a' * 40
PREFIX = 'xczs-0.1.0-linux-x86_64'


class ArchiveBoundary(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.archive = Path(self.work.name) / (PREFIX + '.tar.gz')

    def build(self, *, prefix=PREFIX, revision=SHA, extra=None, services=None, target=None, version=None):
        manifest = {'identity': {'product': 'xczs', 'source_revision': revision, 'version': version or '0.1.0', 'target': target or 'x86_64-unknown-linux-gnu'},
                    'services': services if services is not None else [{'name': 'xczs.service'}]}
        with tarfile.open(self.archive, 'w:gz') as bundle:
            data = json.dumps(manifest).encode()
            member = tarfile.TarInfo(prefix + '/share/package.json')
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
            if extra:
                bundle.addfile(extra)
        self.checksum()

    def checksum(self):
        self.archive.with_name('SHA256SUMS').write_text(
            lifecycle.archive_digest(self.archive) + '  ' + self.archive.name + '\n')

    def test_current_envelope(self):
        self.build()
        self.assertEqual(lifecycle.verify_archive(self.archive, SHA), lifecycle.archive_digest(self.archive))

    def test_reject_wrong_version(self):
        self.build(version='9.9.9')
        with self.assertRaisesRegex(RuntimeError, 'package identity'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_wrong_target(self):
        self.build(target='aarch64-unknown-linux-gnu')
        with self.assertRaisesRegex(RuntimeError, 'package identity'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_extra_or_missing_service(self):
        for services in ([], [{'name': 'xczs.service'}, {'name': 'extra.service'}]):
            self.build(services=services)
            with self.assertRaisesRegex(RuntimeError, 'Unexpected service set'):
                lifecycle.verify_archive(self.archive, SHA)

    def test_reject_wrong_revision(self):
        self.build(revision='b' * 40)
        with self.assertRaisesRegex(RuntimeError, 'candidate revision'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_wrong_envelope(self):
        self.build(prefix='flat')
        with self.assertRaisesRegex(RuntimeError, 'package envelope'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_checksum_tampering(self):
        self.build()
        self.archive.write_bytes(self.archive.read_bytes() + b'tamper')
        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_link(self):
        link = tarfile.TarInfo(PREFIX + '/link')
        link.type = tarfile.SYMTYPE
        link.linkname = '/etc/passwd'
        self.build(extra=link)
        with self.assertRaisesRegex(RuntimeError, 'regular package entries'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_parent_path(self):
        self.build(extra=tarfile.TarInfo(PREFIX + '/../escape'))
        with self.assertRaisesRegex(RuntimeError, 'Unsafe package path'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_reject_duplicate(self):
        self.build(extra=tarfile.TarInfo(PREFIX + '/share/package.json'))
        with self.assertRaisesRegex(RuntimeError, 'Duplicate package path'):
            lifecycle.verify_archive(self.archive, SHA)

    def test_formal_extractor_selects_real_envelope(self):
        self.build()
        destination = Path(self.work.name) / 'unpacked'
        destination.mkdir()
        subprocess.run(['tar', '--extract', '--gzip', '--no-same-owner', '--file', str(self.archive),
                        '--directory', str(destination)], check=True)
        self.assertFalse((destination / 'share/package.json').exists(), 'Old flat path must fail')
        self.assertTrue((destination / PREFIX / 'share/package.json').is_file())

    def test_real_extraction_preserves_package_directories_under_private_umask(self):
        with tarfile.open(self.archive, 'w:gz') as bundle:
            for name in (PREFIX, PREFIX + '/share'):
                directory = tarfile.TarInfo(name)
                directory.type, directory.mode = tarfile.DIRTYPE, 0o755
                bundle.addfile(directory)
        legacy, fixed = Path(self.work.name) / 'legacy', Path(self.work.name) / 'fixed'
        legacy.mkdir()
        fixed.mkdir()
        previous = os.umask(0o077)
        try:
            with tarfile.open(self.archive) as bundle:
                bundle.extractall(legacy, filter='data')
            package = lifecycle.extract_package(self.archive, fixed)
        finally:
            os.umask(previous)
        # This reproduces the observed CI preflight failure without executing
        # a fixture installer or changing the real package verifier.
        self.assertNotEqual(stat.S_IMODE((legacy / PREFIX / 'share').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(package.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((package / 'share').stat().st_mode), 0o755)

    def test_extraction_rejects_noncontract_directory_mode(self):
        with tarfile.open(self.archive, 'w:gz') as bundle:
            directory = tarfile.TarInfo(PREFIX)
            directory.type, directory.mode = tarfile.DIRTYPE, 0o777
            bundle.addfile(directory)
        with self.assertRaisesRegex(RuntimeError, 'directory mode must be 0755'):
            lifecycle.extract_package(self.archive, Path(self.work.name) / 'rejected')

    def test_install_parent_requires_every_ancestor_to_be_root_controlled(self):
        parent = Path('/var/lib')
        safe = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        unsafe = [SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777),
                  SimpleNamespace(st_uid=1001, st_mode=stat.S_IFDIR | 0o755),
                  SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o755)]
        with patch.object(Path, 'lstat', return_value=safe) as inspect:
            lifecycle.verify_install_parent(parent)
            self.assertEqual(inspect.call_count, 3)
        for bad in unsafe:
            for position in range(3):
                records = [safe, safe, safe]
                records[position] = bad
                with self.subTest(mode=bad.st_mode, uid=bad.st_uid, ancestor=position), \
                        patch.object(Path, 'lstat', side_effect=records):
                    with self.assertRaisesRegex(RuntimeError, 'root-controlled'):
                        lifecycle.verify_install_parent(parent)

    def test_config_permissions_follow_readonly_product_contract(self):
        directory = SimpleNamespace(st_uid=0, st_gid=987, st_mode=stat.S_IFDIR | 0o750)
        config = SimpleNamespace(st_uid=0, st_gid=987, st_mode=stat.S_IFREG | 0o640)
        with patch.object(Path, 'lstat', side_effect=[directory, config]):
            lifecycle.verify_config_permissions(Path('/installed'), 987)
        for changes in ({'st_uid': 987}, {'st_gid': 0},
                        {'st_mode': stat.S_IFREG | 0o600},
                        {'st_mode': stat.S_IFREG | 0o660},
                        {'st_mode': stat.S_IFLNK | 0o640}):
            bad = SimpleNamespace(**(vars(config) | changes))
            with self.subTest(changes=changes), \
                    patch.object(Path, 'lstat', side_effect=[directory, bad]):
                with self.assertRaisesRegex(RuntimeError, 'read-only configuration'):
                    lifecycle.verify_config_permissions(Path('/installed'), 987)

    def test_journal_diagnostics_only_return_public_whitelisted_fields(self):
        root = Path(self.work.name)
        (root / 'maintenance').mkdir()
        journal = root / 'maintenance/install.json'
        journal.write_text(json.dumps({'product': 'xczs', 'phase': 'staging',
                                       'password': 'never-include', 'unexpected': 'private'}))
        self.assertEqual(lifecycle.installation_observation(root),
                         {'product': 'xczs', 'installation_phase': 'staging'})
        journal.write_text(json.dumps({'product': 'xczs', 'phase': 'private-value'}))
        with self.assertRaisesRegex(RuntimeError, 'unknown public'):
            lifecycle.installation_observation(root)

    def test_failure_diagnostics_redact_exact_temporary_credentials(self):
        directory = Path(self.work.name) / 'diagnostics'
        password, token = 'temporary-password-123', 'temporary-token-456'
        with patch.dict(os.environ, {'LIFECYCLE_DIAGNOSTICS': str(directory)}), \
                patch.object(lifecycle, 'SECRETS', [password, token]), \
                patch.object(lifecycle, 'STAGE', 'regression'):
            with self.assertRaisesRegex(RuntimeError, 'regression'):
                lifecycle.run(sys.executable, '-c',
                              f"import sys; print('{password}'); print('{token}', file=sys.stderr); sys.exit(3)")
        evidence = (directory / 'lifecycle.jsonl').read_text()
        self.assertNotIn(password, evidence)
        self.assertNotIn(token, evidence)
        self.assertIn('[REDACTED]', evidence)
        self.assertEqual(json.loads(evidence)['exit_code'], 3)
        self.assertEqual(json.loads(evidence)['stage'], 'regression')

    def test_refuses_non_runner_before_reading_archive(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--adapter', '/not-an-adapter', '/not-an-archive', SHA],
                                env={}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Requires root on a disposable GitHub-hosted runner', result.stderr)


class CameraConfiguration(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        product = patch.object(lifecycle, 'PRODUCT', 'xcos')
        product.start()
        self.addCleanup(product.stop)

    def files(self, config, root, directory):
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        result = {}
        for name in ('rtsp-cert.pem', 'rtsp-key.pem', 'mediamtx.env'):
            path = directory / name
            path.write_bytes(b'private import fixture')
            path.chmod(0o600)
            result[name] = path
        return result

    def test_import_arguments_reach_real_installer_without_installed_writes(self):
        root = self.base / 'installed'
        adapter = SimpleNamespace(configuration_files=self.files)
        arguments = lifecycle.configuration_arguments(adapter, {}, root, self.base)
        expected = []
        for name in ('mediamtx.env', 'rtsp-cert.pem', 'rtsp-key.pem'):
            expected.extend(('--configuration-file', name + '=' + str(self.base / 'configuration-inputs' / name)))
        self.assertEqual(arguments, expected)
        self.assertFalse(root.exists())
        # The actual install invocation passes the validated arguments unchanged.
        source = SCRIPT.read_text()
        self.assertIn("imports = configuration_arguments(adapter, config, root, base)", source)
        self.assertIn("'--json', *imports, input=(password + '\\n').encode()", source)

    def test_main_passes_imports_to_real_install_command(self):
        package = self.base / 'unpacked'
        (package / 'share/config').mkdir(parents=True)
        (package / 'share/config/config.json.example').write_text('{}')
        archive = self.base / 'candidate.tar.gz'
        archive.write_bytes(b'opaque command-wiring fixture')
        adapter = SimpleNamespace(PRODUCT='xcos', ACCOUNT='isarmg-xcos',
                                  SERVICES=('xcos.service', 'xcos-mediamtx.service'),
                                  configure=lambda config, root, shared, port: config.update(
                                      development=False, bind=f'127.0.0.1:{port}'),
                                  configuration_files=self.files)
        commands = []
        class StopAtInstall(Exception):
            pass
        def run(*command, input=None):
            if command[0] == 'bash':
                commands.append((command, input))
                raise StopAtInstall()
            return b''
        with patch.object(sys, 'argv', ['installed_lifecycle.py', '--adapter', '/adapter', str(archive), SHA]), \
                patch.object(lifecycle, 'runner_preflight'), \
                patch.object(lifecycle, 'load_adapter', return_value=adapter), \
                patch.object(lifecycle, 'verify_archive', return_value=lifecycle.archive_digest(archive)), \
                patch.object(lifecycle, 'authority_preflight'), \
                patch.object(lifecycle, 'verify_install_parent'), \
                patch.object(lifecycle.tempfile, 'mkdtemp', return_value=str(self.base)), \
                patch.object(lifecycle, 'extract_package', return_value=package), \
                patch.object(lifecycle, 'run', side_effect=run), \
                patch.object(lifecycle, 'PRODUCT', 'xcos'), \
                patch.object(lifecycle, 'SERVICES', adapter.SERVICES), \
                patch.object(lifecycle, 'ACCOUNT', adapter.ACCOUNT), \
                patch.object(lifecycle, 'SECRETS', []):
            with self.assertRaises(StopAtInstall):
                lifecycle.main()
        self.assertEqual(len(commands), 1)
        command, password = commands[0]
        self.assertEqual(command[:2], ('bash', str(package / 'install.sh')))
        self.assertEqual(command.count('--configuration-file'), 3)
        for name in ('mediamtx.env', 'rtsp-cert.pem', 'rtsp-key.pem'):
            self.assertIn(name + '=' + str(self.base / 'configuration-inputs' / name), command)
        self.assertTrue(password.endswith(b'\n'))
        self.assertFalse((self.base / 'installed').exists())

    def test_camera_archive_requires_exact_ordered_dual_services(self):
        archive = self.base / 'xcos-1.0.1-linux-x86_64.tar.gz'
        prefix = archive.name.removesuffix('.tar.gz')
        expected = ('xcos.service', 'xcos-mediamtx.service')
        for services in (expected, expected[:1], tuple(reversed(expected))):
            document = {'identity': {'product': 'xcos', 'version': '1.0.1',
                                    'source_revision': SHA, 'target': 'x86_64-unknown-linux-gnu'},
                        'services': [{'name': name} for name in services]}
            with tarfile.open(archive, 'w:gz') as bundle:
                data = json.dumps(document).encode()
                member = tarfile.TarInfo(prefix + '/share/package.json')
                member.size = len(data)
                bundle.addfile(member, io.BytesIO(data))
            (self.base / 'SHA256SUMS').write_text(lifecycle.archive_digest(archive) + '  ' + archive.name + '\n')
            with patch.object(lifecycle, 'SERVICES', expected):
                if services == expected:
                    lifecycle.verify_archive(archive, SHA)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected service set'):
                        lifecycle.verify_archive(archive, SHA)

    def test_other_products_never_invoke_configuration_import_hook(self):
        adapter = SimpleNamespace(configuration_files=lambda *_: self.fail('unexpected hook'))
        for product in ('xscs', 'xsos', 'xszs', 'xocs'):
            with patch.object(lifecycle, 'PRODUCT', product):
                self.assertEqual(lifecycle.configuration_arguments(adapter, {}, self.base / 'root', self.base), [])
        self.assertFalse((self.base / 'configuration-inputs').exists())

    def test_rejects_unsafe_imports_before_installer(self):
        for case in ('outside', 'symlink', 'hardlink', 'public', 'directory', 'missing', 'extra', 'relative'):
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir=self.base) as temporary:
                base = Path(temporary)
                def bad(config, root, directory):
                    files = self.files(config, root, directory)
                    target = files['rtsp-key.pem']
                    if case == 'outside':
                        outside = base / 'outside'
                        target.rename(outside)
                        files['rtsp-key.pem'] = outside
                    elif case == 'symlink':
                        target.unlink()
                        target.symlink_to(files['rtsp-cert.pem'])
                    elif case == 'hardlink':
                        os.link(target, directory / 'linked')
                    elif case == 'public':
                        target.chmod(0o644)
                    elif case == 'directory':
                        target.unlink()
                        target.mkdir(mode=0o600)
                    elif case == 'missing':
                        files.pop('mediamtx.env')
                    elif case == 'extra':
                        files['../escape'] = target
                    elif case == 'relative':
                        files['rtsp-key.pem'] = Path('rtsp-key.pem')
                    return files
                with self.assertRaises(RuntimeError):
                    lifecycle.configuration_arguments(SimpleNamespace(configuration_files=bad), {}, base / 'root', base)

    def test_imported_and_managed_configuration_exact_permissions(self):
        directory = SimpleNamespace(st_uid=0, st_gid=987, st_mode=stat.S_IFDIR | 0o750)
        file = SimpleNamespace(st_uid=0, st_gid=987, st_mode=stat.S_IFREG | 0o640)
        with patch.object(Path, 'lstat', side_effect=[directory] + [file] * 5) as inspect:
            lifecycle.verify_config_permissions(Path('/installed'), 987)
            self.assertEqual(inspect.call_count, 6)
        for position in range(2, 6):
            records = [directory] + [file] * 5
            records[position] = SimpleNamespace(st_uid=0, st_gid=987, st_mode=stat.S_IFREG | 0o600)
            with patch.object(Path, 'lstat', side_effect=records):
                with self.assertRaisesRegex(RuntimeError, 'configuration permissions'):
                    lifecycle.verify_config_permissions(Path('/installed'), 987)

    def test_camera_declares_and_restarts_both_services(self):
        source = SCRIPT.read_text()
        for call in ("run('systemctl', 'enable', '--now', *SERVICES)",
                     "run('systemctl', 'restart', *SERVICES)",
                     "run('systemctl', 'disable', '--now', *SERVICES)"):
            self.assertIn(call, source)
        self.assertIn("for unit, pid in first_pids.items()", source)
        self.assertIn('adapter.persisted(request, session, state, require)', source)
        with patch.object(lifecycle, 'SERVICES', ('xcos.service', 'xcos-mediamtx.service')), \
                patch.object(lifecycle.pwd, 'getpwnam', side_effect=KeyError), \
                patch.object(lifecycle.grp, 'getgrnam', side_effect=KeyError), \
                patch.object(lifecycle.os.path, 'lexists', return_value=False), \
                patch.object(lifecycle, 'property_value', return_value='not-found') as inspect:
            lifecycle.authority_preflight()
        self.assertEqual(inspect.call_args_list,
                         [unittest.mock.call('LoadState', 'xcos.service'),
                          unittest.mock.call('LoadState', 'xcos-mediamtx.service')])


class SharedAuthority(unittest.TestCase):
    def test_git_trust_is_scoped_to_one_exact_checkout_command(self):
        root = Path('/runner/exact-checkout')
        with patch.object(lifecycle, 'run', return_value=b'abc') as command:
            self.assertEqual(lifecycle.checkout_git(root, 'rev-parse', 'HEAD'), b'abc')
        command.assert_called_once_with('git', '-c', 'safe.directory=/runner/exact-checkout',
                                        '-C', '/runner/exact-checkout', 'rev-parse', 'HEAD')

    @unittest.skipUnless(os.geteuid() == 0, 'Requires root for a disposable foreign-owned Git checkout')
    def test_exact_safe_directory_supports_real_foreign_owned_checkout(self):
        import pwd
        try:
            owner = pwd.getpwnam('nobody')
        except KeyError:
            self.skipTest('No nobody identity on this runner')
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            source.mkdir()
            subprocess.run(['git', 'init', '--quiet', str(source)], check=True)
            for path in [source, *source.rglob('*')]:
                os.chown(path, owner.pw_uid, owner.pw_gid)
            denied = subprocess.run(['git', '-c', 'safe.directory=', '-C', str(source), 'status', '--porcelain'],
                                    capture_output=True)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn(b'dubious ownership', denied.stderr)
            self.assertEqual(lifecycle.checkout_git(source, 'status', '--porcelain'), b'')

    def test_every_declared_service_checked_before_install(self):
        with patch.object(lifecycle, 'SERVICES', ('first.service', 'second.service')), \
                patch.object(lifecycle.pwd, 'getpwnam', side_effect=KeyError), \
                patch.object(lifecycle.grp, 'getgrnam', side_effect=KeyError), \
                patch.object(lifecycle.os.path, 'lexists', return_value=False) as exists, \
                patch.object(lifecycle, 'property_value', return_value='not-found') as property_value:
            lifecycle.authority_preflight()
            self.assertEqual(exists.call_count, 24)
            self.assertEqual(property_value.call_count, 2)

    def test_existing_group_or_unit_blocks_installation(self):
        with patch.object(lifecycle.pwd, 'getpwnam', side_effect=KeyError), \
                patch.object(lifecycle.grp, 'getgrnam', return_value=object()):
            with self.assertRaisesRegex(RuntimeError, 'existing service account or group'):
                lifecycle.authority_preflight()
        with patch.object(lifecycle.pwd, 'getpwnam', side_effect=KeyError), \
                patch.object(lifecycle.grp, 'getgrnam', side_effect=KeyError), \
                patch.object(lifecycle.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'Existing service authority'):
                lifecycle.authority_preflight()

    def test_uninstall_validates_all_files_before_any_unlink(self):
        root = Path('/fresh/installed')
        unit = '/etc/systemd/system/xczs.service'
        dropin = unit + '.d/state.conf'
        record = {'device': 10, 'inode': 20, 'sha256': lifecycle.hashlib.sha256(b'unit').hexdigest()}
        journal = {'product': 'xczs', 'phase': 'complete', 'root': str(root),
                   'unit_files': {unit: record, dropin: record}}
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_dev=10, st_ino=20)
        bad = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_dev=10, st_ino=21)
        with patch.object(Path, 'read_text', return_value=json.dumps(journal)), \
                patch.object(Path, 'lstat', side_effect=[good, bad]), \
                patch.object(Path, 'read_bytes', return_value=b'unit'), \
                patch.object(Path, 'unlink') as unlink:
            with self.assertRaisesRegex(RuntimeError, 'ownership changed'):
                lifecycle.remove_recorded_units(root)
            unlink.assert_not_called()
        journal['unit_files']['/etc/unrelated'] = record
        with patch.object(Path, 'read_text', return_value=json.dumps(journal)), \
                patch.object(Path, 'unlink') as unlink:
            with self.assertRaisesRegex(RuntimeError, 'Unexpected installed units'):
                lifecycle.remove_recorded_units(root)
            unlink.assert_not_called()

    def test_wrong_product_journal_cannot_authorize_cleanup(self):
        with patch.object(Path, 'read_text', return_value=json.dumps({
                'phase': 'complete', 'root': '/fresh', 'product': 'other', 'unit_files': {}})), \
                patch.object(Path, 'unlink') as unlink:
            with self.assertRaisesRegex(RuntimeError, 'Wrong installation authority'):
                lifecycle.remove_recorded_units(Path('/fresh'))
            unlink.assert_not_called()


if __name__ == '__main__':
    unittest.main()
