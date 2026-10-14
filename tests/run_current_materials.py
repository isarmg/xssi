"""Exercise the real independent ELF against generated owner materials in /tmp.

This is a test runner, never a production installation entry or package asset.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import uuid


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        result[str(path.relative_to(root))] = (
            info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_mtime_ns,
            sha(path) if path.is_file() else None,
        )
    return result


def run_one(base, setup, companion, product):
    with tempfile.TemporaryDirectory(prefix=f'xssi-{product}-current-') as temporary:
        Path(temporary).chmod(0o755)
        root = Path(temporary) / 'root'
        package = root / 'maintenance' / 'install-payload'
        for name, mode in [('', 0o755), ('maintenance', 0o700), ('config', 0o750),
                           ('state', 0o700), ('logs', 0o700), ('run', 0o700)]:
            target = root / name
            target.mkdir(mode=mode)
            target.chmod(mode)
        for name in ['state', 'logs', 'run']:
            os.chown(root / name, 33, 33)
        os.chown(root/'config', 0, 33)
        package.mkdir(mode=0o700)
        (package / 'libexec').mkdir(mode=0o755)
        (package / 'share').mkdir(mode=0o755)
        shutil.copytree(base / f'{product}-material-17' / 'contracts', package / 'share/contracts')
        for path in (package / 'share/contracts').rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        shutil.copyfile(setup, package / 'libexec/setup')
        (package / 'libexec/setup').chmod(0o755)
        contract = json.loads((package / 'share/contracts/install.json').read_text())
        config = {}
        if product == 'xcos':
            config['public_rtsp_publish_base_url'] = 'rtsps://camera.example.org:8322'
            (package / 'bin').mkdir(mode=0o755)
            shutil.copyfile(companion, package / 'bin/mediamtx')
            (package / 'bin/mediamtx').chmod(0o755)
            source = base.parent.parent / 'xcos/config/mediamtx.lock'
            shutil.copyfile(source, package / 'share/mediamtx.lock')
            certificate=root/'config/rtsp-cert.pem';private_key=root/'config/rtsp-key.pem'
            subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','ec','-pkeyopt',
                            'ec_paramgen_curve:prime256v1','-nodes','-days','2',
                            '-subj','/CN=current-contract-fixture',
                            '-addext','subjectAltName=DNS:camera.example.org',
                            '-keyout',str(private_key),'-out',str(certificate)],
                           check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,timeout=20)
            for path in (certificate,private_key):
                path.chmod(0o640)
                os.chown(path, 0, 33)
        if product == 'xczs':
            config['serve_path'] = str(root / 'business')
        configuration = root / 'config/config.json'
        configuration.write_text(json.dumps(config))
        configuration.chmod(0o640)
        os.chown(configuration, 0, 33)
        entries = []
        for path in sorted(package.rglob('*')):
            if path.is_file():
                entries.append(dict(path=str(path.relative_to(package)), mode=f'{stat.S_IMODE(path.stat().st_mode):04o}', size=path.stat().st_size, sha256=sha(path)))
        manifest = dict(manifest_version=1, identity=contract['identity'], schema_identity=contract['schema_identity'],
                        server=f'bin/{product}', setup='libexec/setup', services=[], files=entries)
        manifest_path = package / 'share/package.json'
        manifest_path.write_text(json.dumps(manifest, separators=(',', ':')))
        (package / 'share/package.sha256').write_text(sha(manifest_path) + '\n')
        lock = root / 'maintenance/tool.lock'
        lock.touch(mode=0o600)
        lock.chmod(0o600)
        with lock.open('r+b') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            common = [str(package / 'libexec/setup'), '--product', product, '--root', str(root),
                      '--tool-lock-fd', str(held.fileno()), '--service-uid', '33', '--service-gid', '33', '--json']

            def invoke(command, password=None, valid=True):
                descriptor=os.open(package/'libexec/setup',os.O_RDONLY|os.O_NOFOLLOW)
                try:
                    result = subprocess.run(common + command, executable=f'/proc/self/fd/{descriptor}', input=password, text=True, capture_output=True,
                                            timeout=90, pass_fds=(held.fileno(),descriptor),
                                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
                finally:os.close(descriptor)
                if (result.returncode == 0) != valid:
                    raise AssertionError(f'{product} {command}: {result.returncode}: {result.stderr}: {result.stdout}')
                return json.loads(result.stdout)

            before = snapshot(root)
            report = invoke(['config-validate'])
            assert snapshot(root) == before, 'config validation modified installation'
            for raw in report['business_paths']:
                path = Path(raw)
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o775)
                os.chown(path, 33, 33)
                existing = path / 'retained-user-file'
                existing.write_bytes(b'existing business content')
                os.chown(existing, 65534, 65534)
            imports = {}
            if product == 'xcos':
                for name in ['rtsp-cert.pem', 'rtsp-key.pem']:
                    path = root / 'config' / name
                    info = path.stat()
                    imports[name] = dict(written=True, device=info.st_dev, inode=info.st_ino, sha256=sha(path))
            operation = str(uuid.uuid4())
            journal = dict(version=1, operation_id=operation, product=product, root=str(root),
                           phase='initialize-intent', package_sha256=sha(manifest_path), configuration_files=imports)
            install_record = root / 'maintenance/install.json'
            install_record.write_text(json.dumps(journal))
            install_record.chmod(0o600)
            initialize = ['--operation-id', operation, 'initialize', '--username', 'admin']
            password = 'Current-test-password-001!\n'
            invoke(initialize, password)
            initialized = snapshot(root)
            access = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c',
                "import json,os,pathlib,sys,uuid; r=json.loads(sys.argv[1]); "
                "[pathlib.Path(p).read_bytes() for p in r['private_files']]; "
                "[(lambda p: (p.write_bytes(b'actual service UID fixture'),p.unlink()))(pathlib.Path(d)/('.xssi-fixture-'+str(uuid.uuid4()))) for d in r['business_paths']+r['business_directories']]; "
                "assert not os.access(sys.argv[2],os.W_OK)", json.dumps(report),str(configuration)],
                capture_output=True,text=True,user=33,group=33,extra_groups=[],
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'},timeout=30)
            assert access.returncode==0,access.stderr
            invoke(initialize, password)
            # Completing the same intent changes only its private record atomically.
            assert (root / 'maintenance/install' / operation / 'created.json').is_file()
            # Model a kill after an inode and partial SQLite contents were
            # durably recorded, before completion. Retry must retain locks.
            created_path = root / 'maintenance/install' / operation / 'created.json'
            created = json.loads(created_path.read_text())
            runtime_inodes = {item['path']: Path(item['path']).stat().st_ino for item in report['runtime_locks']}
            created['complete'] = False
            created_path.write_text(json.dumps(created))
            database_record = next(item for item in created['objects'] if not item['directory'] and not item['retained'] and any(Path(item['path']).name == Path(d['path']['suffix']).name for d in contract['databases']))
            Path(database_record['path']).write_bytes(b'interrupted current SQLite initialization')
            invoke(initialize, password)
            assert all(Path(path).stat().st_ino == inode for path, inode in runtime_inodes.items())
            before = snapshot(root)
            invoke(['check'])
            assert snapshot(root) == before, 'readonly check modified original installation'
            file_lock = next((Path(item['path']) for item in report['runtime_locks'] if item['kind'] == 'file'), None)
            if file_lock:
                with file_lock.open('r+b') as busy:
                    fcntl.flock(busy, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    invoke(['check'], valid=False)
                    assert snapshot(root) == before, 'busy writer check changed state'
            invoke(['admin-reset', '--username', 'admin'], 'Current-test-password-002!\n')
            invoke(['check'])
            for raw in report['business_paths']:
                existing = Path(raw) / 'retained-user-file'
                assert existing.read_bytes() == b'existing business content'
                assert existing.stat().st_uid == 65534
                assert stat.S_IMODE(Path(raw).stat().st_mode) == 0o775
            current = snapshot(root)
            invoke(['--operation-id', str(uuid.uuid4()), 'initialize', '--username', 'admin'], password, valid=False)
            assert snapshot(root) == current, 'another operation changed existing state'
            print(json.dumps({'product': product, 'status': 'passed', 'vectors': sum(len(d['validation']) for d in contract['databases']), 'files_after_initialize': len(initialized)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--materials', required=True, type=Path)
    parser.add_argument('--setup', required=True, type=Path)
    parser.add_argument('--mediamtx', required=True, type=Path)
    parser.add_argument('--product', action='append', choices=['xcos', 'xczs', 'xocs', 'xsos', 'xscs', 'xszs'])
    args = parser.parse_args()
    for product in args.product or ['xcos', 'xczs', 'xocs', 'xsos', 'xscs', 'xszs']:
        run_one(args.materials, args.setup, args.mediamtx, product)
