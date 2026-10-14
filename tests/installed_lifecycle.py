#!/usr/bin/env python3
"""Exercise the exact release archive on a disposable GitHub-hosted Linux VM.

No fixture switches, rebuilding, production hosts or persistent credentials.
Failed installations are left for VM disposal rather than guessing cleanup authority.
"""
import argparse
import importlib.util
import hashlib
import grp
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request

PRODUCT = None
SERVICES = ()
ACCOUNT = None
SECRETS = []
STAGE = 'preflight'
INSTALL_ROOT = None


def diagnostic(event, **fields):
    destination = os.environ.get('LIFECYCLE_DIAGNOSTICS')
    if not destination:
        return
    directory = Path(destination)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    text = json.dumps({'event': event, 'stage': STAGE, **fields})
    for secret in SECRETS:
        if secret:
            text = text.replace(secret, '[REDACTED]')
    # Defense in depth for structured diagnostic fields and HTTP headers.
    text = re.sub(r'(?i)(bearer\s+)[a-z0-9._~+/-]+', r'\1[REDACTED]', text)
    with (directory / 'lifecycle.jsonl').open('a') as output:
        output.write(text[:262144] + '\n')


def phase(name):
    global STAGE
    STAGE = name
    diagnostic('phase')



def verify_install_parent(parent):
    """Match the real installer's root-controlled ancestor requirement."""
    for path in (parent, *parent.parents):
        info = path.lstat()
        diagnostic('installation_parent', path=str(path), uid=info.st_uid,
                   mode=oct(stat.S_IMODE(info.st_mode)))
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022,
                f'Installation parent must be a root-controlled directory: {path}')


def verify_config_permissions(root, service_gid):
    # These server adapters declare no mutable configuration paths. Only the administrator
    # owns configuration; the service's primary group receives read access.
    for relative, kind, mode in (('config', stat.S_ISDIR, 0o750),
                                 ('config/config.json', stat.S_ISREG, 0o640)):
        info = (root / relative).lstat()
        require(kind(info.st_mode) and info.st_uid == 0
                and info.st_gid == service_gid and stat.S_IMODE(info.st_mode) == mode,
                'Installed read-only configuration permissions differ')


def installation_observation(root):
    """Read only the fixed public journal fields, never credentials or state."""
    journal = root / 'maintenance/install.json'
    info = journal.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 1024 * 1024,
            'Installation journal is not one bounded regular file')
    document = json.loads(journal.read_text())
    allowed_phases = {'staging', 'configuration-validated', 'initialize-intent',
                      'initialized', 'publish-intent', 'published', 'units-intent',
                      'units-installed', 'permissions-verified', 'startup-restored', 'complete'}
    require(document.get('product') == PRODUCT and document.get('phase') in allowed_phases,
            'Installation journal has an unknown public identity or phase')
    return {'product': PRODUCT, 'installation_phase': document['phase']}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(*command, input=None):
    # Capture all output: installation/authentication output can contain secrets.
    result = subprocess.run(command, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=180, check=False)
    if result.returncode != 0:
        diagnostic('command_failed', command=list(command), exit_code=result.returncode,
                   stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
    require(result.returncode == 0, f'{Path(command[0]).name} failed at {STAGE} (exit {result.returncode})')
    return result.stdout


def property_value(name, service=None):
    return run('systemctl', 'show', service or SERVICES[0], f'--property={name}', '--value').decode().strip()


def archive_digest(archive):
    with archive.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_archive(archive, revision):
    require(archive.is_file() and not archive.is_symlink(), 'Expected one regular release archive')
    expected = archive_digest(archive)
    lines = (archive.parent / 'SHA256SUMS').read_text().splitlines()
    matches = [line.split() for line in lines if len(line.split()) == 2
               and line.split()[1].lstrip('*') == archive.name]
    require(len(matches) == 1 and matches[0][0] == expected, 'Release archive checksum mismatch')
    require(len(revision) == 40 and all(c in '0123456789abcdef' for c in revision), 'Expected exact source SHA')
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        require(all(member.isfile() or member.isdir() for member in members), 'Only regular package entries allowed')
        require(all(not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
                    for member in members), 'Unsafe package path')
        require(len({member.name for member in members}) == len(members), 'Duplicate package path')
        prefix = archive.name.removesuffix('.tar.gz')
        require(prefix.startswith(PRODUCT + '-') and prefix.endswith('-linux-x86_64'), 'Wrong archive name')
        require(all(Path(member.name).parts[0] == prefix for member in members), 'Wrong package envelope')
        manifest = json.load(bundle.extractfile(prefix + '/share/package.json'))
        require(manifest['identity']['product'] == PRODUCT, 'Wrong product')
        require(manifest['identity']['source_revision'] == revision, 'Wrong candidate revision')
        require(tuple(entry['name'] for entry in manifest['services']) == SERVICES, 'Unexpected service set')
        identity = manifest['identity']
        require(identity.get('target') == 'x86_64-unknown-linux-gnu'
                and prefix == f"{PRODUCT}-{identity.get('version')}-linux-x86_64", 'Wrong package identity')
    return expected



def extract_package(archive, destination):
    def package_filter(member, target):
        filtered = tarfile.data_filter(member, target)
        if filtered is not None and filtered.isdir():
            # data_filter intentionally clears directory mode. Reapply only
            # the exact immutable package contract, never a permissive mode
            # from untrusted metadata or the caller's current umask.
            require(member.mode == 0o755, 'Package directory mode must be 0755')
            filtered = filtered.replace(mode=0o755)
        return filtered

    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter=package_filter)
    return destination / archive.name.removesuffix('.tar.gz')


def tls_frontend(base, backend_port):
    """A loopback-only TLS terminator, matching the supported production topology."""
    certificate, key = base / 'cert.pem', base / 'key.pem'
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
        '-keyout', str(key), '-out', str(certificate))
    key.chmod(0o600)

    class Proxy(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def forward(self):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 <= length <= 65536:
                self.send_error(413)
                return
            connection = http.client.HTTPConnection('127.0.0.1', backend_port, timeout=5)
            try:
                connection.request(self.command, self.path, self.rfile.read(length), dict(self.headers))
                response = connection.getresponse()
                body = response.read(1024 * 1024)
                self.send_response(response.status)
                for name, value in response.getheaders():
                    if name.lower() not in ('connection', 'transfer-encoding', 'content-length'):
                        self.send_header(name, value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                self.send_error(502)
            finally:
                connection.close()

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = forward

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, ssl.create_default_context(cafile=str(certificate))


def runner_preflight():
    require(os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
            'Requires root on a disposable GitHub-hosted runner; no fixture fallback')
    require(Path('/run/systemd/system').is_dir(), 'Real systemd is required')


def checkout_git(root, *arguments):
    # sudo changes ownership expectations on the disposable runner. Scope trust
    # to this exact checked-out path for this command; never change global Git config.
    return run('git', '-c', 'safe.directory=' + str(root), '-C', str(root), *arguments)


def load_adapter(path, revision):
    """Load test code only from a clean source checkout, never the archive."""
    path = path.resolve(strict=True)
    source = path.parent.parent
    require(path.parent.name == 'scripts' and path.is_file(), 'Expected source scripts adapter')
    require(checkout_git(source, 'rev-parse', 'HEAD').decode().strip() == revision
            and not checkout_git(source, 'status', '--porcelain=v1', '--untracked-files=all').strip(),
            'Adapter source must be the exact clean candidate revision')
    installer = Path(__file__).resolve().parents[1]
    pin = (source / 'config/xssi.lock').read_text()
    require(re.fullmatch(r'git_rev=[0-9a-f]{40}\n', pin) is not None,
            'Expected exact installer lock')
    require(checkout_git(installer, 'rev-parse', 'HEAD').decode().strip() == pin[8:].strip()
            and not checkout_git(installer, 'status', '--porcelain=v1', '--untracked-files=all').strip(),
            'Harness must run from the exact clean pinned installer checkout')
    require(checkout_git(source, 'ls-files', '--error-unmatch', str(path)).strip(),
            'Adapter must be tracked source')
    spec = importlib.util.spec_from_file_location('product_adapter', path)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    require(re.fullmatch(r'[a-z][a-z0-9]+', adapter.PRODUCT) is not None,
            'Invalid adapter product')
    require(adapter.ACCOUNT == 'isarmg-' + adapter.PRODUCT, 'Invalid adapter account')
    require(isinstance(adapter.SERVICES, tuple) and adapter.SERVICES
            and len(set(adapter.SERVICES)) == len(adapter.SERVICES)
            and all(re.fullmatch(r'[a-z][a-z0-9-]*\.service', unit) for unit in adapter.SERVICES),
            'Invalid adapter service set')
    return adapter


def authority_preflight():
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup(ACCOUNT)
        except KeyError:
            pass
        else:
            raise RuntimeError('Refusing to reuse an existing service account or group')
    for service in SERVICES:
        for parent in ('/etc/systemd/system', '/run/systemd/system', '/run/systemd/transient',
                       '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
            for suffix in ('', '.d'):
                require(not os.path.lexists(Path(parent) / (service + suffix)),
                        'Existing service authority must be preserved')
        require(property_value('LoadState', service) == 'not-found',
                'Existing systemd registration must be preserved')


def remove_recorded_units(root):
    """Validate the complete exact unit authority before removing any file."""
    journal = json.loads((root / 'maintenance/install.json').read_text())
    require(journal['phase'] == 'complete' and journal['root'] == str(root)
            and journal.get('product') == PRODUCT, 'Wrong installation authority')
    allowed = {Path('/etc/systemd/system') / relative
               for unit in SERVICES for relative in (unit, unit + '.d/state.conf')}
    require({Path(path) for path in journal['unit_files']} == allowed, 'Unexpected installed units')
    for name, record in journal['unit_files'].items():
        path = Path(name)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and (info.st_dev, info.st_ino) == (record['device'], record['inode'])
                and hashlib.sha256(path.read_bytes()).hexdigest() == record['sha256'],
                'Installed unit ownership changed; refusing cleanup')
    # Verify every authority before removing any of the files.
    for path in allowed:
        path.unlink()
    for unit in SERVICES:
        (Path('/etc/systemd/system') / (unit + '.d')).rmdir()


def main():
    global INSTALL_ROOT, PRODUCT, SERVICES, ACCOUNT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('archive', type=Path)
    parser.add_argument('revision')
    args = parser.parse_args()
    runner_preflight()
    adapter = load_adapter(args.adapter, args.revision)
    PRODUCT, SERVICES, ACCOUNT = adapter.PRODUCT, adapter.SERVICES, adapter.ACCOUNT
    archive = args.archive.resolve(strict=True)
    digest = verify_archive(archive, args.revision)
    authority_preflight()
    # GitHub runner images make /opt world-writable; never change that
    # shared system directory or weaken the installer's ancestor check.
    parent = Path('/var/lib')
    verify_install_parent(parent)
    base = Path(tempfile.mkdtemp(prefix=PRODUCT + '-install-smoke-', dir=parent))
    base.chmod(0o755)
    root, package, shared = base / 'installed', base / 'package', base / 'shared'
    INSTALL_ROOT = root
    package.mkdir(mode=0o700)
    package = extract_package(archive, package)
    require(archive_digest(archive) == digest, 'Archive changed during extraction')
    run('python3', '-I', '-B', str(package / 'libexec/package.py'), 'verify', str(package))
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config = json.loads((package / 'share/config/config.json.example').read_text())
    adapter.configure(config, root, shared, port)
    require(config.get('development') is False and config.get('bind') == f'127.0.0.1:{port}',
            'Adapter must use production mode on loopback')
    config_path = base / 'input.json'
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    password = secrets.token_urlsafe(32)
    SECRETS.append(password)
    phase('install-and-initialize')
    result = json.loads(run('bash', str(package / 'install.sh'), '--package', str(package),
                           '--root', str(root), '--config', str(config_path), '--username', 'admin',
                           '--json', input=(password + '\n').encode()))
    require(result['status'] == 'installed' and result['services_started'] is False
            and result['state_checked'] is True and result['permissions_verified'] is True,
            'Installer did not confirm initialized, verified, stopped installation')
    require(all(property_value('ActiveState', unit) == 'inactive' and property_value('MainPID', unit) == '0' for unit in SERVICES),
            'Fresh install unexpectedly started')
    identity = pwd.getpwnam(ACCOUNT)
    require(identity.pw_uid != 0 and all(property_value('User', unit) == ACCOUNT for unit in SERVICES), 'Service identity is incorrect')
    verify_config_permissions(root, identity.pw_gid)
    print('PASS: verified exact release archive; real installer initialized state and left service stopped', flush=True)
    proxy, client_tls = tls_frontend(base, port)
    origin = f'https://127.0.0.1:{proxy.server_port}'
    # Disable proxy use explicitly; every HTTP request stays on loopback.
    cookies = http.cookiejar.CookieJar()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise RuntimeError('Installed lifecycle HTTP redirects are forbidden')

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=client_tls),
                                        urllib.request.HTTPCookieProcessor(cookies))

    def request(path, method='GET', body=None, headers=None):
        selected = {'Origin': origin, 'Sec-Fetch-Site': 'same-origin'}
        selected.update(headers or {})
        with opener.open(urllib.request.Request(origin + path, data=body, method=method,
                                               headers=selected), timeout=5) as response:
            return response.status, response.read(1024 * 1024)

    def ready():
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if request('/readyz')[0] == 200:
                    require(all(property_value('ActiveState', unit) == 'active' for unit in SERVICES), 'Service is not active')
                    return
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                pass
            time.sleep(.5)
        raise RuntimeError('Installed service did not become ready within 60 seconds')

    phase('start-and-ready')
    run('systemctl', 'enable', '--now', *SERVICES)
    ready()
    first_pids = {unit: property_value('MainPID', unit) for unit in SERVICES}
    require(all(pid.isdecimal() and int(pid) > 0 for pid in first_pids.values()),
            'No real service process')
    phase('administrator-login-and-business')
    status, body = request('/api/v1/auth/login', 'POST',
                           json.dumps({'username': 'admin', 'password': password}).encode(),
                           {'Content-Type': 'application/json'})
    session = json.loads(body)
    SECRETS.append(session.get('csrf_token', ''))
    SECRETS.extend(cookie.value for cookie in cookies)
    require(status == 200 and session['authenticated'] is True and session['role'] == 'admin',
            'Initialized administrator login failed')
    state = adapter.exercise(request, session, SECRETS, require)
    phase('restart-and-persistence')
    run('systemctl', 'restart', *SERVICES)
    ready()
    require(all(property_value('MainPID', unit) != pid
                and property_value('MainPID', unit).isdecimal()
                and int(property_value('MainPID', unit)) > 0 for unit, pid in first_pids.items()),
            'Restart did not replace every service process')
    adapter.persisted(request, session, state, require)
    print('PASS: real systemd start, administrator login, business mutations, restart and persisted session/data', flush=True)
    phase('stop-and-offline-check')
    run('systemctl', 'disable', '--now', *SERVICES)
    require(all(property_value('MainPID', unit) == '0' for unit in SERVICES), 'Writer still running after stop')
    run('bash', str(root / 'maintenance.sh'), '--root', str(root), '--json', 'check')
    # Uninstall is deliberately operator-managed in this product. Only remove
    # files whose recorded inode and digest still match this installation.
    phase('operator-uninstall-retaining-data')
    retained = {}
    for relative in adapter.RETAINED_FILES:
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts,
                'Invalid retained state path')
        path = root / relative
        require(stat.S_ISREG(path.lstat().st_mode), 'Retained state must be a regular file')
        retained[path] = archive_digest(path)
    require(retained, 'Adapter must declare retained state files')
    remove_recorded_units(root)
    run('systemctl', 'daemon-reload')
    require(all(property_value('LoadState', unit) == 'not-found' for unit in SERVICES), 'Service registration still exists')
    for name in ('bin', 'libexec', 'share'):
        shutil.rmtree(root / name)
    require(all(stat.S_ISREG(path.lstat().st_mode) and archive_digest(path) == digest
                for path, digest in retained.items()), 'Operator uninstall changed retained state')
    adapter.retained(root, shared, state, require)
    require(pwd.getpwnam(ACCOUNT) == identity, 'Account identity changed; refusing cleanup')
    run('userdel', ACCOUNT)
    try:
        remaining_group = grp.getgrnam(ACCOUNT)
    except KeyError:
        pass
    else:
        require(remaining_group.gr_gid == identity.pw_gid and not remaining_group.gr_mem,
                'Group identity changed; refusing cleanup')
        run('groupdel', ACCOUNT)
    proxy.shutdown()
    proxy.server_close()
    # This exact fresh /var/lib child is the only data tree disposed by the test.
    shutil.rmtree(base)
    phase('complete')
    print('PASS: offline state check; operator uninstall retained data; isolated test resources removed', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not print response bodies, subprocess output, passwords or tokens.
        diagnostic('failed', error_type=type(error).__name__, message=str(error))
        if INSTALL_ROOT is not None:
            try:
                diagnostic('installation_journal', **installation_observation(INSTALL_ROOT))
            except (OSError, ValueError, RuntimeError):
                diagnostic('installation_journal_unavailable')
        print(f'Installed lifecycle FAILED: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
