"""Inode authority and explicit retention for closed tool-owned materials."""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time
import uuid
import package

KINDS = {'download': 'downloads', 'maintenance': 'operations', 'installation': 'install'}
MAX_OBJECTS = package.MAX_FILES + 256


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino}


def private(path):
    package.private_chain(path)
    info = path.lstat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('material control directory differs from root authority')
    return info


def lock_authority(root, descriptor):
    private(root / 'maintenance')
    held, named = os.fstat(descriptor), (root / 'maintenance/tool.lock').lstat()
    if identity(held) != identity(named) or not stat.S_ISREG(held.st_mode) or held.st_uid != 0 or held.st_nlink != 1 or stat.S_IMODE(held.st_mode) != 0o600:
        raise ValueError('material collection requires the same root tool lock')
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)


def control_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700)
        sync_directory(path.parent)
    return private(path)


def save(path, record):
    from install import atomic
    encoded = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError('material authority exceeds its bound')
    atomic(path, encoded, 0o600)


def operation_id(value):
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError('material operation must be canonical UUIDv4')
    return value


def inventory(work):
    objects = []
    total = 0
    for current, directories, files in os.walk(work, followlinks=False):
        paths = [Path(current)] + [Path(current) / name for name in files]
        for name in directories:
            if (Path(current) / name).is_symlink():
                raise ValueError('material directory uses a symlink')
        for path in paths:
            info = path.lstat()
            directory = stat.S_ISDIR(info.st_mode)
            if info.st_uid != 0 or info.st_mode & 0o7022 or not (directory or stat.S_ISREG(info.st_mode)) or (not directory and info.st_nlink != 1):
                raise ValueError('material inventory ownership or type differs')
            data = b'' if directory else package.bytes_regular(path, package.MAX_FILE_BYTES)
            total += len(data)
            if total > package.MAX_TOTAL_BYTES or len(objects) >= MAX_OBJECTS:
                raise ValueError('material inventory exceeds its bound')
            objects.append({'path': str(path.relative_to(work)), **identity(info),
                            'directory': directory, 'mode': stat.S_IMODE(info.st_mode),
                            'size': len(data), 'sha256': None if directory else hashlib.sha256(data).hexdigest()})
    return sorted(objects, key=lambda item: item['path'])


def load(root, path):
    record = package.loads(package.bytes_regular(path, 16 * 1024 * 1024, (0o600, 0)))
    required = {'version', 'operation_id', 'root', 'kind', 'phase', 'parent', 'directory', 'completed_at_utc_micros', 'objects', 'auxiliary'}
    if not isinstance(record,dict) or set(record) != required or type(record['version']) is not int or record['version'] != 1 or record['root'] != str(root) or record['kind'] not in KINDS:
        raise ValueError('material record contract differs')
    operation_id(record['operation_id'])
    if path.name != record['operation_id'] + '.json' or record['phase'] not in ['intent', 'complete', 'collecting', 'collected']:
        raise ValueError('material record identity differs')
    for seal in [record['parent'], record['directory']]:
        if seal is None and record['phase'] == 'intent':
            continue
        if not isinstance(seal, dict) or set(seal) != {'device', 'inode'} or any(type(value) is not int or not 0 <= value < 2**64 for value in seal.values()):
            raise ValueError('material record inode authority differs')
    if record['phase'] != 'intent' and (type(record['completed_at_utc_micros']) is not int or not 0 < record['completed_at_utc_micros'] <= time.time_ns() // 1000):
        raise ValueError('material completion time differs')
    if not isinstance(record['objects'], list) or len(record['objects']) > MAX_OBJECTS or not isinstance(record['auxiliary'], list) or len(record['auxiliary']) > 1:
        raise ValueError('material object count differs')
    names = set()
    for item in record['objects']:
        if set(item) != {'path', 'device', 'inode', 'directory', 'mode', 'size', 'sha256'} or type(item['directory']) is not bool:
            raise ValueError('material object contract differs')
        relative = PurePosixPath(item['path'])
        if relative.is_absolute() or str(relative) != item['path'] or any(part in ('', '..') for part in relative.parts) or item['path'] in names:
            raise ValueError('material object mapping differs')
        names.add(item['path'])
        if any(type(item[key]) is not int or not 0 <= item[key] < 2**64 for key in ['device', 'inode', 'mode', 'size']):
            raise ValueError('material object metadata differs')
        if item['directory']:
            if item['sha256'] is not None or item['size'] != 0:
                raise ValueError('directory material has file contents')
        elif not isinstance(item['sha256'], str) or not package.re.fullmatch('[0-9a-f]{64}', item['sha256']) or item['size'] > package.MAX_FILE_BYTES:
            raise ValueError('material SHA256 differs')
    if record['phase'] != 'intent':
        roots = [item for item in record['objects'] if item['path'] == '.']
        if len(roots) != 1 or not roots[0]['directory'] or roots[0]['mode'] != 0o700 or {key: roots[0][key] for key in ['device', 'inode']} != record['directory']:
            raise ValueError('material root object differs from its creation authority')
    work = root / 'maintenance' / KINDS[record['kind']] / record['operation_id']
    if identity(private(work.parent)) != record['parent']:
        raise ValueError('material parent identity changed')
    for item in record['auxiliary']:
        expected = root / 'maintenance/install' / (record['operation_id'] + '.json')
        if record['kind'] != 'installation' or set(item) != {'path', 'device', 'inode', 'sha256'} or item['path'] != str(expected):
            raise ValueError('auxiliary material authority differs')
        if any(type(item[key]) is not int or not 0 <= item[key] < 2**64 for key in ['device', 'inode']) or not isinstance(item['sha256'],str) or not package.re.fullmatch('[0-9a-f]{64}',item['sha256']):
            raise ValueError('auxiliary material metadata differs')
    return record, work


def begin(root, kind, descriptor, operation=None):
    lock_authority(root, descriptor)
    if kind not in ('download', 'maintenance'):
        raise ValueError('only a new download or maintenance creates a material operation')
    operation = operation_id(operation or str(uuid.uuid4()))
    parent = root / 'maintenance' / KINDS[kind]
    parent_info = control_directory(parent)
    records = root / 'maintenance/material-records'
    control_directory(records)
    path = records / (operation + '.json')
    work = parent / operation
    if path.exists():
        record, recorded_work = load(root, path)
        if record['kind'] != kind or record['phase'] != 'intent' or recorded_work != work:
            raise ValueError('material operation cannot be replayed')
    else:
        if work.exists() or work.is_symlink():
            raise ValueError('unknown material operation must be preserved')
        record = dict(version=1, operation_id=operation, root=str(root), kind=kind, phase='intent',
                      parent=identity(parent_info), directory=None, completed_at_utc_micros=None, objects=[], auxiliary=[])
        save(path, record)
    if record['directory'] is None:
        if work.exists() or work.is_symlink():
            raise ValueError('unrecorded material inode must be preserved')
        work.mkdir(mode=0o700)
        record['directory'] = identity(work.lstat())
        save(path, record)
        sync_directory(parent)
    if identity(private(work)) != record['directory']:
        raise ValueError('material operation directory changed')
    return path, work


def complete(root, record_path, descriptor, expected_files):
    lock_authority(root, descriptor)
    record, work = load(root, record_path)
    if record['phase'] != 'intent' or identity(private(work)) != record['directory']:
        raise ValueError('material completion lacks its original inode')
    objects = inventory(work)
    actual = {item['path'] for item in objects if not item['directory']}
    if actual != set(expected_files):
        raise ValueError('unknown or missing material cannot be registered for collection')
    expected_directories = {'.'}
    for value in expected_files:
        relative = PurePosixPath(value)
        expected_directories.update(str(parent) for parent in relative.parents)
    if {item['path'] for item in objects if item['directory']} != expected_directories:
        raise ValueError('unknown material directory must be preserved')
    record.update(phase='complete', objects=objects, completed_at_utc_micros=time.time_ns() // 1000)
    save(record_path, record)


def record_install(root, operation, descriptor):
    lock_authority(root, descriptor)
    operation_id(operation)
    parent = root / 'maintenance/install'
    work = parent / operation
    authority_path = parent / (operation + '.json')
    authority = package.loads(package.bytes_regular(authority_path, 65536, (0o600, 0)))
    created = package.loads(package.bytes_regular(work / 'created.json', 4 * 1024 * 1024, (0o600, 0)))
    installed = package.loads(package.bytes_regular(root / 'maintenance/install.json', 4 * 1024 * 1024, (0o600, 0)))
    if authority.get('version') != 1 or authority.get('operation_id') != operation or authority.get('root') != str(root) or installed.get('operation_id') != operation or installed.get('phase') not in ('startup-restored', 'complete') or created.get('operation_id') != operation or created.get('complete') is not True:
        raise ValueError('installation material still has recovery obligations')
    parent_info, work_info = private(parent), private(work)
    if authority['parent_device'] != parent_info.st_dev or authority['parent_inode'] != parent_info.st_ino or authority['directory_device'] != work_info.st_dev or authority['directory_inode'] != work_info.st_ino:
        raise ValueError('installation creation authority differs')
    objects = inventory(work)
    if {item['path'] for item in objects} != {'.', 'created.json'}:
        raise ValueError('unknown installation work must be preserved')
    records = root / 'maintenance/material-records'
    control_directory(records)
    path = records / (operation + '.json')
    if path.exists():
        load(root, path)
        return
    info = authority_path.lstat()
    save(path, dict(version=1, operation_id=operation, root=str(root), kind='installation', phase='complete',
                    parent=identity(parent_info), directory=identity(work_info), completed_at_utc_micros=time.time_ns() // 1000,
                    objects=objects, auxiliary=[dict(path=str(authority_path), **identity(info), sha256=package.digest(authority_path))]))


def references(root, work):
    def points(value):
        if isinstance(value, str):
            candidate = Path(value)
            return candidate.is_absolute() and candidate.is_relative_to(work)
        if isinstance(value, list): return any(points(item) for item in value)
        if isinstance(value, dict): return any(points(item) for item in value.values())
        return False
    paths = []
    for namespace, filename in [('upgrades', 'upgrade.json'), ('operations', 'startup-control.json')]:
        parent = root / 'maintenance' / namespace
        if parent.exists():
            entries = list(parent.iterdir())
            if len(entries) > 4096: raise ValueError('reference list exceeds bound')
            for entry in entries:
                if entry == work: continue
                operation_id(entry.name)
                info = entry.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('unknown transaction cannot prove lack of references')
                path = entry / filename
                if not path.exists(): raise ValueError('unfinished transaction lacks reference authority')
                paths.append(path)
    for namespace in ['collections']:
        parent = root / 'maintenance' / namespace
        if parent.exists(): paths.extend(parent.glob('*.json'))
    if len(paths) > 8192: raise ValueError('reference records exceed bound')
    for path in paths:
        value = package.loads(package.bytes_regular(path, 64 * 1024 * 1024, (0o600, 0)))
        if not isinstance(value,dict):raise ValueError('reference record is not an object')
        if path.parent.name=='collections':
            required={'version','operation_id','root','parent_device','parent_inode','policy','candidates','retired_records','complete','completed_at_micros'}
            if set(value)!=required or type(value['version'])is not int or value['version']!=1 or value['root']!=str(root) or type(value['complete'])is not bool or not isinstance(value['candidates'],list):raise ValueError('collection reference authority differs')
            operation_id(value['operation_id'])
            if path.name!=value['operation_id']+'.json':raise ValueError('collection reference filename differs')
            if value['complete'] is True:continue
        elif path.name=='startup-control.json':
            import writer_control
            value=writer_control.inspect_control(path)
            if value['phase']=='startup-restored':continue
        if points(value): return True
    return False


def verify_objects(record, work, missing=False):
    if not work.exists():
        if missing: return
        raise ValueError('material root disappeared')
    if identity(private(work)) != record['directory']:
        raise ValueError('material root inode changed')
    current = {item['path']: item for item in inventory(work)}
    expected = {item['path']: item for item in record['objects']}
    if set(current) - set(expected) or (not missing and set(current) != set(expected)):
        raise ValueError('unknown material must be preserved')
    if any(item != expected[name] for name, item in current.items()):
        raise ValueError('material contents or inode changed')
    for item in record['auxiliary']:
        path = Path(item['path'])
        if not path.exists() and missing: continue
        info = path.lstat()
        if identity(info) != {key: item[key] for key in ['device', 'inode']} or package.digest(path) != item['sha256']:
            raise ValueError('auxiliary material changed')


def collect(root, descriptor, minimum_age_seconds, keep_completed, execute=False):
    lock_authority(root, descriptor)
    if type(minimum_age_seconds) is not int or not 0 <= minimum_age_seconds <= 2**53 - 1 or type(keep_completed) is not int or not 0 <= keep_completed <= 4096:
        raise ValueError('explicit material retention policy differs')
    parent = root / 'maintenance/material-records'
    if not parent.exists(): return {'status': 'material-collection-plan', 'eligible': [], 'retained': []}
    private(parent)
    paths = sorted(parent.iterdir())
    if len(paths) > 4096: raise ValueError('material records exceed bound')
    known, retained = [], []
    for path in paths:
        try:
            record, work = load(root, path)
            if record['phase'] == 'intent':
                retained.append({'path': str(path), 'reason': 'unfinished'});continue
            known.append((path, record, work))
        except (ValueError, OSError, KeyError, TypeError):
            retained.append({'path': str(path), 'reason': 'unknown-authority'})
    known.sort(key=lambda item: item[1]['completed_at_utc_micros'], reverse=True)
    eligible = []
    now = time.time_ns() // 1000
    for index, (path, record, work) in enumerate(known):
        try:
            if record['kind'] == 'installation':
                installed = package.loads(package.bytes_regular(root / 'maintenance/install.json', 4 * 1024 * 1024, (0o600, 0)))
                if installed.get('operation_id') != record['operation_id'] or installed.get('phase') != 'complete':
                    retained.append({'path': str(work), 'reason': 'installation-unfinished'});continue
            if record['phase'] != 'collecting' and index < keep_completed: reason = 'keep-completed'
            elif now - record['completed_at_utc_micros'] < minimum_age_seconds * 1000000: reason = 'retention-age'
            elif references(root, work): reason = 'referenced'
            else:
                if record['phase'] == 'collected':
                    if work.exists() or any(Path(item['path']).exists() for item in record['auxiliary']): raise ValueError('collected material has returned')
                else: verify_objects(record, work, record['phase'] == 'collecting')
                eligible.append((path, record, work));continue
            retained.append({'path': str(work), 'reason': reason})
        except (ValueError, OSError, KeyError, TypeError):
            retained.append({'path': str(work), 'reason': 'changed-or-unknown-references'})
    if execute:
        for path, _, work in eligible:
            record, current = load(root, path)
            if current != work or references(root, work) or time.time_ns() // 1000 - record['completed_at_utc_micros'] < minimum_age_seconds * 1000000:
                raise ValueError('material became retained before execution')
            if record['phase'] == 'collected':
                if work.exists() or any(Path(item['path']).exists() for item in record['auxiliary']): raise ValueError('collected material returned before execution')
                path.unlink();sync_directory(path.parent);continue
            verify_objects(record, work, record['phase'] == 'collecting')
            record['phase'] = 'collecting';save(path, record)
            for item in sorted(record['objects'], key=lambda item: len(PurePosixPath(item['path']).parts), reverse=True):
                target = work / item['path']
                if target.exists():
                    if identity(target.lstat()) != {key: item[key] for key in ['device', 'inode']}: raise ValueError('material inode changed before removal')
                    if not item['directory'] and package.digest(target) != item['sha256']: raise ValueError('material bytes changed before removal')
                    target.rmdir() if item['directory'] else target.unlink()
                    sync_directory(target.parent)
            for item in record['auxiliary']:
                target = Path(item['path'])
                if target.exists():
                    if identity(target.lstat()) != {key: item[key] for key in ['device', 'inode']} or package.digest(target) != item['sha256']: raise ValueError('auxiliary material changed before removal')
                    target.unlink();sync_directory(target.parent)
            record['phase'] = 'collected';save(path, record)
    return {'status': 'material-collection-complete' if execute else 'material-collection-plan',
            'policy': {'minimum_age_seconds': minimum_age_seconds, 'keep_completed': keep_completed},
            'eligible': [str(item[2]) for item in eligible], 'retained': retained}
