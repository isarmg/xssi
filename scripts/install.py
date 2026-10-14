#!/usr/bin/env python3
"""Operating-system installation transaction; product state belongs to Rust setup."""
import argparse
import fcntl
import grp
import getpass
import hashlib
import json
import os
from pathlib import Path
import pwd
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import package
from unit_validation import template_bytes, writable_bytes

MAX_OUTPUT = 1024 * 1024
INSTALL_JOURNAL_VERSION = 4
MAX_CONFIGURATION_FILES = 16
MAX_CONFIGURATION_FILE_BYTES = 1024 * 1024
MAX_CONFIGURATION_TOTAL_BYTES = 8 * 1024 * 1024
INSTALL_PHASES = {'staging', 'configuration-validated', 'initialize-intent',
                  'initialized', 'publish-intent', 'published', 'units-intent',
                  'units-installed', 'permissions-verified', 'startup-restored', 'complete'}

def save_install_journal(path, journal):
    atomic(path, (json.dumps(journal, sort_keys=True) + '\n').encode())

def installation_unit_roots(root, fixture):
    return ([root/'run/fixture-systemd'] if fixture else
            [Path(value) for value in ('/etc/systemd/system','/run/systemd/system',
             '/run/systemd/transient','/usr/local/lib/systemd/system',
             '/usr/lib/systemd/system','/lib/systemd/system')])

def verify_recorded_file(path, record, *, incomplete=False):
    if not isinstance(record,dict) or set(record)!={'device','inode','sha256','written'} or any(type(record[key]) is not int or not 0<=record[key]<2**64 for key in ('device','inode')) or type(record['written']) is not bool or not isinstance(record['sha256'],str) or len(record['sha256'])!=64 or any(character not in '0123456789abcdef' for character in record['sha256']):
        raise ValueError('invalid installed systemd file authority')
    information=path.lstat()
    value=package.bytes_regular(path,65536,(0o644,os.geteuid()))
    if (information.st_dev,information.st_ino)!=(record['device'],record['inode']):
        raise ValueError('installed systemd file identity changed')
    if record['written'] or not incomplete:
        if hashlib.sha256(value).hexdigest()!=record['sha256']:
            raise ValueError('installed systemd file bytes changed')
    return value

def publish_recorded_unit(path, value, journal, journal_path):
    """Record creation authority before writing a systemd file, retaining its inode."""
    record=journal['unit_files'].get(str(path))
    expected=hashlib.sha256(value).hexdigest()
    if record is None:
        descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
        try:
            os.fchmod(descriptor,0o644)
            information=os.fstat(descriptor)
            record={'device':information.st_dev,'inode':information.st_ino,'sha256':expected,'written':False}
            journal['unit_files'][str(path)]=record
            save_install_journal(journal_path,journal)
        finally:os.close(descriptor)
    existing=verify_recorded_file(path,record,incomplete=True)
    if record['sha256']!=expected or (not record['written'] and not value.startswith(existing)):
        raise ValueError('unexplained installed systemd content must be preserved')
    if not record['written']:
        descriptor=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            opened=os.fstat(descriptor)
            if (opened.st_dev,opened.st_ino)!=(record['device'],record['inode']):
                raise ValueError('installed systemd file changed before publication')
            view=memoryview(value)
            while view:view=view[os.write(descriptor,view):]
            os.ftruncate(descriptor,len(value));os.fsync(descriptor)
        finally:os.close(descriptor)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(parent)
        finally:os.close(parent)
        record['written']=True
        save_install_journal(journal_path,journal)

def verify_install_unit_namespace(root, manifest, journal, fixture, startup=None):
    """Allow only this operation's recorded units and its verified startup guard."""
    guards={} if startup is None else {Path(writer['control_path']):writer for writer in startup['writers']}
    owned={Path(entry['path']):entry for entry in journal['created_directories']}
    for service in manifest['services']:
        for parent in installation_unit_roots(root,fixture):
            unit=parent/service['name'];dropin=unit.with_name(unit.name+'.d')
            if unit.exists() or unit.is_symlink():
                if str(unit) not in journal['unit_files']:
                    raise ValueError('installation refuses an unrecorded service unit')
                verify_recorded_file(unit,journal['unit_files'][str(unit)],incomplete=True)
            elif str(unit) in journal['unit_files']:
                raise ValueError('recorded installed systemd file is missing')
            if dropin.exists() or dropin.is_symlink():
                information=dropin.lstat()
                if not stat.S_ISDIR(information.st_mode) or information.st_uid!=os.geteuid() or information.st_mode&0o7022:
                    raise ValueError('systemd drop-in directory is unsafe')
                guard=next((writer for path,writer in guards.items() if path.parent==dropin),None)
                if guard is not None:
                    if (information.st_dev,information.st_ino)!=(guard['parent']['device'],guard['parent']['inode']):
                        raise ValueError('startup control directory identity changed')
                elif dropin not in owned:
                    raise ValueError('installation refuses an unrecorded drop-in directory')
                else:verify_directory_seal(owned[dropin],dropin)
                for entry in dropin.iterdir():
                    if entry in guards:
                        continue # The shared startup controller verified its inode and bytes.
                    if str(entry) not in journal['unit_files']:
                        raise ValueError('unknown service drop-in must be preserved')
                    verify_recorded_file(entry,journal['unit_files'][str(entry)],incomplete=True)

def installation_startup(journal, root, manifest, *, stopped=True):
    if journal['startup_record']!=str(root/'maintenance/install-startup.json'):
        raise ValueError('installation startup record mapping differs')
    from writer_control import verify_control
    record=verify_control(Path(journal['startup_record']),120,allow_fresh=True)
    if {writer['service'] for writer in record['writers']}!={service['name'] for service in manifest['services']} or any(not writer['fresh'] for writer in record['writers']):
        raise ValueError('startup control does not cover the exact installation writers')
    if record['phase'] not in ('stopped','restore-startup-intent','startup-restored'):
        raise ValueError('installation startup control has not completed safely')
    if stopped:
        for writer in record['writers']:
            observation=process(['/usr/bin/systemctl','show',writer['service'],
                '--property=MainPID','--property=ActiveState','--property=SubState']).decode().splitlines()
            values=dict(line.split('=',1) for line in observation)
            if set(values)!={'MainPID','ActiveState','SubState'} or values['MainPID']!='0' or values['ActiveState'] not in ('inactive','failed') or values['SubState'] not in ('dead','failed') or not writer['stopped']:
                raise ValueError('installation writer is not stopped')
    return record

def directory_seal(path):
    path = safe_path(Path(path))
    package.private_chain(path.absolute())
    parent = path.parent.lstat()
    current = path.lstat()
    if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid() or current.st_mode & 0o7022:
        raise ValueError('installation staging is not administrator controlled')
    return {'path': str(path), 'parent_device': parent.st_dev, 'parent_inode': parent.st_ino,
            'directory_device': current.st_dev, 'directory_inode': current.st_ino}

def verify_directory_seal(seal, path, *, missing=False):
    path = Path(path)
    if not isinstance(seal, dict) or set(seal) != {'path', 'parent_device', 'parent_inode', 'directory_device', 'directory_inode'} or seal['path'] != str(path):
        raise ValueError('installation staging authority differs from this operation')
    if any(type(seal[name]) is not int or seal[name] < 0 for name in ('parent_device', 'parent_inode', 'directory_device', 'directory_inode')):
        raise ValueError('invalid installation staging identity')
    package.private_chain(path.parent)
    parent = path.parent.lstat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o7022 or (parent.st_dev, parent.st_ino) != (seal['parent_device'], seal['parent_inode']):
        raise ValueError('installation staging parent identity changed')
    try:
        current = path.lstat()
    except FileNotFoundError:
        if missing: return False
        raise ValueError('recorded installation staging is missing') from None
    if not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid() or current.st_mode & 0o7022 or (current.st_dev, current.st_ino) != (seal['directory_device'], seal['directory_inode']):
        raise ValueError('installation staging directory identity changed')
    return True

def prepare_recorded_directory(path, journal, field, journal_path):
    path = Path(path)
    seal = journal[field]
    if seal is not None:
        if verify_directory_seal(seal, path, missing=True): return
        journal[field]=None
        save_install_journal(journal_path,journal)
    # Existence, ownership and a reserved name do not establish creation authority.
    if path.exists() or path.is_symlink():
        raise ValueError('unrecorded installation staging must be preserved')
    path.mkdir(mode=0o700)
    journal[field] = directory_seal(path)
    save_install_journal(journal_path, journal)
    path.chmod(0o755)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)

def cleanup_recorded_directory(path, journal, field):
    path = Path(path)
    seal = journal[field]
    if seal is None:
        if path.exists() or path.is_symlink():
            raise ValueError('cannot remove unrecorded installation staging')
        return
    if not verify_directory_seal(seal, path, missing=True): return
    inspected = 0
    def remove(entry, depth):
        nonlocal inspected
        inspected += 1
        if inspected > package.MAX_FILES + 512 or depth > 128:
            raise ValueError('installation staging cleanup exceeds its bound')
        before = entry.lstat()
        if before.st_uid != os.geteuid() or before.st_mode & 0o7022:
            raise ValueError('unsafe installation staging entry must be preserved')
        if stat.S_ISDIR(before.st_mode):
            with os.scandir(entry) as children:
                for child in children: remove(Path(child.path), depth + 1)
            after = entry.lstat()
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('installation staging directory was replaced')
            entry.rmdir()
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            descriptor=os.open(entry,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            try: after = os.fstat(descriptor)
            finally: os.close(descriptor)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError('installation staging file was replaced')
            entry.unlink()
        else:
            raise ValueError('unknown installation staging entry must be preserved')
        descriptor = os.open(entry.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    remove(path, 0)

def managed_directory(path, journal, journal_path, mode, owner=None):
    path=Path(path)
    package.private_chain(path.parent)
    recorded=next((entry for entry in journal['created_directories'] if entry['path']==str(path)),None)
    if recorded is None:
        if path.exists() or path.is_symlink():
            raise ValueError('unknown installation directory must be preserved')
        path.mkdir(mode=0o700)
        recorded=directory_seal(path)
        journal['created_directories'].append(recorded)
        save_install_journal(journal_path,journal)
    else:
        parent=path.parent.lstat();current=path.lstat()
        if not stat.S_ISDIR(current.st_mode) or (parent.st_dev,parent.st_ino)!=(recorded['parent_device'],recorded['parent_inode']) or (current.st_dev,current.st_ino)!=(recorded['directory_device'],recorded['directory_inode']):
            raise ValueError('installation directory identity changed')
        allowed={os.geteuid()} if owner is None else {os.geteuid(),owner[0]}
        if current.st_uid not in allowed or current.st_mode&0o7002:
            raise ValueError('installation directory ownership changed')
    path.chmod(mode)
    if owner:os.chown(path,*owner)

def configuration_inputs(values):
    """Read bounded, physical input files before creating installation resources."""
    if len(values)>MAX_CONFIGURATION_FILES:
        raise ValueError('too many provided configuration files')
    result={};total=0
    for value in values:
        if not isinstance(value,str) or '=' not in value:
            raise ValueError('configuration file must use REL=SOURCE')
        relative,source=value.split('=',1)
        path=safe_path(Path(relative))
        if not relative or not source or not path.parts or path.is_absolute() or path.as_posix()!=relative or any(part in ('.','..') for part in path.parts) or '\\' in relative or relative=='config.json' or relative in result:
            raise ValueError('configuration file name must be a unique normalized path below config')
        source=safe_path(Path(source).absolute())
        package.private_chain(source.parent)
        data=package.bytes_regular(source,MAX_CONFIGURATION_FILE_BYTES)
        total+=len(data)
        if not data or total>MAX_CONFIGURATION_TOTAL_BYTES:
            raise ValueError('provided configuration bytes exceed their contract')
        result[relative]=data
    return result

def import_configuration_files(root, inputs, report, journal, journal_path):
    """Import only exact declared read-only files, recording creation before writes."""
    config=root/'config'
    readonly={Path(value) for value in report['readonly_paths']}
    mutable={Path(value) for value in report['config_write_paths']}
    if set(journal['configuration_files'])-set(inputs):
        raise ValueError('provided configuration inputs differ from this installation')
    for relative,value in inputs.items():
        path=config/relative
        if path not in readonly or path==config/'config.json' or any(path==selected or path.is_relative_to(selected) or selected.is_relative_to(path) for selected in mutable):
            raise ValueError('configuration input is not an exact declared read-only file')
        parents=[];parent=path.parent
        while parent!=config:
            parents.append(parent);parent=parent.parent
        for parent in reversed(parents):
            managed_directory(parent,journal,journal_path,0o700)
        write_recorded_configuration(path,value,journal['configuration_files'],relative,journal,journal_path)

def write_recorded_configuration(path, value, records, key, journal, journal_path, *, replace=False):
    """Create or resume one exact file; corrections retain the recorded inode."""
    digest=hashlib.sha256(value).hexdigest()
    record=records.get(key)
    if record is None:
        descriptor=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            os.fchmod(descriptor,0o600)
            information=os.fstat(descriptor)
            record={'device':information.st_dev,'inode':information.st_ino,
                    'sha256':digest,'size':len(value),'written':False,
                    'previous_sha256':None,'previous_size':None}
            records[key]=record
            save_install_journal(journal_path,journal)
            parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:os.fsync(parent_fd)
            finally:os.close(parent_fd)
        finally:os.close(descriptor)
    fields={'device','inode','sha256','size','written','previous_sha256','previous_size'}
    valid_digest=lambda item:isinstance(item,str) and len(item)==64 and all(character in '0123456789abcdef' for character in item)
    if not isinstance(record,dict) or set(record)!=fields or any(type(record[name]) is not int or not 0<=record[name]<2**64 for name in ('device','inode')) or type(record['size']) is not int or not 0<=record['size']<=MAX_CONFIGURATION_FILE_BYTES or not valid_digest(record['sha256']) or type(record['written']) is not bool:
        raise ValueError('configuration file authority is invalid')
    previous=record['previous_sha256']
    if (previous is None)!=(record['previous_size'] is None) or (previous is not None and (record['written'] or not valid_digest(previous) or type(record['previous_size']) is not int or not 0<=record['previous_size']<=MAX_CONFIGURATION_FILE_BYTES)):
        raise ValueError('configuration correction authority is invalid')
    information=path.lstat()
    if not stat.S_ISREG(information.st_mode) or information.st_uid!=os.geteuid() or information.st_nlink!=1 or stat.S_IMODE(information.st_mode) not in (0o600,0o640) or (information.st_dev,information.st_ino)!=(record['device'],record['inode']):
        raise ValueError('configuration file identity or ownership changed')
    existing=package.bytes_regular(path,MAX_CONFIGURATION_FILE_BYTES)
    existing_digest=hashlib.sha256(existing).hexdigest()
    if record['written'] and (len(existing)!=record['size'] or existing_digest!=record['sha256']):
        raise ValueError('unknown configuration file bytes must be preserved')
    if (record['sha256'],record['size'])!=(digest,len(value)):
        if not replace or not record['written']:
            raise ValueError('configuration inputs differ from the durable operation')
        record.update(previous_sha256=record['sha256'],previous_size=record['size'],
                      sha256=digest,size=len(value),written=False)
        save_install_journal(journal_path,journal)
    if record['written']:return
    previous_matches=(record['previous_sha256'] is not None and len(existing)==record['previous_size'] and existing_digest==record['previous_sha256'])
    if not value.startswith(existing) and not previous_matches:
        raise ValueError('unexplained partial configuration must be preserved')
    expected=information
    descriptor=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(descriptor)
        def identity(info):
            return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
                    info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if identity(opened)!=identity(expected) or (opened.st_dev,opened.st_ino)!=(record['device'],record['inode']):
            raise ValueError('configuration file changed before writing')
        os.fchmod(descriptor,0o600)
        os.ftruncate(descriptor,0)
        view=memoryview(value)
        while view:view=view[os.write(descriptor,view):]
        os.fsync(descriptor)
    finally:os.close(descriptor)
    record.update(written=True,previous_sha256=None,previous_size=None)
    save_install_journal(journal_path,journal)

def retain_private_directory(path, journal, journal_path, identity):
    """Retain a proven empty private ancestor without adopting its business tree."""
    path=Path(path)
    package.private_chain(path)
    current=path.lstat();parent=path.parent.lstat()
    if not stat.S_ISDIR(current.st_mode) or current.st_uid not in {os.geteuid(),identity[0]} or current.st_mode&0o7022:
        raise ValueError('preexisting private ancestor is not controlled')
    record=next((entry for entry in journal['retained_directories'] if entry['path']==str(path)),None)
    observed={'path':str(path),'parent_device':parent.st_dev,'parent_inode':parent.st_ino,
              'directory_device':current.st_dev,'directory_inode':current.st_ino}
    if record is None:
        if journal['phase'] not in ('staging','configuration-validated'):
            raise ValueError('unrecorded private directory must be preserved')
        journal['retained_directories'].append(observed)
        save_install_journal(journal_path,journal)
    elif record!=observed:
        raise ValueError('retained private directory identity changed')
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(descriptor)
        if (opened.st_dev,opened.st_ino)!=(current.st_dev,current.st_ino):
            raise ValueError('retained private ancestor changed before assignment')
        os.fchmod(descriptor,0o700);os.fchown(descriptor,*identity);os.fsync(descriptor)
    finally:os.close(descriptor)

def verify_empty_private_tree(data, business):
    """Only exact business roots and their directory ancestors can preexist."""
    allowed={path for path in business if path.is_relative_to(data)}
    inspected=0
    def visit(path,depth):
        nonlocal inspected
        inspected+=1
        if inspected>4096 or depth>128:
            raise ValueError('private-state inspection exceeds its bound')
        if path in allowed:
            package.private_chain(path)
            return
        information=path.lstat()
        if not stat.S_ISDIR(information.st_mode):
            raise ValueError('preexisting private state must be preserved')
        for entry in path.iterdir():
            if not any(selected.is_relative_to(entry) for selected in allowed):
                raise ValueError('first initialization requires empty private state')
            visit(entry,depth+1)
    if data.exists() or data.is_symlink():visit(data,0)

def declared_config_permissions(root, report, identity):
    """Freeze generated configuration; runtime writes need an exact declaration."""
    config=root/'config'
    mutable={Path(value) for value in report['config_write_paths']}
    for path in mutable:
        if not path.is_relative_to(config) or path==config:
            raise ValueError('configuration writes must use a minimum path below config')
    paths=[config]
    for parent,directories,files in os.walk(config,followlinks=False):
        for name in directories+files:
            path=Path(parent)/name
            information=path.lstat()
            if not (stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode)) or (stat.S_ISREG(information.st_mode) and information.st_nlink!=1):
                raise ValueError('configuration contains an unsupported resource')
            paths.append(path)
    for path in sorted(paths,key=lambda value:len(value.parts),reverse=True):
        writable=any(path==selected or path.is_relative_to(selected) for selected in mutable)
        information=path.lstat()
        os.chown(path,identity[0] if writable else os.geteuid(),identity[1])
        path.chmod((0o700 if writable else 0o750) if stat.S_ISDIR(information.st_mode) else (0o600 if writable else 0o640))

def materialize_payload(source, destination, manifest):
    expected={entry['path']:entry for entry in manifest['files']}
    for name in (package.MANIFEST,package.CHECKSUM):
        value=package.bytes_regular(source/name)
        expected[name]={'path':name,'mode':'0644','size':len(value),'sha256':hashlib.sha256(value).hexdigest()}
    parents={str(Path(name).parent) for name in expected}
    for selected in list(parents):
        parents.update(str(parent) for parent in Path(selected).parents)
    for parent,directories,files in os.walk(destination,followlinks=False):
        for name in directories+files:
            relative=(Path(parent)/name).relative_to(destination).as_posix()
            if relative not in expected and relative not in parents:
                raise ValueError('unknown staged content must be preserved')
            information=(destination/relative).lstat()
            if information.st_uid!=os.geteuid() or information.st_mode&0o7022 or not (stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode)):
                raise ValueError('staged resource changed or is unsafe')
    for entry in manifest['files']:
        target=destination/entry['path']
        directory(target.parent,0o755)
        value=package.bytes_regular(source/entry['path'],package.MAX_FILE_BYTES)
        if hashlib.sha256(value).hexdigest()!=entry['sha256']:
            raise ValueError('verified source payload changed')
        if target.exists():
            existing=package.bytes_regular(target,package.MAX_FILE_BYTES,(int(entry['mode'],8),os.geteuid()))
            if existing!=value: raise ValueError('staged file changed; preserve it for inspection')
        else:atomic(target,value,int(entry['mode'],8))
    for name in (package.MANIFEST,package.CHECKSUM):
        value=package.bytes_regular(source/name)
        if (destination/name).exists():
            if package.bytes_regular(destination/name,expected=(0o644,os.geteuid()))!=value:
                raise ValueError('staged SHA256 authority changed')
        else:atomic(destination/name,value,0o644)

PERMISSION_PROBE = r'''
import errno,json,os,pathlib,stat,sys,uuid
spec=json.loads(sys.argv[1]);nonce='.xssi-permission-'+uuid.uuid4().hex
for value in spec['read_files']:
    descriptor=os.open(value,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    os.close(descriptor)
for value in spec['write_paths']:
    path=pathlib.Path(value)
    if path.is_dir():
        original=path/nonce;renamed=path/(nonce+'-renamed')
        descriptor=os.open(original,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        before=os.fstat(descriptor)
        try:os.write(descriptor,b'xssi permission verification');os.fsync(descriptor)
        finally:os.close(descriptor)
        os.rename(original,renamed)
        after=renamed.lstat()
        if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise RuntimeError('probe identity changed')
        renamed.unlink()
    else:
        descriptor=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        os.close(descriptor)
if not spec['fixture_root']:
    for value in spec['deny_paths']:
        path=pathlib.Path(value);created=None
        try:
            if path.is_dir():
                created=path/nonce
                descriptor=os.open(created,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            else:descriptor=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except OSError as error:
            if error.errno in (errno.EACCES,errno.EPERM,errno.EROFS,errno.ENOTDIR):continue
            raise
        else:
            os.close(descriptor)
            if created is not None:created.unlink()
            raise RuntimeError('service identity can write a protected installation resource')
print(json.dumps({'status':'permissions_verified','uid':os.geteuid()}))
'''

def verify_installation_permissions(root,manifest,report,identity,journal,fixture):
    """Check effective UID permissions and the final systemd filesystem sandbox."""
    files=[root/manifest['server'],root/manifest['setup'],root/'config/config.json']
    readonly={Path(value) for value in report['readonly_paths']}
    protected={root,root/'bin',root/'libexec',root/'share',root/'maintenance'}|readonly
    for value in readonly:
        if value.is_file():files.append(value)
    spec={'read_files':[str(path) for path in files],
          'write_paths':report['writable_paths'],
          'deny_paths':[str(path) for path in sorted(protected)],
          'fixture_root':bool(fixture and identity[0]==0)}
    probe=['/usr/bin/python3','-I','-B','-c',PERMISSION_PROBE,json.dumps(spec)]
    process(probe,identity=identity)
    for service in manifest['services']:
        unit=installation_unit_roots(root,fixture)[0]/service['name']
        dropin=unit.with_name(unit.name+'.d')/'state.conf'
        expected=template_bytes(package.bytes_regular(root/service['path']),root,manifest['identity']['product'])
        if package.bytes_regular(unit)!=expected or package.bytes_regular(dropin)!=writable_bytes(report['writable_paths'],report['readonly_paths']):
            raise ValueError('final systemd permission contract differs from this installation')
        if fixture:continue
        observed=process(['/usr/bin/systemctl','show',service['name'],'--property=LoadState',
            '--property=FragmentPath','--property=DropInPaths','--property=NeedDaemonReload']).decode().splitlines()
        values=dict(line.split('=',1) for line in observed)
        from writer_control import CONTROL_NAME
        expected_dropins={str(dropin),str(dropin.with_name(CONTROL_NAME))}
        if set(values)!={'LoadState','FragmentPath','DropInPaths','NeedDaemonReload'} or values['LoadState']!='loaded' or values['FragmentPath']!=str(unit) or values['NeedDaemonReload']!='no' or set(values['DropInPaths'].split())!=expected_dropins:
            raise ValueError('system manager did not load the exact final installation files')
        properties={}
        section=None
        for source in (expected,package.bytes_regular(dropin)):
            for line in source.decode().splitlines():
                line=line.strip()
                if line.startswith('['):section=line
                elif section=='[Service]' and '=' in line:
                    name,value=line.split('=',1)
                    if name in {'User','Group','UMask','NoNewPrivileges','ProtectSystem','ProtectHome',
                                'PrivateDevices','PrivateTmp','ProtectKernelTunables','ProtectKernelModules',
                                'ProtectKernelLogs','ProtectControlGroups','RestrictSUIDSGID','LockPersonality',
                                'CapabilityBoundingSet','AmbientCapabilities','ReadWritePaths','ReadOnlyPaths',
                                'ProtectClock','ProtectHostname','RestrictNamespaces','RestrictRealtime',
                                'RestrictAddressFamilies','MemoryDenyWriteExecute','SystemCallArchitectures',
                                'SystemCallFilter','SystemCallErrorNumber','ProtectProc','ProcSubset','RemoveIPC',
                                'PrivateUsers','PrivateNetwork','NetworkNamespacePath','RootDirectory','RootImage',
                                'MountAPIVFS','BindReadOnlyPaths','BindPaths','InaccessiblePaths','TemporaryFileSystem',
                                'PrivateMounts','NoExecPaths','ExecPaths'}:
                        properties[name]=value
        account='isarmg-'+manifest['identity']['product']
        if properties.get('User')!=account or properties.get('Group')!=account or properties.get('ProtectSystem')!='strict':
            raise ValueError('final service lacks its required identity or filesystem protection')
        probe_unit='xssi-install-permissions-'+journal['operation_id']+'-'+service['role']
        command=['/usr/bin/systemd-run','--quiet','--wait','--pipe','--collect','--unit',probe_unit,
                 '--property=Type=exec','--property=Restart=no']
        command.extend('--property='+name+'='+value for name,value in properties.items())
        command.extend(probe)
        try:process(command)
        except BaseException:
            # A timed-out systemd-run client does not stop its transient service.
            process(['/usr/bin/systemctl','stop',probe_unit],timeout=120)
            observation=process(['/usr/bin/systemctl','show',probe_unit,'--property=MainPID',
                                 '--property=ActiveState'],timeout=120).decode().splitlines()
            values=dict(line.split('=',1) for line in observation)
            if values.get('MainPID')!='0' or values.get('ActiveState') not in ('inactive','failed'):
                raise ValueError('installation permission probe did not exit completely') from None
            raise

def require_root():
    if os.geteuid()!=0:raise ValueError('operating-system maintenance requires root')

def credential_input():
    value=(getpass.getpass('Administrator password: ').encode('utf-8')+b'\n'
           if sys.stdin.isatty() else sys.stdin.buffer.read(4097))
    if len(value)>4096:raise ValueError('credential input exceeds its bound')
    return value

def safe_path(path):
    value=str(path)
    if len(os.fsencode(value))>4096 or any(ord(character)<32 or ord(character)==127 for character in value):
        raise ValueError('installation and writable paths cannot contain control characters')
    return path

def atomic(path, value, mode=0o600, owner=None):
    path = Path(path)
    temporary = path.with_name('.state-atomic-' + str(uuid.uuid4()))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(descriptor, mode)
        if owner: os.fchown(descriptor, *owner)
        view = memoryview(value)
        while view:
            count = os.write(descriptor, view)
            view = view[count:]
        os.fsync(descriptor)
    finally: os.close(descriptor)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)

def directory(path, mode, owner=None):
    path = safe_path(Path(path))
    if path.is_symlink(): raise ValueError('directory must not be a symlink')
    path.mkdir(parents=True, exist_ok=True)
    package.private_chain(path.absolute())
    if not path.is_dir(): raise ValueError('directory path has another file type')
    information=path.lstat()
    allowed={os.geteuid()} if owner is None else {os.geteuid(),owner[0]}
    if information.st_uid not in allowed:raise ValueError('directory ownership differs from the installation authority')
    path.chmod(mode)
    if owner: os.chown(path, *owner)

def process(command, *, input=None, identity=None, pass_fds=(), timeout=120):
    arguments = {'stdin':subprocess.PIPE if input is not None else subprocess.DEVNULL,
                 'stdout':subprocess.PIPE,'stderr':subprocess.PIPE,'env':{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','TZ':'UTC'},
                 'pass_fds':pass_fds,'start_new_session':True}
    if identity and os.geteuid() == 0 and identity != (os.geteuid(),os.getegid()):
        arguments.update(user=identity[0],group=identity[1],extra_groups=[])
    child = subprocess.Popen(command, **arguments)
    poll = selectors.DefaultSelector()
    buffers = {child.stdout:bytearray(),child.stderr:bytearray()}
    deadline = time.monotonic()+timeout
    try:
        if input is not None:
            child.stdin.write(input)
            child.stdin.close()
        for stream in buffers:
            os.set_blocking(stream.fileno(),False)
            poll.register(stream,selectors.EVENT_READ)
        while poll.get_map():
            if time.monotonic() >= deadline: raise TimeoutError('maintenance subprocess exceeded its time bound')
            for key,_ in poll.select(min(.1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),16384)
                if chunk:
                    buffers[key.fileobj].extend(chunk)
                    if len(buffers[key.fileobj]) > MAX_OUTPUT: raise ValueError('maintenance output exceeds its byte bound')
                else: poll.unregister(key.fileobj)
        status=child.wait(timeout=max(.001,deadline-time.monotonic()))
        if status != 0: raise ValueError('maintenance subprocess failed')
        return bytes(buffers[child.stdout])
    except BaseException:
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        raise
    finally:
        poll.close()
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close();child.stderr.close()

def sealed_setup(path, expected, arguments, identity, input=None, timeout=120, tool_lock_fd=None):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        current=os.fstat(descriptor)
        if current.st_nlink!=1 or not stat.S_ISREG(current.st_mode) or stat.S_IMODE(current.st_mode)!=0o755:
            raise ValueError('setup is not one regular executable with exact declared mode')
        hash=hashlib.sha256();total=0
        while True:
            chunk=os.read(descriptor,1024*1024)
            if not chunk:break
            total+=len(chunk)
            if total>package.MAX_FILE_BYTES:raise ValueError('setup exceeds its byte bound')
            hash.update(chunk)
        after=os.fstat(descriptor)
        fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        if any(getattr(current,f)!=getattr(after,f) or getattr(after,f)!=getattr(Path(path).lstat(),f) for f in fields):
            raise ValueError('setup identity changed')
        if hash.hexdigest()!=expected: raise ValueError('sealed setup digest mismatch')
        # The installed/staged executable is root-owned and its parents are not writable by the service identity.
        fds=(descriptor,) if tool_lock_fd is None else (descriptor,tool_lock_fd)
        if tool_lock_fd is not None:
            arguments=[*arguments,'--tool-lock-fd',str(tool_lock_fd)]
        return process([f'/proc/self/fd/{descriptor}',*arguments],identity=identity,pass_fds=fds,input=input,
                       timeout=timeout)
    finally: os.close(descriptor)

class ServiceIdentityError(ValueError):
    pass


def service_identity(product, fixture, *, create=True):
    if fixture: return (os.geteuid(),os.getegid())
    account='isarmg-'+product
    message=(f'Service account {account} must use its matching non-root primary group and no supplementary groups. '
             'Grant shared-directory access using the service UID ACL or primary group; correct existing memberships manually.')
    try: entry=pwd.getpwnam(account)
    except KeyError:
        if not create:raise ServiceIdentityError(message) from None
        process(['/usr/sbin/useradd','--system','--user-group','--home-dir','/nonexistent','--no-create-home','--shell','/usr/sbin/nologin',account])
        entry=pwd.getpwnam(account)
    try:
        group=grp.getgrnam(account)
        groups=os.getgrouplist(account,entry.pw_gid)
    except (KeyError,OSError):raise ServiceIdentityError(message) from None
    if entry.pw_uid==0 or entry.pw_gid==0 or group.gr_gid!=entry.pw_gid or set(groups)!={entry.pw_gid}:
        raise ServiceIdentityError(message)
    return (entry.pw_uid,entry.pw_gid)

def controlled_chain(path):
    for parent in (Path(path),*Path(path).parents):
        if not parent.exists():continue
        metadata=parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid!=0 or metadata.st_mode&0o022:
            raise ValueError('installation directories must have a root-controlled parent chain')

def coordinator_lock(root, *, create=False):
    maintenance=package.private_chain(Path(root)/'maintenance')
    information=maintenance.lstat()
    if information.st_uid!=os.geteuid() or stat.S_IMODE(information.st_mode)!=0o700:
        raise ValueError('tool maintenance must be private to the administrator')
    path=maintenance/'tool.lock'
    descriptor=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_CREAT if create else 0),0o600)
    try:
        def verify():
            opened=os.fstat(descriptor);named=path.lstat()
            fields=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink')
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1 or opened.st_uid!=os.geteuid() or stat.S_IMODE(opened.st_mode)!=0o600 or any(getattr(opened,name)!=getattr(named,name) for name in fields):
                raise ValueError('tool lock is not the exact private administrator-owned inode')
        verify()
        fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
        verify()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def covered_paths(values):
    paths = sorted({Path(value) for value in values}, key=lambda p:(len(p.parts),str(p)))
    output=[]
    for path in paths:
        if not path.is_absolute() or path==Path('/') or '..' in path.parts:
            raise ValueError('invalid selected persistent/writable path')
        if not any(path.is_relative_to(ancestor) for ancestor in output): output.append(path)
    return output

def bootstrap_control(root):
    """Create only the checked ancestor chain and the minimum lock control area."""
    missing=[];parent=root
    while not parent.exists() and not parent.is_symlink():
        missing.append(parent);parent=parent.parent
    package.private_chain(parent)
    for target in reversed(missing):
        target.mkdir(mode=0o755)
        target.chmod(0o755)
    for target,mode in ((root,0o755),(root/'maintenance',0o700)):
        if target.exists() or target.is_symlink():
            information=target.lstat()
            if not stat.S_ISDIR(information.st_mode) or information.st_uid!=os.geteuid() or stat.S_IMODE(information.st_mode)!=mode:
                raise ValueError('existing installation control directory is unsafe')
        else:
            target.mkdir(mode=mode)
            target.chmod(mode)

def install(args):
    if not args.fixture: require_root()
    root=args.root.absolute()
    if args.fixture and (root==Path('/') or not str(root).startswith('/tmp/')):
        raise ValueError('fixture must remain under a private /tmp root')
    safe_path(root)
    if root==Path('/') or '..' in root.parts or root.is_symlink() or '$' in str(root):
        raise ValueError('invalid installation root')
    if not args.fixture: controlled_chain(root)
    manifest=package.verify(args.package)
    product=manifest['identity']['product']
    selected=package.bytes_regular(args.config)
    if not isinstance(package.loads(selected),dict): raise ValueError('configuration must be an object')
    provided=configuration_inputs(getattr(args,'configuration_file',[]))
    password=credential_input()
    # Only the minimum administrator control area precedes the installation lock.
    bootstrap_control(root)
    maintenance=root/'maintenance'
    lock=coordinator_lock(root,create=True)
    try:
        journal_path=maintenance/'install.json'
        package_digest=hashlib.sha256(package.bytes_regular(args.package/package.MANIFEST)).hexdigest()
        fields={'version','operation_id','product','root','package_sha256','phase','root_seal',
                'maintenance_seal','stage_seal','created_directories','retained_directories',
                'input_config_sha256','main_configuration','configuration_files',
                'published_files','unit_files','identity','startup_record'}
        if journal_path.exists() or journal_path.is_symlink():
            journal=package.loads(package.bytes_regular(journal_path,expected=(0o600,os.geteuid())))
            if set(journal)!=fields or type(journal['version']) is not int or journal['version']!=INSTALL_JOURNAL_VERSION or journal['phase'] not in INSTALL_PHASES:
                raise ValueError('unsupported installation journal contract')
            operation=uuid.UUID(journal['operation_id'])
            if operation.version!=4 or str(operation)!=journal['operation_id']:
                raise ValueError('installation operation must use a canonical v4 UUID')
            if journal['root']!=str(root) or journal['product']!=product or journal['package_sha256']!=package_digest:
                raise ValueError('another installation owns this unfinished journal')
            if not isinstance(journal['created_directories'],list) or len(journal['created_directories'])>2048 or not isinstance(journal['retained_directories'],list) or len(journal['retained_directories'])>2048 or not isinstance(journal['configuration_files'],dict) or len(journal['configuration_files'])>MAX_CONFIGURATION_FILES or not isinstance(journal['published_files'],dict) or len(journal['published_files'])>package.MAX_FILES+2 or not isinstance(journal['unit_files'],dict) or len(journal['unit_files'])>32:
                raise ValueError('installation journal resources exceed their contract')
            allowed_payload={entry['path'] for entry in manifest['files']}|{package.MANIFEST,package.CHECKSUM}
            units=installation_unit_roots(root,args.fixture)[0]
            allowed_units={str(units/service['name']) for service in manifest['services']}
            allowed_units.update(str(units/(service['name']+'.d')/'state.conf') for service in manifest['services'])
            if not set(journal['published_files']).issubset(allowed_payload) or not set(journal['unit_files']).issubset(allowed_units):
                raise ValueError('installation journal names undeclared published resources')
            if len({entry['path'] for entry in journal['created_directories']+journal['retained_directories']})!=len(journal['created_directories'])+len(journal['retained_directories']):
                raise ValueError('duplicate installed directory authority')
            verify_directory_seal(journal['root_seal'],root)
            verify_directory_seal(journal['maintenance_seal'],maintenance)
            if journal['phase']=='complete': raise ValueError('installation already initialized')
        else:
            unknown=set(entry.name for entry in maintenance.iterdir())-{'tool.lock'}
            if unknown: raise ValueError('unknown installation control content must be preserved')
            if (root/'config').exists() or (root/'bin').exists() or (root/'libexec').exists() or (root/'share').exists():
                raise ValueError('installation refuses preexisting private configuration or programs')
            journal={'version':INSTALL_JOURNAL_VERSION,'operation_id':str(uuid.uuid4()),
                     'product':product,'root':str(root),'package_sha256':package_digest,'phase':'staging',
                     'root_seal':directory_seal(root),'maintenance_seal':directory_seal(maintenance),
                     'stage_seal':None,'created_directories':[],'retained_directories':[],
                     'input_config_sha256':None,'main_configuration':None,'configuration_files':{},
                     'published_files':{},'unit_files':{},'identity':None,'startup_record':None}
            save_install_journal(journal_path,journal)
        def phase(value):
            journal['phase']=value
            save_install_journal(journal_path,journal)
        stage=maintenance/'install-payload'
        startup=None
        if journal['startup_record'] is not None:
            startup_path=maintenance/'install-startup.json'
            if journal['startup_record']!=str(startup_path):
                raise ValueError('installation startup record mapping differs')
            if not startup_path.exists() and not startup_path.is_symlink():
                if journal['phase']!='configuration-validated':
                    raise ValueError('recorded installation startup control is missing')
                journal['startup_record']=None
                save_install_journal(journal_path,journal)
            else:
                from writer_control import inspect_control, resume_control
                if inspect_control(startup_path)['phase'] in ('control-intent','control-written','control-failed'):
                    resume_control(startup_path,[service['name'] for service in manifest['services']],120)
        if journal['startup_record'] is not None:
            startup=installation_startup(journal,root,manifest,
                stopped=journal['phase'] not in ('permissions-verified','startup-restored'))
        verify_install_unit_namespace(root,manifest,journal,args.fixture,startup)
        if journal['phase'] in ('permissions-verified','startup-restored'):
            # A cleanup retry does not initialize, change configuration permissions,
            # or inspect a database whose service may already have been started.
            expected={entry['path']:entry for entry in manifest['files']}
            for name in (package.MANIFEST,package.CHECKSUM):
                value=package.bytes_regular(args.package/name)
                expected[name]={'mode':'0644','sha256':hashlib.sha256(value).hexdigest()}
            if set(journal['published_files'])!=set(expected):
                raise ValueError('verified installation payload record is incomplete')
            for name,entry in expected.items():
                destination=root/name;information=destination.lstat()
                current={'device':information.st_dev,'inode':information.st_ino,'sha256':entry['sha256']}
                value=package.bytes_regular(destination,package.MAX_FILE_BYTES,(int(entry['mode'],8),os.geteuid()))
                if journal['published_files'][name]!=current or hashlib.sha256(value).hexdigest()!=entry['sha256']:
                    raise ValueError('verified installation file identity or bytes changed')
            for name,record in journal['unit_files'].items():
                if not record['written']:raise ValueError('verified installation contains an unfinished unit')
                verify_recorded_file(Path(name),record)
            if not args.fixture and startup['phase']!='startup-restored':
                from writer_control import restore_startup
                restore_startup(Path(journal['startup_record']),120)
            phase('startup-restored')
            cleanup_recorded_directory(stage,journal,'stage_seal')
            journal['stage_seal']=None
            if not args.fixture:
                import material_store
                material_store.record_install(root,journal['operation_id'],lock)
            phase('complete')
            print(json.dumps({'product':product,'root':str(root),'status':'installed','services_started':False,
                              'state_checked':True,'permissions_verified':True}))
            return
        prepare_recorded_directory(stage,journal,'stage_seal',journal_path)
        # This is this operation's recorded private arena, never a guessed old path.
        materialize_payload(args.package,stage,manifest)
        if package.verify(stage)!=manifest:
            raise ValueError('staged release contract differs from the selected package')
        identity=service_identity(product,args.fixture)
        if journal['identity'] is not None and journal['identity']!=list(identity):
            raise ValueError('service identity changed during installation')
        journal['identity']=list(identity)
        save_install_journal(journal_path,journal)
        setup=stage/manifest['setup']
        setup_digest=next(entry['sha256'] for entry in manifest['files'] if entry['path']==manifest['setup'])
        common=['--product',product,'--root',str(root),'--service-uid',str(identity[0]),
                '--service-gid',str(identity[1]),'--json']
        def helper(command,*,credential=None):
            verify_directory_seal(journal['stage_seal'],stage)
            return package.loads(sealed_setup(setup,setup_digest,[*common,*command],None,
                                              credential,tool_lock_fd=lock))
        helper(['validate-credentials','--username',args.username],credential=password)
        config_dir=root/'config'
        managed_directory(config_dir,journal,journal_path,0o700)
        config=config_dir/'config.json'
        replace_input=journal['phase'] in ('staging','configuration-validated')
        if not replace_input and journal['input_config_sha256']!=hashlib.sha256(selected).hexdigest():
            raise ValueError('initialization input differs from the durable install operation')
        write_recorded_configuration(config,selected,journal,'main_configuration',journal,journal_path,replace=replace_input)
        journal['input_config_sha256']=hashlib.sha256(selected).hexdigest()
        save_install_journal(journal_path,journal)
        report=helper(['--config',str(config),'config-validate'])
        if report['product']!=product or Path(report['root'])!=root or report['schema_identity']!=manifest['schema_identity']:
            raise ValueError('configuration/schema report differs from verified package')
        for name in ('state_paths','writable_paths','readonly_paths','config_write_paths',
                     'shared_paths','business_paths','private_directories','private_files'):
            if not isinstance(report.get(name),list) or len(report[name])>128 or len(set(report[name]))!=len(report[name]):
                raise ValueError('declared product path report is incomplete or invalid')
            for value in report[name]:
                selected_path=safe_path(Path(value))
                if not selected_path.is_absolute() or selected_path==Path('/') or '..' in selected_path.parts:
                    raise ValueError('invalid declared product path')
        shared={Path(value) for value in report['shared_paths']}
        business={Path(value) for value in report['business_paths']}
        if len(shared)>16 or (shared and product!='xczs'):
            raise ValueError('invalid product shared-data policy')
        data=Path(report['data_dir'])
        private_directories={Path(value) for value in report['private_directories']}
        private_files={Path(value) for value in report['private_files']}
        writable={Path(value) for value in report['writable_paths']}
        config_writes={Path(value) for value in report['config_write_paths']}
        if any(path==config_dir or not path.is_relative_to(config_dir) or path not in writable for path in config_writes) or any(path==config_dir or (path.is_relative_to(config_dir) and path not in config_writes) for path in writable):
            raise ValueError('runtime configuration writes must use their precise declared minimum paths')
        declared={Path(value) for value in report['state_paths']}
        if data not in writable or data not in declared or data not in private_directories or not data.is_absolute() or data==Path('/') or '..' in data.parts:
            raise ValueError('invalid selected private state path')
        for destination in business:
            if destination not in writable or destination==root or data.is_relative_to(destination) or any(destination==path or path.is_relative_to(destination) or (destination.is_relative_to(path) and path!=data) for path in private_directories) or any(destination.is_relative_to(path) or path.is_relative_to(destination) for path in private_files) or any(destination.is_relative_to(root/name) or (root/name).is_relative_to(destination) for name in ('config','logs','run','bin','libexec','share','maintenance')):
                raise ValueError('business data cannot broaden or relax private state/configuration')
        for destination in shared:
            if destination not in business or destination not in writable or destination not in declared or destination.is_relative_to(data) or data.is_relative_to(destination) or any(destination.is_relative_to(root/name) or (root/name).is_relative_to(destination) for name in ('config','logs','run','bin','libexec','share','maintenance')):
                raise ValueError('shared data cannot broaden or relax private state/configuration')
        retained_allowed={data}
        for destination in business:
            parent=destination.parent
            while parent!=data and parent.is_relative_to(data):
                retained_allowed.add(parent);parent=parent.parent
        if any(Path(entry['path']) not in retained_allowed for entry in journal['retained_directories']):
            raise ValueError('retained directories exceed the exact private business ancestors')
        known={'maintenance'}|{Path(entry['path']).relative_to(root).parts[0] for entry in journal['created_directories']+journal['retained_directories'] if Path(entry['path']).is_relative_to(root)}
        allowed_business={destination.relative_to(root).parts[0] for destination in business if destination.is_relative_to(root)}
        known.update(allowed_business)
        if journal['phase'] in ('staging','configuration-validated'):
            if any(entry.name not in known for entry in root.iterdir()):
                raise ValueError('unknown installation content must be preserved')
            verify_empty_private_tree(data,business)
            phase('configuration-validated')
        verify_install_unit_namespace(root,manifest,journal,args.fixture,startup)
        for destination in covered_paths(report['writable_paths']):
            if destination==config_dir or destination.is_relative_to(config_dir):
                continue # The root helper generates precisely declared configuration.
            if root.is_relative_to(destination) or any(destination.is_relative_to(root/name) or (root/name).is_relative_to(destination) for name in ('bin','libexec','share','maintenance')):
                raise ValueError('writable directory overlaps immutable payload or tool control')
            if destination in business:
                if not destination.exists(): managed_directory(destination,journal,journal_path,0o700,identity)
                package.private_chain(destination)
                if destination.lstat().st_mode&0o4002:
                    raise ValueError('business root has unsafe mode bits')
            else:
                created=any(entry['path']==str(destination) for entry in journal['created_directories'])
                if destination==data and destination.exists() and not created:
                    retain_private_directory(destination,journal,journal_path,identity)
                else:managed_directory(destination,journal,journal_path,0o700,identity)
        # Covered writable roots may hide separately declared business subtrees.
        # Only the private ancestors are assigned; existing business roots retain
        # their own permissions, ACLs and contents.
        for destination in sorted(business,key=lambda path:(len(path.parts),str(path))):
            parents=[];parent=destination.parent
            while parent!=data and parent.is_relative_to(data):
                parents.append(parent);parent=parent.parent
            for parent in reversed(parents):
                created=any(entry['path']==str(parent) for entry in journal['created_directories'])
                if parent.exists() and not created:retain_private_directory(parent,journal,journal_path,identity)
                else:managed_directory(parent,journal,journal_path,0o700,identity)
            if not destination.exists():managed_directory(destination,journal,journal_path,0o700,identity)
            package.private_chain(destination)
            if destination.lstat().st_mode&0o4002:
                raise ValueError('business root has unsafe mode bits')
        for name in ('logs','run'):
            target=root/name
            if not any(entry['path']==str(target) for entry in journal['created_directories']):
                managed_directory(target,journal,journal_path,0o700,identity)
        # Newly installed units cannot be enabled/started while state is generated.
        if not args.fixture:
            from writer_control import control_writers
            startup_path=maintenance/'install-startup.json'
            if journal['startup_record'] is None:
                journal['startup_record']=str(startup_path)
                save_install_journal(journal_path,journal)
                control_writers([service['name'] for service in manifest['services']],startup_path,120,
                                fresh=True,unit_directory=installation_unit_roots(root,args.fixture)[0])
            startup=installation_startup(journal,root,manifest)
        import_configuration_files(root,provided,report,journal,journal_path)
        checked=journal['phase'] in ('initialized','publish-intent','published','units-intent','units-installed')
        if checked:
            helper(['check'])
        else:
            phase('initialize-intent')
            helper(['--operation-id',journal['operation_id'],'initialize','--username',args.username],credential=password)
        if journal['phase'] in ('initialize-intent','initialized'):
            phase('initialized')
        if not checked:helper(['check'])
        declared_config_permissions(root,report,identity)
        # No final program/resource is published until generated state passed check.
        if journal['phase']=='initialized': phase('publish-intent')
        payload=[*manifest['files']]
        for name in (package.MANIFEST,package.CHECKSUM):
            value=package.bytes_regular(stage/name)
            payload.append({'path':name,'mode':'0644','size':len(value),'sha256':hashlib.sha256(value).hexdigest()})
        for entry in payload:
            destination=root/entry['path']
            parents=[];parent=destination.parent
            while parent!=root and not parent.exists():
                parents.append(parent);parent=parent.parent
            for parent in reversed(parents):managed_directory(parent,journal,journal_path,0o755)
            if destination.exists() or destination.is_symlink():
                value=package.bytes_regular(destination,package.MAX_FILE_BYTES,(int(entry['mode'],8),os.geteuid()))
                if hashlib.sha256(value).hexdigest()!=entry['sha256']:
                    raise ValueError('unknown published file must be preserved')
            else:
                atomic(destination,package.bytes_regular(stage/entry['path'],package.MAX_FILE_BYTES),int(entry['mode'],8))
            information=destination.lstat()
            previous=journal['published_files'].get(entry['path'])
            current={'device':information.st_dev,'inode':information.st_ino,'sha256':entry['sha256']}
            if previous is not None and previous!=current:
                raise ValueError('published installation file identity changed')
            journal['published_files'][entry['path']]=current
            save_install_journal(journal_path,journal)
        if journal['phase']=='publish-intent':phase('published')
        if journal['phase']=='published':phase('units-intent')
        for service in manifest['services']:
            destination=installation_unit_roots(root,args.fixture)[0]/service['name']
            rendered=template_bytes(package.bytes_regular(root/service['path']),root,product)
            dropin=destination.with_name(destination.name+'.d')
            if args.fixture and not destination.parent.exists():
                managed_directory(destination.parent,journal,journal_path,0o755)
            for selected,value in ((destination,rendered),(dropin/'state.conf',writable_bytes(report['writable_paths'],report['readonly_paths']))):
                if not selected.parent.exists():managed_directory(selected.parent,journal,journal_path,0o755)
                publish_recorded_unit(selected,value,journal,journal_path)
        if not args.fixture:process(['/usr/bin/systemctl','daemon-reload'])
        phase('units-installed')
        if not args.fixture:installation_startup(journal,root,manifest)
        verify_installation_permissions(root,manifest,report,identity,journal,args.fixture)
        phase('permissions-verified')
        if not args.fixture:
            from writer_control import restore_startup
            restore_startup(Path(journal['startup_record']),120)
        phase('startup-restored')
        cleanup_recorded_directory(stage,journal,'stage_seal')
        journal['stage_seal']=None
        if not args.fixture:
            import material_store
            material_store.record_install(root,journal['operation_id'],lock)
        phase('complete')
        print(json.dumps({'product':product,'root':str(root),'status':'installed','services_started':False,
                          'state_checked':True,'permissions_verified':True}))
    finally:os.close(lock)

def main():
    class InstallationParser(argparse.ArgumentParser):
        def error(self,message):
            if '--json' in sys.argv:
                print(json.dumps({'error':{'code':'INVALID_ARGUMENTS',
                    'message':'Invalid installation arguments; see --help.','retryable':False}}))
                raise SystemExit(1)
            super().error(message)
    parser=InstallationParser()
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--configuration-file',action='append',default=[],metavar='REL=SOURCE',
                        help='Import an exact declared read-only file below ROOT/config; REL is relative to config')
    parser.add_argument('--username',default='admin')
    parser.add_argument('--json',action='store_true',help='Emit the machine-readable installation result')
    args=parser.parse_args();args.fixture=False
    args.package=args.package.absolute()
    try: install(args)
    except ServiceIdentityError as failure:
        if args.json:print(json.dumps({'error':{'code':'SERVICE_IDENTITY_INVALID',
            'message':str(failure),'retryable':False}}))
        else:print(str(failure),file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        message='Installation failed. Inspect the operation journal and preserved payload, if created, before retrying.'
        if args.json:print(json.dumps({'error':{'code':'INSTALLATION_FAILED','message':message,'retryable':False}}))
        else:print(message,file=sys.stderr)
        raise SystemExit(1)

if __name__=='__main__':main()
