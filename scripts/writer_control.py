"""Administrator startup inhibition owned by one durable tool operation.

The system manager reads the condition; product processes do not know this
record or participate in tool locking. All callers hold the installation lock.
"""
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
import package

CONTROL_NAME='90-xssi-startup-control.conf'
_CGROUP_ROOT=Path('/sys/fs/cgroup')


def _calls():
    from install import atomic,process
    return atomic,process


def _directory(path):
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o022:
        raise ValueError('startup control parent is not administrator controlled')
    return info


def _same(info,identity):
    return info.st_dev==identity['device'] and info.st_ino==identity['inode']


def _identity(info):
    return {'device':info.st_dev,'inode':info.st_ino}


def _state(service,timeout):
    _,process=_calls()
    names=['LoadState','UnitFileState','ActiveState','SubState','MainPID','ControlPID','Job','ControlGroup','NeedDaemonReload','DropInPaths','ConditionResult']
    output=process(['/usr/bin/systemctl','show',service,*['--property='+name for name in names]],timeout=timeout)
    if len(output)>64*1024:raise ValueError('writer observation exceeds its bound')
    values={}
    for line in output.decode().splitlines():
        key,value=line.split('=',1)
        if key in values:raise ValueError('duplicate writer state property')
        values[key]=value
    if set(values)!=set(names) or not values['MainPID'].isdecimal() or not values['ControlPID'].isdecimal() or len(values['Job'])>128 or any(ord(c)<32 or ord(c)==127 for c in values['Job']) or values['NeedDaemonReload'] not in ('yes','no') or values['ConditionResult'] not in ('yes','no'):
        raise ValueError('incomplete writer state observation')
    values['observed_at_utc_micros']=time.time_ns()//1000
    return values


def _read(record):
    data=package.loads(package.bytes_regular(record,1024*1024,(0o600,os.geteuid())))
    if set(data)!={'version','operation_id','record_parent','permit','phase','services','before','writers'} or type(data['version']) is not int or data['version']!=2 or not isinstance(data.get('writers'),list) or not 0<=len(data['writers'])<=16:
        raise ValueError('invalid startup control record')
    operation=uuid.UUID(data['operation_id'])
    if operation.version!=4 or str(operation)!=data['operation_id'] or data['phase'] not in ('control-intent','control-written','stopped','control-failed','restore-startup-intent','startup-restored'):
        raise ValueError('startup control operation identity differs')
    seen=set()
    def identity(value):
        if not isinstance(value,dict) or set(value)!={'device','inode'} or any(type(number) is not int or not 0<=number<2**64 for number in value.values()):
            raise ValueError('invalid startup control inode identity')
    identity(data['record_parent'])
    for writer in data['writers']:
        if set(writer)-{'service','fresh','before','current','control_path','parent','file','requested_stop','stopped','released'} or not re.fullmatch(r'[a-z][a-z0-9.-]{0,126}\.service',writer['service']) or writer['service'] in seen or any(type(writer[key]) is not bool for key in ('fresh','requested_stop','stopped')):
            raise ValueError('invalid startup control writer')
        identity(writer['parent'])
        if writer['file'] is not None:identity(writer['file'])
        elif data['phase'] not in ('control-intent','control-failed') or writer['requested_stop']:
            raise ValueError('writer control lacks its inode seal')
        seen.add(writer['service'])
    services=data['services']
    if not isinstance(services,list) or not 1<=len(services)<=16 or len(set(services))!=len(services) or any(not re.fullmatch(r'[a-z][a-z0-9.-]{0,126}\.service',service) for service in services) or not seen.issubset(set(services)):
        raise ValueError('startup control declared writer set differs')
    parent=_directory(record.parent)
    if not _same(parent,data['record_parent']):raise ValueError('startup record parent identity differs')
    if not isinstance(data['before'],dict) or set(data['before'])!=set(services) or any(writer['before']!=data['before'][writer['service']] for writer in data['writers']):
        raise ValueError('original writer observations differ')
    return data


def _save(record,data):
    atomic,_=_calls()
    atomic(record,(json.dumps(data,sort_keys=True)+'\n').encode())


def _verify_files(record,data):
    if {writer['service'] for writer in data['writers']}!=set(data['services']) or any(writer['file'] is None for writer in data['writers']):
        raise ValueError('startup control is incomplete; unrecorded inodes require manual inspection')
    permit=Path(data['permit'])
    if permit.parent!=record.parent or permit.name!='startup-permit-'+data['operation_id'] or permit.exists() or permit.is_symlink():
        raise ValueError('startup permit must be the recorded nonexistent path')
    for writer in data['writers']:
        path=Path(writer['control_path'])
        if path.name!=CONTROL_NAME or path.parent.name!=writer['service']+'.d':raise ValueError('startup control path mapping differs')
        parent=_directory(path.parent)
        if not _same(parent,writer['parent']):raise ValueError('startup control parent identity differs')
        if not path.exists() and not path.is_symlink() and data['phase'] in ('restore-startup-intent','startup-restored'):
            writer['released']=True
            continue
        file=package.bytes_regular(path,65536,(0o644,os.geteuid()))
        info=path.lstat()
        expected=('[Unit]\nConditionPathExists='+str(permit).replace('%','%%')+'\n').encode()
        if not _same(info,writer['file']) or file!=expected:raise ValueError('startup control inode or bytes differ')
    return data


def _cgroup_populated(group):
    if not group:return False
    path=Path(group)
    if not isinstance(group,str) or len(group)>4096 or not path.is_absolute() or str(path)!=group or any(part in ('.','..') for part in path.parts) or any(ord(c)<32 or ord(c)==127 for c in group):
        raise ValueError('invalid writer control group')
    path=_CGROUP_ROOT/group[1:]/'cgroup.events'
    try:
        data=package.bytes_regular(path,4096).decode()
    except FileNotFoundError:
        package.bytes_regular(_CGROUP_ROOT/'cgroup.controllers',4096)
        return False
    values=[line.removeprefix('populated ') for line in data.splitlines() if line.startswith('populated ')]
    if len(values)!=1 or values[0] not in ('0','1'):raise ValueError('writer control group population is unknown')
    return values[0]=='1'


def _stopped(state,before):
    return (state['LoadState']=='loaded' and state['MainPID']=='0' and state['ControlPID']=='0' and not state['Job']
            and state['ActiveState'] in ('inactive','failed') and state['SubState'] in ('dead','failed')
            and not _cgroup_populated(state['ControlGroup']) and not _cgroup_populated(before['ControlGroup']))


def require_stopped(services,before=None,timeout=120):
    """Read actual exit proof without changing service or startup settings."""
    if not isinstance(services,list) or not 1<=len(services)<=16 or len(set(services))!=len(services) or any(not re.fullmatch(r'[a-z][a-z0-9.-]{0,126}\.service',service) for service in services):
        raise ValueError('invalid declared writers')
    if before is not None and (not isinstance(before,dict) or set(before)!=set(services)):
        raise ValueError('original stopped-writer observations differ')
    states={}
    for service in services:
        state=_state(service,timeout)
        if state['NeedDaemonReload']!='no' or not _stopped(state,state if before is None else before[service]):
            raise ValueError('every state writer must have actual exit proof before offline checks')
        states[service]=state
    return states


def _manager_guard(service,path,permit,present,timeout):
    _,process=_calls()
    prefix=['/usr/bin/busctl','--system','--json=short','--auto-start=no','--allow-interactive-authorization=no']
    def call(arguments):
        value=package.loads(process(prefix+arguments,timeout=timeout))
        if not isinstance(value,dict) or set(value)!={'type','data'}:raise ValueError('invalid structured system manager response')
        return value
    reply=call(['call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',service])
    if reply['type']!='o' or not isinstance(reply['data'],list) or len(reply['data'])!=1 or not isinstance(reply['data'][0],str) or not reply['data'][0].startswith('/org/freedesktop/systemd1/unit/'):
        raise ValueError('manager did not identify the declared writer')
    object=reply['data'][0]
    def property(name,kind):
        value=call(['get-property','org.freedesktop.systemd1',object,'org.freedesktop.systemd1.Unit',name])
        if value['type']!=kind:raise ValueError('manager property type differs')
        return value['data']
    if property('LoadState','s')!='loaded':raise ValueError('writer unit is not loaded')
    paths=property('DropInPaths','as');conditions=property('Conditions','a(sbbsi)')
    if not isinstance(paths,list) or any(not isinstance(p,str) for p in paths) or not isinstance(conditions,list):raise ValueError('manager startup properties are incomplete')
    matched=any(isinstance(value,list) and len(value)==5 and value[:4]==['ConditionPathExists',False,False,str(permit)] for value in conditions)
    if (str(path) in paths)!=present or matched!=present:raise ValueError('actual loaded startup condition differs')


def verify_control(record,timeout=120,allow_fresh=False):
    data=_verify_files(record,_read(record))
    for writer in data['writers']:
        observed=_state(writer['service'],timeout)
        if observed['NeedDaemonReload']!='no':raise ValueError('startup control is not loaded')
        if writer.get('released'):
            if not _stopped(observed,writer['before']):
                raise ValueError('released installation writer is not confirmed stopped')
            _manager_guard(writer['service'],Path(writer['control_path']),Path(data['permit']),False,timeout)
        elif allow_fresh and writer['fresh'] and observed['LoadState']=='not-found':
            if observed['MainPID']!='0' or observed['ActiveState']!='inactive':raise ValueError('fresh writer unexpectedly running')
        elif observed['LoadState']!='loaded':
            raise ValueError('system manager did not load the declared writer')
        else:
            _manager_guard(writer['service'],Path(writer['control_path']),Path(data['permit']),not writer.get('released',False),timeout)
        writer['current']=observed
    return data


def control_writers(services,record,timeout=120,fresh=False,unit_directory=Path('/etc/systemd/system')):
    if not isinstance(services,list) or not 1<=len(services)<=16 or len(set(services))!=len(services) or any(not re.fullmatch(r'[a-z][a-z0-9.-]{0,126}\.service',service) for service in services):
        raise ValueError('invalid declared writers')
    record=Path(record)
    if record.exists() or record.is_symlink():raise ValueError('startup control record already exists; inspect the original operation')
    parent=_directory(record.parent);_directory(unit_directory)
    operation=str(uuid.uuid4());permit=record.parent/('startup-permit-'+operation)
    if permit.exists() or permit.is_symlink():raise ValueError('startup permit already exists')
    before={service:_state(service,timeout) for service in services}
    data={'version':2,'operation_id':operation,'record_parent':_identity(parent),'permit':str(permit),'phase':'control-intent','services':services,'before':before,'writers':[]}
    _save(record,data)
    _,process=_calls()
    try:
        for service in services:
            before=data['before'][service]
            if fresh:
                if before['LoadState']!='not-found' or before['MainPID']!='0' or before['ActiveState']!='inactive':raise ValueError('fresh installation writer already exists')
            elif before['LoadState']!='loaded':raise ValueError('cannot prove current loaded writer identity')
            dropin=unit_directory/(service+'.d')
            if not dropin.exists():dropin.mkdir(mode=0o755)
            parent=_directory(dropin);path=dropin/CONTROL_NAME
            writer={'service':service,'fresh':fresh,'before':before,'current':before,'control_path':str(path),'parent':_identity(parent),'file':None,'requested_stop':False,'stopped':False}
            data['writers'].append(writer);_save(record,data)
            flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC
            fd=os.open(path,flags,0o644)
            try:
                writer['file']=_identity(os.fstat(fd));_save(record,data)
                os.fchmod(fd,0o644)
                content=('[Unit]\nConditionPathExists='+str(permit).replace('%','%%')+'\n').encode()
                with os.fdopen(os.dup(fd),'wb') as output:output.write(content);output.flush();os.fsync(output.fileno())
            finally:os.close(fd)
            parent_fd=os.open(dropin,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:os.fsync(parent_fd)
            finally:os.close(parent_fd)
        data['phase']='control-written';_save(record,data)
        process(['/usr/bin/systemctl','daemon-reload'],timeout=timeout)
        verify_control(record,timeout,allow_fresh=fresh)
        for writer in [data['writers'][0],*reversed(data['writers'][1:])]:
            writer['requested_stop']=True;_save(record,data)
            if not fresh:process(['/usr/bin/systemctl','stop',writer['service']],timeout=timeout)
            state=_state(writer['service'],timeout);writer['current']=state
            if not ((fresh and state['LoadState']=='not-found' and state['ControlPID']=='0' and not state['Job'] and not state['ControlGroup'] and state['MainPID']=='0' and state['ActiveState']=='inactive' and state['SubState']=='dead') or _stopped(state,writer['before'])):
                raise ValueError('writer did not exit completely')
            writer['stopped']=True;_save(record,data)
        data['phase']='stopped';_save(record,data)
        return data
    except Exception:
        data['phase']='control-failed';_save(record,data)
        raise


def inspect_control(record):
    """Report durable intent, including a crash before an inode was recorded."""
    return _read(Path(record))


def resume_control(record,services,timeout=120):
    data=_read(Path(record))
    if data['services']!=services or data['phase'] not in ('control-intent','control-written','control-failed','stopped'):
        raise ValueError('startup control is not this operation or cannot be resumed')
    # Do not infer authority over any unknown directory/file after mkdir/create
    # but before its seal. Complete sealed controls can safely be reloaded.
    _verify_files(record,data)
    _,process=_calls()
    process(['/usr/bin/systemctl','daemon-reload'],timeout=timeout)
    data=verify_control(record,timeout,allow_fresh=True)
    for writer in [data['writers'][0],*reversed(data['writers'][1:])]:
        writer['requested_stop']=True;_save(record,data)
        current=_state(writer['service'],timeout)
        if current['LoadState']=='loaded':process(['/usr/bin/systemctl','stop',writer['service']],timeout=timeout)
        current=_state(writer['service'],timeout)
        if not ((writer['fresh'] and current['LoadState']=='not-found' and current['ControlPID']=='0' and not current['Job'] and not current['ControlGroup'] and current['MainPID']=='0' and current['ActiveState']=='inactive' and current['SubState']=='dead') or _stopped(current,writer['before'])):
            raise ValueError('writer remains active during resumed control')
        writer['current']=current;writer['stopped']=True;_save(record,data)
    data['phase']='stopped';_save(record,data)
    return data


def restore_startup(record,timeout=120):
    data=_verify_files(record,_read(record))
    _,process=_calls()
    if data['phase'] in ('restore-startup-intent','startup-restored'):
        process(['/usr/bin/systemctl','daemon-reload'],timeout=timeout)
    data=verify_control(record,timeout)
    data['phase']='restore-startup-intent';_save(record,data)
    for writer in data['writers']:
        if writer.get('released'):continue
        path=Path(writer['control_path'])
        if not _same(path.lstat(),writer['file']):raise ValueError('startup control changed before removal')
        path.unlink();writer['released']=True;_save(record,data)
        parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
    process(['/usr/bin/systemctl','daemon-reload'],timeout=timeout)
    for writer in data['writers']:
        observed=_state(writer['service'],timeout)
        if observed['NeedDaemonReload']!='no':raise ValueError('startup control was not removed from loaded unit')
        if observed['LoadState']=='loaded':_manager_guard(writer['service'],Path(writer['control_path']),Path(data['permit']),False,timeout)
        if not writer['fresh'] and observed['UnitFileState']!=writer['before']['UnitFileState']:
            raise ValueError('original writer enablement state changed')
        fresh_absent = writer['fresh'] and observed['LoadState']=='not-found' and observed['MainPID']=='0' and observed['ControlPID']=='0' and not observed['Job'] and not observed['ControlGroup'] and observed['ActiveState']=='inactive' and observed['SubState']=='dead'
        if not fresh_absent and not _stopped(observed,writer['before']):
            raise ValueError('writer restarted while startup conditions were restored; inspect its actual state')
        writer['current']=observed
    data['phase']='startup-restored';_save(record,data)
    return data
