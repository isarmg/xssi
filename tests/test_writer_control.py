"""Real temporary drop-ins and durable records; system manager fully simulated."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import writer_control as control

class WriterControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.units=self.root/'units';self.units.mkdir(mode=0o755)
        self.record=self.root/'startup.json';self.calls=[];self.fail_reload=False;self.fail_stop=None;self.gc_inactive=False
        self.states={name:{'LoadState':'loaded','UnitFileState':'enabled','ActiveState':'active','SubState':'running','MainPID':'12','ControlPID':'0','Job':'','ControlGroup':'','NeedDaemonReload':'no','DropInPaths':'','ConditionResult':'yes'} for name in ('xcos.service','xcos-mediamtx.service')}
        self.loaded={name:[] for name in self.states}
        self.mock=patch.object(control,'_calls',return_value=(self.atomic,self.process));self.mock.start();self.addCleanup(self.mock.stop)
    def atomic(self,path,value):
        temporary=path.with_name('.state-atomic-test')
        temporary.write_bytes(value);temporary.chmod(0o600);temporary.replace(path)
    def process(self,args,**kwargs):
        self.calls.append(list(args))
        if args[0]=='/usr/bin/busctl':
            if args[5]=='call':
                if args[9] not in ('GetUnit','LoadUnit'):raise AssertionError('unexpected manager method')
                if args[9]=='GetUnit' and self.gc_inactive:raise ValueError('Unit not loaded after inactive unit garbage collection')
                return json.dumps({'type':'o','data':['/org/freedesktop/systemd1/unit/'+args[-1].replace('.','_2e').replace('-','_2d')]}).encode()
            name=args[7].split('/')[-1].replace('_2e','.').replace('_2d','-');property=args[-1]
            if property=='LoadState':value={'type':'s','data':self.states[name]['LoadState']}
            elif property=='DropInPaths':value={'type':'as','data':self.loaded[name]}
            elif property=='Conditions':
                paths=self.loaded[name]
                conditions=[]
                for path in paths:
                    for line in Path(path).read_text().splitlines():
                        if line.startswith('ConditionPathExists='):conditions.append(['ConditionPathExists',False,False,line.split('=',1)[1].replace('%%','%'),0])
                value={'type':'a(sbbsi)','data':conditions}
            return json.dumps(value).encode()
        operation=args[1]
        if operation=='daemon-reload':
            if self.fail_reload:self.fail_reload=False;raise ValueError('simulated reload failure')
            for name in self.states:
                self.loaded[name]=[str(path) for path in (self.units/(name+'.d')).glob('*.conf')]
                self.states[name]['NeedDaemonReload']='no'
                self.states[name]['DropInPaths']=' '.join(self.loaded[name])
            return b''
        name=args[2];value=self.states[name]
        if operation=='stop':
            if name==self.fail_stop:raise ValueError('simulated stop failure')
            value.update(ActiveState='inactive',SubState='dead',MainPID='0',ConditionResult='no');return b''
        if operation=='show':return ''.join(key+'='+value[key]+'\n' for key in value).encode()
        raise AssertionError('unexpected manager operation')
    def start_control(self):
        return control.control_writers(list(self.states),self.record,unit_directory=self.units)
    def test_all_writers_guarded_before_any_stop_and_original_enablement_restored(self):
        result=self.start_control();self.assertEqual(result['phase'],'stopped')
        self.assertEqual(result['version'],1)
        first_stop=next(i for i,args in enumerate(self.calls) if args[1]=='stop')
        self.assertTrue(any(args[1]=='daemon-reload' for args in self.calls[:first_stop]))
        for writer in result['writers']:
            self.assertTrue(Path(writer['control_path']).is_file());self.assertTrue(writer['stopped'])
        restored=control.restore_startup(self.record);self.assertEqual(restored['phase'],'startup-restored')
        self.assertTrue(all(not Path(writer['control_path']).exists() for writer in restored['writers']))
        self.assertTrue(all(state['UnitFileState']=='enabled' for state in self.states.values()))
        self.assertTrue(all(args[0]=='/usr/bin/busctl' or args[1] in ('show','stop','daemon-reload') for args in self.calls))
    def test_only_current_record_format_is_read_without_manager_mutation(self):
        value=self.start_control()
        for version in (2,0,True):
            changed=dict(value,version=version)
            self.atomic(self.record,json.dumps(changed).encode());before=len(self.calls)
            with self.subTest(version=version),self.assertRaises(ValueError):
                control.resume_control(self.record,list(self.states))
            self.assertEqual(len(self.calls),before)
            self.assertTrue(all(Path(writer['control_path']).is_file() for writer in value['writers']))
        self.atomic(self.record,json.dumps(value).encode())
        self.assertEqual(control.resume_control(self.record,list(self.states))['version'],1)
    def test_partial_stop_keeps_inhibition_and_exact_observed_progress(self):
        self.fail_stop='xcos-mediamtx.service'
        with self.assertRaises(ValueError):self.start_control()
        value=control.inspect_control(self.record);self.assertEqual(value['phase'],'control-failed')
        stopped=[writer['service'] for writer in value['writers'] if writer['stopped']]
        self.assertEqual(stopped,['xcos.service'])
        self.assertTrue(all(Path(writer['control_path']).is_file() for writer in value['writers']))
        self.fail_stop=None;resumed=control.resume_control(self.record,list(self.states))
        self.assertEqual(resumed['phase'],'stopped')
    def test_reload_failure_resumes_only_after_static_authority_verification(self):
        self.fail_reload=True
        with self.assertRaises(ValueError):self.start_control()
        for state in self.states.values():state['NeedDaemonReload']='yes'
        before=len(self.calls);control.resume_control(self.record,list(self.states))
        self.assertEqual(self.calls[before][1],'daemon-reload')
    def test_replaced_inode_refuses_reload_or_removal(self):
        value=self.start_control();path=Path(value['writers'][0]['control_path'])
        other=path.with_name('replacement');other.write_bytes(path.read_bytes());other.chmod(0o644);other.replace(path)
        before=len(self.calls)
        with self.assertRaises(ValueError):control.resume_control(self.record,list(self.states))
        with self.assertRaises(ValueError):control.restore_startup(self.record)
        self.assertEqual(len(self.calls),before);self.assertTrue(path.exists())
    def test_unknown_creation_window_cannot_guess_removal_authority(self):
        value=self.start_control();value['phase']='control-failed';value['writers'][0]['file']=None;value['writers'][0]['requested_stop']=False
        self.atomic(self.record,json.dumps(value).encode());before=len(self.calls)
        with self.assertRaises(ValueError):control.resume_control(self.record,list(self.states))
        self.assertEqual(len(self.calls),before)
    def test_restore_interruption_after_unlink_can_reload_and_finish(self):
        self.start_control();self.fail_reload=True
        with self.assertRaises(ValueError):control.restore_startup(self.record)
        for state in self.states.values():state['NeedDaemonReload']='yes'
        restored=control.restore_startup(self.record);self.assertEqual(restored['phase'],'startup-restored')
    def test_released_record_still_checks_actual_stopped_process(self):
        self.start_control();control.restore_startup(self.record)
        self.states['xcos.service'].update(ActiveState='active',SubState='running',MainPID='99')
        with self.assertRaises(ValueError):control.verify_control(self.record)
    def test_restart_during_condition_release_is_not_reported_as_stopped_completion(self):
        self.start_control()
        actual = control._state
        def observe(service, timeout):
            value = actual(service, timeout)
            if not (self.units/(service+'.d')/control.CONTROL_NAME).exists():
                value.update(ActiveState='active', SubState='running', MainPID='99')
            return value
        with patch.object(control, '_state', side_effect=observe):
            with self.assertRaises(ValueError):control.restore_startup(self.record)
        self.assertEqual(control.inspect_control(self.record)['phase'], 'restore-startup-intent')
    def test_fresh_absent_unit_only_allowed_with_installation_authority(self):
        for value in self.states.values():value.update(LoadState='not-found',ActiveState='inactive',SubState='dead',MainPID='0',UnitFileState='')
        result=control.control_writers(list(self.states),self.record,fresh=True,unit_directory=self.units)
        self.assertEqual(result['phase'],'stopped')
        with self.assertRaises(ValueError):control.verify_control(self.record)
        control.verify_control(self.record,allow_fresh=True)

    def test_fresh_installed_inactive_units_can_be_reloaded_for_complete_guard_validation(self):
        for value in self.states.values():value.update(LoadState='not-found',ActiveState='inactive',SubState='dead',MainPID='0',UnitFileState='')
        control.control_writers(list(self.states),self.record,fresh=True,unit_directory=self.units)
        for value in self.states.values():value.update(LoadState='loaded',UnitFileState='disabled')
        self.process(['/usr/bin/systemctl','daemon-reload'])
        self.gc_inactive=True
        before=self.record.read_bytes();calls_before=len(self.calls)
        result=control.verify_control(self.record,allow_fresh=True)
        self.assertEqual(result['phase'],'stopped')
        self.assertEqual(self.record.read_bytes(),before)
        guard_calls=self.calls[calls_before:]
        self.assertEqual(sum(args[5]=='call' and args[9]=='LoadUnit' for args in guard_calls if args[0]=='/usr/bin/busctl'),2)
        self.assertTrue(all(args[0]=='/usr/bin/busctl' or args[1]=='show' for args in guard_calls))
        self.assertTrue(all(value['MainPID']=='0' and value['UnitFileState']=='disabled' for value in self.states.values()))
        restored=control.restore_startup(self.record)
        self.assertEqual(restored['phase'],'startup-restored')
        self.assertTrue(all(not (self.units/(name+'.d')/control.CONTROL_NAME).exists() for name in self.states))
        self.assertTrue(all(value['MainPID']=='0' and value['UnitFileState']=='disabled' for value in self.states.values()))
        self.assertTrue(all(args[0]=='/usr/bin/busctl' or args[1] in ('show','stop','daemon-reload') for args in self.calls))

    def test_reloading_inactive_unit_still_requires_exact_loaded_startup_condition(self):
        self.start_control();self.gc_inactive=True
        before=self.record.read_bytes();actual=self.process
        def process(arguments,**options):
            if arguments[0]=='/usr/bin/busctl' and arguments[-1]=='Conditions':
                return json.dumps({'type':'a(sbbsi)','data':[]}).encode()
            return actual(arguments,**options)
        with patch.object(control,'_calls',return_value=(self.atomic,process)):
            with self.assertRaisesRegex(ValueError,'actual loaded startup condition differs'):
                control.verify_control(self.record)
        self.assertEqual(self.record.read_bytes(),before)
        self.assertTrue(all(path.exists() for path in [self.units/(name+'.d')/control.CONTROL_NAME for name in self.states]))

    def test_metadata_reload_still_rejects_an_unloaded_or_masked_writer(self):
        self.start_control();self.gc_inactive=True
        before=self.record.read_bytes()
        for load_state in ('not-found','masked'):
            self.states['xcos.service']['LoadState']=load_state
            with self.subTest(load_state=load_state),self.assertRaises(ValueError):
                control.verify_control(self.record)
        self.assertEqual(self.record.read_bytes(),before)

class ExitProofTests(unittest.TestCase):
    def test_main_pid_zero_is_insufficient_for_control_job_or_descendant(self):
        original={'ControlGroup':'/writer'}
        state={'LoadState':'loaded','MainPID':'0','ControlPID':'0','Job':'','ControlGroup':'','ActiveState':'inactive','SubState':'dead'}
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'cgroup.controllers').write_text('cpu memory');(root/'writer').mkdir();events=root/'writer/cgroup.events';events.write_text('populated 0\nfrozen 0\n')
            with patch.object(control,'_CGROUP_ROOT',root):
                self.assertTrue(control._stopped(state,original))
                for key,value in [('ControlPID','12'),('Job','42')]:
                    changed=dict(state);changed[key]=value;self.assertFalse(control._stopped(changed,original))
                events.write_text('populated 1\nfrozen 0\n');self.assertFalse(control._stopped(state,original))
                events.unlink();self.assertTrue(control._stopped(state,original))
                (root/'cgroup.controllers').unlink()
                with self.assertRaises(FileNotFoundError):control._stopped(state,original)

    def test_read_only_check_requires_complete_exit_without_service_mutations(self):
        state={'LoadState':'loaded','UnitFileState':'disabled','ActiveState':'inactive','SubState':'dead',
               'MainPID':'0','ControlPID':'0','Job':'','ControlGroup':'','NeedDaemonReload':'no','DropInPaths':'','ConditionResult':'yes'}
        calls=[]
        def process(arguments,**kwargs):
            calls.append(arguments)
            self.assertEqual(arguments[:3],['/usr/bin/systemctl','show','fixture.service'])
            return ''.join(key+'='+value+'\n' for key,value in state.items()).encode()
        with patch.object(control,'_calls',return_value=(None,process)):
            before=control.require_stopped(['fixture.service'])
            self.assertEqual(before['fixture.service']['MainPID'],'0')
            for key,value in [('ControlPID','12'),('Job','42'),('SubState','stop-post'),('LoadState','not-found'),('NeedDaemonReload','yes')]:
                old=state[key];state[key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):
                    control.require_stopped(['fixture.service'],before=before)
                state[key]=old
        self.assertEqual(len(calls),6)

    def test_read_only_recheck_observes_descendants_in_the_original_cgroup(self):
        state={'LoadState':'loaded','MainPID':'0','ControlPID':'0','Job':'','ControlGroup':'',
               'ActiveState':'inactive','SubState':'dead','NeedDaemonReload':'no'}
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'cgroup.controllers').write_text('cpu memory')
            (root/'writer').mkdir();(root/'writer/cgroup.events').write_text('populated 1\n')
            with patch.object(control,'_CGROUP_ROOT',root),patch.object(control,'_state',return_value=state):
                with self.assertRaises(ValueError):
                    control.require_stopped(['fixture.service'],before={'fixture.service':{'ControlGroup':'/writer'}})

if __name__=='__main__':unittest.main()
