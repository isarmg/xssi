"""Installation authority, ordering, lock handoff and effective permission fixtures."""
import argparse
import contextlib
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch

import test_package as fixtures

SOURCE=fixtures.SOURCE

sys.path.insert(0,str(SOURCE/'scripts'))
import install
import package
import material_store
from unit_validation import template_bytes, writable_bytes
from writer_control import CONTROL_NAME


class InstallAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.PackageTests('test_exact_checksum_payload_and_mode')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.temp=self.fixture.temp
        self.root=self.temp/'installed'
        self.config=self.temp/'chosen.json'
        self.config.write_text('{}')

    def invoke(self):
        return self.fixture.invoke(self.root,self.config)

    def failed_stage(self):
        self.config.write_text('{"bind":"invalid"}')
        result=self.invoke()
        self.assertNotEqual(result.returncode,0,result.stdout)
        self.config.write_text('{}')
        return self.root/'maintenance/install-payload'

    def refinalize(self):
        (self.fixture.stage/package.MANIFEST).unlink()
        (self.fixture.stage/package.CHECKSUM).unlink()
        package.finalize(self.fixture.stage,self.fixture.identity,self.fixture.schema)

    def permission_spec(self,**changes):
        value={'read_files':[],'write_paths':[],'deny_paths':[],'fixture_root':False,
               'identity':{'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups()},
               'sandbox':False}
        value.update(changes)
        return json.dumps(value)

    def direct_permission_fixture_command(self,command,identity):
        """Keep this manager model separate from actual systemd sandbox proof."""
        arguments=command[command.index('/usr/bin/python3'):]
        spec=json.loads(arguments[-1])
        self.assertTrue(spec['sandbox'])
        self.assertEqual(spec['identity'],{'uid':identity[0],'gid':identity[1],'groups':[identity[1]]})
        spec['sandbox']=False
        spec['identity']['groups']=[]
        return [*arguments[:-1],json.dumps(spec)]

    def test_unrecorded_stage_is_preserved_before_any_initialization(self):
        maintenance=self.root/'maintenance'
        maintenance.mkdir(parents=True,mode=0o700)
        self.root.chmod(0o755)
        stage=maintenance/'install-payload';stage.mkdir(mode=0o755)
        note=stage/'administrator-note';note.write_bytes(b'never owned by this installation')
        before=(stage.stat().st_ino,note.stat().st_ino,note.read_bytes())
        result=self.invoke()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(before,(stage.stat().st_ino,note.stat().st_ino,note.read_bytes()))
        self.assertFalse((maintenance/'install.json').exists())
        self.assertFalse((self.root/'state').exists())

    def test_public_install_cli_rejects_fixture_bypass(self):
        result=subprocess.run([sys.executable,'-I','-B',str(SOURCE/'scripts/install.py'),
            '--fixture','--package',str(self.fixture.stage),'--root',str(self.root),
            '--config',str(self.config)],input=b'correct horse battery\n',capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'unrecognized arguments: --fixture',result.stderr)
        self.assertFalse(self.root.exists())

    def test_permission_probe_accepts_only_actual_access_denial_errors(self):
        spec=self.permission_spec(deny_paths=[str(self.temp)])
        actual=ctypes.CDLL(None,use_errno=True).syscall;actual.restype=ctypes.c_long
        def filtered(number):
            def syscall(*arguments):
                # The actual root and protected directory opens remain real;
                # inject an error only for the forbidden write, not availability.
                if arguments[3]._obj.flags&os.O_CREAT:
                    ctypes.set_errno(number);return -1
                return actual(*arguments)
            return SimpleNamespace(syscall=Mock(side_effect=syscall))
        for number in (errno.EACCES,errno.EPERM,errno.EROFS,errno.ENOTDIR):
            with self.subTest(errno=number), \
                 patch.object(sys,'argv',['permission-probe',spec]), \
                 patch.object(ctypes,'CDLL',return_value=filtered(number)), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
                self.assertEqual(json.loads(output.getvalue())['status'],'permissions_verified')
        for number in (errno.EIO,errno.ENOENT,errno.ESTALE,errno.EMFILE):
            with self.subTest(errno=number), \
                 patch.object(sys,'argv',['permission-probe',spec]), \
                 patch.object(ctypes,'CDLL',return_value=filtered(number)), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaises(OSError) as raised:
                    exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
                self.assertEqual(raised.exception.errno,number)
                self.assertEqual(output.getvalue(),'')

    def test_permission_probe_rejects_and_cleans_actual_unexpected_write(self):
        spec=self.permission_spec(deny_paths=[str(self.temp)])
        before=set(self.temp.iterdir())
        with patch.object(sys,'argv',['permission-probe',spec]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(RuntimeError,'service identity can write'):
                exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
            self.assertEqual(output.getvalue(),'')
        self.assertEqual(set(self.temp.iterdir()),before)

    def test_permission_probe_rejects_actual_intermediate_symlink(self):
        real=self.temp/'actual';real.mkdir()
        resource=real/'readable';resource.write_text('preserve current material')
        alias=self.temp/'alias';alias.symlink_to(real,target_is_directory=True)
        spec=self.permission_spec(read_files=[str(alias/'readable')])
        with patch.object(sys,'argv',['permission-probe',spec]),contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(OSError) as raised:
                exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
        self.assertEqual(raised.exception.errno,errno.ELOOP)
        self.assertEqual(resource.read_text(),'preserve current material')
        self.assertEqual(output.getvalue(),'')

    def test_permission_probe_requires_actual_openat2_even_without_files(self):
        spec=self.permission_spec()
        def unavailable(*arguments):ctypes.set_errno(errno.ENOSYS);return -1
        libc=SimpleNamespace(syscall=Mock(side_effect=unavailable))
        with patch.object(sys,'argv',['permission-probe',spec]),patch.object(ctypes,'CDLL',return_value=libc),contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(OSError) as raised:
                exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
        self.assertEqual(raised.exception.errno,errno.ENOSYS)
        self.assertEqual(output.getvalue(),'')

    def test_permission_probe_rejects_wrong_process_identity(self):
        current={'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups()}
        for change in ({'uid':current['uid']+1},{'gid':current['gid']+1},
                       {'groups':current['groups']+[max(current['groups']+[0])+1]}):
            spec=self.permission_spec(identity={**current,**change})
            with self.subTest(change=change),patch.object(sys,'argv',['permission-probe',spec]),contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(RuntimeError,'process identity differs'):
                    exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
                self.assertEqual(output.getvalue(),'')

    def test_permission_probe_requires_no_new_privileges_and_empty_capabilities(self):
        zero='0000000000000000'
        valid={'NoNewPrivs':'1','CapPrm':zero,'CapEff':zero,'CapBnd':zero,'CapAmb':zero}
        cases=[('NoNewPrivs','0','permits privilege gain')]
        cases.extend((name,'0000000000000001','retains Linux capabilities') for name in valid if name!='NoNewPrivs')
        cases.extend((name,None,'retains Linux capabilities') for name in valid if name!='NoNewPrivs')
        for name,value,message in cases:
            fields={**valid,name:value};status=''.join(key+':\t'+item+'\n' for key,item in fields.items() if item is not None)
            spec=self.permission_spec(sandbox=True)
            libc=SimpleNamespace(syscall=Mock(),prctl=Mock(return_value=1))
            with self.subTest(field=name,value=value),patch.object(sys,'argv',['permission-probe',spec]),patch.object(ctypes,'CDLL',return_value=libc),patch.object(Path,'read_text',return_value=status),contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(RuntimeError,message):
                    exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})
                self.assertEqual(output.getvalue(),'')
        # /proc fields alone do not substitute for the kernel's actual prctl.
        status=''.join(key+':\t'+item+'\n' for key,item in valid.items())
        with patch.object(sys,'argv',['permission-probe',self.permission_spec(sandbox=True)]),patch.object(ctypes,'CDLL',return_value=SimpleNamespace(syscall=Mock(),prctl=Mock(return_value=0))),patch.object(Path,'read_text',return_value=status):
            with self.assertRaisesRegex(RuntimeError,'permits privilege gain'):
                exec(compile(install.PERMISSION_PROBE,'permission-probe','exec'),{})

    def test_json_failure_uses_machine_contract_without_echoing_bad_argument(self):
        credential='a-private-value-that-must-not-be-echoed'
        result=subprocess.run([sys.executable,'-I','-B',str(SOURCE/'scripts/install.py'),
            '--json','--password',credential],capture_output=True)
        self.assertEqual(result.returncode,1)
        report=json.loads(result.stdout)
        self.assertEqual(set(report),{'error'})
        self.assertEqual(report['error']['code'],'INVALID_ARGUMENTS')
        self.assertEqual(set(report['error']),{'code','message','retryable'})
        self.assertFalse(report['error']['retryable'])
        self.assertNotIn(credential.encode(),result.stdout+result.stderr)

    def test_control_bootstrap_creates_nested_parent_chain_with_explicit_permissions(self):
        root=self.temp/'new-parent/deployment'
        previous=os.umask(0o077)
        try:install.bootstrap_control(root)
        finally:os.umask(previous)
        for directory,mode in ((root.parent,0o755),(root,0o755),(root/'maintenance',0o700)):
            self.assertEqual(directory.stat().st_mode&0o777,mode)
        self.assertEqual(sorted(path.name for path in root.iterdir()),['maintenance'])

    def test_replaced_recorded_stage_is_preserved(self):
        stage=self.failed_stage()
        old=stage.with_name('original-stage');stage.rename(old)
        stage.mkdir(mode=0o755)
        note=stage/'new-owner';note.write_bytes(b'unrelated directory')
        before=(stage.stat().st_ino,note.stat().st_ino,note.read_bytes())
        result=self.invoke()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(before,(stage.stat().st_ino,note.stat().st_ino,note.read_bytes()))
        self.assertTrue((old/'libexec/setup').exists())
        self.assertFalse((self.root/'state').exists())

    def test_replaced_stage_parent_is_preserved(self):
        self.failed_stage()
        maintenance=self.root/'maintenance';old=self.root/'original-maintenance'
        maintenance.rename(old);maintenance.mkdir(mode=0o700)
        for name in ('install.json','tool.lock'):
            shutil.copyfile(old/name,maintenance/name);(maintenance/name).chmod(0o600)
        stage=maintenance/'install-payload';stage.mkdir(mode=0o755)
        note=stage/'untouched';note.write_bytes(b'new parent')
        result=self.invoke()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(note.read_bytes(),b'new parent')
        self.assertTrue((old/'install-payload/libexec/setup').exists())

    def test_missing_creation_authority_is_not_reconstructed_from_name(self):
        stage=self.failed_stage()
        journal_path=self.root/'maintenance/install.json'
        journal=json.loads(journal_path.read_text());journal['stage_seal']=None
        journal_path.write_text(json.dumps(journal))
        before=(stage.stat().st_ino,(stage/'libexec/setup').read_bytes())
        self.assertNotEqual(self.invoke().returncode,0)
        self.assertEqual(before,(stage.stat().st_ino,(stage/'libexec/setup').read_bytes()))

    def test_main_configuration_replacement_is_preserved_before_initialization(self):
        self.failed_stage()
        target=self.root/'config/config.json'
        original=target.read_bytes()
        target.rename(target.with_suffix('.held'))
        target.write_bytes(original);target.chmod(0o600)
        before=(target.stat().st_ino,target.read_bytes())
        result=self.invoke()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(before,(target.stat().st_ino,target.read_bytes()))
        self.assertFalse((self.root/'state').exists())

    def test_main_configuration_without_creation_record_is_never_overwritten(self):
        self.failed_stage()
        target=self.root/'config/config.json';target.write_bytes(b'{"administrator":"evidence"}')
        journal_path=self.root/'maintenance/install.json'
        journal=json.loads(journal_path.read_text());journal['main_configuration']=None
        journal_path.write_text(json.dumps(journal))
        before=(target.stat().st_ino,target.read_bytes())
        self.assertNotEqual(self.invoke().returncode,0)
        self.assertEqual(before,(target.stat().st_ino,target.read_bytes()))

    def test_owned_configuration_correction_intent_recovers_without_changing_inode(self):
        self.failed_stage()
        target=self.root/'config/config.json';before=target.stat().st_ino
        actual=install.save_install_journal;interrupted=False
        def save(path,journal):
            nonlocal interrupted
            actual(path,journal)
            record=journal['main_configuration']
            if not interrupted and record is not None and record['previous_sha256'] is not None:
                interrupted=True
                raise InterruptedError('correction intent durable before old bytes changed')
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'save_install_journal',side_effect=save):
            with self.assertRaises(InterruptedError):install.install(self.arguments())
        self.assertEqual(target.stat().st_ino,before)
        self.assertEqual(json.loads(target.read_text()),{'bind':'invalid'})
        result=self.invoke()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(target.stat().st_ino,before)
        self.assertEqual(json.loads(target.read_text()),{})

    def test_missing_owned_stage_can_be_recreated_but_unknown_journal_is_rejected(self):
        stage=self.failed_stage()
        journal_path=self.root/'maintenance/install.json'
        journal=json.loads(journal_path.read_text())
        install.cleanup_recorded_directory(stage,journal,'stage_seal')
        journal['version']=2;journal_path.write_text(json.dumps(journal))
        self.assertNotEqual(self.invoke().returncode,0)
        self.assertFalse(stage.exists())
        journal['version']=install.INSTALL_JOURNAL_VERSION;journal_path.write_text(json.dumps(journal))
        result=self.invoke()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertFalse(stage.exists())

    def test_partial_verified_staging_resumes_without_replacing_stage(self):
        stage=self.failed_stage();before=stage.stat().st_ino
        (stage/'bin/xocs').unlink()
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'cleanup_recorded_directory') as cleanup:
            install.install(self.arguments())
        self.assertEqual(stage.stat().st_ino,before)
        self.assertEqual((stage/'bin/xocs').read_bytes(),(self.fixture.stage/'bin/xocs').read_bytes())
        cleanup.assert_called_once()

    def test_cleanup_refuses_links_and_never_follows_their_target(self):
        stage=self.failed_stage();outside=self.temp/'outside'
        outside.mkdir();note=outside/'untouched';note.write_bytes(b'outside scope')
        (stage/'linked').symlink_to(outside,target_is_directory=True)
        journal=json.loads((self.root/'maintenance/install.json').read_text())
        with self.assertRaises(ValueError):install.cleanup_recorded_directory(stage,journal,'stage_seal')
        self.assertEqual(note.read_bytes(),b'outside scope')
        self.assertTrue((stage/'linked').is_symlink())

    def test_cleanup_interruption_resumes_without_touching_installed_data(self):
        actual=install.cleanup_recorded_directory
        interrupted=False
        def cleanup(stage,journal,field):
            nonlocal interrupted
            if not interrupted:
                interrupted=True
                (stage/'bin/xocs').unlink()
                raise InterruptedError('simulated cleanup interruption')
            return actual(stage,journal,field)
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'cleanup_recorded_directory',side_effect=cleanup):
            with self.assertRaises(InterruptedError):install.install(self.arguments())
        journal=json.loads((self.root/'maintenance/install.json').read_text())
        self.assertEqual(journal['phase'],'startup-restored')
        marker=self.root/'state/database-marker';marker.write_bytes(b'legitimate later application data')
        config=self.root/'config/config.json';config.write_bytes(b'{"later":"configuration"}')
        before=(marker.stat().st_ino,marker.read_bytes(),config.stat().st_ino,config.read_bytes())
        resumed=self.invoke()
        self.assertEqual(resumed.returncode,0,resumed.stderr.decode())
        self.assertEqual(before,(marker.stat().st_ino,marker.read_bytes(),config.stat().st_ino,config.read_bytes()))
        self.assertFalse((self.root/'maintenance/install-payload').exists())

    def test_initialization_and_readonly_check_precede_publication(self):
        helper=self.fixture.stage/'libexec/setup'
        source=helper.read_text().replace("if a.command=='initialize':\n",
            "if a.command in ('initialize','check'):\n    assert not (root/'bin/xocs').exists(), 'published before state check'\nif a.command=='initialize':\n")
        source=source.replace("cfg=json.loads(pathlib.Path(a.config or root/'config/config.json').read_text());",
            "cfg=json.loads(pathlib.Path(a.config or root/'config/config.json').read_text());assert str(root)==cfg['expected_root'];")
        helper.write_text(source);self.refinalize()
        self.config.write_text(json.dumps({'expected_root':str(self.root)}))
        result=self.invoke()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertTrue((self.root/'state/database-marker').exists())
        self.assertNotIn('install-payload',(self.root/'config/config.json').read_text())

    def test_existing_declared_business_data_preserves_owners_and_modes(self):
        self.root.mkdir(mode=0o755)
        business=self.root/'files';business.mkdir(mode=0o2770);business.chmod(0o2770)
        item=business/'existing-file';item.write_bytes(b'existing business file');item.chmod(0o640)
        if os.geteuid()==0:os.chown(item,65534,65534)
        before=[(path.stat().st_uid,path.stat().st_gid,path.stat().st_mode,path.stat().st_ino) for path in (business,item)]
        self.config.write_text(json.dumps({'business_root':str(business)}))
        result=self.invoke()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(before,[(path.stat().st_uid,path.stat().st_gid,path.stat().st_mode,path.stat().st_ino) for path in (business,item)])
        self.assertEqual(item.read_bytes(),b'existing business file')
        self.assertEqual(sorted(path.name for path in business.iterdir()),[item.name])

    def test_exact_business_subtree_inside_private_data_preserves_its_files(self):
        self.root.mkdir(mode=0o755)
        data=self.root/'state';data.mkdir(mode=0o755)
        ancestor=data/'archive';ancestor.mkdir(mode=0o755)
        business=ancestor/'recordings';business.mkdir(mode=0o2770);business.chmod(0o2770)
        item=business/'existing-video';item.write_bytes(b'existing footage');item.chmod(0o640)
        if os.geteuid()==0:os.chown(item,65534,65534)
        before=[(path.stat().st_uid,path.stat().st_gid,path.stat().st_mode,path.stat().st_ino) for path in (business,item)]
        self.config.write_text(json.dumps({'business_root':str(business)}))
        result=self.invoke()
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(before,[(path.stat().st_uid,path.stat().st_gid,path.stat().st_mode,path.stat().st_ino) for path in (business,item)])
        self.assertEqual(item.read_bytes(),b'existing footage')
        self.assertEqual(sorted(path.name for path in business.iterdir()),[item.name])
        for path in (data,ancestor):self.assertEqual(path.stat().st_mode&0o777,0o700)
        journal=json.loads((self.root/'maintenance/install.json').read_text())
        self.assertEqual({entry['path'] for entry in journal['retained_directories']},{str(data),str(ancestor)})
        self.assertNotIn(str(business),{entry['path'] for entry in journal['created_directories']})

    def test_business_subtree_does_not_authorize_private_siblings_or_sql_overlap(self):
        for case in ('private-sibling','business-is-private-file','business-contains-private-file'):
            with self.subTest(case=case):
                root=self.temp/case;root.mkdir(mode=0o755)
                data=root/'state';data.mkdir(mode=0o700)
                business=data/'media'
                if case=='private-sibling':
                    business.mkdir(mode=0o700);(business/'object').write_bytes(b'keep business')
                    evidence=data/'private-marker';evidence.write_bytes(b'keep private state')
                elif case=='business-is-private-file':business=data/'database-marker';evidence=data/'untouched'
                else:business=data;evidence=data/'untouched'
                if not evidence.exists():evidence.write_bytes(b'keep private state')
                before=evidence.read_bytes()
                self.config.write_text(json.dumps({'business_root':str(business)}))
                result=self.fixture.invoke(root,self.config)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(evidence.read_bytes(),before)
                self.assertFalse((root/'bin/xocs').exists())

    def provided_tls(self):
        certificate=self.temp/'provided-cert.pem';key=self.temp/'provided-key.pem'
        subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(key),'-out',str(certificate),'-days','1','-subj','/CN=test-only.invalid'],
            check=True,capture_output=True)
        key.chmod(0o600)
        self.config.write_text(json.dumps({'readonly_configuration':['rtsp-cert.pem','rtsp-key.pem']}))
        return certificate,key

    def test_user_provided_tls_files_are_checked_before_publication_and_frozen(self):
        certificate,key=self.provided_tls()
        inputs=['rtsp-cert.pem='+str(certificate),'rtsp-key.pem='+str(key)]
        helper=self.fixture.stage/'libexec/setup'
        helper.write_text(helper.read_text().replace("elif a.command=='check':\n",
            "elif a.command=='check':\n    assert not (root/'bin/xocs').exists(), 'payload published before TLS check'\n"))
        self.refinalize()
        result=self.fixture.invoke(self.root,self.config,inputs)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        for relative,source in (('rtsp-cert.pem',certificate),('rtsp-key.pem',key)):
            installed=self.root/'config'/relative
            self.assertEqual(installed.read_bytes(),source.read_bytes())
            self.assertEqual(installed.stat().st_mode&0o777,0o640)
            self.assertEqual(installed.stat().st_uid,os.geteuid())
        self.assertNotIn(key.read_bytes(),result.stdout+result.stderr)
        journal=json.loads((self.root/'maintenance/install.json').read_text())
        self.assertEqual(set(journal['configuration_files']),{'rtsp-cert.pem','rtsp-key.pem'})
        self.assertTrue(all(record['written'] for record in journal['configuration_files'].values()))

    def test_import_creation_interruption_resumes_only_the_recorded_inode_and_inputs(self):
        certificate,key=self.provided_tls()
        arguments=self.arguments()
        arguments.configuration_file=['rtsp-cert.pem='+str(certificate),'rtsp-key.pem='+str(key)]
        actual=install.save_install_journal;interrupted=False
        def save(path,journal):
            nonlocal interrupted
            actual(path,journal)
            if not interrupted and any(not record['written'] for record in journal['configuration_files'].values()):
                interrupted=True
                raise InterruptedError('created file recorded before copy')
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'save_install_journal',side_effect=save):
            with self.assertRaises(InterruptedError):install.install(arguments)
        installed=self.root/'config/rtsp-cert.pem';before=installed.stat().st_ino
        self.assertEqual(installed.read_bytes(),b'')
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'):
            install.install(arguments)
        self.assertEqual(installed.stat().st_ino,before)
        self.assertEqual(installed.read_bytes(),certificate.read_bytes())

    def test_import_rejects_undeclared_unsafe_and_preexisting_files_without_overwrite(self):
        certificate,key=self.provided_tls()
        unsafe=self.temp/'source-link';unsafe.symlink_to(key)
        cases=[['config.json='+str(key)],['../escape='+str(key)],
               ['extra.pem='+str(key)],['rtsp-key.pem='+str(unsafe)],
               ['rtsp-key.pem='+str(key),'rtsp-key.pem='+str(key)]]
        original=key.read_bytes()
        for index,inputs in enumerate(cases):
            with self.subTest(inputs=inputs):
                root=self.temp/('unsafe-import-'+str(index))
                result=self.fixture.invoke(root,self.config,inputs)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse((root/'state/database-marker').exists())
                self.assertEqual(key.read_bytes(),original)
        self.failed_stage()
        self.config.write_text(json.dumps({'readonly_configuration':['rtsp-key.pem']}))
        existing=self.root/'config/rtsp-key.pem';existing.write_bytes(b'unowned key evidence');existing.chmod(0o600)
        before=existing.stat().st_ino
        result=self.fixture.invoke(self.root,self.config,['rtsp-key.pem='+str(key)])
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((existing.stat().st_ino,existing.read_bytes()),(before,b'unowned key evidence'))

    def test_import_changed_or_replaced_retry_input_is_preserved(self):
        certificate,key=self.provided_tls()
        arguments=self.arguments();arguments.configuration_file=['rtsp-cert.pem='+str(certificate),'rtsp-key.pem='+str(key)]
        actual=install.import_configuration_files
        def interrupted(*values):
            actual(*values)
            raise InterruptedError('imported before initialize intent')
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'import_configuration_files',side_effect=interrupted):
            with self.assertRaises(InterruptedError):install.install(arguments)
        installed=self.root/'config/rtsp-key.pem';original=installed.read_bytes();inode=installed.stat().st_ino
        key.write_bytes(b'changed supplied private key')
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'):
            with self.assertRaises(ValueError):install.install(arguments)
        self.assertEqual((installed.stat().st_ino,installed.read_bytes()),(inode,original))
        key.write_bytes(original)
        installed.rename(installed.with_suffix('.held'));installed.write_bytes(original);installed.chmod(0o600)
        replacement=installed.stat().st_ino
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'):
            with self.assertRaises(ValueError):install.install(arguments)
        self.assertEqual((installed.stat().st_ino,installed.read_bytes()),(replacement,original))

    def test_business_declaration_cannot_broaden_private_state_or_control(self):
        for name in ('state','config','logs','run','bin','libexec','share','maintenance'):
            with self.subTest(name=name):
                root=self.temp/('rejected-'+name)
                self.config.write_text(json.dumps({'business_root':str(root/name)}))
                result=self.fixture.invoke(root,self.config)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse((root/'state/database-marker').exists())

    def test_replaced_recorded_systemd_unit_is_preserved(self):
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr.decode())
        journal_path=self.root/'maintenance/install.json'
        journal=json.loads(journal_path.read_text());journal['phase']='permissions-verified'
        journal_path.write_text(json.dumps(journal))
        unit=self.root/'run/fixture-systemd/xocs.service';original=unit.read_bytes()
        unit.rename(unit.with_suffix('.held'));unit.write_bytes(original);unit.chmod(0o644)
        before=unit.stat().st_ino
        self.assertNotEqual(self.invoke().returncode,0)
        self.assertEqual(unit.stat().st_ino,before)
        self.assertEqual(unit.read_bytes(),original)

    def arguments(self):
        return argparse.Namespace(fixture=True,root=self.root,package=self.fixture.stage,
            config=self.config,username='admin')

    def managed_system_fixture(self, *, interrupt_initializer=False):
        """Use real child UID permissions with an entirely temporary manager model."""
        if os.geteuid()!=0:self.skipTest('alternate service UID requires administrator')
        self.temp.chmod(0o755)
        template=self.fixture.stage/'share/systemd/xocs.service'
        template.write_text('[Service]\nUser=isarmg-xocs\nGroup=isarmg-xocs\nProtectSystem=strict\nProtectHome=read-only\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nExecStart="@ROOT@/bin/xocs" --root "@ROOT@"\n')
        if interrupt_initializer:
            helper=self.fixture.stage/'libexec/setup'
            helper.write_text(helper.read_text().replace("    os.chown(data/'database-marker',a.service_uid,a.service_gid)\n",
                "    os.chown(data/'database-marker',a.service_uid,a.service_gid)\n    sys.exit(3)\n"))
        self.refinalize()
        units=self.temp/'systemd';units.mkdir(mode=0o755)
        arguments=self.arguments();arguments.fixture=False
        calls=[];actual=install.process
        def process(command,**options):
            calls.append(command)
            if command[0]=='/usr/bin/busctl':
                if command[5]=='call':return json.dumps({'type':'o','data':['/org/freedesktop/systemd1/unit/'+command[-1].replace('.','_2e').replace('-','_2d')]}).encode()
                name=command[7].split('/')[-1].replace('_2e','.').replace('_2d','-');dropin=units/(name+'.d');property=command[-1]
                if property=='LoadState':value={'type':'s','data':'loaded' if (units/name).is_file() else 'not-found'}
                elif property=='DropInPaths':value={'type':'as','data':[str(path) for path in sorted(dropin.glob('*.conf'))]}
                elif property=='Conditions':
                    conditions=[]
                    for path in dropin.glob('*.conf'):
                        for line in path.read_text().splitlines():
                            if line.startswith('ConditionPathExists='):conditions.append(['ConditionPathExists',False,False,line.split('=',1)[1].replace('%%','%'),0])
                    value={'type':'a(sbbsi)','data':conditions}
                return json.dumps(value).encode()
            if command[:2]==['/usr/bin/systemctl','daemon-reload']:return b''
            if command[:2]==['/usr/bin/systemctl','show']:
                name=command[2];unit=units/name;dropin=units/(name+'.d')
                loaded=unit.is_file()
                values={'LoadState':'loaded' if loaded else 'not-found',
                    'FragmentPath':str(unit) if loaded else '',
                    'DropInPaths':' '.join(str(path) for path in sorted(dropin.glob('*.conf'))),
                    'UnitFileState':'disabled' if loaded else '',
                    'ActiveState':'inactive','SubState':'dead','MainPID':'0',
                    'ControlPID':'0','Job':'','ControlGroup':'',
                    'NeedDaemonReload':'no','ConditionResult':'no'}
                return ''.join(value.removeprefix('--property=')+'='+values[value.removeprefix('--property=')]+'\n' for value in command[3:]).encode()
            if command[:2]==['/usr/bin/systemctl','stop']:
                self.assertTrue(command[2].startswith('xssi-install-permissions-'),command)
                return b''
            if command[0]=='/usr/bin/systemd-run':
                self.assertTrue((units/'xocs.service.d'/CONTROL_NAME).is_file())
                self.assertIn('--property=User=isarmg-xocs',command)
                return actual(self.direct_permission_fixture_command(command,(33,33)),identity=(33,33))
            return actual(command,**options)
        return arguments,units,calls,process

    def test_managed_install_holds_startup_control_until_actual_permission_checks(self):
        arguments,units,calls,process=self.managed_system_fixture()
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'controlled_chain'), \
             patch.object(install,'service_identity',return_value=(33,33)), \
             patch.object(install,'installation_unit_roots',return_value=[units]), \
             patch.object(install,'process',side_effect=process), \
             patch.object(material_store,'record_install'):
            install.install(arguments)
        self.assertTrue((units/'xocs.service').exists())
        self.assertFalse((units/'xocs.service.d'/CONTROL_NAME).exists())
        self.assertFalse(any(command[:2] in (['/usr/bin/systemctl','start'],['/usr/bin/systemctl','enable']) for command in calls))
        self.assertEqual((self.root/'state/database-marker').stat().st_uid,33)
        self.assertEqual((self.root/'config/config.json').stat().st_uid,0)
        self.assertEqual((self.root/'config/config.json').stat().st_gid,33)
        journal=json.loads((self.root/'maintenance/install.json').read_text())
        self.assertEqual(journal['phase'],'complete')
        control=json.loads((self.root/'maintenance/install-startup.json').read_text())
        self.assertEqual(control['phase'],'startup-restored')

    def test_provided_tls_is_readable_but_not_writable_by_actual_service_uid(self):
        certificate,key=self.provided_tls()
        arguments,units,calls,process=self.managed_system_fixture()
        arguments.configuration_file=['rtsp-cert.pem='+str(certificate),'rtsp-key.pem='+str(key)]
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'controlled_chain'), \
             patch.object(install,'service_identity',return_value=(33,33)), \
             patch.object(install,'installation_unit_roots',return_value=[units]), \
             patch.object(install,'process',side_effect=process), \
             patch.object(material_store,'record_install'):
            install.install(arguments)
        for name in ('rtsp-cert.pem','rtsp-key.pem'):
            information=(self.root/'config'/name).stat()
            self.assertEqual((information.st_uid,information.st_gid,information.st_mode&0o777),(0,33,0o640))
        runner=next(command for command in calls if command[0]=='/usr/bin/systemd-run')
        self.assertTrue(any(value.startswith('--property=ReadOnlyPaths=') and 'rtsp-key.pem' in value for value in runner))

    def test_managed_initialization_interruption_resumes_without_reinitializing(self):
        arguments,units,calls,process=self.managed_system_fixture(interrupt_initializer=True)
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'controlled_chain'), \
             patch.object(install,'service_identity',return_value=(33,33)), \
             patch.object(install,'installation_unit_roots',return_value=[units]), \
             patch.object(install,'process',side_effect=process), \
             patch.object(material_store,'record_install'):
            with self.assertRaises(ValueError):install.install(arguments)
            marker=self.root/'state/database-marker';before=(marker.stat().st_ino,marker.read_bytes())
            self.assertTrue((units/'xocs.service.d'/CONTROL_NAME).exists())
            self.assertFalse((self.root/'bin/xocs').exists())
            install.install(arguments)
        self.assertEqual(before,(marker.stat().st_ino,marker.read_bytes()))
        self.assertFalse((units/'xocs.service.d'/CONTROL_NAME).exists())
        self.assertFalse(any(command[:2] in (['/usr/bin/systemctl','start'],['/usr/bin/systemctl','enable']) for command in calls))

    def test_runtime_configuration_write_scope_preserves_readonly_neighbors(self):
        arguments,units,calls,process=self.managed_system_fixture()
        self.config.write_text('{"mutable_config":true}')
        with patch.object(install,'credential_input',return_value=b'correct horse battery\n'), \
             patch.object(install,'controlled_chain'), \
             patch.object(install,'service_identity',return_value=(33,33)), \
             patch.object(install,'installation_unit_roots',return_value=[units]), \
             patch.object(install,'process',side_effect=process), \
             patch.object(material_store,'record_install'):
            install.install(arguments)
        config=self.root/'config';mutable=config/'generated'
        self.assertEqual((config/'config.json').stat().st_uid,0)
        self.assertEqual(mutable.stat().st_uid,33)
        self.assertEqual((mutable/'runtime.conf').stat().st_uid,33)
        self.assertEqual(mutable.stat().st_mode&0o777,0o700)
        self.assertEqual(sorted(path.name for path in mutable.iterdir()),['runtime.conf'])
        runner=next(command for command in calls if command[0]=='/usr/bin/systemd-run')
        self.assertTrue(any(value.startswith('--property=ReadWritePaths=') and str(mutable) in value for value in runner))
        self.assertTrue(any(value.startswith('--property=ReadOnlyPaths=') and str(config) in value for value in runner))

    def permission_fixture(self):
        if os.geteuid()!=0:self.skipTest('effective alternate UID fixture requires administrator')
        template=self.fixture.stage/'share/systemd/xocs.service'
        template.write_text('[Service]\nUser=isarmg-xocs\nGroup=isarmg-xocs\nProtectSystem=strict\nProtectHome=read-only\nNoNewPrivileges=yes\nPrivateDevices=yes\nRestrictNamespaces=yes\nProtectProc=invisible\nCapabilityBoundingSet=\nAmbientCapabilities=\nExecStart="@ROOT@/bin/xocs" --root "@ROOT@"\n')
        self.refinalize()
        result=self.invoke();self.assertEqual(result.returncode,0,result.stderr.decode())
        self.temp.chmod(0o755)
        identity=(33,33)
        for name in ('state','logs','run'):
            directory=self.root/name;os.chown(directory,*identity);directory.chmod(0o700)
        os.chown(self.root/'state/database-marker',*identity)
        report={'writable_paths':[str(self.root/name) for name in ('state','logs','run')],
                'readonly_paths':[str(self.root/'config')],'config_write_paths':[]}
        install.declared_config_permissions(self.root,report,identity)
        units=self.temp/'systemd';units.mkdir(mode=0o755)
        unit=units/'xocs.service';unit.write_bytes(template_bytes(template.read_bytes(),self.root,'xocs'))
        dropin=units/'xocs.service.d';dropin.mkdir(mode=0o755)
        (dropin/'state.conf').write_bytes(writable_bytes(report['writable_paths'],report['readonly_paths']))
        (dropin/CONTROL_NAME).write_bytes(b'[Unit]\nConditionPathExists=/tmp/nonexistent-fixture-permit\n')
        manifest=package.verify(self.fixture.stage)
        journal=json.loads((self.root/'maintenance/install.json').read_text())
        return manifest,report,identity,journal,units

    def test_actual_service_uid_permissions_and_generated_namespace_properties(self):
        manifest,report,identity,journal,units=self.permission_fixture()
        calls=[];actual=install.process
        def process(command,**options):
            calls.append(command)
            if command[0]=='/usr/bin/systemctl':
                self.assertEqual(command[1:3],['show','xocs.service'])
                return ('LoadState=loaded\nFragmentPath='+str(units/'xocs.service')+'\nDropInPaths='+str(units/'xocs.service.d/state.conf')+' '+str(units/'xocs.service.d'/CONTROL_NAME)+'\nNeedDaemonReload=no\n').encode()
            if command[0]=='/usr/bin/systemd-run':
                for value in ('User=isarmg-xocs','Group=isarmg-xocs','ProtectSystem=strict',
                              'RestrictNamespaces=yes','ProtectProc=invisible','CapabilityBoundingSet='):
                    self.assertIn('--property='+value,command)
                self.assertIn('--property=ReadWritePaths='+writable_bytes(report['writable_paths'],report['readonly_paths']).decode().splitlines()[2].split('=',1)[1],command)
                self.assertTrue(any(value.startswith('--property=ReadOnlyPaths=') and str(self.root/'config') in value for value in command))
                return actual(self.direct_permission_fixture_command(command,identity),identity=identity)
            return actual(command,**options)
        with patch.object(install,'installation_unit_roots',return_value=[units]),patch.object(install,'process',side_effect=process):
            install.verify_installation_permissions(self.root,manifest,report,identity,journal,False)
        self.assertEqual(sum(command[0]=='/usr/bin/systemd-run' for command in calls),1)
        self.assertFalse(any(command[:2]==['/usr/bin/systemctl','stop'] for command in calls))
        self.assertFalse(any(path.name.startswith('.xssi-permission-') for name in ('state','logs','run') for path in (self.root/name).iterdir()))
        self.assertEqual((self.root/'config/config.json').stat().st_mode&0o777,0o640)
        self.assertEqual((self.root/'config').stat().st_uid,0)

    def test_actual_service_uid_cannot_read_badly_owned_configuration(self):
        manifest,report,identity,journal,units=self.permission_fixture()
        (self.root/'config/config.json').chmod(0o600)
        with patch.object(install,'installation_unit_roots',return_value=[units]):
            with self.assertRaises(ValueError):install.verify_installation_permissions(self.root,manifest,report,identity,journal,False)

    def test_permission_probe_timeout_stops_only_its_transient_unit(self):
        manifest,report,identity,journal,units=self.permission_fixture()
        calls=[];actual=install.process
        def process(command,**options):
            calls.append(command)
            if command[0]=='/usr/bin/systemd-run':raise TimeoutError('simulated timeout')
            if command[:2]==['/usr/bin/systemctl','stop']:return b''
            if command[:2]==['/usr/bin/systemctl','show']:
                if command[2]=='xocs.service':
                    return ('LoadState=loaded\nFragmentPath='+str(units/'xocs.service')+'\nDropInPaths='+str(units/'xocs.service.d/state.conf')+' '+str(units/'xocs.service.d'/CONTROL_NAME)+'\nNeedDaemonReload=no\n').encode()
                return b'MainPID=0\nActiveState=inactive\n'
            return actual(command,**options)
        with patch.object(install,'installation_unit_roots',return_value=[units]),patch.object(install,'process',side_effect=process):
            with self.assertRaises(TimeoutError):install.verify_installation_permissions(self.root,manifest,report,identity,journal,False)
        stopped=[command[2] for command in calls if command[:2]==['/usr/bin/systemctl','stop']]
        self.assertEqual(stopped,['xssi-install-permissions-'+journal['operation_id']+'-server'])


if __name__=='__main__':unittest.main()
