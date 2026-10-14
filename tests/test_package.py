import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/'scripts'))
import package

FAKE_SETUP='''#!/usr/bin/env python3
import argparse,fcntl,json,os,pathlib,sys
p=argparse.ArgumentParser();p.add_argument('--product');p.add_argument('--root');p.add_argument('--config');p.add_argument('--json',action='store_true');p.add_argument('--service-uid',type=int);p.add_argument('--service-gid',type=int);p.add_argument('--operation-id');p.add_argument('--tool-lock-fd',type=int,required=True);p.add_argument('command');p.add_argument('--username');a=p.parse_args()
root=pathlib.Path(a.root)
opened=os.fstat(a.tool_lock_fd);named=(root/'maintenance/tool.lock').stat()
assert (opened.st_dev,opened.st_ino)==(named.st_dev,named.st_ino)
another=os.open(root/'maintenance/tool.lock',os.O_RDWR)
try:
    try:fcntl.flock(another,fcntl.LOCK_SH|fcntl.LOCK_NB)
    except BlockingIOError:pass
    else:raise RuntimeError('parent tool lock was not held across helper')
finally:os.close(another)
fcntl.flock(a.tool_lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
cfg=json.loads(pathlib.Path(a.config or root/'config/config.json').read_text());data=pathlib.Path(cfg.get('data_dir',str(root/'state')))
if cfg.get('bind')=='invalid':sys.exit(1)
if a.command=='validate-credentials':
    if len(sys.stdin.read().strip())<12:sys.exit(1)
    print('{}');sys.exit(0)
report={'product':a.product,'root':str(root),'data_dir':str(data),'bind':cfg.get('bind','127.0.0.1:18104'),'state_paths':[str(root/'config/config.json'),str(data),str(root/'logs')],'private_directories':[str(data),str(root/'logs'),str(root/'run')],'private_files':[str(data/'database-marker')],'shared_paths':[],'business_paths':[],'writable_paths':[str(data),str(root/'logs'),str(root/'run')],'readonly_paths':[str(root/'config')],'config_write_paths':[],'schema_identity':{'application':a.product,'application_version':'1.0.0','schema_revision':1,'schema_sha256':'a'*64}}
for name in cfg.get('readonly_configuration',[]):report['readonly_paths'].append(str(root/'config'/name))
if 'shared_root' in cfg:
    shared=pathlib.Path(cfg['shared_root']);report['shared_paths'].append(str(shared));report['business_paths'].append(str(shared));report['writable_paths'].append(str(shared))
if 'business_root' in cfg:
    business=pathlib.Path(cfg['business_root']);report['business_paths'].append(str(business));report['writable_paths'].append(str(business))
if cfg.get('mutable_config'):
    mutable=root/'config/generated';report['config_write_paths'].append(str(mutable));report['writable_paths'].append(str(mutable))
if report['bind']=='invalid':sys.exit(1)
if a.command=='initialize':
    if len(sys.stdin.read().strip())<12:sys.exit(1)
    if (data/'database-marker').exists():print(json.dumps(report));sys.exit(0)
    data.mkdir(exist_ok=True)
    with (data/'database-marker').open('x') as f:f.write('fixture initialization')
    os.chown(data/'database-marker',a.service_uid,a.service_gid)
    if cfg.get('mutable_config'):
        mutable.mkdir();(mutable/'runtime.conf').write_text('generated fixture configuration')
elif a.command=='check':
    if not (data/'database-marker').exists():sys.exit(1)
    for name in cfg.get('readonly_configuration',[]):
        if not (root/'config'/name).is_file():sys.exit(1)
    report['initialized']=True
elif a.command!='config-validate':sys.exit(1)
print(json.dumps(report))
'''

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.temp=Path(self.temporary.name)
        self.stage=self.temp/'package'
        for name in ('bin','libexec','share/systemd'):(self.stage/name).mkdir(parents=True,exist_ok=True)
        (self.stage/'bin/xocs').write_bytes(b'fixture server: never execute')
        (self.stage/'libexec/setup').write_text(FAKE_SETUP)
        (self.stage/'share/systemd/xocs.service').write_text('[Service]\nUser=isarmg-xocs\nExecStart="@ROOT@/bin/xocs" --root "@ROOT@"\n')
        identity={'product':'xocs','version':'1.0.0','source_revision':'1'*40,'target':'x86_64-unknown-linux-gnu','state_contract_sha256':'2'*64}
        schema={'application':'xocs','application_version':'1.0.0','schema_revision':1,'schema_sha256':'a'*64}
        self.identity=self.temp/'identity.json';self.identity.write_text(json.dumps(identity))
        self.schema=self.temp/'schema.json';self.schema.write_text(json.dumps(schema))
        package.finalize(self.stage,self.identity,self.schema)

    def test_exact_checksum_payload_and_mode(self):
        report=package.verify(self.stage)
        self.assertEqual(report['setup'],'libexec/setup')
        (self.stage/'bin/xocs').chmod(0o700)
        with self.assertRaises(ValueError):package.verify(self.stage)

    def test_modified_checksum_or_manifest_is_rejected(self):
        checksum_path=self.stage/package.CHECKSUM;original=checksum_path.read_bytes()
        checksum_path.write_bytes(b'0'*64+b'\n')
        with self.assertRaises(ValueError):package.verify(self.stage)
        checksum_path.write_bytes(original)
        (self.stage/package.MANIFEST).write_bytes(package.bytes_regular(self.stage/package.MANIFEST)+b' ')
        with self.assertRaises(ValueError):package.verify(self.stage)

    def test_link_alias_and_undeclared_payload_rejected(self):
        os.link(self.stage/'libexec/setup',self.temp/'alias')
        with self.assertRaises(ValueError):package.verify(self.stage)
        (self.temp/'alias').unlink()
        (self.stage/'unexpected').write_text('not signed')
        with self.assertRaises(ValueError):package.verify(self.stage)

    def invoke(self,root,config,configuration_files=()):
        command=[sys.executable,'-I','-B',str(SOURCE/'tests/install_fixture.py'),'--package',str(self.stage),'--root',str(root),'--config',str(config)]
        for value in configuration_files:command.extend(['--configuration-file',value])
        return subprocess.run(command,input=b'correct horse battery\n',capture_output=True)

    def test_real_install_script_corrected_configuration_retries(self):
        root=self.temp/'installed';config=self.temp/'chosen.json'
        config.write_text(json.dumps({'bind':'invalid'}))
        rejected=self.invoke(root,config);self.assertNotEqual(rejected.returncode,0)
        self.assertEqual(json.loads((root/'maintenance/install.json').read_text())['phase'],'staging')
        self.assertFalse((root/'state').exists())
        config.write_text('{}')
        completed=self.invoke(root,config)
        self.assertEqual(completed.returncode,0,completed.stderr.decode())
        self.assertEqual(json.loads(completed.stdout)['services_started'],False)
        self.assertTrue((root/'state/database-marker').exists())
        before=(root/'state/database-marker').read_bytes()
        self.assertNotEqual(self.invoke(root,config).returncode,0)
        self.assertEqual((root/'state/database-marker').read_bytes(),before)

    def test_selected_configuration_exists_before_credential_context_validation(self):
        root=self.temp/'installed';config=self.temp/'chosen.json'
        selected={'bind':'127.0.0.1:19127'}
        config.write_text(json.dumps(selected))
        completed=self.invoke(root,config)
        self.assertEqual(completed.returncode,0,completed.stderr.decode())
        self.assertEqual(json.loads((root/'config/config.json').read_text()),selected)
        journal=json.loads((root/'maintenance/install.json').read_text())
        self.assertEqual(journal['main_configuration']['sha256'],hashlib.sha256(config.read_bytes()).hexdigest())
        self.assertEqual(journal['phase'],'complete')

    def test_invalid_credentials_with_valid_configuration_do_not_initialize_state(self):
        root=self.temp/'installed';config=self.temp/'chosen.json';config.write_text('{}')
        result=subprocess.run([sys.executable,'-I','-B',str(SOURCE/'tests/install_fixture.py'),
            '--package',str(self.stage),'--root',str(root),'--config',str(config)],
            input=b'short\n',capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((root/'state').exists())
        self.assertFalse((root/'bin').exists())
        self.assertFalse((root/'run/fixture-systemd').exists())

    def test_modified_payload_never_executes_or_creates_install_root(self):
        (self.stage/'libexec/setup').write_text('#!/bin/sh\ntouch /tmp/never-authorized-xssi-marker\n')
        root=self.temp/'installed';config=self.temp/'chosen.json';config.write_text('{}')
        self.assertNotEqual(self.invoke(root,config).returncode,0)
        self.assertFalse(root.exists())

    def test_interruption_after_initializer_resumes_without_reinitializing_data(self):
        root=self.temp/'installed';config=self.temp/'chosen.json';config.write_text('{}')
        self.assertEqual(self.invoke(root,config).returncode,0)
        marker=root/'state/database-marker';before=marker.read_bytes()
        journal_path=root/'maintenance/install.json';journal=json.loads(journal_path.read_text())
        # Model a successful durable child initialization followed by parent
        # interruption before recording the completed phase and installing units.
        journal['phase']='initialize-intent'
        unit=root/'run/fixture-systemd/xocs.service';unit.unlink()
        del journal['unit_files'][str(unit)]
        journal_path.write_text(json.dumps(journal))
        resumed=self.invoke(root,config)
        self.assertEqual(resumed.returncode,0,resumed.stderr.decode())
        self.assertEqual(marker.read_bytes(),before)
        self.assertTrue(unit.is_file())
        self.assertEqual(json.loads(journal_path.read_text())['phase'],'complete')

    def test_installed_payload_verification_excludes_mutable_state_but_checks_programs(self):
        root=self.temp/'installed';config=self.temp/'chosen.json';config.write_text('{}')
        self.assertEqual(self.invoke(root,config).returncode,0)
        package.verify(root,installed=True)
        (root/'state/database-marker').write_bytes(b'legitimate changed application data')
        for name in ('files','media'):
            directory=root/name;directory.mkdir(mode=0o700);(directory/'business-object').write_bytes(b'legitimate configurable business data')
        note=root/'administrator-note';note.write_bytes(b'owned installation content outside package namespaces')
        package.verify(root,installed=True)
        self.assertEqual(note.read_bytes(),b'owned installation content outside package namespaces')
        unexpected=root/'bin/evil';unexpected.write_bytes(b'unsigned executable');unexpected.chmod(0o755)
        with self.assertRaises(ValueError):package.verify(root,installed=True)
        unexpected.unlink()
        (root/'bin/xocs').write_bytes(b'modified program')
        with self.assertRaises(ValueError):package.verify(root,installed=True)

    def test_install_cannot_replace_a_service_owned_by_another_installation(self):
        root=self.temp/'installed';config=self.temp/'chosen.json';config.write_text('{}')
        unit=root/'run/fixture-systemd/xocs.service';unit.parent.mkdir(parents=True)
        unit.write_bytes(b'another installed service')
        result=self.invoke(root,config)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(unit.read_bytes(),b'another installed service')
        self.assertFalse((root/'state/database-marker').exists())

    def test_checksummed_duplicate_keys_and_boolean_protocol_version_are_rejected(self):
        path=self.stage/package.MANIFEST;original=path.read_bytes()
        for changed in [b'{"manifest_version":1,'+original[1:],
                        original.replace(b'"manifest_version":1',b'"manifest_version":true')]:
            path.write_bytes(changed)
            (self.stage/package.CHECKSUM).write_text(hashlib.sha256(changed).hexdigest()+'\n')
            with self.assertRaises(ValueError):package.verify(self.stage)

    def camera_store_package(self):
        (self.stage/'bin/xocs').rename(self.stage/'bin/xczs')
        (self.stage/'share/systemd/xocs.service').rename(self.stage/'share/systemd/xczs.service')
        identity=json.loads(self.identity.read_text());identity['product']='xczs';self.identity.write_text(json.dumps(identity))
        schema=json.loads(self.schema.read_text());schema['application']='xczs';self.schema.write_text(json.dumps(schema))
        (self.stage/package.MANIFEST).unlink();(self.stage/package.CHECKSUM).unlink()
        package.finalize(self.stage,self.identity,self.schema)

    def test_existing_shared_business_root_preserves_permissions_and_mixed_owners(self):
        self.camera_store_package()
        root=self.temp/'installed';shared=self.temp/'shared';shared.mkdir(mode=0o775);shared.chmod(0o775)
        item=shared/'another-service-file';item.write_text('preexisting shared content');item.chmod(0o664)
        if os.geteuid()==0:os.chown(item,65534,65534)
        before={path:(path.stat().st_uid,path.stat().st_gid,path.stat().st_mode,path.read_bytes() if path.is_file() else None) for path in (shared,item)}
        config=self.temp/'chosen.json';config.write_text(json.dumps({'shared_root':str(shared)}))
        completed=self.invoke(root,config)
        self.assertEqual(completed.returncode,0,completed.stderr.decode())
        self.assertEqual(before,{path:(path.stat().st_uid,path.stat().st_gid,path.stat().st_mode,path.read_bytes() if path.is_file() else None) for path in (shared,item)})
        self.assertEqual(sorted(path.name for path in shared.iterdir()),[item.name])
        self.assertEqual((root/'state').stat().st_mode&0o777,0o700)

    def test_shared_report_cannot_relax_private_roots(self):
        self.camera_store_package()
        root=self.temp/'installed';config=self.temp/'chosen.json'
        config.write_text(json.dumps({'shared_root':str(root/'state/nested')}))
        self.assertNotEqual(self.invoke(root,config).returncode,0)
        self.assertFalse((root/'state/database-marker').exists())

    def test_packaged_shell_install_and_next_commands_preserve_the_exact_inventory(self):
        for name in ('install.sh','maintenance.sh','upgrade.sh'):
            shutil.copyfile(SOURCE/name,self.stage/name)
        for name in ('package.py','material_store.py','unit_validation.py','writer_control.py','install.py','maintenance.py','upgrade.py'):
            shutil.copyfile(SOURCE/'scripts'/name,self.stage/'libexec'/name)
        (self.stage/package.MANIFEST).unlink();(self.stage/package.CHECKSUM).unlink()
        package.finalize(self.stage,self.identity,self.schema)
        injected=self.temp/'environment-modules';injected.mkdir()
        marker=self.temp/'environment-module-executed'
        (injected/'argparse.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\nraise RuntimeError("untrusted environment module")\n')
        environment=os.environ.copy();environment['PYTHONPATH']=str(injected)
        root=self.temp/'installed';config=self.temp/'chosen.json';config.write_text('{}')
        help_result=subprocess.run([str(self.stage/'install.sh'),'--help'],env=environment,capture_output=True)
        self.assertEqual(help_result.returncode,0,help_result.stderr.decode())
        self.assertNotIn('--fixture',help_result.stdout.decode())
        completed=subprocess.run([sys.executable,'-I','-B',str(SOURCE/'tests/install_fixture.py'),'--installer',str(self.stage/'libexec/install.py'),'--package',str(self.stage),'--root',str(root),'--config',str(config)],input=b'correct horse battery\n',env=environment,capture_output=True)
        self.assertEqual(completed.returncode,0,completed.stderr.decode())
        for name in ('maintenance.sh','upgrade.sh'):
            imported=subprocess.run([str(root/name),'--help'],env=environment,capture_output=True)
            self.assertEqual(imported.returncode,0,imported.stderr.decode())
            package.verify(root,installed=True)
        self.assertFalse(marker.exists())
        self.assertFalse((root/'libexec/__pycache__').exists())

if __name__=='__main__':unittest.main()
