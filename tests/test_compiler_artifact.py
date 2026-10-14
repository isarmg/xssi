import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('tool_stage_release',SCRIPTS/'stage-release.py')
stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)


@unittest.skipUnless(sys.platform=='linux' and shutil.which('cargo'),
                     'actual Linux Cargo compiler output requires its installed toolchain')
class ActualCompilerArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='xssi-real-compiler-artifact-')
        self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve(strict=True)
        self.source=self.root/'source';(self.source/'src').mkdir(parents=True)
        (self.source/'Cargo.toml').write_text('[package]\nname="xssi"\nversion="1.0.0"\nedition="2024"\n[[bin]]\nname="setup"\npath="src/main.rs"\n')
        (self.source/'src/main.rs').write_text('fn main() { println!("setup 1.0.0"); }\n')
        self.target=self.root/'target';self.target.mkdir(mode=0o700)
        environment=dict(os.environ);environment['CARGO_TARGET_DIR']=str(self.target)
        subprocess.run(['cargo','generate-lockfile','--offline'],cwd=self.source,env=environment,
                       check=True,capture_output=True,timeout=30)
        self.package_id=subprocess.run(['cargo','pkgid','--locked','--offline','--package','xssi'],
            cwd=self.source,env=environment,check=True,capture_output=True,timeout=30).stdout.decode().strip()
        result=subprocess.run(['cargo','build','--frozen','--release','--target',stage.TARGET,
                               '--bin','setup','--message-format=json-render-diagnostics'],
            cwd=self.source,env=environment,check=True,capture_output=True,timeout=60)
        self.messages=result.stdout
        self.binary=self.target/stage.TARGET/'release/setup'
        self.destination=self.root/'delivery/libexec/setup'

    def seal(self,messages=None,version='1.0.0',package_id=None):
        return stage.copy_compiler_artifact(self.messages if messages is None else messages,
            self.source,self.target,self.destination,version,self.package_id if package_id is None else package_id)

    def test_actual_cargo_hardlink_is_sealed_as_a_verified_single_link_delivery(self):
        self.assertEqual(self.binary.stat().st_nlink,2)
        with self.assertRaises(ValueError):stage.release_sbom.digest(self.binary)
        original=self.binary.read_bytes()
        result=self.seal()
        self.assertFalse(result['fresh']);self.assertEqual(result['target'],stage.TARGET)
        self.assertEqual(self.destination.stat().st_nlink,1)
        self.assertEqual(self.destination.read_bytes(),original)
        self.assertEqual(subprocess.run([str(self.destination),'--version'],check=True,
            capture_output=True,timeout=10).stdout,b'setup 1.0.0\n')
        stage.release_sbom.digest(self.destination)
        with self.assertRaises(FileExistsError):self.seal()

    def test_actual_compiler_identity_freshness_profile_target_and_version_are_bound(self):
        original=[json.loads(line) for line in self.messages.splitlines()]
        changes=[('fresh',True),('package_id',self.package_id+'-unknown'),
                 ('manifest_path',str(self.root/'wrong/Cargo.toml')),
                 ('executable',str(self.root/'wrong/setup')),
                 ('profile',{'test':True,'debug_assertions':False,'opt_level':'3'})]
        for field,value in changes:
            rows=copy.deepcopy(original)
            actual=next(row for row in rows if row.get('reason')=='compiler-artifact' and row.get('executable'))
            actual[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                self.seal(('\n'.join(json.dumps(row) for row in rows)+'\n').encode())
            self.assertFalse(self.destination.exists())
        with self.assertRaises(ValueError):self.seal(version='1.0.1')
        with self.assertRaises(ValueError):self.seal(package_id='path+file:///foreign#xssi@1.0.0')

    def test_compiler_artifact_rewrite_during_copy_is_rejected_and_output_removed(self):
        original_read=os.read;changed=False;identity=self.binary.stat()
        def read(descriptor,maximum):
            nonlocal changed
            contents=original_read(descriptor,maximum)
            info=os.fstat(descriptor)
            if contents and not changed and (info.st_dev,info.st_ino)==(identity.st_dev,identity.st_ino):
                changed=True;time.sleep(.02)
                with self.binary.open('r+b') as stream:
                    stream.seek(-1,os.SEEK_END);value=stream.read(1);stream.seek(-1,os.SEEK_END)
                    stream.write(bytes([value[0]^1]));stream.flush();os.fsync(stream.fileno())
                os.utime(self.binary,ns=(identity.st_atime_ns,identity.st_mtime_ns))
            return contents
        with patch.object(stage.os,'read',side_effect=read),self.assertRaisesRegex(ValueError,'changed'):
            self.seal()
        self.assertTrue(changed);self.assertFalse(self.destination.exists())


if __name__=='__main__':unittest.main()
