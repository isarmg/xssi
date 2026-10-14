"""Actual extractor subprocess boundaries shared by Windows and POSIX."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import native_package
from sbom import run
from test_sbom_process import process_alive


class NativeExtractorProcessTests(unittest.TestCase):
    def test_success_nonzero_and_actual_output_bounds(self):
        self.assertEqual(native_package.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"actual extraction report\\n")']),b'actual extraction report\n')
        with self.assertRaisesRegex(ValueError,'extractor failed'):
            native_package.run([sys.executable,'-c','raise SystemExit(7)'])
        with mock.patch.object(native_package.sbom,'MAX_JSON',1024):
            with self.assertRaisesRegex(ValueError,'output exceeds'):
                native_package.run([sys.executable,'-c','import os;os.write(1,b"x"*1048576)'])

    def test_sensitive_environment_is_removed_before_the_actual_extractor(self):
        script='import os,sys;assert "XSSI_FIXTURE_SECRET" not in os.environ;assert "XSSI_FIXTURE_TOKEN" not in os.environ;assert os.environ["TZ"]=="UTC";sys.stdout.buffer.write(b"clean extraction environment\\n")'
        with mock.patch.dict(os.environ,{'XSSI_FIXTURE_SECRET':'public secret fixture','XSSI_FIXTURE_TOKEN':'public token fixture'}):
            self.assertEqual(native_package.run([sys.executable,'-c',script]),b'clean extraction environment\n')

    def test_actual_orphan_with_open_output_is_terminated_after_timeout(self):
        with tempfile.TemporaryDirectory(prefix='xssi-native-extractor-tree-') as temporary:
            path=Path(temporary)/'child.pid'
            def short(command,cwd,environment,maximum,timeout):
                return run(command,cwd,environment,maximum=maximum,timeout=1)
            script='import subprocess,sys;from pathlib import Path;child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);Path(sys.argv[1]).write_text(str(child.pid));raise SystemExit(0)'
            with mock.patch.object(native_package,'bounded_dependency_tool',side_effect=short):
                with self.assertRaises(TimeoutError):native_package.run([sys.executable,'-c',script,str(path)])
            self.assertTrue(path.is_file(),'actual extractor descendant must have started')
            pid=int(path.read_text());deadline=time.monotonic()+3
            while process_alive(pid) and time.monotonic()<deadline:time.sleep(.01)
            self.assertFalse(process_alive(pid),'extractor cleanup must reach the descendant after its parent exits')


if __name__=='__main__':unittest.main()
