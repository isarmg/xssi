import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import sbom


class DependencyToolTests(unittest.TestCase):
    def test_stream_to_file_enforces_bound_before_writing_and_preserves_preexisting_files(self):
        with tempfile.TemporaryDirectory(prefix='xssi-dependency-stream-') as temporary:
            root=Path(temporary);path=root/'payload.cpio'
            self.assertEqual(sbom.run_to_file([sys.executable,'-c','import os;os.write(1,b"actual streamed payload")'],root,os.environ.copy(),path),23)
            self.assertEqual(path.read_bytes(),b'actual streamed payload')
            with self.assertRaises(FileExistsError):
                sbom.run_to_file([sys.executable,'-c','raise SystemExit(0)'],root,os.environ.copy(),path)
            self.assertEqual(path.read_bytes(),b'actual streamed payload')
            path.unlink()
            with self.assertRaisesRegex(ValueError,'exceeds'):
                sbom.run_to_file([sys.executable,'-c','import os;os.write(1,b"x"*1048576)'],root,os.environ.copy(),path,maximum=1024)
            self.assertFalse(path.exists(),'failed new stream output must be removed')
            with self.assertRaises(subprocess.CalledProcessError):
                sbom.run_to_file([sys.executable,'-c','import os;os.write(1,b"partial");raise SystemExit(7)'],root,os.environ.copy(),path)
            self.assertFalse(path.exists())

    def test_stream_timeout_terminates_actual_descendant_and_removes_only_its_new_output(self):
        with tempfile.TemporaryDirectory(prefix='xssi-dependency-stream-tree-') as temporary:
            root=Path(temporary);path=root/'payload.cpio';pid_path=root/'child.pid'
            script='import subprocess,sys;from pathlib import Path;child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);Path(sys.argv[1]).write_text(str(child.pid));raise SystemExit(0)'
            with self.assertRaises(TimeoutError):
                sbom.run_to_file([sys.executable,'-c',script,str(pid_path)],root,os.environ.copy(),path,timeout=1)
            self.assertFalse(path.exists())
            self.assertTrue(pid_path.is_file())
            pid=int(pid_path.read_text());deadline=time.monotonic()+3
            while process_alive(pid) and time.monotonic()<deadline:time.sleep(.01)
            self.assertFalse(process_alive(pid),'stream timeout must terminate the real output-holding descendant')

    @unittest.skipIf(os.name=='nt','POSIX permits renaming a file while its output descriptor remains open')
    def test_failed_stream_preserves_a_replacement_instead_of_deleting_unknown_data(self):
        with tempfile.TemporaryDirectory(prefix='xssi-dependency-stream-replaced-') as temporary:
            root=Path(temporary);path=root/'payload.cpio'
            script='import sys;from pathlib import Path;p=Path(sys.argv[1]);replacement=p.with_suffix(".replacement");replacement.write_bytes(b"unrelated replacement");replacement.replace(p);raise SystemExit(7)'
            with self.assertRaisesRegex(RuntimeError,'preserve the unknown file'):
                sbom.run_to_file([sys.executable,'-c',script,str(path)],root,os.environ.copy(),path)
            self.assertEqual(path.read_bytes(),b'unrelated replacement')

    def test_success_failure_and_output_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.assertEqual(sbom.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"dependency inventory\\n")'],root,os.environ.copy()),b'dependency inventory\n')
            with self.assertRaises(subprocess.CalledProcessError):
                sbom.run([sys.executable,'-c','raise SystemExit(3)'],root,os.environ.copy())
            with self.assertRaises(ValueError):
                sbom.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"x"*1048576)'],root,os.environ.copy(),1024)

    def test_zero_output_small_chunks_and_process_that_closes_output_then_hangs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.assertEqual(sbom.run([sys.executable,'-c','pass'],root,os.environ.copy(),maximum=0),b'')
            actual=sbom.run([sys.executable,'-c','import os;[os.write(1,b"x") for _ in range(257)]'],root,os.environ.copy(),maximum=257)
            self.assertEqual(actual,b'x'*257)
            with self.assertRaises(TimeoutError):
                sbom.run([sys.executable,'-c','import os,time;os.close(1);time.sleep(60)'],root,os.environ.copy(),timeout=.2)

    def test_child_with_open_output_cannot_escape_the_total_time_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_path=Path(temporary)/'descendant.pid'
            started=time.monotonic()
            with self.assertRaises(TimeoutError):
                sbom.run([sys.executable,'-c',
                          'import subprocess,sys;from pathlib import Path;child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);Path(sys.argv[1]).write_text(str(child.pid));raise SystemExit(0)',str(pid_path)],
                         Path(temporary),os.environ.copy(),timeout=1)
            self.assertLess(time.monotonic()-started,5)
            self.assertTrue(pid_path.is_file(),'real descendant must have started')
            pid=int(pid_path.read_text())
            deadline=time.monotonic()+3
            while process_alive(pid) and time.monotonic()<deadline:
                time.sleep(.01)
            self.assertFalse(process_alive(pid),'timeout must terminate the real descendant, even after its parent exits')
            self.assertFalse(any(item.name=='xssi-dependency-output' and item.is_alive() for item in threading.enumerate()))

    @unittest.skipUnless(os.name=='nt','requires actual Windows nested job semantics')
    def test_actual_dependency_job_can_nest_inside_an_existing_kill_job(self):
        from windows_job import DependencyJob
        job=DependencyJob();child=None
        scripts=str(Path(sbom.__file__).resolve().parent)
        program='import sys;sys.stdout.buffer.write(b"nested job child\\n")'
        code='import os,sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import sbom;output=sbom.run([sys.executable,"-c",'+repr(program)+'],Path.cwd(),os.environ.copy(),timeout=5);assert output==b"nested job child\\n";sys.stdout.buffer.write(b"nested job passed\\n")'
        try:
            child=subprocess.Popen([sys.executable,'-c',code,scripts],stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|0x00000004)
            job.assign_and_resume(child.pid)
            output,error=child.communicate(timeout=10)
            self.assertEqual(child.returncode,0,error.decode(errors='replace'))
            self.assertEqual(output,b'nested job passed\n')
        finally:
            job.close()
            if child is not None:
                if child.poll() is None:child.kill()
                child.wait()
                child.stdout.close();child.stderr.close()

    @unittest.skipUnless(os.name=='nt','requires actual suspended Windows process creation')
    def test_job_assignment_failure_cannot_execute_the_suspended_child(self):
        from windows_job import DependencyJob
        with tempfile.TemporaryDirectory(prefix='xssi-unassigned-job-') as temporary:
            marker=Path(temporary)/'unexpected-execution'
            code='import sys;from pathlib import Path;Path(sys.argv[1]).write_text("unexpected")'
            with mock.patch.object(DependencyJob,'assign_and_resume',side_effect=ValueError('fixture refused job assignment')):
                with self.assertRaisesRegex(ValueError,'refused job assignment'):
                    sbom.run([sys.executable,'-c',code,str(marker)],Path(temporary),os.environ.copy(),timeout=5)
            self.assertFalse(marker.exists(),'assignment failure must kill the child before its code runs')


def process_alive(pid):
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        kernel.OpenProcess.restype=wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype=wintypes.BOOL
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        kernel.CloseHandle.restype=wintypes.BOOL
        handle=kernel.OpenProcess(0x1000,False,pid)
        if not handle:
            error=ctypes.get_last_error()
            if error==87:return False  # ERROR_INVALID_PARAMETER: no such PID.
            raise ctypes.WinError(error)
        try:
            status=wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle,ctypes.byref(status)):
                raise ctypes.WinError(ctypes.get_last_error())
            return status.value==259
        finally:
            kernel.CloseHandle(handle)
    try:
        state=(Path('/proc')/str(pid)/'status').read_text()
        return not any(line.startswith('State:') and ('Z' in line or 'X' in line) for line in state.splitlines())
    except FileNotFoundError:
        return False


if __name__=='__main__':unittest.main()
