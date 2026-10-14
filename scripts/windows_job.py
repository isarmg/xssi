"""Bound a suspended Windows dependency tool and its descendants to one job.

All process/thread/job operations use documented Windows APIs. The child stays
suspended until its job assignment succeeds; closing the job ends every member.
"""
import os


class DependencyJob:
    def __init__(self):
        if os.name!='nt':
            raise RuntimeError('Windows dependency job used on another platform')
        import ctypes
        from ctypes import wintypes
        self.ctypes=ctypes
        self.types=wintypes
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        pointer=ctypes.c_size_t

        class BasicLimit(ctypes.Structure):
            _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),
                      ('flags',wintypes.DWORD),('minimum_working_set',pointer),('maximum_working_set',pointer),
                      ('active_process_limit',wintypes.DWORD),('affinity',pointer),
                      ('priority_class',wintypes.DWORD),('scheduling_class',wintypes.DWORD)]

        class IOCounters(ctypes.Structure):
            _fields_=[(name,ctypes.c_ulonglong) for name in ('read_operations','write_operations','other_operations','read_bytes','write_bytes','other_bytes')]

        class ExtendedLimit(ctypes.Structure):
            _fields_=[('basic',BasicLimit),('io',IOCounters),('process_memory',pointer),('job_memory',pointer),('peak_process_memory',pointer),('peak_job_memory',pointer)]

        class ThreadEntry(ctypes.Structure):
            _fields_=[('size',wintypes.DWORD),('usage',wintypes.DWORD),('thread_id',wintypes.DWORD),
                      ('owner_pid',wintypes.DWORD),('base_priority',wintypes.LONG),('delta_priority',wintypes.LONG),('flags',wintypes.DWORD)]

        self.ThreadEntry=ThreadEntry
        declarations={
            'CreateJobObjectW':([ctypes.c_void_p,wintypes.LPCWSTR],wintypes.HANDLE),
            'SetInformationJobObject':([wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD],wintypes.BOOL),
            'AssignProcessToJobObject':([wintypes.HANDLE,wintypes.HANDLE],wintypes.BOOL),
            'CloseHandle':([wintypes.HANDLE],wintypes.BOOL),
            'OpenProcess':([wintypes.DWORD,wintypes.BOOL,wintypes.DWORD],wintypes.HANDLE),
            'CreateToolhelp32Snapshot':([wintypes.DWORD,wintypes.DWORD],wintypes.HANDLE),
            'Thread32First':([wintypes.HANDLE,ctypes.POINTER(ThreadEntry)],wintypes.BOOL),
            'Thread32Next':([wintypes.HANDLE,ctypes.POINTER(ThreadEntry)],wintypes.BOOL),
            'OpenThread':([wintypes.DWORD,wintypes.BOOL,wintypes.DWORD],wintypes.HANDLE),
            'ResumeThread':([wintypes.HANDLE],wintypes.DWORD),
        }
        for name,(arguments,result) in declarations.items():
            function=getattr(self.kernel,name)
            function.argtypes=arguments
            function.restype=result
        self.handle=self.kernel.CreateJobObjectW(None,None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits=ExtendedLimit()
        limits.basic.flags=0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel.SetInformationJobObject(self.handle,9,ctypes.byref(limits),ctypes.sizeof(limits)):
            error=ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign_and_resume(self,pid):
        ctypes=self.ctypes
        process=self.kernel.OpenProcess(0x0101,False,pid)  # SET_QUOTA | TERMINATE
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle,process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.kernel.CloseHandle(process)
        snapshot=self.kernel.CreateToolhelp32Snapshot(0x00000004,0)  # TH32CS_SNAPTHREAD
        if snapshot==ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry=self.ThreadEntry()
            entry.size=ctypes.sizeof(entry)
            found=self.kernel.Thread32First(snapshot,ctypes.byref(entry))
            count=0
            while found:
                count+=1
                if count>1000000:
                    raise ValueError('Windows thread inventory exceeds its bound')
                if entry.owner_pid==pid:
                    thread=self.kernel.OpenThread(0x0002,False,entry.thread_id)  # SUSPEND_RESUME
                    if not thread:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        previous=self.kernel.ResumeThread(thread)
                        if previous==0xffffffff:
                            raise ctypes.WinError(ctypes.get_last_error())
                        if previous!=1:
                            raise ValueError('dependency tool primary thread is not newly suspended')
                        return
                    finally:
                        self.kernel.CloseHandle(thread)
                found=self.kernel.Thread32Next(snapshot,ctypes.byref(entry))
            raise ValueError('newly suspended dependency tool has no primary thread')
        finally:
            self.kernel.CloseHandle(snapshot)

    def close(self):
        if self.handle:
            handle=self.handle
            self.handle=None
            if not self.kernel.CloseHandle(handle):
                raise self.ctypes.WinError(self.ctypes.get_last_error())
