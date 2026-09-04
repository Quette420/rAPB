# freeze.py   —  python freeze.py suspend | resume
import ctypes, sys
from ctypes import wintypes

PROCESS_SUSPEND_RESUME = 0x0800
ntdll, k32 = ctypes.WinDLL('ntdll'), ctypes.WinDLL('kernel32')

def pid_of(name):
    TH32CS_SNAPPROCESS = 2
    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)]
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    e = PE32(); e.dwSize = ctypes.sizeof(PE32)
    ok = k32.Process32First(snap, ctypes.byref(e))
    while ok:
        if e.szExeFile.decode(errors='ignore').lower() == name.lower():
            return e.th32ProcessID
        ok = k32.Process32Next(snap, ctypes.byref(e))
    return None

pid = pid_of("APB.exe")
h = k32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
if sys.argv[1] == "suspend":
    ntdll.NtSuspendProcess(h)
else:
    ntdll.NtResumeProcess(h)
print(sys.argv[1], "pid", pid)