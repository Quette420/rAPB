# rd.py   —   python rd.py 0x4316BA00 0x364
import ctypes, sys
from ctypes import wintypes

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
k32 = ctypes.WinDLL('kernel32')

def pid_of(name):
    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)]
    snap = k32.CreateToolhelp32Snapshot(2, 0)
    e = PE32(); e.dwSize = ctypes.sizeof(PE32)
    ok = k32.Process32First(snap, ctypes.byref(e))
    while ok:
        if e.szExeFile.decode(errors='ignore').lower() == name.lower():
            return e.th32ProcessID
        ok = k32.Process32Next(snap, ctypes.byref(e))
    return None

base = int(sys.argv[1], 0)
off  = int(sys.argv[2], 0)
h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid_of("APB.exe"))
buf = ctypes.c_uint32(); n = ctypes.c_size_t()
ok = k32.ReadProcessMemory(h, ctypes.c_void_p(base + off),
                           ctypes.byref(buf), 4, ctypes.byref(n))
print(f"ok={bool(ok)} [{hex(base)}+{hex(off)}] = {buf.value}  (0x{buf.value:08X})")