# scan_channels.py   —   python scan_channels.py 0x4F240000
import ctypes, sys, struct
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

h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid_of("APB.exe"))

def read(addr, size):
    buf = (ctypes.c_char * size)(); n = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return bytes(buf) if ok else None

def dw(addr):
    b = read(addr, 4)
    return struct.unpack('<I', b)[0] if b else None

def looks_like_ptr(v):
    return v is not None and 0x00100000 <= v <= 0xFFFE0000

base = int(sys.argv[1], 0)
SPAN = 0x6000
blob = read(base, SPAN)
if blob is None:
    print("не читается, процесс жив? заморожен?"); sys.exit(1)

words = struct.unpack('<%dI' % (SPAN // 4), blob)

# открытые каналы: 2,3,4,5,20,21,22   закрытые: 1,7,10,15
OPEN  = [2, 3, 4, 5, 20, 21, 22]
EMPTY = [1, 7, 10, 15]

for i in range(0, len(words) - 40):
    if not all(looks_like_ptr(words[i + c]) for c in OPEN):   continue
    if not all(words[i + c] == 0            for c in EMPTY):  continue
    off = i * 4
    vt = [dw(words[i + c]) for c in (2, 4, 5, 20)]
    print(f"кандидат: Channels @ conn+0x{off:X}")
    for c in OPEN:
        print(f"    Channels[{c:2d}] = 0x{words[i+c]:08X}   vtable=0x{dw(words[i+c]):08X}")
    print()