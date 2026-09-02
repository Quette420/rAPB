#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
apb_reflect.py -- полный дамп UE3-рефлексии из живой памяти клиента APB.

Назначение: получить из памяти то, что раньше доставалось разбором APBGame.u --
иерархию классов, все свойства с типами/offset/ArrayDim, все функции с полными
сигнатурами и net-флагами, структуры, enum'ы и ClassNetCache.

Главный принцип проекта соблюдён: скрипт ничего не предполагает про раскладку
UFunction. Она выводится режимом --probe-ufunction из уже подтверждённых данных
(Children/PropertyFlags/Offset), и только после записи в offsets.json
используется в --dump.

ТРЕБОВАНИЯ: 32-битный Python, запуск от администратора, клиент запущен.

ТИПИЧНЫЙ ПОРЯДОК РАБОТЫ

    python apb_reflect.py --selftest
    python apb_reflect.py --probe-ufunction
    python apb_reflect.py --probe-ufunction --learn        # записать в offsets.json
    python apb_reflect.py --dump reflect.json --package APBGame
    python apb_reflect.py --dump reflect.json --flat reflect.txt --uc uc_out/

Файл reflect.txt -- канонический построчный формат, предназначенный для diff
против такого же экспорта из UELib. Это и есть доказательство дампера.
"""

from __future__ import print_function

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import struct
import sys

VERSION = "apb_reflect.py 0.1.0"

# ---------------------------------------------------------------------------
# Подтверждённая раскладка (источник: APBEMU_RESEARCH.md, APBEMU_VSTATE_DRIVE_HANDOFF.md)
# ---------------------------------------------------------------------------

L = {
    # UObject
    "UObject.Index":            0x04,
    "UObject.StateFrame":       0x18,
    "UObject.NetIndex":         0x20,
    "UObject.Outer":            0x2C,
    "UObject.NameIndex":        0x30,
    "UObject.NameNumber":       0x34,
    "UObject.Class":            0x38,
    "UObject.ObjectArchetype":  0x3C,

    # UField
    "UField.SuperField":        0x40,
    "UField.Next":              0x44,

    # UStruct
    "UStruct.Children":         0x50,
    "UStruct.PropertiesSize":   0x54,   # INT -- ИСПРАВЛЕНО, было 0xA6
    "UStruct.Script":           0x58,   # TArray<BYTE>: Data/Num/Max

    # UProperty
    "UProperty.ArrayDim":       0x48,
    "UProperty.ElementSize":    0x4C,
    "UProperty.PropertyFlags":  0x50,   # u64
    "UProperty.RepIndex":       0x62,   # u16
    "UProperty.Offset":         0x68,
    "UProperty.Inner":          0x88,   # PropertyClass / Struct / Enum / Inner -- ГИПОТЕЗА кроме Object/Struct

    # UClass
    "UClass.ClassCastFlags":    0xEC,
    "UClass.NetFields":         0x10C,  # TArray<UField*>
    "UClass.ClassDefaultObject":0x148,

    # UFunction -- выведено --probe-ufunction, сверено с Children на 900 образцах
    "UFunction.FunctionFlags":   0x94,   # u32
    "UFunction.iNative":         0x98,   # u16
    "UFunction.RepOffset":       0x9A,   # u16
    "UFunction.FriendlyName":    0x9C,   # FName (index 0x9C, number 0xA0)
    "UFunction.OperPrecedence":  0xA4,   # u8
    "UFunction.NumParms":        0xA5,   # u8
    "UFunction.ParmsSize":       0xA6,   # u16
    "UFunction.ReturnValueOffset": 0xA8, # u16, 0xFFFF = возврата нет
    "UFunction.FirstPropertyToInit": 0xAC,
    "UFunction.Func":            0xB0,   # ptr; у скриптовых = ProcessInternal

    # FNameEntry
    "FNameEntry.Index":         0x00,
    "FNameEntry.Flags":         0x04,   # u64
    "FNameEntry.HashNext":      0x0C,
    "FNameEntry.Name":          0x10,
}

CASTCLASS_UProperty      = 0x00008000
CASTCLASS_UBoolProperty  = 0x00020000
CASTCLASS_UFunction      = 0x00080000

CPF = [
    (0x0000000000000002, "const"),
    (0x0000000000000010, "optional"),
    (0x0000000000000020, "net"),
    (0x0000000000000080, "parm"),
    (0x0000000000000100, "out"),
    (0x0000000000000400, "return"),
    (0x0000000000000800, "coerce"),
    (0x0000000000001000, "native"),
    (0x0000000000002000, "transient"),
    (0x0000000000004000, "config"),
    (0x0000000000008000, "localized"),
    (0x0000000000020000, "editconst"),
    (0x0000000000080000, "component"),
    (0x0000000000400000, "needctorlink"),
    (0x0000000020000000, "deprecated"),
    (0x0000000200000000, "repnotify"),
    (0x0000000400000000, "interp"),
    (0x0000004000000000, "repretry"),
]
CPF_PARM   = 0x80
CPF_OUT    = 0x100
CPF_RETURN = 0x400
CPF_OPT    = 0x10
CPF_COERCE = 0x800

FUNC = [
    (0x00000001, "final"),
    (0x00000002, "defined"),
    (0x00000004, "iterator"),
    (0x00000008, "latent"),
    (0x00000010, "preoperator"),
    (0x00000020, "singular"),
    (0x00000040, "net"),
    (0x00000080, "netreliable"),
    (0x00000100, "simulated"),
    (0x00000200, "exec"),
    (0x00000400, "native"),
    (0x00000800, "event"),
    (0x00001000, "operator"),
    (0x00002000, "static"),
    (0x00004000, "hasoptionalparms"),
    (0x00008000, "const"),
    (0x00020000, "public"),
    (0x00040000, "private"),
    (0x00080000, "protected"),
    (0x00100000, "delegate"),
    (0x00200000, "netserver"),
    (0x00400000, "hasoutparms"),
    (0x00800000, "hasdefaults"),
    (0x01000000, "netclient"),
    (0x02000000, "dllimport"),
]
FUNC_DEFINED = 0x2
FUNC_NATIVE  = 0x400


def flagstr(value, table):
    out = [name for bit, name in table if value & bit]
    return ",".join(out)


# ---------------------------------------------------------------------------
# Источник памяти
# ---------------------------------------------------------------------------

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_PATH = 260


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * MAX_PATH)]


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
                ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE),
                ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * MAX_PATH)]


class MemoryError_(Exception):
    pass


class MemorySource(object):
    """Базовый интерфейс. read() обязан бросить MemoryError_ на недоступном адресе."""
    BLOCK = 0x10000

    def __init__(self):
        self._cache = {}

    def _read_raw(self, addr, size):
        raise NotImplementedError

    def read(self, addr, size):
        """Чтение через блочный кэш. Рефлексия статична, кэш = снимок."""
        out = bytearray()
        cur = addr
        left = size
        while left > 0:
            base = cur & ~(self.BLOCK - 1)
            off = cur - base
            blk = self._cache.get(base)
            if blk is None:
                blk = self._read_raw(base, self.BLOCK)
                if blk is None:
                    blk = b""
                self._cache[base] = blk
            if len(blk) <= off:
                raise MemoryError_("unreadable 0x%08X" % cur)
            take = min(left, len(blk) - off)
            out += blk[off:off + take]
            if take == 0:
                raise MemoryError_("unreadable 0x%08X" % cur)
            cur += take
            left -= take
        return bytes(out)

    # удобные примитивы -----------------------------------------------------
    def u8(self, a):   return struct.unpack("<B", self.read(a, 1))[0]
    def u16(self, a):  return struct.unpack("<H", self.read(a, 2))[0]
    def u32(self, a):  return struct.unpack("<I", self.read(a, 4))[0]
    def i32(self, a):  return struct.unpack("<i", self.read(a, 4))[0]
    def u64(self, a):  return struct.unpack("<Q", self.read(a, 8))[0]
    def ptr(self, a):  return self.u32(a)

    def try_u32(self, a, default=None):
        try:
            return self.u32(a)
        except MemoryError_:
            return default


class LiveProcess(MemorySource):
    def __init__(self, exe_name):
        MemorySource.__init__(self)
        self.k32 = ctypes.windll.kernel32
        self.pid = self._find_pid(exe_name)
        if not self.pid:
            raise MemoryError_("процесс %s не найден" % exe_name)
        self.h = self.k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                      False, self.pid)
        if not self.h:
            raise MemoryError_("OpenProcess failed (нужен запуск от администратора)")
        self.module_base, self.module_size = self._find_module(exe_name)

    def _find_pid(self, name):
        snap = self.k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        e = PROCESSENTRY32()
        e.dwSize = ctypes.sizeof(e)
        want = name.lower().encode("ascii")
        ok = self.k32.Process32First(snap, ctypes.byref(e))
        pid = None
        while ok:
            if e.szExeFile.lower() == want:
                pid = e.th32ProcessID
                break
            ok = self.k32.Process32Next(snap, ctypes.byref(e))
        self.k32.CloseHandle(snap)
        return pid

    def _find_module(self, name):
        snap = self.k32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        m = MODULEENTRY32()
        m.dwSize = ctypes.sizeof(m)
        want = name.lower().encode("ascii")
        ok = self.k32.Module32First(snap, ctypes.byref(m))
        res = (None, None)
        while ok:
            if m.szModule.lower() == want:
                res = (ctypes.cast(m.modBaseAddr, ctypes.c_void_p).value, m.modBaseSize)
                break
            ok = self.k32.Module32Next(snap, ctypes.byref(m))
        self.k32.CloseHandle(snap)
        return res

    def _read_raw(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = self.k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf,
                                        size, ctypes.byref(got))
        if not ok or got.value == 0:
            # блок может быть частично валиден -- пробуем поштучно по 0x1000
            out = bytearray()
            for p in range(0, size, 0x1000):
                sub = ctypes.create_string_buffer(0x1000)
                g2 = ctypes.c_size_t(0)
                if self.k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr + p),
                                              sub, 0x1000, ctypes.byref(g2)) and g2.value:
                    out += sub.raw[:g2.value]
                else:
                    break
            return bytes(out)
        return buf.raw[:got.value]


class RegionDumpSource(MemorySource):
    """Оффлайн-чтение выгруженных регионов.

    Каталог должен содержать файлы вида  <hexaddr>_<hexsize>.bin
    (именно так их кладёт экспорт регионов из x64dbg). Позволяет работать с
    полным дампом процесса 1.13.1 без запущенного клиента.
    """

    def __init__(self, directory):
        MemorySource.__init__(self)
        self.regions = []
        for fn in sorted(os.listdir(directory)):
            m = re.match(r"^([0-9A-Fa-f]+)_([0-9A-Fa-f]+)\.bin$", fn)
            if not m:
                continue
            base = int(m.group(1), 16)
            path = os.path.join(directory, fn)
            self.regions.append((base, base + os.path.getsize(path), path))
        if not self.regions:
            raise MemoryError_("в %s нет файлов вида <hexaddr>_<hexsize>.bin" % directory)
        self.module_base = None
        self.module_size = None

    def _read_raw(self, addr, size):
        for base, end, path in self.regions:
            if base <= addr < end:
                with open(path, "rb") as f:
                    f.seek(addr - base)
                    return f.read(min(size, end - addr))
        return b""


# ---------------------------------------------------------------------------
# FName
# ---------------------------------------------------------------------------

class NameTable(object):
    def __init__(self, mem, gnames_addr, wide=True, number_mode="mem"):
        self.mem = mem
        self.addr = gnames_addr
        self.wide = wide
        self.number_mode = number_mode
        self.data = mem.ptr(gnames_addr + 0x00)
        self.num = mem.i32(gnames_addr + 0x04)
        self.max = mem.i32(gnames_addr + 0x08)
        self._cache = {}

    def entry_addr(self, idx):
        return self.mem.ptr(self.data + 4 * idx)

    def raw(self, idx):
        if idx in self._cache:
            return self._cache[idx]
        if idx < 0 or idx >= self.num:
            return "<bad:%d>" % idx
        try:
            e = self.entry_addr(idx)
            if not e:
                return "<null:%d>" % idx
            p = e + L["FNameEntry.Name"]
            chunk = self.mem.read(p, 512)
            if self.wide:
                s = chunk.decode("utf-16-le", "replace")
            else:
                s = chunk.decode("latin-1", "replace")
            s = s.split("\x00")[0]
        except MemoryError_:
            s = "<unreadable:%d>" % idx
        self._cache[idx] = s
        return s

    def fmt(self, idx, number):
        """Режимы:
        mem   -- В ПАМЯТИ UE3: Number 0 (или -1) = суффикса нет, иначе _Number.
                 Это значение по умолчанию.
        uelib -- правило файлового формата: -1 = нет суффикса, 0 = валидный _0.
                 На память НЕ переносится (проверено: даёт Class_0 вместо Class).
        ue4   -- отображаемый суффикс = Number - 1.
        """
        base = self.raw(idx)
        if number in (-1, 0xFFFFFFFF):
            return base
        if self.number_mode == "uelib":
            return "%s_%d" % (base, number)
        if self.number_mode == "ue4":
            return base if number <= 0 else "%s_%d" % (base, number - 1)
        return base if number <= 0 else "%s_%d" % (base, number)


# ---------------------------------------------------------------------------
# Граф объектов
# ---------------------------------------------------------------------------

class Reflection(object):
    def __init__(self, mem, gobjects_addr, names):
        self.mem = mem
        self.names = names
        self.addr = gobjects_addr
        self.data = mem.ptr(gobjects_addr + 0x00)
        self.num = mem.i32(gobjects_addr + 0x04)
        self._name = {}
        self._cls = {}

    # --- базовые чтения ----------------------------------------------------
    def slot(self, i):
        return self.mem.ptr(self.data + 4 * i)

    def obj_name(self, o):
        if o in self._name:
            return self._name[o]
        try:
            idx = self.mem.i32(o + L["UObject.NameIndex"])
            num = self.mem.i32(o + L["UObject.NameNumber"])
            s = self.names.fmt(idx, num)
        except MemoryError_:
            s = "<unreadable>"
        self._name[o] = s
        return s

    def obj_class(self, o):
        try:
            return self.mem.ptr(o + L["UObject.Class"])
        except MemoryError_:
            return 0

    def class_name(self, o):
        c = self.obj_class(o)
        return self.obj_name(c) if c else "<none>"

    def outer(self, o):
        return self.mem.ptr(o + L["UObject.Outer"])

    def full_path(self, o):
        parts = []
        cur = o
        seen = 0
        while cur and seen < 16:
            parts.append(self.obj_name(cur))
            cur = self.outer(cur)
            seen += 1
        return ".".join(reversed(parts))

    def package_of(self, o):
        cur = o
        last = o
        seen = 0
        while cur and seen < 16:
            last = cur
            cur = self.outer(cur)
            seen += 1
        return self.obj_name(last)

    def cast_flags(self, cls_obj):
        try:
            return self.mem.u32(cls_obj + L["UClass.ClassCastFlags"])
        except MemoryError_:
            return 0

    def is_a(self, obj, castflag):
        """Проверка через ClassCastFlags класса объекта -- дёшево и надёжно."""
        c = self.obj_class(obj)
        return bool(c) and bool(self.cast_flags(c) & castflag)

    def children(self, struct_obj):
        """Связный список UField, в порядке объявления (Children -> Next)."""
        out = []
        cur = self.mem.ptr(struct_obj + L["UStruct.Children"])
        guard = 0
        while cur and guard < 4096:
            out.append(cur)
            try:
                cur = self.mem.ptr(cur + L["UField.Next"])
            except MemoryError_:
                break
            guard += 1
        return out

    def super_field(self, o):
        return self.mem.ptr(o + L["UField.SuperField"])

    def netfields(self, cls_obj):
        """TArray<UField*> UClass::NetFields -- порядок репликации."""
        try:
            data = self.mem.ptr(cls_obj + L["UClass.NetFields"])
            num = self.mem.i32(cls_obj + L["UClass.NetFields"] + 4)
        except MemoryError_:
            return []
        if num <= 0 or num > 4096 or not data:
            return []
        out = []
        for i in range(num):
            try:
                out.append(self.mem.ptr(data + 4 * i))
            except MemoryError_:
                break
        return out

    # --- bootstrap: найти UClass "Class" по инварианту o->Class == o -------
    def find_class_class(self, limit=20000):
        for i, o in self.iter_objects():
            if i > limit:
                break
            try:
                if self.mem.ptr(o + L["UObject.Class"]) == o:
                    return o
            except MemoryError_:
                continue
        return 0

    def is_class(self, o, class_class):
        """Не зависит от имён: объект есть UClass, если его Class == ClassClass."""
        return self.obj_class(o) == class_class

    # --- перечисление ------------------------------------------------------
    def iter_objects(self, progress=False):
        for i in range(self.num):
            try:
                o = self.slot(i)
            except MemoryError_:
                continue
            if not o:
                continue
            if progress and i % 50000 == 0:
                sys.stderr.write("  ... slot %d/%d\n" % (i, self.num))
            yield i, o

    def find_class_objects(self, progress=False, class_class=None):
        """Все UClass. Определяется инвариантом Class == ClassClass, не именем."""
        if class_class is None:
            class_class = self.find_class_class()
        res = []
        for i, o in self.iter_objects(progress):
            if self.obj_class(o) == class_class:
                res.append(o)
        return res


# ---------------------------------------------------------------------------
# Разбор свойств
# ---------------------------------------------------------------------------

PRIMITIVES = {
    "IntProperty": "int",
    "FloatProperty": "float",
    "BoolProperty": "bool",
    "NameProperty": "name",
    "StrProperty": "string",
    "StringRefProperty": "stringref",
    "PointerProperty": "pointer",
}


def prop_type(rf, p):
    """Строковый тип свойства. Ссылочные поля читаются из +0x88.

    Подтверждено: ObjectProperty.PropertyClass, StructProperty.Struct.
    Остальное помечено как гипотеза и проверяется инвариантом на месте.
    """
    kind = rf.class_name(p)
    if kind in PRIMITIVES:
        return PRIMITIVES[kind], None
    ref = rf.mem.try_u32(p + L["UProperty.Inner"], 0)
    if kind == "ByteProperty":
        if ref and rf.class_name(ref) == "Enum":
            return rf.obj_name(ref), None
        return "byte", None
    if kind in ("ObjectProperty", "ComponentProperty", "InterfaceProperty"):
        return (rf.obj_name(ref) if ref else "Object"), None
    if kind == "ClassProperty":
        return ("class<%s>" % rf.obj_name(ref)) if ref else "class", None
    if kind == "StructProperty":
        return (rf.obj_name(ref) if ref else "struct"), None
    if kind == "DelegateProperty":
        return ("delegate<%s>" % rf.obj_name(ref)) if ref else "delegate", None
    if kind == "ArrayProperty":
        # инвариант: Inner обязан быть UProperty
        if ref and rf.is_a(ref, CASTCLASS_UProperty):
            t, _ = prop_type(rf, ref)
            return "array<%s>" % t, None
        return "array<?>", "ArrayProperty.Inner не UProperty -- offset 0x88 под вопросом"
    if kind == "MapProperty":
        return "map", None
    return kind, None


def read_property(rf, p):
    m = rf.mem
    t, warn = prop_type(rf, p)
    return {
        "kind": "prop",
        "name": rf.obj_name(p),
        "cls": rf.class_name(p),
        "type": t,
        "offset": m.try_u32(p + L["UProperty.Offset"], 0),
        "array_dim": m.try_u32(p + L["UProperty.ArrayDim"], 1),
        "elem_size": m.try_u32(p + L["UProperty.ElementSize"], 0),
        "flags": m.u64(p + L["UProperty.PropertyFlags"]),
        "rep_index": m.u16(p + L["UProperty.RepIndex"]),
        "net_index": m.try_u32(p + L["UObject.NetIndex"], -1),
        "addr": p,
        "warn": warn,
    }


def parm_size_of(parms):
    """ParmsSize = max(Offset + ElementSize*ArrayDim) по параметрам."""
    if not parms:
        return 0
    return max(x["offset"] + x["elem_size"] * max(1, x["array_dim"]) for x in parms)


# ---------------------------------------------------------------------------
# Probe раскладки UFunction
# ---------------------------------------------------------------------------

def collect_function_samples(rf, limit=400, progress=True, need_parms=True):
    """Функции + вычисленная из Children истина: NumParms и ParmsSize.

    Набираем именно функции с параметрами: без них NumParms/ParmsSize равны
    нулю и не различают offsets.
    """
    samples = []
    scanned = 0
    for i, o in rf.iter_objects(progress=False):
        if rf.class_name(o) != "Function":
            continue
        scanned += 1
        parms = []
        for ch in rf.children(o):
            if not rf.is_a(ch, CASTCLASS_UProperty):
                continue
            pr = read_property(rf, ch)
            if pr["flags"] & CPF_PARM:
                parms.append(pr)
        if need_parms and not parms:
            continue
        samples.append({
            "addr": o,
            "name": rf.obj_name(o),
            "name_index": rf.mem.i32(o + L["UObject.NameIndex"]),
            "num_parms": len(parms),
            "parms_size": parm_size_of(parms),
        })
        if len(samples) >= limit:
            break
    if progress:
        sys.stderr.write("  просмотрено функций: %d, взято образцов: %d\n"
                         % (scanned, len(samples)))
    return samples


def collect_function_addrs(rf, progress=True):
    """Адреса всех UFunction. Дёшево: только Class каждого объекта."""
    out = []
    for i, o in rf.iter_objects(progress=False):
        if rf.class_name(o) == "Function":
            out.append(o)
    if progress:
        sys.stderr.write("  всего функций в памяти: %d\n" % len(out))
    return out


def build_samples(rf, addrs):
    """Для каждой функции считаем истину из подтверждённых Children."""
    samples = []
    for o in addrs:
        parms, locs = [], []
        for ch in rf.children(o):
            if not rf.is_a(ch, CASTCLASS_UProperty):
                continue
            pr = read_property(rf, ch)
            (parms if pr["flags"] & CPF_PARM else locs).append(pr)
        try:
            ni = rf.mem.i32(o + L["UObject.NameIndex"])
        except MemoryError_:
            continue
        samples.append({
            "addr": o,
            "name": rf.obj_name(o),
            "name_index": ni,
            "num_parms": len(parms),
            "num_locals": len(locs),
            "parms_size": parm_size_of(parms),
            "props_size": parm_size_of(parms + locs),
        })
    return samples


def spread(seq, n):
    """Равномерная выборка по всей таблице -- иначе берутся только Core."""
    if len(seq) <= n:
        return list(seq)
    step = len(seq) / float(n)
    return [seq[int(i * step)] for i in range(n)]


def scan_exact(mem, samples, reader, truth, lo, hi, step=1):
    """Offsets, где значение точно равно вычисленной истине на ВСЕХ образцах."""
    hits = []
    for off in range(lo, hi, step):
        ok = True
        for s in samples:
            try:
                if reader(s["addr"] + off) != truth(s):
                    ok = False
                    break
            except MemoryError_:
                ok = False
                break
        if ok:
            hits.append(off)
    return hits


def probe_func_ptr(mem, samples, lo, hi, text_lo, text_hi):
    """Func: указатель в .text у всех, но не одно и то же значение у всех.

    Отбрасываем поля-константы (один адрес на всю выборку) и требуем, чтобы
    у части образцов значение отличалось от модального.
    """
    hits = []
    for off in range(lo, hi, 4):
        ok = True
        vals = {}
        for s in samples:
            try:
                v = mem.u32(s["addr"] + off)
            except MemoryError_:
                ok = False
                break
            if v == 0:
                continue
            if not (text_lo <= v < text_hi):
                ok = False
                break
            vals[v] = vals.get(v, 0) + 1
        if not ok or not vals:
            continue
        top = max(vals.values())
        distinct = len(vals)
        if distinct > 1 and top >= 2:
            hits.append((off, distinct, top))
    return hits


def modal_func_ptr(mem, samples, func_off):
    """Самое частое значение Func = UObject::ProcessInternal.

    UE3 не оставляет Func нулевым у скриптовых функций: туда кладётся общий
    интерпретатор. Поэтому нативность определяется отличием от этого значения,
    а не отличием от нуля.
    """
    counts = {}
    for s in samples:
        try:
            v = mem.u32(s["addr"] + func_off)
        except MemoryError_:
            continue
        counts[v] = counts.get(v, 0) + 1
    if not counts:
        return 0, 0
    best = max(counts.items(), key=lambda kv: kv[1])
    return best[0], best[1]


def func_ptr_histogram(mem, samples, func_off, top=8):
    """Самые частые значения Func.

    Одной ProcessInternal может быть мало: у UE3 есть и другие общие точки
    входа (делегаты, неразрешённые нативы). Все они дают ложную нативность.
    """
    counts = {}
    for smp in samples:
        try:
            v = mem.u32(smp["addr"] + func_off)
        except MemoryError_:
            continue
        counts[v] = counts.get(v, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])[:top]


def check_flags_refined(mem, samples, flags_off, func_off, process_internal):
    """Уточнённый инвариант.

    Нативный биндинг ожидается, когда стоят ОБА бита: FUNC_Native и
    FUNC_Defined. Функция, объявленная native без FUNC_Defined, нативной
    реализации в этом бинарнике не имеет -- у неё Func остаётся
    ProcessInternal. Проверено на выборке: все расхождения строгого критерия
    были именно такими.
    """
    agree = total = 0
    unbound = []
    for smp in samples:
        try:
            fl = mem.u32(smp["addr"] + flags_off)
            fp = mem.u32(smp["addr"] + func_off)
        except MemoryError_:
            continue
        total += 1
        has_binding = fp not in (0, process_internal)
        expect = bool(fl & FUNC_NATIVE) and bool(fl & FUNC_DEFINED)
        if expect == has_binding:
            agree += 1
        if (fl & FUNC_NATIVE) and not (fl & FUNC_DEFINED):
            unbound.append(smp["name"])
    return agree, total, unbound


def probe_flags(mem, samples, func_off, lo, hi, process_internal):
    """FunctionFlags: ищем offset, где FUNC_Native лучше всего совпадает
    с (Func != ProcessInternal).

    Требовать 100% нельзя: часть функций объявлена native, но нативный
    биндинг им не проставлен. Поэтому ранжируем по доле согласия и отдельно
    показываем расхождения -- их состав сам по себе информативен.
    """
    out = []
    for off in range(lo, hi, 4):
        agree = nat = scr = 0
        total = 0
        bad = []
        broken = False
        for s_ in samples:
            try:
                v = mem.u32(s_["addr"] + off)
                fp = mem.u32(s_["addr"] + func_off)
            except MemoryError_:
                broken = True
                break
            if v == 0:
                continue
            total += 1
            is_native = fp not in (0, process_internal)
            if is_native:
                nat += 1
            else:
                scr += 1
            if bool(v & FUNC_NATIVE) == is_native:
                agree += 1
            elif len(bad) < 8:
                bad.append((s_["name"], v, fp))
        if broken or total < len(samples) * 0.5 or not (nat and scr):
            continue
        out.append((off, agree, total, nat, scr, bad))
    out.sort(key=lambda x: -(x[1] / float(x[2])))
    return out[:5]


def probe_ranked(mem, samples, reader, truth, lo, hi, step=4, floor=0.5):
    """Ранжирование по доле совпадений -- для полей вроде FriendlyName."""
    out = []
    for off in range(lo, hi, step):
        ok = 0
        for s in samples:
            try:
                if reader(s["addr"] + off) == truth(s):
                    ok += 1
            except MemoryError_:
                ok = 0
                break
        if ok >= floor * len(samples):
            out.append((off, ok))
    out.sort(key=lambda x: -x[1])
    return out[:5]


def dump_raw_functions(rf, mem, samples, lo, hi, count=4):
    """Сырые байты для глазной проверки раскладки."""
    for s in samples[:count]:
        print("\n%s  addr=0x%08X  parms=%d locals=%d parms_size=%d props_size=%d"
              % (s["name"], s["addr"], s["num_parms"], s["num_locals"],
                 s["parms_size"], s["props_size"]))
        for off in range(lo, hi, 16):
            try:
                b = mem.read(s["addr"] + off, 16)
            except MemoryError_:
                break
            print("  +0x%03X  %s" % (off, " ".join("%02X" % c for c in bytearray(b))))


def probe_ufunction(rf, mem, samples, lo=0x48, hi=0x160,

                    text_lo=None, text_hi=None):
    """Ищем offsets UFunction, опираясь только на подтверждённые данные."""
    res = {}

    def scan(reader, predicate, step=1, width=4):
        hits = []
        for off in range(lo, hi, step):
            ok = 0
            for s in samples:
                try:
                    v = reader(s["addr"] + off)
                except MemoryError_:
                    break
                if predicate(v, s):
                    ok += 1
            if ok == len(samples):
                hits.append(off)
        return hits

    # NumParms: байт, точно равный числу параметров
    res["NumParms"] = scan(mem.u8, lambda v, s: v == s["num_parms"])

    # ParmsSize: u16, точно равный вычисленному
    res["ParmsSize"] = scan(mem.u16, lambda v, s: v == s["parms_size"], step=2)

    # FriendlyName: FName.Index, у большинства совпадает с Name.Index
    fr = []
    for off in range(lo, hi, 4):
        ok = 0
        for s in samples:
            try:
                v = mem.i32(s["addr"] + off)
            except MemoryError_:
                ok = -1
                break
            if v == s["name_index"]:
                ok += 1
        if ok > 0 and ok >= int(len(samples) * 0.9):
            fr.append((off, ok))
    res["FriendlyName"] = fr

    # FunctionFlags: FUNC_Defined выставлен у всех, старшие биты пустые
    ff = []
    for off in range(lo, hi, 4):
        ok = 0
        seen_net = 0
        for s in samples:
            try:
                v = mem.u32(s["addr"] + off)
            except MemoryError_:
                ok = -1
                break
            if (v & FUNC_DEFINED) and (v & 0xFC000000) == 0 and v != 0:
                ok += 1
                if v & 0x00200000:
                    seen_net += 1
        if ok == len(samples):
            ff.append((off, seen_net))
    res["FunctionFlags"] = ff

    # Func: либо 0, либо указатель в .text модуля
    if text_lo and text_hi:
        fn = []
        for off in range(lo, hi, 4):
            ok = 0
            nonzero = 0
            for s in samples:
                try:
                    v = mem.u32(s["addr"] + off)
                except MemoryError_:
                    ok = -1
                    break
                if v == 0 or (text_lo <= v < text_hi):
                    ok += 1
                    if v:
                        nonzero += 1
            if ok == len(samples) and nonzero > 0:
                fn.append((off, nonzero))
        res["Func"] = fn
    else:
        res["Func"] = []

    return res


def cross_check_native(rf, mem, samples, flags_off, func_off):
    """Замкнутый инвариант: FUNC_Native выставлен ровно тогда, когда Func != 0."""
    agree = 0
    total = 0
    for s in samples:
        try:
            fl = mem.u32(s["addr"] + flags_off)
            fp = mem.u32(s["addr"] + func_off)
        except MemoryError_:
            continue
        total += 1
        if bool(fl & FUNC_NATIVE) == bool(fp):
            agree += 1
    return agree, total


# ---------------------------------------------------------------------------
# Полный дамп
# ---------------------------------------------------------------------------

def dump_struct(rf, s, want_functions=True):
    """Разбор UStruct (класс / ScriptStruct / Function) в словарь."""
    m = rf.mem
    props = []
    funcs = []
    for ch in rf.children(s):
        cname = rf.class_name(ch)
        if cname == "Function":
            if not want_functions:
                continue
            funcs.append(dump_function(rf, ch))
        elif cname in ("ScriptStruct", "Struct", "Enum", "Const", "State"):
            continue
        elif rf.is_a(ch, CASTCLASS_UProperty):
            props.append(read_property(rf, ch))
    return props, funcs


def dump_function(rf, f):
    m = rf.mem
    parms = []
    locals_ = []
    for ch in rf.children(f):
        if not rf.is_a(ch, CASTCLASS_UProperty):
            continue
        pr = read_property(rf, ch)
        (parms if pr["flags"] & CPF_PARM else locals_).append(pr)
    rec = {
        "kind": "func",
        "name": rf.obj_name(f),
        "addr": f,
        "net_index": m.try_u32(f + L["UObject.NetIndex"], -1),
        "parms": parms,
        "locals": locals_,
        "num_parms_calc": len(parms),
        "parms_size_calc": parm_size_of(parms),
    }
    if L["UFunction.FunctionFlags"] is not None:
        rec["flags"] = m.try_u32(f + L["UFunction.FunctionFlags"], 0)
    if L["UFunction.Func"] is not None:
        rec["func_ptr"] = m.try_u32(f + L["UFunction.Func"], 0)
    if L["UFunction.iNative"] is not None:
        rec["i_native"] = m.u16(f + L["UFunction.iNative"])
    if L["UFunction.NumParms"] is not None:
        rec["num_parms"] = m.u8(f + L["UFunction.NumParms"])
    if L["UFunction.ParmsSize"] is not None:
        rec["parms_size"] = m.u16(f + L["UFunction.ParmsSize"])
    if L.get("UFunction.RepOffset") is not None:
        rec["rep_offset"] = m.u16(f + L["UFunction.RepOffset"])
    if L.get("UFunction.ReturnValueOffset") is not None:
        rv = m.u16(f + L["UFunction.ReturnValueOffset"])
        rec["return_value_offset"] = None if rv == 0xFFFF else rv
    if L.get("UFunction.FriendlyName") is not None:
        rec["friendly_name"] = rf.names.fmt(
            m.i32(f + L["UFunction.FriendlyName"]),
            m.i32(f + L["UFunction.FriendlyName"] + 4))
    fl = rec.get("flags", 0)
    rec["declared_native_unbound"] = bool(
        (fl & FUNC_NATIVE) and not (fl & FUNC_DEFINED))
    rec["script_size"] = m.try_u32(f + L["UStruct.Script"] + 4, 0)
    rec["properties_size"] = m.try_u32(f + L["UStruct.PropertiesSize"], 0)
    return rec


def dump_all(rf, package=None, progress=True):
    m = rf.mem
    out = {"classes": [], "structs": [], "enums": []}
    if progress:
        sys.stderr.write("Перечисление объектов (%d слотов)...\n" % rf.num)

    classes = []
    structs = []
    enums = []
    for i, o in rf.iter_objects(progress=progress):
        cn = rf.class_name(o)
        if cn == "Class":
            classes.append(o)
        elif cn == "ScriptStruct":
            structs.append(o)
        elif cn == "Enum":
            enums.append(o)

    if progress:
        sys.stderr.write("Классов %d, структур %d, enum %d\n"
                         % (len(classes), len(structs), len(enums)))

    def keep(o):
        return package is None or rf.package_of(o) == package

    for c in classes:
        if not keep(c):
            continue
        props, funcs = dump_struct(rf, c)
        nf = []
        for fld in rf.netfields(c):
            nf.append({"name": rf.obj_name(fld), "cls": rf.class_name(fld),
                       "addr": fld})
        sup = rf.super_field(c)
        out["classes"].append({
            "name": rf.obj_name(c),
            "path": rf.full_path(c),
            "package": rf.package_of(c),
            "super": rf.obj_name(sup) if sup else None,
            "addr": c,
            "net_index": m.try_u32(c + L["UObject.NetIndex"], -1),
            "cast_flags": rf.cast_flags(c),
            "properties_size": m.try_u32(c + L["UStruct.PropertiesSize"], 0),
            "cdo": m.try_u32(c + L["UClass.ClassDefaultObject"], 0),
            "props": props,
            "funcs": funcs,
            "netfields": nf,
        })

    for s in structs:
        if not keep(s):
            continue
        props, _ = dump_struct(rf, s, want_functions=False)
        sup = rf.super_field(s)
        out["structs"].append({
            "name": rf.obj_name(s),
            "path": rf.full_path(s),
            "package": rf.package_of(s),
            "super": rf.obj_name(sup) if sup else None,
            "addr": s,
            "net_index": m.try_u32(s + L["UObject.NetIndex"], -1),
            "properties_size": m.try_u32(s + L["UStruct.PropertiesSize"], 0),
            "props": props,
        })

    for e in enums:
        if not keep(e):
            continue
        # UEnum : UField { TArray<FName> Names; }  -- сразу после UField
        names = []
        for off in (0x48,):
            try:
                data = m.ptr(e + off)
                num = m.i32(e + off + 4)
            except MemoryError_:
                continue
            if 0 < num < 1024 and data:
                for k in range(num):
                    try:
                        ni = m.i32(data + 8 * k)
                        nn = m.i32(data + 8 * k + 4)
                        names.append(rf.names.fmt(ni, nn))
                    except MemoryError_:
                        break
                break
        out["enums"].append({
            "name": rf.obj_name(e),
            "path": rf.full_path(e),
            "package": rf.package_of(e),
            "addr": e,
            "net_index": m.try_u32(e + L["UObject.NetIndex"], -1),
            "names": names,
        })

    return out


# ---------------------------------------------------------------------------
# Выводы: канонический flat и .uc
# ---------------------------------------------------------------------------

def sig_of(f):
    parts = []
    ret = "void"
    for p in f["parms"]:
        if p["flags"] & CPF_RETURN:
            ret = p["type"]
            continue
        mods = []
        if p["flags"] & CPF_OUT:
            mods.append("out")
        if p["flags"] & CPF_OPT:
            mods.append("optional")
        if p["flags"] & CPF_COERCE:
            mods.append("coerce")
        dim = "[%d]" % p["array_dim"] if p["array_dim"] > 1 else ""
        parts.append(("%s %s %s%s" % (" ".join(mods), p["type"], p["name"], dim)).strip())
    return ret, ", ".join(parts)


def write_flat(data, path):
    """Канонический построчный формат для diff против экспорта из UELib."""
    lines = []
    for c in sorted(data["classes"], key=lambda x: x["name"]):
        lines.append("class %s super=%s pkg=%s psize=%d"
                     % (c["name"], c["super"], c["package"], c["properties_size"]))
        for p in c["props"]:
            lines.append("  prop %s.%s type=%s dim=%d size=%d off=0x%X flags=%s"
                         % (c["name"], p["name"], p["type"], p["array_dim"],
                            p["elem_size"], p["offset"], flagstr(p["flags"], CPF)))
        for f in c["funcs"]:
            ret, args = sig_of(f)
            fl = flagstr(f.get("flags", 0), FUNC)
            lines.append("  func %s.%s(%s) : %s flags=%s script=%d"
                         % (c["name"], f["name"], args, ret, fl,
                            f.get("script_size", 0)))
        for n, fld in enumerate(c["netfields"]):
            lines.append("  netfield %s %d %s" % (c["name"], n, fld["name"]))
    for s in sorted(data["structs"], key=lambda x: x["name"]):
        lines.append("struct %s super=%s pkg=%s psize=%d"
                     % (s["name"], s["super"], s["package"], s["properties_size"]))
        for p in s["props"]:
            lines.append("  member %s.%s type=%s dim=%d size=%d off=0x%X"
                         % (s["name"], p["name"], p["type"], p["array_dim"],
                            p["elem_size"], p["offset"]))
    for e in sorted(data["enums"], key=lambda x: x["name"]):
        lines.append("enum %s pkg=%s count=%d" % (e["name"], e["package"], len(e["names"])))
        for n, nm in enumerate(e["names"]):
            lines.append("  value %s %d %s" % (e["name"], n, nm))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


def write_uc(data, outdir):
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    for c in data["classes"]:
        lines = ["class %s extends %s;" % (c["name"], c["super"] or "Object"), ""]
        for p in c["props"]:
            dim = "[%d]" % p["array_dim"] if p["array_dim"] > 1 else ""
            mods = []
            if p["flags"] & 0x20:
                mods.append("repnotify" if p["flags"] & 0x200000000 else "")
            lines.append("var %s %s%s;   // off=0x%X size=%d flags=%s"
                         % (p["type"], p["name"], dim, p["offset"],
                            p["elem_size"], flagstr(p["flags"], CPF)))
        lines.append("")
        for f in c["funcs"]:
            ret, args = sig_of(f)
            fl = f.get("flags", 0)
            kw = []
            if fl & 0x2000:
                kw.append("static")
            if fl & 0x1:
                kw.append("final")
            if fl & 0x100:
                kw.append("simulated")
            if fl & 0x400:
                kw.append("native")
            if fl & 0x40:
                kw.append("reliable" if fl & 0x80 else "unreliable")
                kw.append("server" if fl & 0x200000 else ("client" if fl & 0x1000000 else ""))
            head = " ".join(x for x in kw if x)
            word = "event" if fl & 0x800 else "function"
            lines.append("%s %s %s %s(%s);   // %s"
                         % (head, word, ret if ret != "void" else "",
                            f["name"], args,
                            ("0x%08X" % f.get("func_ptr", 0)) if f.get("func_ptr") else "script"))
        with open(os.path.join(outdir, c["name"] + ".uc"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def write_unbound(data, path):
    """Функции, объявленные native, но без реализации в клиентском бинарнике.

    Для эмулятора это перечень серверной логики: клиент её знает по сигнатуре,
    но исполнить не может.
    """
    rows = []
    for c in data["classes"]:
        for f in c["funcs"]:
            if f.get("declared_native_unbound"):
                ret, args = sig_of(f)
                rows.append("%s.%s(%s) : %s flags=%s"
                            % (c["name"], f["name"], args, ret,
                               flagstr(f.get("flags", 0), FUNC)))
    rows.sort()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rows) + "\n")
    return len(rows)


def write_ghidra_names(data, path, module_base=None, ghidra_base=0x10900000,
                       process_internal=None):
    """Имена нативных функций по UFunction::Func.

    Скриптовые функции указывают на общий UObject::ProcessInternal -- их надо
    отбросить, иначе тысячи разных имён лягут на один адрес.
    """
    if process_internal is None:
        counts = {}
        for c in data["classes"]:
            for f in c["funcs"]:
                fp = f.get("func_ptr", 0)
                if fp:
                    counts[fp] = counts.get(fp, 0) + 1
        process_internal = max(counts, key=counts.get) if counts else 0
    rows = []
    for c in data["classes"]:
        for f in c["funcs"]:
            fp = f.get("func_ptr", 0)
            if not fp or fp == process_internal:
                continue
            if module_base is not None:
                ga = fp - module_base + ghidra_base
            else:
                ga = fp
            rows.append((ga, "%s_%s" % (c["name"], f["name"])))
    rows.sort()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# ghidra: address name\n")
        for a, n in rows:
            fh.write("%08X %s\n" % (a, n))
    return len(rows)


# ---------------------------------------------------------------------------
# offsets.json
# ---------------------------------------------------------------------------

def find_key(obj, key):
    """Терпимый поиск ключа на любой глубине offsets.json."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, (str, int)):
                return v
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None


def as_addr(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    return int(str(v), 16 if str(v).lower().startswith("0x") else 10)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    print(VERSION)

    ap = argparse.ArgumentParser(description="Дамп UE3-рефлексии из памяти APB")
    ap.add_argument("--exe", default="APB.exe")
    ap.add_argument("--regions", help="каталог с выгруженными регионами (оффлайн)")
    ap.add_argument("--offsets", default="offsets.json")
    ap.add_argument("--gobjects", help="адрес GObjObjects (hex)")
    ap.add_argument("--gnames", help="адрес GNames (hex)")
    ap.add_argument("--ghidra-base", default="0x10900000")
    ap.add_argument("--runtime-addrs", action="store_true",
                    help="считать --gobjects/--gnames уже runtime-адресами")
    ap.add_argument("--ansi-names", action="store_true", help="FNameEntry в ANSI, не wide")
    ap.add_argument("--name-number-mode", default="mem", choices=("mem", "uelib", "ue4"),
                    help="как FName.Number превращается в суффикс (по умолчанию mem)")

    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--probe-ufunction", action="store_true")
    ap.add_argument("--samples", type=int, default=300)
    ap.add_argument("--probe-lo", default="0x48")
    ap.add_argument("--probe-hi", default="0x160")
    ap.add_argument("--raw", action="store_true",
                    help="печатать сырые байты нескольких UFunction")
    ap.add_argument("--learn", action="store_true", help="записать найденные offsets в offsets.json")

    ap.add_argument("--dump", help="выходной JSON")
    ap.add_argument("--flat", help="канонический текст для diff")
    ap.add_argument("--uc", help="каталог для .uc-подобного вывода")
    ap.add_argument("--ghidra-names", help="файл 'адрес имя' для переименования в Ghidra")
    ap.add_argument("--unbound", help="отчёт: native-объявления без реализации")
    ap.add_argument("--package", help="фильтр по пакету, например APBGame")
    args = ap.parse_args()

    if struct.calcsize("P") * 8 != 32:
        print("(!) Python %d-бит; для 32-битного клиента это обычно работает, "
              "но остальные скрипты проекта требуют 32-бит"
              % (struct.calcsize("P") * 8))

    cfg = {}
    if os.path.isfile(args.offsets):
        try:
            with open(args.offsets, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except UnicodeDecodeError:
            with open(args.offsets, "r", encoding="utf-8-sig", errors="replace") as f:
                cfg = json.load(f)
        except ValueError as e:
            print("!! offsets.json не разобран (%s), продолжаю без него" % e)
            cfg = {}

    gobj = as_addr(args.gobjects) or as_addr(find_key(cfg, "GObjObjects"))
    gnam = as_addr(args.gnames) or as_addr(find_key(cfg, "GNames"))
    if not gobj or not gnam:
        print("!! нужны адреса GObjObjects и GNames "
              "(--gobjects/--gnames или ключи в offsets.json)")
        return 2

    # источник памяти
    if args.regions:
        mem = RegionDumpSource(args.regions)
        mod_base = None
    else:
        mem = LiveProcess(args.exe)
        mod_base = mem.module_base
        print("процесс pid=%d module=0x%08X size=0x%X"
              % (mem.pid, mem.module_base or 0, mem.module_size or 0))

    gbase = as_addr(args.ghidra_base)
    if not args.runtime_addrs and mod_base:
        gobj_rt = gobj - gbase + mod_base
        gnam_rt = gnam - gbase + mod_base
    else:
        gobj_rt, gnam_rt = gobj, gnam
    print("GObjObjects=0x%08X  GNames=0x%08X" % (gobj_rt, gnam_rt))

    names = NameTable(mem, gnam_rt, wide=not args.ansi_names,
                      number_mode=args.name_number_mode)
    rf = Reflection(mem, gobj_rt, names)

    # ---------------- selftest ----------------
    if args.selftest:
        print("\n== selftest ==")
        print("GNames.Num = %d, GObjObjects.Num = %d" % (names.num, rf.num))
        print("name[0] = %r  (ожидается 'None')" % names.raw(0))
        bad = 0
        checked = 0
        for i, o in rf.iter_objects():
            if checked >= 20000:
                break
            checked += 1
            try:
                if mem.i32(o + L["UObject.Index"]) != i:
                    bad += 1
            except MemoryError_:
                bad += 1
        print("Index==slot: проверено %d, расхождений %d" % (checked, bad))
        cc = rf.find_class_class()
        print("ClassClass (o->Class == o): 0x%08X name=%r  (ожидается 'Class')"
              % (cc, rf.obj_name(cc) if cc else 0))
        if cc and rf.obj_name(cc) != "Class":
            print("   !! имя не 'Class' -> неверен --name-number-mode или ширина FNameEntry")

        # распределение FName.Number: показывает, какое правило суффикса верно
        dist = {}
        shown = 0
        for i, o in rf.iter_objects():
            if i > 5000:
                break
            try:
                num = mem.i32(o + L["UObject.NameNumber"])
            except MemoryError_:
                continue
            dist[num] = dist.get(num, 0) + 1
        top = sorted(dist.items(), key=lambda kv: -kv[1])[:6]
        print("FName.Number на 5000 объектах: %s"
              % ", ".join("%d:%d" % (k, v) for k, v in top))

        kinds = {}
        objs = 0
        for i, o in rf.iter_objects():
            objs += 1
            kinds[rf.class_name(o)] = kinds.get(rf.class_name(o), 0) + 1
        for k in ("Class", "Function", "ScriptStruct", "Enum", "State"):
            print("  объектов класса %-13s : %d" % (k, kinds.get(k, 0)))

        for i, o in rf.iter_objects():
            if rf.obj_class(o) == cc and rf.obj_name(o) == "Object":
                print("UClass Object: super=%r (ожидается 0), path=%s"
                      % (rf.super_field(o), rf.full_path(o)))
                break
        print("== selftest готов ==\n")

    # ---------------- probe UFunction ----------------
    if args.probe_ufunction:
        print("\n== probe UFunction ==")
        addrs = collect_function_addrs(rf)
        picked = spread(addrs, args.samples * 3)
        allsamples = build_samples(rf, picked)
        withparms = [x for x in allsamples if x["num_parms"] > 0]
        withlocals = [x for x in allsamples if x["num_locals"] > 0]
        print("выборка: %d функций, из них с параметрами %d, с локальными %d"
              % (len(allsamples), len(withparms), len(withlocals)))
        if len(withparms) < 20:
            print("!! мало образцов с параметрами")
            return 3

        plo, phi = as_addr(args.probe_lo), as_addr(args.probe_hi)

        if args.raw:
            dump_raw_functions(rf, mem, withlocals or withparms, plo, phi)
            print("")

        # --- фаза A: якоря по подтверждённым Children -----------------------
        np_hits = scan_exact(mem, withparms, mem.u8,
                             lambda s: s["num_parms"], plo, phi, 1)
        print("NumParms      : %s" % [hex(x) for x in np_hits])

        ps_hits = scan_exact(mem, withparms, mem.u16,
                             lambda s: s["parms_size"], plo, phi, 2)
        print("ParmsSize     : %s" % [hex(x) for x in ps_hits])

        # разделяем ParmsSize и UStruct::PropertiesSize -- только функции
        # с локальными переменными дают разные значения
        if withlocals:
            ps_strict = scan_exact(mem, withlocals, mem.u16,
                                   lambda s: s["parms_size"], plo, phi, 2)
            prop_hits = scan_exact(mem, withlocals, mem.u16,
                                   lambda s: s["props_size"], plo, phi, 2)
            print("ParmsSize   (только функции с локальными) : %s"
                  % [hex(x) for x in ps_strict])
            print("PropertiesSize (parms+locals)             : %s"
                  % [hex(x) for x in prop_hits])
        else:
            print("(!) нет функций с локальными -- ParmsSize и PropertiesSize "
                  "не различить")

        # --- фаза B: Func и флаги, на смешанной выборке ----------------------
        fn_hits = []
        if mod_base:
            tlo, thi = mod_base, mod_base + (mem.module_size or 0x2800000)
            fn_hits = probe_func_ptr(mem, allsamples, plo, phi, tlo, thi)
            print("Func          : %s"
                  % [(hex(o), "разных=%d самое частое=%d" % (d, t))
                     for o, d, t in fn_hits])
            for fo, _, _ in fn_hits:
                pi, cnt = modal_func_ptr(mem, allsamples, fo)
                gh = pi - mod_base + gbase if pi else 0
                print("  Func=0x%X: самое частое = 0x%08X (ghidra 0x%08X), "
                      "у %d/%d образцов" % (fo, pi, gh, cnt, len(allsamples)))
                print("    гистограмма Func (общие заглушки видны сразу):")
                for hv, hn in func_ptr_histogram(mem, allsamples, fo):
                    print("      0x%08X (ghidra 0x%08X) : %4d %s"
                          % (hv, hv - mod_base + gbase, hn,
                             "<- модальная" if hv == pi else ""))
                fl_hits = probe_flags(mem, allsamples, fo, plo, phi, pi)
                for off, agree, total, nat, scr, bad in fl_hits:
                    print("  FunctionFlags 0x%02X : согласие %d/%d (%.1f%%), "
                          "native=%d script=%d"
                          % (off, agree, total, 100.0 * agree / total, nat, scr))
                    if bad and off == fl_hits[0][0]:
                        print("    расхождения:")
                        for nm, v, fp in bad:
                            print("      %-34s flags=0x%08X func=0x%08X %s"
                                  % (nm, v, fp,
                                     "(native-флаг без биндинга)"
                                     if (v & FUNC_NATIVE) else "(биндинг без флага)"))
                if fl_hits:
                    bo = fl_hits[0][0]
                    a2, t2, unb = check_flags_refined(mem, allsamples, bo, fo, pi)
                    print("    уточнённый инвариант "
                          "(Native AND Defined) <-> биндинг : %d/%d" % (a2, t2))
                    if unb:
                        print("    объявлены native без реализации в клиенте: %d, "
                              "например %s" % (len(unb), ", ".join(unb[:5])))

        fr = probe_ranked(mem, allsamples, mem.i32,
                          lambda s: s["name_index"], plo, phi)
        print("FriendlyName  : %s"
              % [(hex(o), "%d/%d" % (n, len(allsamples))) for o, n in fr])

        if args.learn:
            picked_off = {}
            if len(np_hits) == 1:
                picked_off["UFunction.NumParms"] = np_hits[0]
            if withlocals and len(ps_strict) == 1:
                picked_off["UFunction.ParmsSize"] = ps_strict[0]
            if len(fn_hits) == 1:
                fo = fn_hits[0][0]
                picked_off["UFunction.Func"] = fo
                pi, _ = modal_func_ptr(mem, allsamples, fo)
                cfg["_ProcessInternal_ghidra"] = "0x%08X" % (
                    pi - mod_base + gbase if pi and mod_base else pi)
                fl = probe_flags(mem, allsamples, fo, plo, phi, pi)
                if fl and fl[0][1] >= 0.98 * fl[0][2]:
                    picked_off["UFunction.FunctionFlags"] = fl[0][0]
            if not picked_off:
                print("\n!! однозначных кандидатов нет, offsets.json не тронут")
            else:
                cfg.setdefault("_note_ufunction",
                               "выведено apb_reflect.py --probe-ufunction; "
                               "NumParms/ParmsSize сверены с Children, "
                               "FunctionFlags -- инвариантом FUNC_Native<->Func")
                cfg.setdefault("UFunction", {})
                for k, v in picked_off.items():
                    cfg["UFunction"][k.split(".", 1)[1]] = "0x%X" % v
                    L[k] = v
                with open(args.offsets, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2, ensure_ascii=False)
                print("\nзаписано в %s: %s"
                      % (args.offsets, {k: hex(v) for k, v in picked_off.items()}))
        print("== probe готов ==\n")

    # подхватить ранее выученные offsets
    uf = cfg.get("UFunction") or {}
    for k in ("FunctionFlags", "NumParms", "ParmsSize", "iNative", "Func", "FriendlyName"):
        if k in uf and L["UFunction." + k] is None:
            L["UFunction." + k] = as_addr(uf[k])

    # ---------------- dump ----------------
    if args.dump or args.flat or args.uc or args.ghidra_names or args.unbound:
        if L["UFunction.FunctionFlags"] is None:
            print("!! раскладка UFunction неизвестна -- сначала "
                  "--probe-ufunction --learn (дамп пойдёт без флагов функций)")
        data = dump_all(rf, package=args.package)
        print("собрано: классов %d, структур %d, enum %d"
              % (len(data["classes"]), len(data["structs"]), len(data["enums"])))
        if args.dump:
            with open(args.dump, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1, ensure_ascii=False)
            print("JSON -> %s" % args.dump)
        if args.flat:
            n = write_flat(data, args.flat)
            print("flat -> %s (%d строк)" % (args.flat, n))
        if args.uc:
            write_uc(data, args.uc)
            print("uc   -> %s/" % args.uc)
        if args.ghidra_names:
            n = write_ghidra_names(data, args.ghidra_names, mod_base, gbase)
            print("ghidra names -> %s (%d нативных функций)" % (args.ghidra_names, n))
        if args.unbound:
            n = write_unbound(data, args.unbound)
            print("unbound -> %s (%d объявлений без реализации)" % (args.unbound, n))

    return 0


if __name__ == "__main__":
    sys.exit(main())
