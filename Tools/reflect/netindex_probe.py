# -*- coding: utf-8 -*-
"""
netindex_probe_v22.py -- runtime UE3 reflection/network inspector; определение offset UObject::NetIndex в APB 1.13.1
и снятие локальных NetIndex из живой памяти клиента.

Кладётся рядом с apb_reflect.py (Tools/reflect/). Из apb_reflect берётся
только доступ к памяти; таблица L оттуда НЕ используется -- она унаследована
от сборки 1.1.0.534979 и для 1.13.1 частично неверна.

Подтверждено на 1.13.1:
    UObject +0x20  InternalIndex
    (GObjects[i] = obj; obj->+0x20 = i)

FNameEntry для APB:
    +0x00 uint32 Flags
    +0x10 union {
        char  Name[];
        char* NamePtr;
    }

Если Flags & 0x4000, имя лежит по указателю NamePtr.
Иначе имя лежит inline начиная с +0x10.
Имена ANSI.

Следовательно NetIndex -- один из +0x1C / +0x24 / +0x28.

Инвариант:
в пределах пакета валидные NetIndex попарно различны и лежат в
0..NetObjectCount-1, объекты без сетевого индекса несут -1.

Примеры:

  python netindex_probe.py --expect Core=3 --expect Engine=3 ^
      --expect EngineResources=194 --expect EngineFonts=11

  python netindex_probe.py --netindex-off 0x1C --find cAPBPlayerController
"""

import argparse
import sys
import ctypes
import struct
import json
import csv
import math
from pathlib import Path
from collections import defaultdict

import apb_reflect as R

MemErr = R.MemoryError_

DEFAULT_GNAMES = 0x12538938
DEFAULT_GOBJECTS = 0x1259EF3C

# UObject, APB 1.13.1
UO_INDEX = 0x20
UO_OUTER = 0x2C
UO_NAME_INDEX = 0x30
UO_NAME_NUMBER = 0x34
UO_CLASS = 0x38
UPROPERTY_OFFSET = 0x64  # APB 1.13.1, CONFIRMED

INDEX_CANDIDATES = [0x04, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28]
NET_CANDIDATES = [0x1C, 0x24, 0x28]

# FNameEntry
FNE_FLAGS = 0x00
FNE_NAME = 0x10
FNE_NAMEPTR_FLAG = 0x4000

SANE_MAX_OBJECTS = 5_000_000
SANE_MAX_NAMES = 2_000_000
MAX_NAME_BYTES = 1024


def conv(v):
    return int(str(v), 0)


def sgn32(v):
    return v - 0x100000000 if v >= 0x80000000 else v


# ---------------------------------------------------------------------------
# FNameEntry
# ---------------------------------------------------------------------------

class NameTable(object):
    def __init__(self, mem, addr, number_mode="mem"):
        self.mem = mem
        self.addr = addr
        self.number_mode = number_mode

        self.data = mem.ptr(addr + 0x00)
        self.num = mem.i32(addr + 0x04)
        self.max = mem.i32(addr + 0x08)

        self._cache = {}

        if not (0 < self.num <= self.max <= SANE_MAX_NAMES):
            raise MemErr(
                "GNames невалиден: Data=0x%08X Num=%d Max=%d. "
                "Адрес не тот или нужен/лишний --rebase."
                % (self.data, self.num, self.max)
            )

        # Замкнутая проверка layout.
        first = self.raw(0)
        if first != "None":
            try:
                e = self.entry_addr(0)
                flags = self.mem.u32(e + FNE_FLAGS)

                if flags & FNE_NAMEPTR_FLAG:
                    p = self.mem.ptr(e + FNE_NAME)
                    mode = "ptr"
                else:
                    p = e + FNE_NAME
                    mode = "inline"

                raise MemErr(
                    "FNameEntry layout не прошёл self-test:\n"
                    "  entry=0x%08X flags=0x%08X mode=%s name_addr=0x%08X\n"
                    "  raw[0]=%r, ожидалось 'None'"
                    % (e, flags, mode, p, first)
                )
            except MemErr:
                raise
            except Exception as exc:
                raise MemErr(
                    "FNameEntry self-test failed: raw[0]=%r (%s)"
                    % (first, exc)
                )

    def entry_addr(self, idx):
        if idx < 0 or idx >= self.num:
            raise MemErr("FName index out of range: %d" % idx)

        e = self.mem.ptr(self.data + 4 * idx)
        if not e:
            raise MemErr("GNames[%d] == NULL" % idx)
        return e

    def _read_cstr(self, p):
        if not p:
            return ""

        out = bytearray()

        for i in range(MAX_NAME_BYTES):
            ch = self.mem.read(p + i, 1)
            if ch == b"\x00":
                break
            out += ch

        return bytes(out).decode("latin-1", "replace")

    def raw(self, idx):
        if idx in self._cache:
            return self._cache[idx]

        if idx < 0 or idx >= self.num:
            return "<bad:%d>" % idx

        try:
            e = self.entry_addr(idx)
            flags = self.mem.u32(e + FNE_FLAGS)

            if flags & FNE_NAMEPTR_FLAG:
                p = self.mem.ptr(e + FNE_NAME)
            else:
                p = e + FNE_NAME

            s = self._read_cstr(p)

        except MemErr:
            s = "<unreadable:%d>" % idx

        self._cache[idx] = s
        return s

    def fmt(self, idx, number):
        s = self.raw(idx)

        if number is None or number <= 0:
            return s

        if self.number_mode == "uelib":
            return "%s_%d" % (s, number - 1)

        return "%s_%d" % (s, number)

    def selftest(self):
        sample_indices = [0, 1, 2, 3, 100, 1000]
        sample = []

        for i in sample_indices:
            if i < self.num:
                sample.append((i, self.raw(i)))

        return self.raw(0) == "None", sample


# ---------------------------------------------------------------------------
# UObject graph
# ---------------------------------------------------------------------------

class Objects(object):
    def __init__(self, mem, addr, names):
        self.mem = mem
        self.names = names
        self.addr = addr

        self.data = mem.ptr(addr + 0x00)
        self.num = mem.i32(addr + 0x04)

        try:
            self.max = mem.i32(addr + 0x08)
        except MemErr:
            self.max = None

        self._name = {}

        if not (0 < self.num <= SANE_MAX_OBJECTS):
            raise MemErr(
                "GObjects невалиден: Data=0x%08X Num=%d. "
                "Адрес не тот или нужен/лишний --rebase."
                % (self.data, self.num)
            )

        if self.max is not None:
            if self.max < self.num or self.max > SANE_MAX_OBJECTS * 2:
                raise MemErr(
                    "GObjects Max выглядит неверно: Num=%d Max=%d"
                    % (self.num, self.max)
                )

    def slot(self, i):
        return self.mem.ptr(self.data + 4 * i)

    def name(self, o):
        if o in self._name:
            return self._name[o]

        try:
            idx = self.mem.i32(o + UO_NAME_INDEX)
            num = self.mem.i32(o + UO_NAME_NUMBER)
            s = self.names.fmt(idx, num)
        except MemErr:
            s = "<unreadable>"

        self._name[o] = s
        return s

    def class_name(self, o):
        try:
            c = self.mem.ptr(o + UO_CLASS)
            return self.name(c) if c else "<none>"
        except MemErr:
            return "<none>"

    def outermost(self, o):
        cur = o
        last = o
        n = 0
        seen = set()

        while cur and n < 24:
            if cur in seen:
                break
            seen.add(cur)

            last = cur
            try:
                cur = self.mem.ptr(cur + UO_OUTER)
            except MemErr:
                break
            n += 1

        return last

    def path(self, o):
        parts = []
        cur = o
        n = 0
        seen = set()

        while cur and n < 24:
            if cur in seen:
                parts.append("<cycle>")
                break
            seen.add(cur)

            parts.append(self.name(cur))

            try:
                cur = self.mem.ptr(cur + UO_OUTER)
            except MemErr:
                break

            n += 1

        return ".".join(reversed(parts))

    def iter_objects(self, progress=True):
        for i in range(self.num):
            if progress and i and i % 50000 == 0:
                sys.stderr.write("  ... %d/%d\n" % (i, self.num))

            try:
                o = self.slot(i)
            except MemErr:
                continue

            if o:
                yield i, o


# ---------------------------------------------------------------------------
# Phase 1: InternalIndex
# ---------------------------------------------------------------------------

def phase1(objs, mem, limit=20000):
    hits = defaultdict(int)
    total = 0

    for i, o in objs.iter_objects(progress=False):
        if total >= limit:
            break

        total += 1

        for off in INDEX_CANDIDATES:
            if mem.try_u32(o + off, None) == i:
                hits[off] += 1

    print(
        "\n== фаза 1: InternalIndex (obj[off] == slot), %d объектов =="
        % total
    )

    best = None

    for off in INDEX_CANDIDATES:
        h = hits.get(off, 0)
        frac = (h / float(total)) if total else 0.0

        print(
            "  +0x%02X : %6d совпадений  (%.1f%%)"
            % (off, h, frac * 100.0)
        )

        if best is None and frac > 0.99:
            best = off

    print(
        "  -> InternalIndex = %s"
        % ("+0x%02X" % best if best is not None else "НЕ ОПРЕДЕЛЁН")
    )

    return best


# ---------------------------------------------------------------------------
# Grouping by package
# ---------------------------------------------------------------------------

def build_groups(objs):
    print("\n== группировка по пакетам ==")

    groups = defaultdict(list)
    n = 0

    for _, o in objs.iter_objects():
        n += 1

        top = objs.outermost(o)
        pkg = objs.name(top) if top else "<null>"

        groups[pkg].append(o)

    sizes = sorted(
        ((len(v), k) for k, v in groups.items()),
        reverse=True
    )

    print("объектов %d, пакетов %d" % (n, len(groups)))
    print("крупнейшие:")

    for cnt, nm in sizes[:12]:
        print("   %8d  %s" % (cnt, nm))

    singles = sum(1 for c, _ in sizes if c == 1)
    print("пакетов ровно с одним объектом: %d" % singles)

    if groups and singles > len(groups) * 0.5:
        print(
            "!! больше половины 'пакетов' одиночные -- "
            "имена или Outer читаются неверно; "
            "результатам фазы 2 верить нельзя"
        )

    return groups


# ---------------------------------------------------------------------------
# Phase 2: NetIndex invariant
# ---------------------------------------------------------------------------

def score(mem, obj_list, expected, off):
    vals = []

    for o in obj_list:
        v = mem.try_u32(o + off, None)

        if v is None:
            continue

        sv = sgn32(v)

        if sv == -1:
            continue

        # Явный мусор/указатель/flags вместо индекса.
        if sv < 0 or sv > 0x00FFFFFF:
            return (False, 0.0, sv, 0, 0)

        vals.append(sv)

    if not vals:
        return (False, 0.0, -1, 0, 0)

    uniq = set(vals)
    dups = len(vals) - len(uniq)
    mx = max(uniq)

    ok = (dups == 0 and mx < expected)
    coverage = len(uniq) / float(expected) if expected else 0.0

    return (ok, coverage, mx, dups, len(uniq))


def phase2(mem, groups, expects, skip):
    print("\n== фаза 2: NetIndex (инвариант по пакетам) ==")

    passed = []

    for off in NET_CANDIDATES:
        if off == skip:
            continue

        rows = []
        all_ok = True
        cov = 0.0
        tested = 0

        for pkg, cnt in expects:
            lst = groups.get(pkg)

            if not lst:
                rows.append(
                    "    %-18s НЕТ В ПАМЯТИ"
                    % pkg
                )
                continue

            ok, c, mx, dups, seen = score(mem, lst, cnt, off)

            tested += 1
            cov += c
            all_ok = all_ok and ok

            rows.append(
                "    %-18s ожид=%-5d уник=%-5d max=%-8d "
                "дублей=%-4d %s"
                % (
                    pkg,
                    cnt,
                    seen,
                    mx,
                    dups,
                    "OK" if ok else "НАРУШЕН",
                )
            )

        if not tested:
            continue

        print(
            "\n  +0x%02X : %s (покрытие %.0f%%)"
            % (
                off,
                "ПРОХОДИТ" if all_ok else "отвергнут",
                100.0 * cov / tested,
            )
        )

        for r in rows:
            print(r)

        if all_ok:
            passed.append(off)

    print("\n  ---")

    if len(passed) == 1:
        print("  -> NetIndex = +0x%02X" % passed[0])
        return passed[0]

    if not passed:
        print("  !! ни один кандидат не прошёл")
        print("     Возможные причины:")
        print("       - NetIndex не в UObject для этой сборки;")
        print("       - NetObjectCount взят не из той generation;")
        print("       - пакет сгруппирован неверно из-за forced export;")
        print("       - нужные пакеты загружены не полностью.")
    else:
        print(
            "  !! прошли несколько: %s -- "
            "добавьте --expect на большой пакет"
            % ", ".join("+0x%02X" % p for p in passed)
        )

    return None


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

def dump_package(objs, mem, groups, pkg, off, out=None):
    lst = groups.get(pkg)

    if not lst:
        print("\n!! пакет %r не найден в памяти" % pkg)
        return

    rows = []

    for o in lst:
        v = mem.try_u32(o + off, None)

        if v is None:
            continue

        sv = sgn32(v)

        if sv < 0:
            continue

        rows.append(
            (
                sv,
                objs.path(o),
                objs.class_name(o),
                o,
            )
        )

    rows.sort()

    print(
        "\n== %s: %d сетевых объектов =="
        % (pkg, len(rows))
    )

    if rows:
        print(
            "   индексы %d..%d"
            % (rows[0][0], rows[-1][0])
        )

    if out:
        with open(out, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(
                    "%d\t%s\t%s\t0x%08X\n"
                    % r
                )

        print("   записано в %s" % out)

    else:
        for r in rows[:40]:
            print(
                "   %6d  %-58s %s"
                % (r[0], r[1], r[2])
            )

        if len(rows) > 40:
            print(
                "   ... ещё %d"
                % (len(rows) - 40)
            )


def find_object(objs, mem, groups, needle, off):
    print("\n== поиск %r ==" % needle)

    found = 0

    for pkg, lst in groups.items():
        for o in lst:
            if objs.name(o) != needle:
                continue

            v = mem.try_u32(o + off, None)
            cls = objs.class_name(o)

            extra = ""
            if cls.endswith("Property"):
                prop_off = mem.try_u32(o + UPROPERTY_OFFSET, None)
                if prop_off is not None:
                    extra = " PropertyOffset=0x%X" % prop_off

            print(
                "   %-46s пакет=%-20s класс=%-24s "
                "NetIndex=%s addr=0x%08X%s"
                % (
                    objs.path(o),
                    pkg,
                    cls,
                    sgn32(v) if v is not None else "?",
                    o,
                    extra,
                )
            )

            found += 1

    if not found:
        print(
            "   не найден "
            "(объект может быть не загружен "
            "или имя отличается)"
        )


def _find_package_root(objs, mem, groups, pkg):
    lst = groups.get(pkg)
    if not lst:
        return None

    candidates = []

    for o in lst:
        try:
            outer = mem.ptr(o + UO_OUTER)
        except MemErr:
            continue

        if outer != 0:
            continue

        if objs.name(o) != pkg:
            continue

        candidates.append(o)

    if not candidates:
        return None

    # Обычно единственный top-level UObject с этим именем и Outer == NULL
    # является самим UPackage. Если их несколько, предпочитаем Class == Package.
    for o in candidates:
        if objs.class_name(o) == "Package":
            return o

    return candidates[0]


def _collect_netindex_pairs(mem, group, netindex_off):
    by_index = {}
    duplicates = []

    for o in group:
        raw = mem.try_u32(o + netindex_off, None)
        if raw is None:
            continue

        idx = sgn32(raw)
        if idx < 0 or idx > 0x00FFFFFF:
            continue

        prev = by_index.get(idx)
        if prev is not None and prev != o:
            duplicates.append((idx, prev, o))
            continue

        by_index[idx] = o

    return by_index, duplicates


def _sample_pairs(by_index, limit=256):
    items = sorted(by_index.items())
    if len(items) <= limit:
        return items

    # Равномерный sample по всему диапазону, обязательно включая края.
    out = []
    last_pos = -1

    for n in range(limit):
        pos = int(round(n * (len(items) - 1) / float(limit - 1)))
        if pos == last_pos:
            continue
        out.append(items[pos])
        last_pos = pos

    return out


def _read_tarray_header(mem, addr):
    data = mem.ptr(addr + 0x00)
    num = mem.i32(addr + 0x04)
    maxv = mem.i32(addr + 0x08)
    return data, num, maxv


def _scan_netobjects_candidates(
    mem,
    package_obj,
    by_index,
    scan_start=0x40,
    scan_end=0x400,
):
    if not by_index:
        return []

    max_idx = max(by_index)
    sample = _sample_pairs(by_index)

    candidates = []

    for off in range(scan_start, scan_end, 4):
        try:
            data, num, maxv = _read_tarray_header(mem, package_obj + off)
        except MemErr:
            continue

        # NetObjects.Num обязан покрывать максимальный живой NetIndex.
        if not data:
            continue
        if num <= max_idx:
            continue
        if num < 0 or num > 2_000_000:
            continue
        if maxv < num or maxv > 4_000_000:
            continue

        matched = 0
        failed = False

        for idx, expected_obj in sample:
            try:
                actual = mem.ptr(data + idx * 4)
            except MemErr:
                failed = True
                break

            if actual != expected_obj:
                failed = True
                break

            matched += 1

        if failed:
            continue

        candidates.append(
            {
                "off": off,
                "data": data,
                "num": num,
                "max": maxv,
                "sample_matches": matched,
                "sample_total": len(sample),
            }
        )

    return candidates


def _count_non_null_ptrs(mem, data, num):
    count = 0

    for i in range(num):
        try:
            if mem.ptr(data + i * 4):
                count += 1
        except MemErr:
            return None

    return count


def _read_generation_array(mem, package_obj, netobjects_off):
    # UE3 UPackage declaration:
    #   TArray<UObject*> NetObjects;
    #   INT CurrentNumNetObjects;
    #   TArray<INT> GenerationNetObjectCount;
    current_addr = package_obj + netobjects_off + 0x0C
    gen_addr = package_obj + netobjects_off + 0x10

    current = mem.i32(current_addr)
    data, num, maxv = _read_tarray_header(mem, gen_addr)

    if num < 0 or num > 64 or maxv < num or maxv > 256:
        return current, data, num, maxv, None

    values = []
    for i in range(num):
        values.append(mem.i32(data + i * 4))

    return current, data, num, maxv, values


def probe_package_net(
    objs,
    mem,
    groups,
    pkg,
    netindex_off,
    scan_start=0x40,
    scan_end=0x400,
):
    print("\n== probe UPackage net state: %s ==" % pkg)

    group = groups.get(pkg)
    if not group:
        print("!! пакет %r не найден в группировке" % pkg)
        return None

    package_obj = _find_package_root(objs, mem, groups, pkg)
    if not package_obj:
        print("!! не найден top-level UPackage object %r" % pkg)
        return None

    print(
        "   UPackage=0x%08X class=%s"
        % (package_obj, objs.class_name(package_obj))
    )

    by_index, duplicates = _collect_netindex_pairs(
        mem,
        group,
        netindex_off,
    )

    if not by_index:
        print("!! в пакете нет объектов с валидным NetIndex")
        return None

    max_idx = max(by_index)

    print(
        "   runtime объектов с NetIndex: %d, диапазон 0..%d"
        % (len(by_index), max_idx)
    )

    if duplicates:
        print(
            "!! обнаружено %d duplicate NetIndex; "
            "проверка NetObjects ненадёжна"
            % len(duplicates)
        )
        for idx, a, b in duplicates[:5]:
            print(
                "      idx=%d  0x%08X / 0x%08X"
                % (idx, a, b)
            )
        return None

    candidates = _scan_netobjects_candidates(
        mem,
        package_obj,
        by_index,
        scan_start=scan_start,
        scan_end=scan_end,
    )

    if not candidates:
        print(
            "!! NetObjects не найден в UPackage+0x%X..+0x%X"
            % (scan_start, scan_end)
        )
        print(
            "   попробуйте увеличить --package-scan-end, "
            "например до 0x800"
        )
        return None

    print("   кандидаты NetObjects:")

    for c in candidates:
        print(
            "      +0x%03X  Data=0x%08X Num=%d Max=%d "
            "mapping=%d/%d"
            % (
                c["off"],
                c["data"],
                c["num"],
                c["max"],
                c["sample_matches"],
                c["sample_total"],
            )
        )

    # Полное отображение NetObjects[NetIndex] == UObject уже делает этот
    # инвариант практически уникальным. При нескольких кандидатах
    # предпочитаем минимальный Num, затем меньший offset.
    candidates.sort(key=lambda c: (c["num"], c["off"]))
    c = candidates[0]

    if len(candidates) > 1:
        print(
            "!! кандидатов несколько; выбран +0x%03X. "
            "Сверьте остальные строки."
            % c["off"]
        )

    print(
        "   -> NetObjects = UPackage+0x%03X"
        % c["off"]
    )

    non_null = _count_non_null_ptrs(
        mem,
        c["data"],
        c["num"],
    )

    if non_null is not None:
        print(
            "      NetObjects: Num=%d Max=%d non-null=%d"
            % (c["num"], c["max"], non_null)
        )
    else:
        print(
            "      NetObjects: Num=%d Max=%d "
            "(не удалось посчитать non-null)"
            % (c["num"], c["max"])
        )

    try:
        current, gen_data, gen_num, gen_max, gen_values = \
            _read_generation_array(mem, package_obj, c["off"])
    except MemErr as exc:
        print(
            "!! NetObjects найден, но соседние поля "
            "не прочитались: %s"
            % exc
        )
        return c

    print(
        "      CurrentNumNetObjects @ +0x%03X = %d"
        % (c["off"] + 0x0C, current)
    )

    if non_null is not None:
        print(
            "      CurrentNum vs non-null: %s"
            % ("MATCH" if current == non_null else "DIFF")
        )

    print(
        "      GenerationNetObjectCount @ +0x%03X: "
        "Data=0x%08X Num=%d Max=%d"
        % (
            c["off"] + 0x10,
            gen_data,
            gen_num,
            gen_max,
        )
    )

    if gen_values is None:
        print(
            "      !! header GenerationNetObjectCount "
            "не прошёл sanity-check"
        )
        return c

    print(
        "      generations = [%s]"
        % ", ".join(str(v) for v in gen_values)
    )

    if gen_values:
        local_generation = len(gen_values)
        latest_count = gen_values[-1]

        print(
            "      LocalGeneration=%d  "
            "GetNetObjectCount(LocalGeneration-1)=%d"
            % (local_generation, latest_count)
        )

        if latest_count == c["num"]:
            print(
                "      Generation.Last == NetObjects.Num: MATCH"
            )
        else:
            print(
                "      Generation.Last != NetObjects.Num: "
                "%d vs %d"
                % (latest_count, c["num"])
            )

        print(
            "      USES candidate: Generation=%d "
            "ObjectCount=%d"
            % (local_generation, latest_count)
        )

    c["non_null"] = non_null
    c["current_num"] = current
    c["generation_num"] = gen_num
    c["generation_values"] = gen_values

    return c


# ---------------------------------------------------------------------------
# UNetConnection -> UPackageMap -> FPackageInfo runtime probe
# ---------------------------------------------------------------------------

DEFAULT_MAP_PACKAGES = ("Core", "Engine", "APBGame")
KNOWN_CORE_GUID = (
    0x0FE825BC,
    0x4970D0BC,
    0xE10969A8,
    0x4C498AF9,
)


def _iter_all_group_objects(groups):
    seen = set()
    for lst in groups.values():
        for o in lst:
            if o in seen:
                continue
            seen.add(o)
            yield o


def _find_packagemap_objects(objs, mem, groups):
    out = []

    for o in _iter_all_group_objects(groups):
        cls = objs.class_name(o)

        if "PackageMap" not in cls:
            continue

        try:
            outer = mem.ptr(o + UO_OUTER)
        except MemErr:
            outer = 0

        out.append(
            {
                "obj": o,
                "class": cls,
                "name": objs.name(o),
                "outer": outer,
                "outer_class": objs.class_name(outer) if outer else "<none>",
                "outer_name": objs.name(outer) if outer else "<none>",
            }
        )

    return out


def _find_pointer_offsets(mem, owner, target, start=0x40, end=0x300):
    hits = []

    if not owner or not target:
        return hits

    for off in range(start, end, 4):
        if mem.try_u32(owner + off, None) == target:
            hits.append(off)

    return hits


def _runtime_package_count_quiet(objs, mem, groups, pkg, netindex_off):
    group = groups.get(pkg)
    if not group:
        return None

    package_obj = _find_package_root(objs, mem, groups, pkg)
    if not package_obj:
        return None

    by_index, duplicates = _collect_netindex_pairs(
        mem,
        group,
        netindex_off,
    )

    if not by_index or duplicates:
        return None

    candidates = _scan_netobjects_candidates(
        mem,
        package_obj,
        by_index,
        scan_start=0x40,
        scan_end=0x400,
    )

    if not candidates:
        return None

    candidates.sort(key=lambda c: (c["num"], c["off"]))
    c = candidates[0]

    try:
        current, gen_data, gen_num, gen_max, gen_values = \
            _read_generation_array(mem, package_obj, c["off"])
    except MemErr:
        return None

    if not gen_values:
        return None

    return {
        "package_obj": package_obj,
        "netobjects_off": c["off"],
        "netobjects_num": c["num"],
        "current_num": current,
        "generation_num": gen_num,
        "generation_values": gen_values,
        "local_generation": len(gen_values),
        "object_count": gen_values[-1],
    }


def _expected_map_state(objs, mem, groups, package_names, netindex_off):
    expected = []
    base = 0

    for pkg in package_names:
        state = _runtime_package_count_quiet(
            objs,
            mem,
            groups,
            pkg,
            netindex_off,
        )

        if state is None:
            return None

        row = dict(state)
        row["name"] = pkg
        row["object_base"] = base
        expected.append(row)

        base += row["object_count"]

    return expected


def _find_fpackageinfo_layout(
    objs,
    mem,
    list_data,
    list_num,
    expected_roots,
):
    """
    Не доверяем заранее ни старой заметке Parent@+0x00, ни stock UE3
    Parent@+0x08. Ищем одновременно:
      - размер записи;
      - offset Parent;
    по трем подряд живым UPackage* Core/Engine/APBGame.

    После Parent поля FGuid/ObjectBase/ObjectCount/Generation идут подряд
    согласно FPackageInfo declaration.
    """
    if list_num < len(expected_roots):
        return []

    results = []

    for entry_size in range(0x40, 0x61, 4):
        for parent_off in range(0x00, 0x15, 4):
            ok = True

            for i, expected_parent in enumerate(expected_roots):
                p = mem.try_u32(
                    list_data + i * entry_size + parent_off,
                    None,
                )

                if p != expected_parent:
                    ok = False
                    break

            if not ok:
                continue

            results.append(
                {
                    "entry_size": entry_size,
                    "parent_off": parent_off,
                    "guid_off": parent_off + 0x04,
                    "object_base_off": parent_off + 0x14,
                    "object_count_off": parent_off + 0x18,
                    "local_generation_off": parent_off + 0x1C,
                    "remote_generation_off": parent_off + 0x20,
                }
            )

    return results


def _read_guid(mem, addr):
    return tuple(mem.u32(addr + i * 4) for i in range(4))


def _guid_string(g):
    return "%08X-%08X-%08X-%08X" % g


def _probe_one_packagemap(
    objs,
    mem,
    groups,
    pm,
    expected,
    list_scan_start=0x40,
    list_scan_end=0x100,
):
    package_names = [row["name"] for row in expected]
    roots = [row["package_obj"] for row in expected]

    candidates = []

    for list_off in range(list_scan_start, list_scan_end, 4):
        try:
            data, num, maxv = _read_tarray_header(mem, pm["obj"] + list_off)
        except MemErr:
            continue

        if not data:
            continue
        if num < len(package_names) or num > 128:
            continue
        if maxv < num or maxv > 512:
            continue

        layouts = _find_fpackageinfo_layout(
            objs,
            mem,
            data,
            num,
            roots,
        )

        for layout in layouts:
            candidate = {
                "list_off": list_off,
                "data": data,
                "num": num,
                "max": maxv,
            }
            candidate.update(layout)
            candidates.append(candidate)

    if not candidates:
        return None

    # Three exact Parent pointers make the candidate very strong.
    # Prefer stock-looking List@+0x40 and entry size 0x50 if several aliases
    # accidentally survive.
    candidates.sort(
        key=lambda c: (
            0 if c["list_off"] == 0x40 else 1,
            abs(c["entry_size"] - 0x50),
            c["list_off"],
            c["entry_size"],
            c["parent_off"],
        )
    )

    return candidates[0], candidates



def _collect_package_roots(objs, mem, groups):
    roots = {}

    for pkg, lst in groups.items():
        for o in lst:
            try:
                if mem.ptr(o + UO_OUTER) != 0:
                    continue
            except MemErr:
                continue

            if objs.name(o) != pkg:
                continue

            if objs.class_name(o) == "Package":
                roots[o] = pkg
                break

    return roots


def _decode_fpackageinfo_entry(
    objs,
    mem,
    entry,
    layout,
):
    try:
        parent = mem.ptr(entry + layout["parent_off"])
        guid = _read_guid(mem, entry + layout["guid_off"])
        base = mem.i32(entry + layout["object_base_off"])
        count = mem.i32(entry + layout["object_count_off"])
        local_gen = mem.i32(entry + layout["local_generation_off"])
        remote_gen = mem.i32(entry + layout["remote_generation_off"])
    except MemErr:
        return None

    try:
        name = objs.name(parent) if parent else "<null>"
        cls = objs.class_name(parent) if parent else "<none>"
    except Exception:
        name = "<bad>"
        cls = "<bad>"

    return {
        "parent": parent,
        "name": name,
        "class": cls,
        "guid": guid,
        "base": base,
        "count": count,
        "local_gen": local_gen,
        "remote_gen": remote_gen,
    }


def _score_list_layout(
    objs,
    mem,
    data,
    num,
    package_roots,
    entry_size,
    parent_off,
):
    if num <= 0 or num > 128:
        return None

    layout = {
        "entry_size": entry_size,
        "parent_off": parent_off,
        "guid_off": parent_off + 0x04,
        "object_base_off": parent_off + 0x14,
        "object_count_off": parent_off + 0x18,
        "local_generation_off": parent_off + 0x1C,
        "remote_generation_off": parent_off + 0x20,
    }

    valid_parent = 0
    plausible_fields = 0
    decoded = []

    for i in range(num):
        row = _decode_fpackageinfo_entry(
            objs,
            mem,
            data + i * entry_size,
            layout,
        )
        if row is None:
            break

        decoded.append(row)

        if row["parent"] in package_roots:
            valid_parent += 1

        # FPackageInfo runtime sanity, deliberately loose.
        if (
            -1 <= row["base"] < 0x7FFFFFFF
            and 0 <= row["count"] < 0x10000000
            and 0 <= row["local_gen"] <= 64
            and 0 <= row["remote_gen"] <= 64
        ):
            plausible_fields += 1

    if not decoded:
        return None

    return {
        "layout": layout,
        "decoded": decoded,
        "valid_parent": valid_parent,
        "plausible_fields": plausible_fields,
        "score": valid_parent * 1000 + plausible_fields,
    }


def _fallback_dump_packagemap_list(
    objs,
    mem,
    groups,
    pm,
    list_scan_start=0x40,
    list_scan_end=0x100,
):
    print(
        "\n   -- fallback dump for PackageMap 0x%08X (%s/%s) --"
        % (pm["obj"], pm["class"], pm["name"])
    )

    if pm["outer"]:
        ptr_hits = _find_pointer_offsets(
            mem,
            pm["outer"],
            pm["obj"],
            start=0x40,
            end=0x300,
        )
        print(
            "      Outer/connection=0x%08X class=%s name=%s"
            % (
                pm["outer"],
                pm["outer_class"],
                pm["outer_name"],
            )
        )
        if ptr_hits:
            print(
                "      connection -> PackageMap offsets: %s"
                % ", ".join("+0x%03X" % x for x in ptr_hits)
            )
        else:
            print(
                "      connection -> PackageMap pointer "
                "не найден в +0x40..+0x2FC"
            )

    package_roots = _collect_package_roots(
        objs,
        mem,
        groups,
    )

    tarray_candidates = []

    for list_off in range(list_scan_start, list_scan_end, 4):
        try:
            data, num, maxv = _read_tarray_header(
                mem,
                pm["obj"] + list_off,
            )
        except MemErr:
            continue

        if not data:
            continue
        if num <= 0 or num > 128:
            continue
        if maxv < num or maxv > 512:
            continue

        best_here = None

        for entry_size in range(0x40, 0x61, 4):
            for parent_off in range(0x00, 0x15, 4):
                scored = _score_list_layout(
                    objs,
                    mem,
                    data,
                    num,
                    package_roots,
                    entry_size,
                    parent_off,
                )

                if scored is None:
                    continue

                if (
                    best_here is None
                    or scored["score"] > best_here["score"]
                ):
                    best_here = scored

        if best_here is not None:
            tarray_candidates.append(
                {
                    "list_off": list_off,
                    "data": data,
                    "num": num,
                    "max": maxv,
                    "best": best_here,
                }
            )

    if not tarray_candidates:
        print(
            "      не найден ни один plausible TArray<FPackageInfo> "
            "в +0x40..+0xFC"
        )
        return None

    tarray_candidates.sort(
        key=lambda c: (
            -c["best"]["valid_parent"],
            -c["best"]["plausible_fields"],
            0 if c["list_off"] == 0x40 else 1,
            abs(c["best"]["layout"]["entry_size"] - 0x50),
            c["list_off"],
        )
    )

    c = tarray_candidates[0]
    b = c["best"]
    layout = b["layout"]

    print(
        "      лучший List candidate: +0x%03X "
        "Data=0x%08X Num=%d Max=%d"
        % (
            c["list_off"],
            c["data"],
            c["num"],
            c["max"],
        )
    )
    print(
        "      layout: size=0x%02X Parent=+0x%02X "
        "Guid=+0x%02X Base=+0x%02X Count=+0x%02X "
        "Local=+0x%02X Remote=+0x%02X "
        "(valid package parents %d/%d)"
        % (
            layout["entry_size"],
            layout["parent_off"],
            layout["guid_off"],
            layout["object_base_off"],
            layout["object_count_off"],
            layout["local_generation_off"],
            layout["remote_generation_off"],
            b["valid_parent"],
            c["num"],
        )
    )

    for i, row in enumerate(b["decoded"]):
        marker = (
            "PACKAGE"
            if row["parent"] in package_roots
            else "?"
        )

        print(
            "      [%02d] %-18s %-8s "
            "Parent=0x%08X Base=%-8d Count=%-8d "
            "Local=%-3d Remote=%-3d Guid=%s"
            % (
                i,
                row["name"],
                marker,
                row["parent"],
                row["base"],
                row["count"],
                row["local_gen"],
                row["remote_gen"],
                _guid_string(row["guid"]),
            )
        )

    return c



def _scan_guid_offsets(mem, obj, guid_words, start=0x40, end=0x200):
    hits = []

    for off in range(start, end - 0x0F, 4):
        try:
            words = tuple(
                mem.u32(obj + off + i * 4)
                for i in range(4)
            )
        except MemErr:
            continue

        if words == guid_words:
            hits.append(off)

    return hits


def probe_package_guids(
    objs,
    mem,
    groups,
    package_names=DEFAULT_MAP_PACKAGES,
):
    print("\n== UPackage GUID probe ==")

    core = _find_package_root(
        objs,
        mem,
        groups,
        "Core",
    )

    if not core:
        print("!! UPackage Core не найден")
        return None

    hits = _scan_guid_offsets(
        mem,
        core,
        KNOWN_CORE_GUID,
        start=0x40,
        end=0x200,
    )

    if not hits:
        print(
            "!! известный Core GUID не найден "
            "в UPackage Core +0x40..+0x1FC"
        )
        return None

    print(
        "   Core known GUID найден по offset(s): %s"
        % ", ".join("+0x%03X" % x for x in hits)
    )

    # При нескольких совпадениях печатаем все, но обычно будет один.
    results = {}

    for off in hits:
        print(
            "\n   candidate UPackage::Guid = +0x%03X"
            % off
        )

        rows = []

        for pkg in package_names:
            root = _find_package_root(
                objs,
                mem,
                groups,
                pkg,
            )

            if not root:
                print(
                    "      %-8s UPackage не найден"
                    % pkg
                )
                continue

            try:
                g = tuple(
                    mem.u32(root + off + i * 4)
                    for i in range(4)
                )
            except MemErr as exc:
                print(
                    "      %-8s unreadable: %s"
                    % (pkg, exc)
                )
                continue

            rows.append((pkg, root, g))

            print(
                "      %-8s UPackage=0x%08X GUID=%s"
                % (
                    pkg,
                    root,
                    _guid_string(g),
                )
            )

        results[off] = rows

    if len(hits) == 1:
        print(
            "\n   -> UPackage::Guid = +0x%03X CONFIRMED "
            "by exact Core GUID"
            % hits[0]
        )

    return results


def probe_packagemap(
    objs,
    mem,
    groups,
    netindex_off,
    package_names=DEFAULT_MAP_PACKAGES,
    player_controller_local_index=12772,
):
    print("\n== PackageMap end-to-end probe ==")

    expected = _expected_map_state(
        objs,
        mem,
        groups,
        package_names,
        netindex_off,
    )

    if expected is None:
        print(
            "!! не удалось вычислить runtime ObjectCount "
            "для Core/Engine/APBGame"
        )
        return None

    print("   ожидаемая карта из живых UPackage:")

    for row in expected:
        print(
            "      %-8s Base=%-6d Count=%-6d LocalGen=%d "
            "UPackage=0x%08X"
            % (
                row["name"],
                row["object_base"],
                row["object_count"],
                row["local_generation"],
                row["package_obj"],
            )
        )

    total = sum(row["object_count"] for row in expected)

    if "APBGame" in package_names:
        apb_i = package_names.index("APBGame")
        pc_global = (
            expected[apb_i]["object_base"]
            + player_controller_local_index
        )
        print(
            "      cAPBPlayerController: local=%d global=%d"
            % (player_controller_local_index, pc_global)
        )

    print("      MaxObjectIndex after list = %d" % total)

    maps = _find_packagemap_objects(objs, mem, groups)

    if not maps:
        print("!! UPackageMap UObject не найден")
        return None

    print("   найденные UPackageMap UObject:")

    for pm in maps:
        print(
            "      0x%08X %-24s name=%-20s "
            "Outer=0x%08X %s/%s"
            % (
                pm["obj"],
                pm["class"],
                pm["name"],
                pm["outer"],
                pm["outer_class"],
                pm["outer_name"],
            )
        )

    valid = []

    for pm in maps:
        probed = _probe_one_packagemap(
            objs,
            mem,
            groups,
            pm,
            expected,
        )

        if probed is None:
            continue

        chosen, all_candidates = probed
        valid.append((pm, chosen, all_candidates))

    if not valid:
        print(
            "!! ни один UPackageMap не содержит первые записи "
            "Core/Engine/APBGame в ожидаемом порядке"
        )
        print(
            "   Печатаю фактический List для runtime-карт, "
            "чтобы увидеть реально принятые Uses."
        )

        runtime_maps = [
            pm for pm in maps
            if pm["outer"]
            and (
                "Connection" in pm["outer_class"]
                or not pm["name"].startswith("Default__")
            )
        ]

        if not runtime_maps:
            runtime_maps = maps

        for pm in runtime_maps:
            _fallback_dump_packagemap_list(
                objs,
                mem,
                groups,
                pm,
            )

        return None

    if len(valid) > 1:
        print(
            "!! подходящих PackageMap несколько; "
            "печатаю каждый, PASS должен быть у активного соединения"
        )

    final_pass = False
    final_result = None

    for pm, layout, all_candidates in valid:
        print(
            "\n   PackageMap=0x%08X class=%s"
            % (pm["obj"], pm["class"])
        )

        conn = pm["outer"]
        conn_ptr_offsets = _find_pointer_offsets(
            mem,
            conn,
            pm["obj"],
            start=0x40,
            end=0x300,
        )

        if conn:
            print(
                "      Outer/connection=0x%08X class=%s name=%s"
                % (
                    conn,
                    pm["outer_class"],
                    pm["outer_name"],
                )
            )

            if conn_ptr_offsets:
                print(
                    "      connection -> PackageMap offsets: %s"
                    % ", ".join(
                        "+0x%03X" % x
                        for x in conn_ptr_offsets
                    )
                )
            else:
                print(
                    "      connection -> PackageMap pointer "
                    "не найден в +0x40..+0x2FC"
                )

        print(
            "      List = PackageMap+0x%03X "
            "Data=0x%08X Num=%d Max=%d"
            % (
                layout["list_off"],
                layout["data"],
                layout["num"],
                layout["max"],
            )
        )

        print(
            "      FPackageInfo: size=0x%02X "
            "Parent=+0x%02X Guid=+0x%02X "
            "ObjectBase=+0x%02X ObjectCount=+0x%02X "
            "LocalGen=+0x%02X RemoteGen=+0x%02X"
            % (
                layout["entry_size"],
                layout["parent_off"],
                layout["guid_off"],
                layout["object_base_off"],
                layout["object_count_off"],
                layout["local_generation_off"],
                layout["remote_generation_off"],
            )
        )

        if len(all_candidates) > 1:
            print(
                "      layout-кандидатов=%d; выбран наиболее "
                "stock-compatible"
                % len(all_candidates)
            )

        all_ok = True

        for i, exp in enumerate(expected):
            entry = layout["data"] + i * layout["entry_size"]

            try:
                parent = mem.ptr(entry + layout["parent_off"])
                guid = _read_guid(mem, entry + layout["guid_off"])
                base = mem.i32(entry + layout["object_base_off"])
                count = mem.i32(entry + layout["object_count_off"])
                local_gen = mem.i32(
                    entry + layout["local_generation_off"]
                )
                remote_gen = mem.i32(
                    entry + layout["remote_generation_off"]
                )
            except MemErr as exc:
                print(
                    "      [%d] !! unreadable: %s"
                    % (i, exc)
                )
                all_ok = False
                continue

            name = objs.name(parent) if parent else "<null>"

            ok_parent = parent == exp["package_obj"]
            ok_base = base == exp["object_base"]
            ok_count = count == exp["object_count"]
            ok_local = local_gen == exp["local_generation"]

            # RemoteGeneration should equal the Generation supplied by
            # the server. We currently expect Generation=2 for all three.
            ok_remote = remote_gen == 2

            ok = (
                ok_parent
                and ok_base
                and ok_count
                and ok_local
                and ok_remote
            )

            all_ok = all_ok and ok

            print(
                "      [%d] %-8s Parent=0x%08X "
                "Guid=%s Base=%-6d Count=%-6d "
                "Local=%d Remote=%d  %s"
                % (
                    i,
                    name,
                    parent,
                    _guid_string(guid),
                    base,
                    count,
                    local_gen,
                    remote_gen,
                    "MATCH" if ok else "MISMATCH",
                )
            )

            if not ok:
                problems = []

                if not ok_parent:
                    problems.append(
                        "Parent expected 0x%08X"
                        % exp["package_obj"]
                    )
                if not ok_base:
                    problems.append(
                        "Base expected %d"
                        % exp["object_base"]
                    )
                if not ok_count:
                    problems.append(
                        "Count expected %d"
                        % exp["object_count"]
                    )
                if not ok_local:
                    problems.append(
                        "LocalGen expected %d"
                        % exp["local_generation"]
                    )
                if not ok_remote:
                    problems.append(
                        "RemoteGen expected 2"
                    )

                print(
                    "           -> %s"
                    % "; ".join(problems)
                )

        if all_ok:
            print(
                "\n      END-TO-END PackageMap: PASS"
            )
            final_pass = True
            final_result = {
                "packagemap": pm,
                "layout": layout,
                "expected": expected,
            }
        else:
            print(
                "\n      END-TO-END PackageMap: FAIL"
            )

    if final_pass:
        return final_result

    return None


# ---------------------------------------------------------------------------
# PlayerController actor-open probe
# ---------------------------------------------------------------------------

def _find_objects_named(objs, groups, name, package=None):
    out = []

    if package is not None:
        source = groups.get(package, [])
    else:
        source = list(_iter_all_group_objects(groups))

    for o in source:
        try:
            if objs.name(o) == name:
                out.append(o)
        except Exception:
            pass

    return out


def _find_object_by_path(objs, groups, wanted_path):
    for o in _iter_all_group_objects(groups):
        try:
            if objs.path(o) == wanted_path:
                return o
        except Exception:
            pass
    return None


def probe_playercontroller_open(
    objs,
    mem,
    groups,
    netindex_off,
):
    print("\n== PlayerController actor-open probe ==")

    expected = _expected_map_state(
        objs,
        mem,
        groups,
        DEFAULT_MAP_PACKAGES,
        netindex_off,
    )

    if expected is None:
        print("!! не удалось вычислить runtime package map")
        return None

    apb = None
    for row in expected:
        if row["name"] == "APBGame":
            apb = row
            break

    if apb is None:
        print("!! APBGame отсутствует в ожидаемой карте")
        return None

    cdo_candidates = _find_objects_named(
        objs,
        groups,
        "Default__cAPBPlayerController",
        package="APBGame",
    )

    if not cdo_candidates:
        print("!! APBGame.Default__cAPBPlayerController не найден")
        return None

    cdo = cdo_candidates[0]

    raw_local = mem.try_u32(cdo + netindex_off, None)
    if raw_local is None:
        print("!! не удалось прочитать CDO NetIndex")
        return None

    local = sgn32(raw_local)
    if local < 0:
        print(
            "!! Default__cAPBPlayerController NetIndex=%d"
            % local
        )
        return None

    global_index = apb["object_base"] + local

    print(
        "   CDO: %s"
        % objs.path(cdo)
    )
    print(
        "      addr=0x%08X class=%s"
        % (cdo, objs.class_name(cdo))
    )
    print(
        "      APBGame local NetIndex=%d"
        % local
    )
    print(
        "      APBGame ObjectBase=%d"
        % apb["object_base"]
    )
    print(
        "      actor-open archetype GLOBAL NetIndex=%d"
        % global_index
    )

    # Discover UBoolProperty::BitMask from runtime layout.
    #
    # BitMask is a native member of UBoolProperty, not necessarily a reflected
    # Core.BoolProperty.BitMask UProperty.  Instead of depending on its name,
    # scan all live BoolProperty objects.  The real member is a 32-bit one-hot
    # value for essentially every BoolProperty: 1,2,4,...,0x80000000.
    bool_props = []

    for o in _iter_all_group_objects(groups):
        try:
            if objs.class_name(o) == "BoolProperty":
                bool_props.append(o)
        except Exception:
            pass

    bitmask_member_off = None

    if not bool_props:
        print("   !! BoolProperty objects не найдены")
    else:
        samples = bool_props[:20000]
        scores = []

        for candidate_off in range(0x60, 0x91, 4):
            readable = 0
            one_hot = 0
            zero = 0

            for bp in samples:
                value = mem.try_u32(bp + candidate_off, None)
                if value is None:
                    continue

                readable += 1

                if value == 0:
                    zero += 1
                elif (value & (value - 1)) == 0:
                    one_hot += 1

            if readable:
                scores.append(
                    (
                        one_hot,
                        -zero,
                        readable,
                        candidate_off,
                    )
                )

        scores.sort(reverse=True)

        print(
            "   UBoolProperty native-layout candidates "
            "(one-hot/zero/readable):"
        )

        for one_hot, neg_zero, readable, off_c in scores[:8]:
            print(
                "      +0x%02X : %d / %d / %d"
                % (
                    off_c,
                    one_hot,
                    -neg_zero,
                    readable,
                )
            )

        if scores:
            one_hot, neg_zero, readable, best_off = scores[0]

            # Require strong evidence, not merely "best of weak candidates".
            if (
                readable >= 100
                and one_hot >= int(readable * 0.90)
            ):
                bitmask_member_off = best_off
                print(
                    "   -> UBoolProperty::BitMask = +0x%X "
                    "(runtime one-hot invariant)"
                    % bitmask_member_off
                )
            else:
                print(
                    "   !! ни один BitMask candidate "
                    "не прошёл 90%% one-hot threshold"
                )

    rotation_prop = None

    candidates = _find_objects_named(
        objs,
        groups,
        "bNetInitialRotation",
        package="Engine",
    )

    # Prefer the property whose outer chain contains Actor.
    for o in candidates:
        try:
            if ".Actor.bNetInitialRotation" in objs.path(o):
                rotation_prop = o
                break
        except Exception:
            pass

    if rotation_prop is None and candidates:
        rotation_prop = candidates[0]

    if rotation_prop is None:
        print(
            "   !! bNetInitialRotation BoolProperty не найден"
        )
    else:
        print(
            "   bNetInitialRotation metadata:"
        )
        print(
            "      object=%s addr=0x%08X class=%s"
            % (
                objs.path(rotation_prop),
                rotation_prop,
                objs.class_name(rotation_prop),
            )
        )

        prop_off = mem.try_u32(
            rotation_prop + UPROPERTY_OFFSET,
            None,
        )

        if prop_off is None:
            print(
                "      !! UProperty::Offset unreadable"
            )
        else:
            print(
                "      PropertyOffset=0x%X"
                % prop_off
            )

            if bitmask_member_off is None:
                print(
                    "      BitMask unavailable"
                )
            else:
                mask = mem.try_u32(
                    rotation_prop + bitmask_member_off,
                    None,
                )

                if mask is None:
                    print(
                        "      !! BitMask unreadable"
                    )
                elif mask == 0 or (mask & (mask - 1)) != 0:
                    print(
                        "      !! BitMask candidate is not one-hot: "
                        "0x%08X"
                        % mask
                    )
                else:
                    raw_value = mem.try_u32(
                        cdo + prop_off,
                        None,
                    )

                    if raw_value is None:
                        print(
                            "      !! CDO storage unreadable"
                        )
                    else:
                        enabled = (raw_value & mask) != 0

                        print(
                            "      BitMask=0x%08X "
                            "CDO raw=0x%08X -> %s"
                            % (
                                mask,
                                raw_value,
                                "TRUE" if enabled else "FALSE",
                            )
                        )

    # PlayerController initial actor bunch always serializes NetPlayerIndex
    # after spawn transform. The main local player must receive zero.
    net_player_prop = _find_object_by_path(
        objs,
        groups,
        "Engine.PlayerController.NetPlayerIndex",
    )

    if net_player_prop is None:
        candidates = _find_objects_named(
            objs,
            groups,
            "NetPlayerIndex",
            package="Engine",
        )
        if candidates:
            net_player_prop = candidates[0]

    if net_player_prop is not None:
        npi_off = mem.try_u32(
            net_player_prop + UPROPERTY_OFFSET,
            None,
        )

        if npi_off is not None:
            try:
                default_npi = mem.u8(cdo + npi_off)
            except Exception:
                default_npi = None

            print(
                "   NetPlayerIndex:"
            )
            print(
                "      PropertyOffset=0x%X CDO default=%s"
                % (
                    npi_off,
                    str(default_npi)
                    if default_npi is not None
                    else "?",
                )
            )

    print(
        "\n   REQUIRED initial PC actor payload:"
    )
    print(
        "      1) UObject package-map ref -> "
        "Default__cAPBPlayerController global=%d"
        % global_index
    )
    print(
        "      2) FVector::SerializeCompressed spawn location"
    )
    print(
        "      3) compressed rotation ONLY if "
        "bNetInitialRotation == TRUE"
    )
    print(
        "      4) BYTE NetPlayerIndex = 0"
    )
    print(
        "      5) optional initial reflected property stream"
    )

    return {
        "cdo": cdo,
        "local_netindex": local,
        "global_netindex": global_index,
    }


# ---------------------------------------------------------------------------
# cAPBPlayerController ClassNetCache / FieldNetIndex probe
# ---------------------------------------------------------------------------

def _outermost_package_name(objs, mem, obj):
    cur = obj
    seen = set()

    while cur and cur not in seen:
        seen.add(cur)
        try:
            outer = mem.ptr(cur + UO_OUTER)
        except MemErr:
            return None

        if not outer:
            try:
                return objs.name(cur)
            except Exception:
                return None

        cur = outer

    return None


def _is_netfield_object(objs, obj):
    try:
        cls = objs.class_name(obj)
    except Exception:
        return False

    return cls == "Function" or cls.endswith("Property")


def _scan_uclass_netfields_offset(objs, mem, cls_obj):
    candidates = []

    for off in range(0x80, 0x181, 4):
        try:
            data, num, maxv = _read_tarray_header(mem, cls_obj + off)
        except MemErr:
            continue

        if num < 1 or num > 4096:
            continue
        if maxv < num or maxv > 8192:
            continue
        if not data:
            continue

        sample_n = min(num, 256)
        readable = 0
        netfield_like = 0
        direct_outer = 0

        for i in range(sample_n):
            p = mem.try_u32(data + i * 4, None)
            if p is None or p == 0:
                continue

            readable += 1

            if _is_netfield_object(objs, p):
                netfield_like += 1

            try:
                if mem.ptr(p + UO_OUTER) == cls_obj:
                    direct_outer += 1
            except MemErr:
                pass

        if readable == 0:
            continue

        # NetFields should overwhelmingly be UFunction/UProperty pointers and
        # normally be owned directly by this UClass.
        score = netfield_like * 1000 + direct_outer * 10

        if netfield_like >= int(readable * 0.90):
            candidates.append({
                "off": off,
                "data": data,
                "num": num,
                "max": maxv,
                "readable": readable,
                "netfield_like": netfield_like,
                "direct_outer": direct_outer,
                "score": score,
            })

    candidates.sort(
        key=lambda c: (
            -c["score"],
            0 if c["off"] == 0x10C else 1,
            c["off"],
        )
    )

    return candidates


def _read_class_netfields_at(mem, cls_obj, off):
    data, num, maxv = _read_tarray_header(mem, cls_obj + off)
    out = []

    for i in range(num):
        p = mem.try_u32(data + i * 4, None)
        if p:
            out.append(p)

    return data, num, maxv, out


def _class_super(mem, objs, cls_obj, verbose=False):
    """
    APB's exact SDK-generator target has:
        sizeof(UObject) = 0x40
        UField::Next    = +0x40
        UStruct unknown = +0x44..+0x4B
        UStruct::SuperField = +0x4C

    v9 incorrectly treated +0x40 as SuperField, which is why it lost the
    inheritance chain.  Prefer +0x4C, but also scan nearby pointer-sized slots
    and require the target to be a UClass.
    """
    preferred = 0x4C
    offsets = [preferred] + [
        off for off in range(0x40, 0x81, 4)
        if off != preferred
    ]

    hits = []

    for off in offsets:
        p = mem.try_u32(cls_obj + off, None)
        if not p:
            continue

        try:
            if objs.class_name(p) != "Class":
                continue
            path = objs.path(p)
        except Exception:
            continue

        # A superclass should not point back to the same class.
        if p == cls_obj:
            continue

        hits.append((off, p, path))

    if verbose:
        if hits:
            print(
                "      superclass pointer candidates for %s:"
                % objs.path(cls_obj)
            )
            for off, p, path in hits:
                print(
                    "         +0x%02X -> 0x%08X %s%s"
                    % (
                        off,
                        p,
                        path,
                        "  [preferred]" if off == preferred else "",
                    )
                )
        else:
            print(
                "      superclass pointer candidates for %s: <none>"
                % objs.path(cls_obj)
            )

    # Strong preference for the exact-target layout.
    for off, p, path in hits:
        if off == preferred:
            return p

    # Fallback only if there is a unique semantic candidate.
    if len(hits) == 1:
        return hits[0][1]

    return 0


def probe_playercontroller_netfields(
    objs,
    mem,
    groups,
    netindex_off,
    target_handles=(80, 138, 158),
):
    print("\n== cAPBPlayerController ClassNetCache probe ==")

    class_candidates = []

    for o in groups.get("APBGame", []):
        try:
            if (
                objs.name(o) == "cAPBPlayerController"
                and objs.class_name(o) == "Class"
            ):
                class_candidates.append(o)
        except Exception:
            pass

    if not class_candidates:
        print("!! Class APBGame.cAPBPlayerController не найден")
        return None

    cls_obj = class_candidates[0]

    print(
        "   class=%s addr=0x%08X"
        % (objs.path(cls_obj), cls_obj)
    )

    candidates = _scan_uclass_netfields_offset(
        objs,
        mem,
        cls_obj,
    )

    if not candidates:
        print("!! UClass::NetFields candidate не найден")
        return None

    print("   UClass::NetFields candidates:")

    for c in candidates[:8]:
        print(
            "      +0x%03X Data=0x%08X Num=%d Max=%d "
            "fieldLike=%d/%d directOuter=%d"
            % (
                c["off"],
                c["data"],
                c["num"],
                c["max"],
                c["netfield_like"],
                c["readable"],
                c["direct_outer"],
            )
        )

    netfields_off = candidates[0]["off"]

    print(
        "   -> using UClass::NetFields = +0x%03X"
        % netfields_off
    )

    # Build inheritance chain root -> cAPBPlayerController.
    chain = []
    cur = cls_obj
    seen = set()

    while cur and cur not in seen:
        seen.add(cur)
        chain.append(cur)
        cur = _class_super(
            mem,
            objs,
            cur,
            verbose=True,
        )

    chain.reverse()

    print("   inheritance chain:")

    for c in chain:
        print(
            "      0x%08X %s"
            % (c, objs.path(c))
        )

    expected = _expected_map_state(
        objs,
        mem,
        groups,
        DEFAULT_MAP_PACKAGES,
        netindex_off,
    )

    supported = {}

    if expected:
        for row in expected:
            supported[row["name"]] = row["object_count"]

    entries = []
    next_handle = 0

    for c in chain:
        try:
            data, num, maxv, fields = _read_class_netfields_at(
                mem,
                c,
                netfields_off,
            )
        except MemErr:
            print(
                "   !! unreadable NetFields for %s"
                % objs.path(c)
            )
            continue

        class_base = next_handle
        added = 0

        for field in fields:
            raw_ni = mem.try_u32(field + netindex_off, None)
            if raw_ni is None:
                continue

            local_ni = sgn32(raw_ni)
            if local_ni < 0:
                continue

            pkg = _outermost_package_name(
                objs,
                mem,
                field,
            )

            if pkg not in supported:
                continue

            if local_ni >= supported[pkg]:
                continue

            handle = next_handle
            next_handle += 1
            added += 1

            entries.append({
                "handle": handle,
                "field": field,
                "path": objs.path(field),
                "name": objs.name(field),
                "class": objs.class_name(field),
                "owner_class": objs.path(c),
                "package": pkg,
                "local_netindex": local_ni,
            })

        print(
            "   %-45s FieldsBase=%-4d added=%-4d MaxIndex=%d"
            % (
                objs.path(c),
                class_base,
                added,
                next_handle,
            )
        )

    print(
        "\n   computed cAPBPlayerController GetMaxIndex()=%d"
        % next_handle
    )

    # Do not compare against the historical 634 from an older APB
    # emulator/build.  For this build the cache must be derived from the live
    # inheritance chain itself.  The useful self-check is arithmetic:
    # every class starts at the previous class' MaxIndex, and the final
    # GetMaxIndex equals the total number of supported live NetFields added.
    arithmetic_total = len(entries)
    arithmetic_ok = arithmetic_total == next_handle

    if arithmetic_ok:
        print(
            "   -> ClassNetCache arithmetic self-check: PASS "
            "(sum(chain added)=%d == GetMaxIndex)"
            % arithmetic_total
        )
        print(
            "   -> observed runtime-derived GetMaxIndex for this build = %d"
            % next_handle
        )
    else:
        print(
            "   !! ClassNetCache arithmetic self-check: FAIL "
            "(sum(chain added)=%d, GetMaxIndex=%d)"
            % (arithmetic_total, next_handle)
        )

    targets = set(int(x) for x in target_handles)

    print("\n   requested handles:")

    by_handle = {e["handle"]: e for e in entries}

    for h in sorted(targets):
        e = by_handle.get(h)

        if e is None:
            print(
                "      %3d -> NOT FOUND"
                % h
            )
        else:
            print(
                "      %3d -> %-8s %s "
                "(NetIndex=%d package=%s)"
                % (
                    h,
                    e["class"],
                    e["path"],
                    e["local_netindex"],
                    e["package"],
                )
            )

    print("\n   DISTRICT_ENTER / hosting-related net functions:")

    matches = []

    for e in entries:
        if e["class"] != "Function":
            continue

        upper = e["name"].upper()

        if (
            "DISTRICT_ENTER" in upper
            or "GC2DS" in upper
            or "DS2GC" in upper
            or "HOST" in upper
        ):
            matches.append(e)

    if not matches:
        print("      <none>")
    else:
        for e in matches:
            print(
                "      %3d -> %s"
                % (e["handle"], e["path"])
            )

    print(
        "\n   packet-log correlation already observed:"
    )
    print(
        "      reliable seq=1 198 bits -> first handle 138"
    )
    print(
        "      reliable seq=2 176 bits -> first handle 158 "
        "(contains 'PlayerWaiting')"
    )
    print(
        "      unreliable 155 bits every ~1s -> first handle 80"
    )

    return {
        "netfields_off": netfields_off,
        "max_index": next_handle,
        "self_check_pass": arithmetic_ok,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Live class-instance / inheritance probe
# ---------------------------------------------------------------------------

def _find_class_by_path(objs, groups, wanted_path):
    for o in _iter_all_group_objects(groups):
        try:
            if (
                objs.class_name(o) == "Class"
                and objs.path(o) == wanted_path
            ):
                return o
        except Exception:
            pass
    return None


def _is_class_or_subclass_of(mem, objs, cls_obj, target_cls):
    cur = cls_obj
    seen = set()

    while cur and cur not in seen:
        seen.add(cur)

        if cur == target_cls:
            return True

        cur = _class_super(
            mem,
            objs,
            cur,
            verbose=False,
        )

    return False


def _active_default_package_bases(
    objs,
    mem,
    groups,
    netindex_off,
):
    expected = _expected_map_state(
        objs,
        mem,
        groups,
        DEFAULT_MAP_PACKAGES,
        netindex_off,
    )

    if expected is None:
        return {}

    return {
        row["name"]: {
            "base": row["object_base"],
            "count": row["object_count"],
        }
        for row in expected
    }


def probe_class_instances(
    objs,
    mem,
    groups,
    class_path,
    netindex_off,
    include_subclasses=True,
    limit=200,
):
    print(
        "\n== live class instances: %s =="
        % class_path
    )

    target_cls = _find_class_by_path(
        objs,
        groups,
        class_path,
    )

    if not target_cls:
        print("!! UClass не найден")
        return None

    print(
        "   target UClass=0x%08X"
        % target_cls
    )

    print("   UClass inheritance:")
    cur = target_cls
    seen = set()
    depth = 0

    while cur and cur not in seen and depth < 64:
        seen.add(cur)

        print(
            "      %2d 0x%08X %s"
            % (
                depth,
                cur,
                objs.path(cur),
            )
        )

        cur = _class_super(
            mem,
            objs,
            cur,
            verbose=False,
        )
        depth += 1

    bases = _active_default_package_bases(
        objs,
        mem,
        groups,
        netindex_off,
    )

    matches = []

    for pkg, lst in groups.items():
        for o in lst:
            cls_ptr = mem.try_u32(
                o + UO_CLASS,
                None,
            )

            if not cls_ptr:
                continue

            if include_subclasses:
                is_match = _is_class_or_subclass_of(
                    mem,
                    objs,
                    cls_ptr,
                    target_cls,
                )
            else:
                is_match = cls_ptr == target_cls

            if not is_match:
                continue

            raw_net = mem.try_u32(
                o + netindex_off,
                None,
            )

            local_net = (
                sgn32(raw_net)
                if raw_net is not None
                else None
            )

            global_net = None
            base_info = bases.get(pkg)

            if (
                base_info is not None
                and local_net is not None
                and 0 <= local_net < base_info["count"]
            ):
                global_net = (
                    base_info["base"]
                    + local_net
                )

            matches.append(
                {
                    "obj": o,
                    "path": objs.path(o),
                    "name": objs.name(o),
                    "class": objs.class_name(o),
                    "class_ptr": cls_ptr,
                    "package": pkg,
                    "local_net": local_net,
                    "global_net": global_net,
                }
            )

    matches.sort(
        key=lambda r: (
            r["package"],
            r["class"],
            r["path"],
            r["obj"],
        )
    )

    print(
        "   matching live objects: %d%s"
        % (
            len(matches),
            " (target + subclasses)"
            if include_subclasses
            else " (exact class only)",
        )
    )

    if not matches:
        print("      <none>")
        return {
            "target_class": target_cls,
            "matches": [],
        }

    for row in matches[:limit]:
        local_text = (
            str(row["local_net"])
            if row["local_net"] is not None
            else "?"
        )
        global_text = (
            str(row["global_net"])
            if row["global_net"] is not None
            else "-"
        )

        print(
            "      0x%08X %-28s "
            "pkg=%-24s localNet=%-7s globalNet=%-7s"
            % (
                row["obj"],
                row["class"],
                row["package"],
                local_text,
                global_text,
            )
        )
        print(
            "            %s"
            % row["path"]
        )

    if len(matches) > limit:
        print(
            "      ... ещё %d"
            % (len(matches) - limit)
        )

    by_package = defaultdict(int)
    net_supported = 0

    for row in matches:
        by_package[row["package"]] += 1
        if row["global_net"] is not None:
            net_supported += 1

    print("\n   package summary:")

    for pkg, count in sorted(
        by_package.items(),
        key=lambda kv: (-kv[1], kv[0]),
    ):
        print(
            "      %-28s %d"
            % (pkg, count)
        )

    print(
        "\n   objects directly addressable through current "
        "Core/Engine/APBGame PackageMap: %d/%d"
        % (net_supported, len(matches))
    )

    return {
        "target_class": target_cls,
        "matches": matches,
    }


# ---------------------------------------------------------------------------
# UFunction parameter / RPC signature probe
# ---------------------------------------------------------------------------

UFIELD_NEXT = 0x40
USTRUCT_SUPERFIELD = 0x4C
USTRUCT_CHILDREN = 0x50

UPROPERTY_ARRAY_DIM = 0x44
UPROPERTY_ELEMENT_SIZE = 0x48
UPROPERTY_FLAGS = 0x4C       # uint64
UPROPERTY_PROPERTY_SIZE = 0x54
UPROPERTY_OFFSET_LIVE = 0x64
UPROPERTY_TYPE_SLOT = 0x74

CPF_OPTIONAL_PARM = 0x0000000000000010
CPF_NET           = 0x0000000000000020
CPF_PARM          = 0x0000000000000080
CPF_OUT_PARM      = 0x0000000000000100
CPF_SKIP_PARM     = 0x0000000000000200
CPF_RETURN_PARM   = 0x0000000000000400
CPF_COERCE_PARM   = 0x0000000000000800

_PARAM_FLAG_NAMES = (
    (CPF_OPTIONAL_PARM, "OptionalParm"),
    (CPF_NET, "Net"),
    (CPF_PARM, "Parm"),
    (CPF_OUT_PARM, "OutParm"),
    (CPF_SKIP_PARM, "SkipParm"),
    (CPF_RETURN_PARM, "ReturnParm"),
    (CPF_COERCE_PARM, "CoerceParm"),
)


def _try_u64(mem, addr):
    lo = mem.try_u32(addr, None)
    hi = mem.try_u32(addr + 4, None)
    if lo is None or hi is None:
        return None
    return lo | (hi << 32)


def _format_property_flags(flags):
    if flags is None:
        return "?"

    names = [
        name
        for bit, name in _PARAM_FLAG_NAMES
        if flags & bit
    ]

    if names:
        return "|".join(names)

    return "0"


def _find_functions_by_name(objs, groups, query):
    exact = []
    partial = []
    q = query.lower()

    for o in _iter_all_group_objects(groups):
        try:
            if objs.class_name(o) != "Function":
                continue
            name = objs.name(o)
            path = objs.path(o)
        except Exception:
            continue

        if name == query or path == query:
            exact.append(o)
        elif q in name.lower() or q in path.lower():
            partial.append(o)

    return exact if exact else partial


def _describe_object_ptr(objs, ptr):
    if not ptr:
        return "<null>"
    try:
        return "%s @0x%08X" % (objs.path(ptr), ptr)
    except Exception:
        return "0x%08X" % ptr


def _read_enum_names(objs, mem, enum_obj, limit=64):
    # APB target: UEnum inherits UField (sizeof 0x44), then TArray<FName>.
    try:
        data, num, maxv = _read_tarray_header(mem, enum_obj + 0x44)
    except MemErr:
        return None

    if not data or num < 0 or num > 4096 or maxv < num:
        return None

    names = []

    for i in range(min(num, limit)):
        try:
            idx = mem.u32(data + i * 8)
            number = mem.u32(data + i * 8 + 4)
            base = objs.names.get(idx)
        except Exception:
            base = None
            number = 0

        if base is None:
            names.append("<bad:%d>" % i)
        elif number:
            names.append("%s_%d" % (base, number))
        else:
            names.append(base)

    return {
        "num": num,
        "max": maxv,
        "names": names,
        "truncated": num > limit,
    }


def _property_type_details(objs, mem, prop):
    cls = objs.class_name(prop)
    slot = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, None)

    if cls == "BoolProperty":
        return "BitMask=0x%08X" % (slot or 0)

    if cls == "ByteProperty":
        if not slot:
            return "Enum=<null> (raw byte)"
        enum_info = _read_enum_names(objs, mem, slot)
        if enum_info is None:
            return "Enum=%s" % _describe_object_ptr(objs, slot)
        preview = ", ".join(enum_info["names"][:12])
        if enum_info["truncated"]:
            preview += ", ..."
        return (
            "Enum=%s Num=%d [%s]"
            % (
                _describe_object_ptr(objs, slot),
                enum_info["num"],
                preview,
            )
        )

    if cls in ("ObjectProperty", "ClassProperty"):
        text = "PropertyClass=%s" % _describe_object_ptr(objs, slot)
        if cls == "ClassProperty":
            meta = mem.try_u32(prop + UPROPERTY_TYPE_SLOT + 4, None)
            text += " MetaClass=%s" % _describe_object_ptr(objs, meta or 0)
        return text

    if cls == "InterfaceProperty":
        return "InterfaceClass=%s" % _describe_object_ptr(objs, slot)

    if cls == "StructProperty":
        return "Struct=%s" % _describe_object_ptr(objs, slot)

    if cls == "ArrayProperty":
        return "Inner=%s" % _describe_object_ptr(objs, slot)

    if cls == "MapProperty":
        key = slot or 0
        value = mem.try_u32(prop + UPROPERTY_TYPE_SLOT + 4, None) or 0
        return (
            "Key=%s Value=%s"
            % (
                _describe_object_ptr(objs, key),
                _describe_object_ptr(objs, value),
            )
        )

    if cls == "DelegateProperty":
        return "SignatureFunction=%s" % _describe_object_ptr(objs, slot)

    return ""


def _walk_function_children(objs, mem, function_obj, max_nodes=512):
    children = []
    current = mem.try_u32(function_obj + USTRUCT_CHILDREN, None) or 0
    seen = set()

    while current and current not in seen and len(children) < max_nodes:
        seen.add(current)

        try:
            cls = objs.class_name(current)
            name = objs.name(current)
            path = objs.path(current)
        except Exception:
            cls = "<bad>"
            name = "<bad>"
            path = "<bad>"

        children.append(
            {
                "obj": current,
                "class": cls,
                "name": name,
                "path": path,
            }
        )

        current = mem.try_u32(current + UFIELD_NEXT, None) or 0

    return children


def probe_function_params(
    objs,
    mem,
    groups,
    query,
    netindex_off,
):
    print(
        "\n== UFunction parameter probe: %s =="
        % query
    )

    funcs = _find_functions_by_name(
        objs,
        groups,
        query,
    )

    if not funcs:
        print("!! UFunction не найден")
        return None

    if len(funcs) > 1:
        print(
            "   найдено %d совпадений; печатаю все"
            % len(funcs)
        )

    results = []

    for fn in funcs:
        try:
            path = objs.path(fn)
            name = objs.name(fn)
        except Exception:
            path = "<bad>"
            name = "<bad>"

        raw_ni = mem.try_u32(fn + netindex_off, None)
        netindex = sgn32(raw_ni) if raw_ni is not None else None

        super_field = mem.try_u32(fn + USTRUCT_SUPERFIELD, None) or 0
        children_ptr = mem.try_u32(fn + USTRUCT_CHILDREN, None) or 0
        struct_property_size = mem.try_u32(fn + 0x54, None)

        print(
            "\n   Function: %s"
            % path
        )
        print(
            "      addr=0x%08X NetIndex=%s"
            % (
                fn,
                str(netindex)
                if netindex is not None
                else "?",
            )
        )
        print(
            "      UStruct::SuperField(+0x4C)=%s"
            % _describe_object_ptr(objs, super_field)
        )
        print(
            "      UStruct::Children(+0x50)=0x%08X"
            % children_ptr
        )
        print(
            "      UStruct::PropertySize(+0x54)=%s"
            % (
                "0x%X" % struct_property_size
                if struct_property_size is not None
                else "?"
            )
        )

        children = _walk_function_children(
            objs,
            mem,
            fn,
        )

        print(
            "      child chain nodes=%d"
            % len(children)
        )

        params = []
        returns = []
        non_params = []

        for child in children:
            obj = child["obj"]
            cls = child["class"]

            if not cls.endswith("Property"):
                non_params.append(child)
                continue

            array_dim = mem.try_u32(
                obj + UPROPERTY_ARRAY_DIM,
                None,
            )
            elem_size = mem.try_u32(
                obj + UPROPERTY_ELEMENT_SIZE,
                None,
            )
            flags = _try_u64(
                mem,
                obj + UPROPERTY_FLAGS,
            )
            prop_size = mem.try_u32(
                obj + UPROPERTY_PROPERTY_SIZE,
                None,
            )
            offset = mem.try_u32(
                obj + UPROPERTY_OFFSET_LIVE,
                None,
            )

            row = dict(child)
            row.update(
                {
                    "array_dim": array_dim,
                    "element_size": elem_size,
                    "flags": flags,
                    "property_size": prop_size,
                    "offset": offset,
                    "details": _property_type_details(
                        objs,
                        mem,
                        obj,
                    ),
                }
            )

            if flags is not None and (flags & CPF_RETURN_PARM):
                returns.append(row)
            elif flags is not None and (flags & CPF_PARM):
                params.append(row)
            else:
                non_params.append(row)

        # UE3 serializes function parameters in property-chain order; offsets
        # are printed too as a cross-check against the params memory layout.
        print("\n      PARAMETERS (CPF_Parm && !CPF_ReturnParm):")

        if not params:
            print("         <none>")
        else:
            for i, p in enumerate(params):
                print(
                    "         [%02d] %-18s %-32s "
                    "Off=%-5s Elem=%-5s Arr=%-3s "
                    "PropSize=%-5s Flags=%s"
                    % (
                        i,
                        p["class"],
                        p["name"],
                        (
                            "0x%X" % p["offset"]
                            if p["offset"] is not None
                            else "?"
                        ),
                        (
                            "0x%X" % p["element_size"]
                            if p["element_size"] is not None
                            else "?"
                        ),
                        str(p["array_dim"])
                        if p["array_dim"] is not None
                        else "?",
                        (
                            "0x%X" % p["property_size"]
                            if p["property_size"] is not None
                            else "?"
                        ),
                        _format_property_flags(
                            p["flags"],
                        ),
                    )
                )
                if p["details"]:
                    print(
                        "              %s"
                        % p["details"]
                    )

        print("\n      RETURN PARAMETERS:")

        if not returns:
            print("         <none>")
        else:
            for p in returns:
                print(
                    "         %-18s %-32s Off=%s Flags=%s"
                    % (
                        p["class"],
                        p["name"],
                        (
                            "0x%X" % p["offset"]
                            if p["offset"] is not None
                            else "?"
                        ),
                        _format_property_flags(
                            p["flags"],
                        ),
                    )
                )

        if non_params:
            print(
                "\n      NON-PARAM CHILDREN / sanity:"
            )
            for p in non_params[:32]:
                print(
                    "         %-18s %s"
                    % (
                        p["class"],
                        p["path"],
                    )
                )
            if len(non_params) > 32:
                print(
                    "         ... %d more"
                    % (len(non_params) - 32)
                )

        # A conservative derived params span. This is NOT declared
        # UFunction::ParmsSize; it is computed from live property offsets.
        span = 0

        for p in params + returns:
            off = p["offset"]
            elem = p["element_size"]
            arr = p["array_dim"]

            if off is None or elem is None:
                continue

            count = arr if arr not in (None, 0) else 1
            span = max(
                span,
                off + elem * count,
            )

        print(
            "\n      derived params memory span >= 0x%X bytes"
            % span
        )
        print(
            "      NOTE: это вычисленный span по UProperty::Offset/ElementSize, "
            "не утверждение о native UFunction::ParmsSize offset."
        )

        results.append(
            {
                "function": fn,
                "path": path,
                "netindex": netindex,
                "params": params,
                "returns": returns,
                "children": children,
                "derived_span": span,
            }
        )

    return results


# ---------------------------------------------------------------------------
# Direct live FClassNetCache probe
# ---------------------------------------------------------------------------

# Stock UE3 32-bit FClassNetCache layout from UnCoreNet.h:
#
#   +0x00 TArray<FFieldNetCache*> RepProperties
#   +0x0C INT FieldsBase
#   +0x10 FClassNetCache* Super
#   +0x14 INT RepConditionCount
#   +0x18 UClass* Class
#   +0x1C TArray<FFieldNetCache> Fields
#
# FFieldNetCache:
#   +0x00 UField* Field
#   +0x04 INT FieldNetIndex
#   +0x08 INT ConditionIndex
#
FCLASSNETCACHE_REP_PROPERTIES = 0x00
FCLASSNETCACHE_FIELDS_BASE = 0x0C
FCLASSNETCACHE_SUPER = 0x10
FCLASSNETCACHE_REP_CONDITION_COUNT = 0x14
FCLASSNETCACHE_CLASS = 0x18
FCLASSNETCACHE_FIELDS = 0x1C

FFIELDNETCACHE_SIZE = 0x0C
FFIELDNETCACHE_FIELD = 0x00
FFIELDNETCACHE_INDEX = 0x04
FFIELDNETCACHE_CONDITION_INDEX = 0x08


def _win_readable_regions(pid):
    """
    Enumerate committed readable regions in a 32-bit target process.

    This code deliberately uses Win32 directly instead of depending on
    apb_reflect internals, so the probe remains compatible with the existing
    LiveProcess wrapper.
    """
    if sys.platform != "win32":
        raise RuntimeError(
            "--probe-live-classnetcache requires Windows"
        )

    kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    )

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("PartitionId", ctypes.c_ushort),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    OpenProcess.restype = ctypes.c_void_p

    VirtualQueryEx = kernel32.VirtualQueryEx
    VirtualQueryEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    VirtualQueryEx.restype = ctypes.c_size_t

    handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        int(pid),
    )

    if not handle:
        raise RuntimeError(
            "OpenProcess failed: %d"
            % ctypes.get_last_error()
        )

    addr = 0
    max_addr = 0x100000000

    try:
        while addr < max_addr:
            mbi = MEMORY_BASIC_INFORMATION()

            got = VirtualQueryEx(
                handle,
                ctypes.c_void_p(addr),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )

            if not got:
                # On a 32-bit target the useful address space ends below 4 GB.
                break

            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)

            if size <= 0:
                addr += 0x1000
                continue

            protect = int(mbi.Protect)

            if (
                int(mbi.State) == MEM_COMMIT
                and not (protect & PAGE_GUARD)
                and not (protect & PAGE_NOACCESS)
            ):
                yield handle, base, size

            next_addr = base + size
            if next_addr <= addr:
                break
            addr = next_addr

    finally:
        kernel32.CloseHandle(handle)


def _scan_process_u32(pid, value, max_hits=20000):
    """
    Return addresses where the little-endian uint32 value occurs in committed
    readable memory. Reads in chunks, preserving 3-byte overlap.
    """
    kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    )

    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    ReadProcessMemory.restype = ctypes.c_int

    pattern = struct.pack("<I", value & 0xFFFFFFFF)
    hits = []
    chunk_size = 1024 * 1024

    # _win_readable_regions owns/closes its handle after iteration. We need a
    # stable handle for each yielded iteration, and consume the generator in
    # one pass.
    for handle, base, size in _win_readable_regions(pid):
        offset = 0
        overlap = b""
        overlap_addr = base

        while offset < size:
            want = min(
                chunk_size,
                size - offset,
            )

            buf = ctypes.create_string_buffer(want)
            got = ctypes.c_size_t(0)

            ok = ReadProcessMemory(
                handle,
                ctypes.c_void_p(base + offset),
                buf,
                want,
                ctypes.byref(got),
            )

            if not ok or got.value == 0:
                overlap = b""
                offset += want
                continue

            data = overlap + buf.raw[:got.value]
            data_base = (
                overlap_addr
                if overlap
                else base + offset
            )

            pos = 0
            while True:
                found = data.find(pattern, pos)
                if found < 0:
                    break

                addr = data_base + found

                if addr % 4 == 0:
                    hits.append(addr)

                    if len(hits) >= max_hits:
                        return hits

                pos = found + 1

            keep = min(3, len(data))
            overlap = data[-keep:]
            overlap_addr = (
                base + offset + got.value - keep
            )

            offset += got.value

    return hits


def _find_class_object(
    objs,
    groups,
    package_name,
    class_name,
):
    for o in groups.get(package_name, []):
        try:
            if (
                objs.class_name(o) == "Class"
                and objs.name(o) == class_name
            ):
                return o
        except Exception:
            pass

    return None


def _read_fieldnetcache_records(
    objs,
    mem,
    data,
    num,
    limit=None,
):
    out = []
    count = num if limit is None else min(num, limit)

    for i in range(count):
        rec = data + i * FFIELDNETCACHE_SIZE

        field = mem.try_u32(
            rec + FFIELDNETCACHE_FIELD,
            None,
        )
        raw_index = mem.try_u32(
            rec + FFIELDNETCACHE_INDEX,
            None,
        )
        raw_condition = mem.try_u32(
            rec + FFIELDNETCACHE_CONDITION_INDEX,
            None,
        )

        if (
            field is None
            or raw_index is None
            or raw_condition is None
        ):
            return None

        try:
            field_class = objs.class_name(field)
            field_name = objs.name(field)
            field_path = objs.path(field)
        except Exception:
            field_class = "<bad>"
            field_name = "<bad>"
            field_path = "<bad>"

        out.append(
            {
                "record": rec,
                "field": field,
                "index": sgn32(raw_index),
                "condition": sgn32(raw_condition),
                "class": field_class,
                "name": field_name,
                "path": field_path,
            }
        )

    return out


def _validate_classnetcache_candidate(
    objs,
    mem,
    candidate,
    expected_class,
    expected_netfields=None,
):
    class_ptr = mem.try_u32(
        candidate + FCLASSNETCACHE_CLASS,
        None,
    )

    if class_ptr != expected_class:
        return None

    # Strong independent invariant: live FClassNetCache::Super must correspond
    # to the live UClass::SuperField.  This is especially important for
    # classes with zero own NetFields, where an arbitrary zeroed structure
    # containing the UClass pointer could otherwise look valid.
    expected_super_class = _class_super(
        mem,
        objs,
        expected_class,
        verbose=False,
    )

    fields_base_raw = mem.try_u32(
        candidate + FCLASSNETCACHE_FIELDS_BASE,
        None,
    )
    super_ptr = mem.try_u32(
        candidate + FCLASSNETCACHE_SUPER,
        None,
    )
    rep_cond_raw = mem.try_u32(
        candidate + FCLASSNETCACHE_REP_CONDITION_COUNT,
        None,
    )

    fields_data = mem.try_u32(
        candidate + FCLASSNETCACHE_FIELDS,
        None,
    )
    fields_num_raw = mem.try_u32(
        candidate + FCLASSNETCACHE_FIELDS + 4,
        None,
    )
    fields_max_raw = mem.try_u32(
        candidate + FCLASSNETCACHE_FIELDS + 8,
        None,
    )

    if None in (
        fields_base_raw,
        super_ptr,
        rep_cond_raw,
        fields_data,
        fields_num_raw,
        fields_max_raw,
    ):
        return None

    fields_base = sgn32(fields_base_raw)
    rep_cond = sgn32(rep_cond_raw)
    fields_num = sgn32(fields_num_raw)
    fields_max = sgn32(fields_max_raw)

    if expected_super_class:
        if not super_ptr:
            return None

        actual_super_class = mem.try_u32(
            super_ptr + FCLASSNETCACHE_CLASS,
            None,
        )

        if actual_super_class != expected_super_class:
            return None
    else:
        # Core.Object/root-class cache has no superclass.
        if super_ptr:
            actual_super_class = mem.try_u32(
                super_ptr + FCLASSNETCACHE_CLASS,
                None,
            )
            if actual_super_class:
                return None

    if fields_base < 0 or fields_base > 10000:
        return None

    if rep_cond < 0 or rep_cond > 10000:
        return None

    if fields_num < 0 or fields_num > 5000:
        return None

    if fields_max < fields_num or fields_max > 10000:
        return None

    if fields_num > 0 and not fields_data:
        return None

    if expected_super_class:
        super_fields_base_raw = mem.try_u32(
            super_ptr + FCLASSNETCACHE_FIELDS_BASE,
            None,
        )
        super_fields_num_raw = mem.try_u32(
            super_ptr + FCLASSNETCACHE_FIELDS + 4,
            None,
        )

        if (
            super_fields_base_raw is None
            or super_fields_num_raw is None
        ):
            return None

        super_get_max = (
            sgn32(super_fields_base_raw)
            + sgn32(super_fields_num_raw)
        )

        if fields_base != super_get_max:
            return None

    sample_num = min(fields_num, 128)

    records = _read_fieldnetcache_records(
        objs,
        mem,
        fields_data,
        fields_num,
        limit=sample_num,
    )

    if records is None:
        return None

    valid_type = 0
    sequential_index = 0
    expected_member = 0

    expected_set = (
        set(expected_netfields)
        if expected_netfields is not None
        else None
    )

    for i, rec in enumerate(records):
        cls = rec["class"]

        if cls == "Function" or cls.endswith("Property"):
            valid_type += 1

        if rec["index"] == fields_base + i:
            sequential_index += 1

        if (
            expected_set is not None
            and rec["field"] in expected_set
        ):
            expected_member += 1

    if sample_num:
        if valid_type < int(sample_num * 0.90):
            return None
        if sequential_index != sample_num:
            return None

    # If we know the UClass::NetFields array, the cache's own Fields should be
    # drawn from it after SupportsObject filtering. Require strong membership.
    if (
        expected_set is not None
        and sample_num
        and expected_member < int(sample_num * 0.90)
    ):
        return None

    return {
        "addr": candidate,
        "fields_base": fields_base,
        "super": super_ptr,
        "rep_condition_count": rep_cond,
        "class": class_ptr,
        "fields_data": fields_data,
        "fields_num": fields_num,
        "fields_max": fields_max,
        "get_max_index": fields_base + fields_num,
        "sample_valid_type": valid_type,
        "sample_sequential": sequential_index,
        "sample_expected_member": expected_member,
        "sample_num": sample_num,
    }


def _get_class_netfields_for_validation(
    objs,
    mem,
    cls_obj,
    netfields_off=0xF4,
):
    try:
        data, num, maxv = _read_tarray_header(
            mem,
            cls_obj + netfields_off,
        )
    except MemErr:
        return []

    if (
        not data
        or num < 0
        or num > 5000
        or maxv < num
    ):
        return []

    fields = []

    for i in range(num):
        p = mem.try_u32(
            data + i * 4,
            None,
        )
        if p:
            fields.append(p)

    return fields


def _validate_super_cache(
    objs,
    mem,
    cache_addr,
):
    class_ptr = mem.try_u32(
        cache_addr + FCLASSNETCACHE_CLASS,
        None,
    )

    if not class_ptr:
        return None

    expected_fields = _get_class_netfields_for_validation(
        objs,
        mem,
        class_ptr,
    )

    return _validate_classnetcache_candidate(
        objs,
        mem,
        cache_addr,
        class_ptr,
        expected_fields,
    )


def probe_live_classnetcache(
    objs,
    mem,
    groups,
    target_handles=(80, 138, 139, 158),
    target_class_path="APBGame.cAPBPlayerController",
    name_filters=(),
):
    print(
        "\n== direct live FClassNetCache probe =="
    )

    if "." not in target_class_path:
        print(
            "!! --classnetcache-class должен быть Package.Class, "
            "например APBGame.cAPBPlayerController"
        )
        return None

    target_package, target_class_name = target_class_path.split(".", 1)

    target_class = _find_class_object(
        objs,
        groups,
        target_package,
        target_class_name,
    )

    if not target_class:
        print(
            "!! %s UClass не найден"
            % target_class_path
        )
        return None

    print(
        "   target class: %s @0x%08X"
        % (
            objs.path(target_class),
            target_class,
        )
    )

    expected_netfields = _get_class_netfields_for_validation(
        objs,
        mem,
        target_class,
    )

    print(
        "   live UClass::NetFields(+0xF4): %d pointers"
        % len(expected_netfields)
    )

    print(
        "   scanning committed readable process memory for UClass*..."
    )

    hits = _scan_process_u32(
        mem.pid,
        target_class,
        max_hits=50000,
    )

    print(
        "   raw aligned pointer hits: %d"
        % len(hits)
    )

    candidates = []

    for hit in hits:
        candidate = hit - FCLASSNETCACHE_CLASS

        if candidate <= 0:
            continue

        parsed = _validate_classnetcache_candidate(
            objs,
            mem,
            candidate,
            target_class,
            expected_netfields,
        )

        if parsed is not None:
            candidates.append(parsed)

    # De-duplicate if the same structure was seen more than once.
    by_addr = {
        c["addr"]: c
        for c in candidates
    }
    candidates = list(by_addr.values())

    if not candidates:
        print(
            "!! валидный FClassNetCache для "
            "%s не найден" % target_class_path
        )
        print(
            "   Это не доказывает отсутствие cache: "
            "возможен APB-specific layout."
        )
        return None

    candidates.sort(
        key=lambda c: (
            -c["sample_expected_member"],
            -c["sample_valid_type"],
            c["addr"],
        )
    )

    print(
        "   validated FClassNetCache candidates: %d"
        % len(candidates)
    )

    for c in candidates[:8]:
        print(
            "      0x%08X FieldsBase=%d Fields.Num=%d "
            "Fields.Max=%d GetMaxIndex=%d Super=0x%08X "
            "RepCond=%d sample=%d/%d netfield-members"
            % (
                c["addr"],
                c["fields_base"],
                c["fields_num"],
                c["fields_max"],
                c["get_max_index"],
                c["super"],
                c["rep_condition_count"],
                c["sample_expected_member"],
                c["sample_num"],
            )
        )

    cache = candidates[0]

    print(
        "\n   -> selected live cache 0x%08X"
        % cache["addr"]
    )
    print(
        "      FieldsBase=%d"
        % cache["fields_base"]
    )
    print(
        "      Fields.Num=%d"
        % cache["fields_num"]
    )
    print(
        "      LIVE GetMaxIndex()=%d"
        % cache["get_max_index"]
    )

    # Follow exact cache->Super pointers, independently validating every node.
    chain = []
    cur = cache
    seen = set()

    while cur and cur["addr"] not in seen:
        seen.add(cur["addr"])
        chain.append(cur)

        super_addr = cur["super"]

        if not super_addr:
            break

        parent = _validate_super_cache(
            objs,
            mem,
            super_addr,
        )

        if parent is None:
            print(
                "   !! Super cache 0x%08X failed validation"
                % super_addr
            )
            break

        cur = parent

    print(
        "\n   live FClassNetCache super chain:"
    )

    for c in chain:
        try:
            class_path = objs.path(c["class"])
        except Exception:
            class_path = "<bad>"

        print(
            "      0x%08X %-45s "
            "Base=%-4d Num=%-4d Max=%d"
            % (
                c["addr"],
                class_path,
                c["fields_base"],
                c["fields_num"],
                c["get_max_index"],
            )
        )

    # Direct equivalent of FClassNetCache::GetFromIndex().
    print(
        "\n   DIRECT GetFromIndex(handle):"
    )

    resolved = {}

    for handle in sorted(set(int(x) for x in target_handles)):
        found = None

        for c in chain:
            lo = c["fields_base"]
            hi = lo + c["fields_num"]

            if lo <= handle < hi:
                rec_addr = (
                    c["fields_data"]
                    + (handle - lo) * FFIELDNETCACHE_SIZE
                )

                records = _read_fieldnetcache_records(
                    objs,
                    mem,
                    rec_addr,
                    1,
                    limit=1,
                )

                if records:
                    found = records[0]
                break

        if found is None:
            print(
                "      %3d -> NOT FOUND"
                % handle
            )
            continue

        resolved[handle] = found

        print(
            "      %3d -> %-18s %s"
            % (
                handle,
                found["class"],
                found["path"],
            )
        )
        print(
            "            stored FieldNetIndex=%d "
            "ConditionIndex=%d Field*=0x%08X"
            % (
                found["index"],
                found["condition"],
                found["field"],
            )
        )

    normalized_filters = tuple(
        f.strip().lower()
        for f in name_filters
        if f.strip()
    )

    if normalized_filters:
        print(
            "\n   DIRECT live cache name search:"
        )
        print(
            "      filters: %s"
            % ", ".join(normalized_filters)
        )

        matches = []

        for c in chain:
            records = _read_fieldnetcache_records(
                objs,
                mem,
                c["fields_data"],
                c["fields_num"],
                limit=None,
            )

            if records is None:
                continue

            for rec in records:
                haystack = (
                    rec["name"] + " " + rec["path"]
                ).lower()

                matched = [
                    f
                    for f in normalized_filters
                    if f in haystack
                ]

                if matched:
                    row = dict(rec)
                    row["matched"] = matched
                    matches.append(row)

        matches.sort(
            key=lambda r: (
                r["index"],
                r["path"],
            )
        )

        if not matches:
            print("      <none>")
        else:
            for rec in matches:
                print(
                    "      %3d -> %-18s %s"
                    % (
                        rec["index"],
                        rec["class"],
                        rec["path"],
                    )
                )
                print(
                    "            ConditionIndex=%d "
                    "matches=%s"
                    % (
                        rec["condition"],
                        ",".join(rec["matched"]),
                    )
                )

    print(
        "\n   proof status:"
    )
    print(
        "      LIVE GetMaxIndex and handle mappings above come from the "
        "actual heap FClassNetCache used by this process, not reconstruction."
    )

    return {
        "cache": cache,
        "chain": chain,
        "resolved": resolved,
    }



# ---------------------------------------------------------------------------
# v18 operator-oriented commands
# ---------------------------------------------------------------------------

# APB 1.13.1 layout follows the stock 32-bit UE3 UFunction layout:
# UObject(0x40) + UField.Next(4) + UStruct fields -> FunctionFlags at +0x88.
# Keep this explicitly separate from UProperty::PropertyFlags.
UFUNCTION_FLAGS = 0x88

_FUNCTION_FLAG_NAMES = (
    (0x00000001, "Final"),
    (0x00000002, "Defined"),
    (0x00000004, "Iterator"),
    (0x00000008, "Latent"),
    (0x00000010, "PreOperator"),
    (0x00000020, "Singular"),
    (0x00000040, "Net"),
    (0x00000080, "NetReliable"),
    (0x00000100, "Simulated"),
    (0x00000200, "Exec"),
    (0x00000400, "Native"),
    (0x00000800, "Event"),
    (0x00001000, "Operator"),
    (0x00002000, "Static"),
    (0x00004000, "HasOptionalParms"),
    (0x00008000, "Const"),
    (0x00020000, "Public"),
    (0x00040000, "Private"),
    (0x00080000, "Protected"),
    (0x00100000, "Delegate"),
    (0x00200000, "NetServer"),
    (0x00400000, "HasOutParms"),
    (0x00800000, "HasDefaults"),
    (0x01000000, "NetClient"),
    (0x02000000, "DLLImport"),
)

_PROPERTY_FLAG_NAMES_FULL = (
    (0x0000000000000001, "Editable"),
    (0x0000000000000002, "Const"),
    (0x0000000000000004, "Input"),
    (0x0000000000000008, "ExportObject"),
    (0x0000000000000010, "OptionalParm"),
    (0x0000000000000020, "Net"),
    (0x0000000000000040, "EditFixedSize"),
    (0x0000000000000080, "Parm"),
    (0x0000000000000100, "OutParm"),
    (0x0000000000000200, "SkipParm"),
    (0x0000000000000400, "ReturnParm"),
    (0x0000000000000800, "CoerceParm"),
    (0x0000000000001000, "Native"),
    (0x0000000000002000, "Transient"),
    (0x0000000000004000, "Config"),
    (0x0000000000008000, "Localized"),
    (0x0000000000020000, "EditConst"),
    (0x0000000000040000, "GlobalConfig"),
    (0x0000000000080000, "Component"),
    (0x0000000000100000, "AlwaysInit"),
    (0x0000000000200000, "DuplicateTransient"),
    (0x0000000000400000, "CtorLink"),
    (0x0000000000800000, "NoExport"),
    (0x0000000001000000, "NoImport"),
    (0x0000000002000000, "NoClear"),
    (0x0000000004000000, "EditInline"),
    (0x0000000010000000, "EditInlineUse"),
    (0x0000000020000000, "Deprecated"),
    (0x0000000040000000, "DataBinding"),
    (0x0000000080000000, "SerializeText"),
    (0x0000000100000000, "RepNotify"),
    (0x0000000200000000, "Interp"),
    (0x0000000400000000, "NonTransactional"),
    (0x0000000800000000, "EditorOnly"),
    (0x0000001000000000, "NotForConsole"),
    (0x0000002000000000, "RepRetry"),
    (0x0000004000000000, "PrivateWrite"),
    (0x0000008000000000, "ProtectedWrite"),
    (0x0000010000000000, "ArchetypeProperty"),
    (0x0000020000000000, "EditHide"),
    (0x0000040000000000, "EditTextBox"),
    (0x0000100000000000, "CrossLevelPassive"),
    (0x0000200000000000, "CrossLevelActive"),
)


def _format_named_flags(flags, table):
    if flags is None:
        return "?"
    parts = []
    known = 0
    for bit, name in table:
        if flags & bit:
            parts.append("0x%X:%s" % (bit, name))
            known |= bit
    unknown = flags & ~known
    if unknown:
        parts.append("0x%X:Unknown" % unknown)
    return ";".join(parts) + (";" if parts else "")


def _function_flags_data(mem, fn):
    flags = mem.try_u32(fn + UFUNCTION_FLAGS, None)
    return flags, _format_named_flags(flags, _FUNCTION_FLAG_NAMES)


def _property_flags_full_text(flags):
    return _format_named_flags(flags, _PROPERTY_FLAG_NAMES_FULL)


def _resolve_one_uclass(objs, groups, query):
    matches = _resolve_uclass_query(objs, groups, query)
    if not matches:
        print("!! UClass не найден: %s" % query)
        return None
    if len(matches) != 1:
        print("!! имя класса неоднозначно: %s" % query)
        for o in matches[:50]:
            print("   0x%08X %s" % (o, objs.path(o)))
        print("   Укажи полный Package.Class.")
        return None
    return matches[0]


def _class_chain_target_to_root(objs, mem, target):
    out = []
    cur = target
    seen = set()
    while cur and cur not in seen and len(out) < 128:
        seen.add(cur)
        out.append(cur)
        cur = _class_super(mem, objs, cur, verbose=False)
    return out


def _class_chain_root_to_target(objs, mem, target):
    return list(reversed(_class_chain_target_to_root(objs, mem, target)))


def _direct_properties_for_class(objs, mem, cls_obj):
    out = []
    for child in _walk_struct_children(objs, mem, cls_obj):
        if not child["class"].endswith("Property"):
            continue
        flags = _try_u64(mem, child["obj"] + UPROPERTY_FLAGS)
        if flags is not None and (flags & CPF_PARM):
            continue
        out.append(child["obj"])
    return out


def _direct_functions_for_class(objs, mem, cls_obj, include_states=True):
    out = []
    for child in _walk_struct_children(objs, mem, cls_obj):
        if child["class"] == "Function":
            out.append((child["obj"], None))
        elif include_states and child["class"] == "State":
            state_path = child["path"]
            for sc in _walk_struct_children(objs, mem, child["obj"]):
                if sc["class"] == "Function":
                    out.append((sc["obj"], state_path))
    return out


def command_instances(
    objs,
    mem,
    groups,
    query,
    netindex_off,
    include_subclasses=True,
    limit=200,
):
    target = _resolve_one_uclass(objs, groups, query)
    if target is None:
        return None
    return probe_class_instances(
        objs,
        mem,
        groups,
        objs.path(target),
        netindex_off,
        include_subclasses=include_subclasses,
        limit=limit,
    )


def _known_object_addresses(groups):
    # build_groups already performed the expensive GObjects traversal.
    return {
        o
        for lst in groups.values()
        for o in lst
    }


def _read_fstring_live(mem, addr, max_chars=512):
    data = mem.try_u32(addr, None)
    num = mem.try_u32(addr + 4, None)
    maxv = mem.try_u32(addr + 8, None)
    if data is None or num is None or maxv is None:
        return "<unreadable FString>"
    num = sgn32(num)
    maxv = sgn32(maxv)
    if num < 0 or maxv < num or num > 1_000_000:
        return "<invalid FString Data=0x%08X Num=%d Max=%d>" % (
            data or 0, num, maxv
        )
    if not data or num == 0:
        return '""'
    take = min(num, max_chars)
    try:
        raw = mem.read(data, take * 2)
        text = raw.decode("utf-16-le", "replace").rstrip("\x00")
    except Exception:
        return "<unreadable FString Data=0x%08X Num=%d Max=%d>" % (
            data, num, maxv
        )
    suffix = "..." if num > max_chars else ""
    return '%r%s (Num=%d Max=%d Data=0x%08X)' % (
        text, suffix, num, maxv, data
    )


def _safe_raw_hex(mem, addr, size, limit=32):
    if size is None or size <= 0:
        size = 4
    take = min(int(size), limit)
    try:
        raw = mem.read(addr, take)
        text = " ".join("%02X" % b for b in raw)
        if size > take:
            text += " ..."
        return text
    except Exception:
        return "<unreadable>"


def _instance_property_value(
    objs,
    mem,
    known_objects,
    instance,
    prop,
):
    cls = objs.class_name(prop)
    off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
    elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None)
    arr = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None)
    if off is None:
        return "<offset unreadable>"
    addr = instance + off

    try:
        if cls == "BoolProperty":
            mask = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, 0) or 0
            raw = mem.try_u32(addr, None)
            if raw is None:
                return "<unreadable>"
            return "%s (raw=0x%08X mask=0x%08X)" % (
                "true" if (raw & mask) else "false",
                raw,
                mask,
            )

        if cls == "ByteProperty":
            raw = mem.read(addr, 1)[0]
            enum_ptr = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, None) or 0
            if enum_ptr:
                enum_info = _read_enum_names(objs, mem, enum_ptr, limit=512)
                if enum_info and raw < len(enum_info["names"]):
                    return "%d (%s)" % (raw, enum_info["names"][raw])
            return str(raw)

        if cls == "IntProperty":
            return str(struct.unpack("<i", mem.read(addr, 4))[0])

        if cls in ("UIntProperty",):
            return str(struct.unpack("<I", mem.read(addr, 4))[0])

        if cls == "FloatProperty":
            v = struct.unpack("<f", mem.read(addr, 4))[0]
            return "%.9g" % v

        if cls == "DoubleProperty":
            v = struct.unpack("<d", mem.read(addr, 8))[0]
            return "%.17g" % v

        if cls in ("QWordProperty", "UInt64Property"):
            return str(struct.unpack("<Q", mem.read(addr, 8))[0])

        if cls == "NameProperty":
            idx, number = struct.unpack("<II", mem.read(addr, 8))
            return "%s (Index=%d Number=%d)" % (
                objs.names.fmt(idx, number), idx, number
            )

        if cls == "StrProperty":
            return _read_fstring_live(mem, addr)

        if cls in (
            "ObjectProperty",
            "ClassProperty",
            "ComponentProperty",
            "InterfaceProperty",
        ):
            ptr = mem.try_u32(addr, None)
            if ptr is None:
                return "<unreadable>"
            if not ptr:
                return "<null>"
            if ptr in known_objects:
                return "0x%08X %s" % (ptr, objs.path(ptr))
            return "0x%08X <not in recognized GObjects set>" % ptr

        if cls == "ArrayProperty":
            data = mem.try_u32(addr, None)
            num = mem.try_u32(addr + 4, None)
            maxv = mem.try_u32(addr + 8, None)
            if data is None or num is None or maxv is None:
                return "<unreadable TArray>"
            return "TArray(Data=0x%08X Num=%d Max=%d)" % (
                data or 0, sgn32(num), sgn32(maxv)
            )

        if cls == "StructProperty":
            return "raw[%s] %s" % (
                _fmt_optional_int(elem, hex_mode=True),
                _safe_raw_hex(mem, addr, elem),
            )

        if cls == "MapProperty":
            return "raw %s" % _safe_raw_hex(mem, addr, max(elem or 0, 12))

        if cls == "DelegateProperty":
            return "raw %s" % _safe_raw_hex(mem, addr, elem or 12)

        size = (elem or 1) * max(arr or 1, 1)
        return "raw[%s] %s" % (
            _fmt_optional_int(size, hex_mode=True),
            _safe_raw_hex(mem, addr, size),
        )
    except Exception as exc:
        return "<read error: %s>" % exc


def dump_instance_fields(
    objs,
    mem,
    groups,
    address,
    netindex_off,
    include_inherited=False,
):
    known_objects = _known_object_addresses(groups)
    if address not in known_objects:
        print(
            "!! 0x%08X не найден среди распознанных live GObjects"
            % address
        )
        return None

    cls_obj = mem.try_u32(address + UO_CLASS, None) or 0
    if not cls_obj:
        print("!! UObject::Class unreadable/null")
        return None

    package_bases = _active_default_package_bases(
        objs, mem, groups, netindex_off
    )
    ident = _object_net_identity(
        objs, mem, address, netindex_off, package_bases
    )

    print("\n============================================================")
    print("INSTANCE FIELD STATE: 0x%08X" % address)
    print("============================================================")
    print("[OBJECT]")
    print("  Path              : %s" % objs.path(address))
    print("  Class             : %s" % objs.path(cls_obj))
    print("  Address           : 0x%08X" % address)
    print("  Package           : %s" % (ident["package"] or "-"))
    print("  UObject NetIndex  : %s" % _fmt_optional_int(ident["local_netindex"]))
    print("  Global NetIndex   : %s" % _fmt_optional_int(ident["global_netindex"]))
    print(
        "  Field scope       : %s"
        % ("own + inherited" if include_inherited else "own only")
    )

    chain = (
        _class_chain_root_to_target(objs, mem, cls_obj)
        if include_inherited
        else [cls_obj]
    )

    rows = []
    for owner in chain:
        for prop in _direct_properties_for_class(objs, mem, owner):
            off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
            flags = _try_u64(mem, prop + UPROPERTY_FLAGS)
            rows.append({
                "owner": objs.path(owner),
                "prop": prop,
                "name": objs.name(prop),
                "type": objs.class_name(prop),
                "offset": off,
                "element_size": mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None),
                "array_dim": mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None),
                "flags": flags,
                "details": _property_type_details(objs, mem, prop),
                "value": _instance_property_value(
                    objs, mem, known_objects, address, prop
                ),
            })

    rows.sort(
        key=lambda r: (
            r["offset"] if r["offset"] is not None else 0xFFFFFFFF,
            r["owner"],
            r["name"],
        )
    )

    print("\n[FIELDS] %d" % len(rows))
    for r in rows:
        print(
            "  %-8s %-18s %-36s = %s"
            % (
                _fmt_optional_int(r["offset"], hex_mode=True),
                r["type"],
                r["name"],
                r["value"],
            )
        )
        print("           owner=%s" % r["owner"])
        print(
            "           elem=%s arr=%s flags=%s"
            % (
                _fmt_optional_int(r["element_size"], hex_mode=True),
                _fmt_optional_int(r["array_dim"]),
                _property_flags_full_text(r["flags"]),
            )
        )
        if r["details"]:
            print("           %s" % r["details"])

    return rows


def list_class_functions(
    objs,
    mem,
    groups,
    query,
    netindex_off,
    include_inherited=False,
):
    target = _resolve_one_uclass(objs, groups, query)
    if target is None:
        return None

    package_bases = _active_default_package_bases(
        objs, mem, groups, netindex_off
    )
    classes = (
        _class_chain_root_to_target(objs, mem, target)
        if include_inherited
        else [target]
    )

    # Try live cache first; fall back to derived mapping.
    live = _find_live_classnetcache_quiet(objs, mem, target)
    if live:
        field_map = live["field_map"]
        mapping_source = "LIVE"
        field_max = live["cache"]["get_max_index"]
    else:
        derived = _reconstruct_classnet_field_map(
            objs,
            mem,
            _class_chain_root_to_target(objs, mem, target),
            netindex_off,
            package_bases,
        )
        field_map = derived["field_map"] if derived else {}
        mapping_source = "DERIVED" if derived else "NONE"
        field_max = derived["get_max_index"] if derived else None

    print("\n============================================================")
    print("CLASS FUNCTIONS: %s" % objs.path(target))
    print("============================================================")
    print(
        "scope=%s networkMapping=%s fieldMax=%s"
        % (
            "own+inherited" if include_inherited else "own",
            mapping_source,
            _fmt_optional_int(field_max),
        )
    )

    rows = []
    for owner in classes:
        for fn, state in _direct_functions_for_class(objs, mem, owner):
            sig = _function_signature_data(
                objs, mem, fn, netindex_off, package_bases
            )
            net = field_map.get(fn)
            flags, flags_text = _function_flags_data(mem, fn)
            rows.append((owner, state, sig, net, flags, flags_text))

    rows.sort(
        key=lambda row: (
            objs.path(row[0]),
            row[1] or "",
            row[2]["name"],
        )
    )

    for owner, state, sig, net, flags, flags_text in rows:
        ret = "void"
        if sig["returns"]:
            ret = ", ".join(
                "%s %s" % (p["type"], p["name"])
                for p in sig["returns"]
            )
        params = ", ".join(
            "%s %s" % (p["type"], p["name"])
            for p in sig["params"]
        )
        field_text = (
            "%d [%s]" % (net["field_index"], net["source"])
            if net else "-"
        )
        scope = objs.path(owner)
        if state:
            scope += " :: state " + state
        print("\n  %s %s(%s)" % (ret, sig["name"], params))
        print("      owner=%s" % scope)
        print(
            "      UFunction=0x%08X localNet=%s globalNet=%s FieldIndex=%s"
            % (
                sig["address"],
                _fmt_optional_int(sig["local_netindex"]),
                _fmt_optional_int(sig["global_netindex"]),
                field_text,
            )
        )
        print(
            "      FunctionFlags=0x%08X %s"
            % ((flags or 0), flags_text)
        )
        for i, p in enumerate(sig["params"]):
            print(
                "      param[%02d] %-18s %-28s off=%s %s"
                % (
                    i,
                    p["type"],
                    p["name"],
                    _fmt_optional_int(p["offset"], hex_mode=True),
                    p["details"] or "",
                )
            )

    print("\n[SUMMARY] functions=%d" % len(rows))
    return rows


def _supported_direct_netfields(
    objs,
    mem,
    cls_obj,
    netindex_off,
    package_bases,
):
    supported = {
        pkg: info["count"]
        for pkg, info in package_bases.items()
    }
    out = []
    for field in _get_class_netfields_for_validation(objs, mem, cls_obj):
        raw = mem.try_u32(field + netindex_off, None)
        if raw is None:
            continue
        local_net = sgn32(raw)
        pkg = _outermost_package_name(objs, mem, field)
        if (
            local_net < 0
            or pkg not in supported
            or local_net >= supported[pkg]
        ):
            continue
        out.append(field)
    return out


def dump_class_netfields_compact(
    objs,
    mem,
    groups,
    query,
    netindex_off,
    include_inherited=False,
):
    target = _resolve_one_uclass(objs, groups, query)
    if target is None:
        return None

    package_bases = _active_default_package_bases(
        objs, mem, groups, netindex_off
    )
    chain = _class_chain_root_to_target(objs, mem, target)
    if not chain:
        return None

    derived = _reconstruct_classnet_field_map(
        objs, mem, chain, netindex_off, package_bases
    )
    if derived is None:
        print("!! невозможно построить derived ClassNetCache mapping")
        return None

    # Prefer actual heap cache when it exists, but the output remains usable
    # for classes whose cache has not yet been instantiated by UE3.
    live = _find_live_classnetcache_quiet(objs, mem, target)
    if live is not None:
        field_map = live["field_map"]
        source = "LIVE heap FClassNetCache"
        field_max = live["cache"]["get_max_index"]
        own_base = live["cache"]["fields_base"]
        own_fields = [
            rec["field"]
            for rec in (
                _read_fieldnetcache_records(
                    objs,
                    mem,
                    live["cache"]["fields_data"],
                    live["cache"]["fields_num"],
                    limit=None,
                ) or []
            )
        ]
    else:
        field_map = derived["field_map"]
        source = "DERIVED from UClass::NetFields + PackageMap"
        target_row = derived["rows"][-1]
        own_base = target_row["fields_base"]
        field_max = target_row["max_index"]
        own_fields = _supported_direct_netfields(
            objs, mem, target, netindex_off, package_bases
        )

    parent = _class_super(mem, objs, target, verbose=False)
    parent_name = objs.path(parent) if parent else "<none>"
    target_name = objs.name(target)
    package = _outermost_package_name(objs, mem, target)

    print("\n============================================================")
    print("CLASS NETFIELDS: %s" % objs.path(target))
    print("============================================================")
    print(
        "class %s extends %s"
        % (
            target_name,
            objs.name(parent) if parent else "<none>",
        )
    )
    print(
        "  base=%d ownSlots=%d fieldMax=%d (%s) [%s] order=ordinal asc"
        % (
            own_base,
            len(own_fields),
            field_max,
            source,
            package,
        )
    )

    fields_to_print = []
    if include_inherited:
        for cls in chain:
            fields_to_print.extend(
                _supported_direct_netfields(
                    objs, mem, cls, netindex_off, package_bases
                )
            )
    else:
        fields_to_print = own_fields

    # Deduplicate and sort by actual mapping handle.
    unique = []
    seen = set()
    for field in fields_to_print:
        if field in seen:
            continue
        seen.add(field)
        if field in field_map:
            unique.append(field)
    unique.sort(key=lambda f: field_map[f]["field_index"])

    for field in unique:
        net = field_map[field]
        kind = objs.class_name(field)
        name = objs.name(field)
        if kind == "Function":
            flags, flags_text = _function_flags_data(mem, field)
            kind_text = "function"
            flag_text = flags_text
        else:
            flags = _try_u64(mem, field + UPROPERTY_FLAGS)
            kind_text = "property"
            flag_text = _property_flags_full_text(flags)
        print(
            "    %-4d %-42s [%-8s] %s"
            % (
                net["field_index"],
                name,
                kind_text,
                flag_text,
            )
        )

    print(
        "\n  mappingSource=%s; UObject NetIndex and FieldIndex are separate spaces."
        % source
    )
    print(
        "  UFunction::FunctionFlags is read at +0x%X (stock UE3/APB layout); "
        "verify against known RPCs when moving to another build."
        % UFUNCTION_FLAGS
    )
    return {
        "target": target,
        "source": source,
        "base": own_base,
        "own_slots": len(own_fields),
        "field_max": field_max,
        "fields": unique,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# One-command structured UClass dump
# ---------------------------------------------------------------------------

def _resolve_uclass_query(objs, groups, query):
    q = query.strip()
    if not q:
        return []

    exact_path = []
    exact_name = []
    q_lower = q.lower()
    partial = []

    for o in _iter_all_group_objects(groups):
        try:
            if objs.class_name(o) != "Class":
                continue
            name = objs.name(o)
            path = objs.path(o)
        except Exception:
            continue

        if path == q:
            exact_path.append(o)
        elif name == q:
            exact_name.append(o)
        elif q_lower in name.lower() or q_lower in path.lower():
            partial.append(o)

    if exact_path:
        return exact_path
    if exact_name:
        return exact_name
    return partial


def _object_net_identity(
    objs,
    mem,
    obj,
    netindex_off,
    package_bases,
):
    try:
        package = _outermost_package_name(
            objs,
            mem,
            obj,
        )
    except Exception:
        package = None

    raw = mem.try_u32(
        obj + netindex_off,
        None,
    )
    local_netindex = (
        sgn32(raw)
        if raw is not None
        else None
    )

    global_netindex = None
    base_info = package_bases.get(package)

    if (
        base_info is not None
        and local_netindex is not None
        and 0 <= local_netindex < base_info["count"]
    ):
        global_netindex = (
            base_info["base"]
            + local_netindex
        )

    return {
        "package": package,
        "local_netindex": local_netindex,
        "global_netindex": global_netindex,
    }


def _walk_struct_children(
    objs,
    mem,
    struct_obj,
    max_nodes=20000,
):
    # UClass/UState/UFunction all derive from UStruct in this target.
    return _walk_function_children(
        objs,
        mem,
        struct_obj,
        max_nodes=max_nodes,
    )


def _function_signature_data(
    objs,
    mem,
    fn,
    netindex_off,
    package_bases,
):
    ident = _object_net_identity(
        objs,
        mem,
        fn,
        netindex_off,
        package_bases,
    )

    children = _walk_function_children(
        objs,
        mem,
        fn,
    )

    params = []
    returns = []

    for child in children:
        obj = child["obj"]
        cls = child["class"]

        if not cls.endswith("Property"):
            continue

        flags = _try_u64(
            mem,
            obj + UPROPERTY_FLAGS,
        )

        if flags is None or not (flags & CPF_PARM):
            continue

        row = {
            "address": obj,
            "name": child["name"],
            "path": child["path"],
            "type": cls,
            "offset": mem.try_u32(
                obj + UPROPERTY_OFFSET_LIVE,
                None,
            ),
            "element_size": mem.try_u32(
                obj + UPROPERTY_ELEMENT_SIZE,
                None,
            ),
            "array_dim": mem.try_u32(
                obj + UPROPERTY_ARRAY_DIM,
                None,
            ),
            "property_size": mem.try_u32(
                obj + UPROPERTY_PROPERTY_SIZE,
                None,
            ),
            "flags": flags,
            "flags_text": _format_property_flags(flags),
            "details": _property_type_details(
                objs,
                mem,
                obj,
            ),
        }

        if flags & CPF_RETURN_PARM:
            returns.append(row)
        else:
            params.append(row)

    return {
        "address": fn,
        "name": objs.name(fn),
        "path": objs.path(fn),
        "package": ident["package"],
        "local_netindex": ident["local_netindex"],
        "global_netindex": ident["global_netindex"],
        "property_size": mem.try_u32(
            fn + 0x54,
            None,
        ),
        "params": params,
        "returns": returns,
    }


def _collect_class_reflection_members(
    objs,
    mem,
    class_chain_root_to_target,
    netindex_off,
    package_bases,
):
    properties = []
    functions = []
    other = []

    for cls_obj in class_chain_root_to_target:
        owner_path = objs.path(cls_obj)
        direct = _walk_struct_children(
            objs,
            mem,
            cls_obj,
        )

        for child in direct:
            obj = child["obj"]
            kind = child["class"]

            if kind.endswith("Property"):
                flags = _try_u64(
                    mem,
                    obj + UPROPERTY_FLAGS,
                )

                # Parameters belong to UFunctions, not directly to a UClass;
                # this is only a defensive guard.
                if flags is not None and (flags & CPF_PARM):
                    continue

                ident = _object_net_identity(
                    objs,
                    mem,
                    obj,
                    netindex_off,
                    package_bases,
                )

                properties.append({
                    "address": obj,
                    "owner": owner_path,
                    "name": child["name"],
                    "path": child["path"],
                    "type": kind,
                    "offset": mem.try_u32(
                        obj + UPROPERTY_OFFSET_LIVE,
                        None,
                    ),
                    "element_size": mem.try_u32(
                        obj + UPROPERTY_ELEMENT_SIZE,
                        None,
                    ),
                    "array_dim": mem.try_u32(
                        obj + UPROPERTY_ARRAY_DIM,
                        None,
                    ),
                    "property_size": mem.try_u32(
                        obj + UPROPERTY_PROPERTY_SIZE,
                        None,
                    ),
                    "flags": flags,
                    "flags_text": _format_property_flags(flags),
                    "details": _property_type_details(
                        objs,
                        mem,
                        obj,
                    ),
                    "package": ident["package"],
                    "local_netindex": ident["local_netindex"],
                    "global_netindex": ident["global_netindex"],
                })
                continue

            if kind == "Function":
                fn = _function_signature_data(
                    objs,
                    mem,
                    obj,
                    netindex_off,
                    package_bases,
                )
                fn["owner"] = owner_path
                fn["state"] = None
                functions.append(fn)
                continue

            # State functions are UFunctions nested under UState rather than
            # directly under the UClass. Include them so overrides such as
            # cAPBPlayerController.Dead.ClientReceiveRespawnInfo are not lost.
            if kind == "State":
                state_path = child["path"]

                for state_child in _walk_struct_children(
                    objs,
                    mem,
                    obj,
                ):
                    if state_child["class"] != "Function":
                        continue

                    fn = _function_signature_data(
                        objs,
                        mem,
                        state_child["obj"],
                        netindex_off,
                        package_bases,
                    )
                    fn["owner"] = owner_path
                    fn["state"] = state_path
                    functions.append(fn)

                continue

            other.append({
                "address": obj,
                "owner": owner_path,
                "name": child["name"],
                "path": child["path"],
                "type": kind,
            })

    return properties, functions, other


def _find_live_classnetcache_quiet(
    objs,
    mem,
    target_class,
):
    expected_netfields = _get_class_netfields_for_validation(
        objs,
        mem,
        target_class,
    )

    hits = _scan_process_u32(
        mem.pid,
        target_class,
        max_hits=50000,
    )

    candidates = []

    for hit in hits:
        candidate = hit - FCLASSNETCACHE_CLASS

        if candidate <= 0:
            continue

        parsed = _validate_classnetcache_candidate(
            objs,
            mem,
            candidate,
            target_class,
            expected_netfields,
        )

        if parsed is not None:
            candidates.append(parsed)

    by_addr = {
        c["addr"]: c
        for c in candidates
    }
    candidates = list(by_addr.values())

    if not candidates:
        return None

    candidates.sort(
        key=lambda c: (
            -c["sample_expected_member"],
            -c["sample_valid_type"],
            c["addr"],
        )
    )

    cache = candidates[0]
    chain = []
    cur = cache
    seen = set()

    while cur and cur["addr"] not in seen:
        seen.add(cur["addr"])
        chain.append(cur)

        super_addr = cur["super"]
        if not super_addr:
            break

        parent = _validate_super_cache(
            objs,
            mem,
            super_addr,
        )

        if parent is None:
            break

        cur = parent

    field_map = {}

    for cache_node in chain:
        records = _read_fieldnetcache_records(
            objs,
            mem,
            cache_node["fields_data"],
            cache_node["fields_num"],
            limit=None,
        )

        if records is None:
            continue

        for rec in records:
            field_map[rec["field"]] = {
                "field_index": rec["index"],
                "condition_index": rec["condition"],
                "source": "LIVE",
            }

    return {
        "cache": cache,
        "chain": chain,
        "field_map": field_map,
    }


def _reconstruct_classnet_field_map(
    objs,
    mem,
    class_chain_root_to_target,
    netindex_off,
    package_bases,
):
    if not package_bases:
        return None

    supported = {
        pkg: info["count"]
        for pkg, info in package_bases.items()
    }

    field_map = {}
    next_handle = 0
    rows = []

    for cls_obj in class_chain_root_to_target:
        netfields = _get_class_netfields_for_validation(
            objs,
            mem,
            cls_obj,
        )

        fields_base = next_handle
        added = 0

        for field in netfields:
            raw = mem.try_u32(
                field + netindex_off,
                None,
            )

            if raw is None:
                continue

            local_net = sgn32(raw)
            pkg = _outermost_package_name(
                objs,
                mem,
                field,
            )

            if (
                local_net < 0
                or pkg not in supported
                or local_net >= supported[pkg]
            ):
                continue

            field_map[field] = {
                "field_index": next_handle,
                "condition_index": None,
                "source": "DERIVED",
            }

            next_handle += 1
            added += 1

        rows.append({
            "class": objs.path(cls_obj),
            "fields_base": fields_base,
            "added": added,
            "max_index": next_handle,
        })

    return {
        "field_map": field_map,
        "get_max_index": next_handle,
        "rows": rows,
    }


def _fmt_optional_int(value, hex_mode=False):
    if value is None:
        return "-"
    if hex_mode:
        return "0x%X" % value
    return str(value)


def _compact_type_name(prop_type, details):
    # Keep the exact reflection type authoritative; append pointed-to type
    # metadata instead of pretending to reconstruct full C++ declarations.
    if details:
        return "%s {%s}" % (prop_type, details)
    return prop_type


def dump_class_structured(
    objs,
    mem,
    groups,
    query,
    netindex_off,
    json_path=None,
):
    print(
        "\n============================================================"
    )
    print(
        "CLASS DUMP: %s"
        % query
    )
    print(
        "============================================================"
    )

    matches = _resolve_uclass_query(
        objs,
        groups,
        query,
    )

    if not matches:
        print("!! UClass не найден")
        return None

    if len(matches) != 1:
        print(
            "!! запрос неоднозначен: найдено %d UClass"
            % len(matches)
        )
        for cls_obj in matches[:50]:
            print(
                "   0x%08X %s"
                % (
                    cls_obj,
                    objs.path(cls_obj),
                )
            )
        if len(matches) > 50:
            print(
                "   ... ещё %d"
                % (len(matches) - 50)
            )
        print(
            "   Укажи полный Package.Class."
        )
        return None

    target_class = matches[0]
    target_path = objs.path(target_class)

    package_bases = _active_default_package_bases(
        objs,
        mem,
        groups,
        netindex_off,
    )

    target_ident = _object_net_identity(
        objs,
        mem,
        target_class,
        netindex_off,
        package_bases,
    )

    # Target -> root, then root -> target.
    chain_target_to_root = []
    cur = target_class
    seen = set()

    while cur and cur not in seen and len(chain_target_to_root) < 128:
        seen.add(cur)
        chain_target_to_root.append(cur)
        cur = _class_super(
            mem,
            objs,
            cur,
            verbose=False,
        )

    chain = list(reversed(chain_target_to_root))

    print("\n[CLASS]")
    print(
        "  Path              : %s"
        % target_path
    )
    print(
        "  Address           : 0x%08X"
        % target_class
    )
    print(
        "  Package           : %s"
        % (target_ident["package"] or "-")
    )
    print(
        "  UObject NetIndex  : %s (local package index)"
        % _fmt_optional_int(
            target_ident["local_netindex"],
        )
    )
    print(
        "  Global NetIndex   : %s (current PackageMap)"
        % _fmt_optional_int(
            target_ident["global_netindex"],
        )
    )

    print("\n[INHERITANCE] root -> target")
    for depth, cls_obj in enumerate(chain):
        ident = _object_net_identity(
            objs,
            mem,
            cls_obj,
            netindex_off,
            package_bases,
        )

        print(
            "  %2d 0x%08X %-55s "
            "localNet=%-7s globalNet=%s"
            % (
                depth,
                cls_obj,
                objs.path(cls_obj),
                _fmt_optional_int(
                    ident["local_netindex"],
                ),
                _fmt_optional_int(
                    ident["global_netindex"],
                ),
            )
        )

    print("\n[NETWORK CACHE]")
    live_cache = _find_live_classnetcache_quiet(
        objs,
        mem,
        target_class,
    )

    if live_cache is not None:
        network_source = "LIVE"
        network_map = live_cache["field_map"]
        get_max_index = live_cache["cache"]["get_max_index"]

        print(
            "  Source            : LIVE heap FClassNetCache"
        )
        print(
            "  Cache address     : 0x%08X"
            % live_cache["cache"]["addr"]
        )
        print(
            "  GetMaxIndex       : %d"
            % get_max_index
        )
        print(
            "  Cache chain nodes : %d"
            % len(live_cache["chain"])
        )
    else:
        derived = _reconstruct_classnet_field_map(
            objs,
            mem,
            chain,
            netindex_off,
            package_bases,
        )

        if derived is not None:
            network_source = "DERIVED"
            network_map = derived["field_map"]
            get_max_index = derived["get_max_index"]

            print(
                "  Source            : DERIVED from UClass::NetFields "
                "+ current PackageMap"
            )
            print(
                "  GetMaxIndex       : %d [DERIVED, not direct heap proof]"
                % get_max_index
            )
        else:
            network_source = "NONE"
            network_map = {}
            get_max_index = None

            print(
                "  Source            : unavailable"
            )
            print(
                "  FieldIndex        : cannot be assigned"
            )

    properties, functions, other = _collect_class_reflection_members(
        objs,
        mem,
        chain,
        netindex_off,
        package_bases,
    )

    for row in properties:
        net = network_map.get(row["address"])
        row["field_index"] = (
            net["field_index"]
            if net is not None
            else None
        )
        row["condition_index"] = (
            net["condition_index"]
            if net is not None
            else None
        )
        row["field_index_source"] = (
            net["source"]
            if net is not None
            else None
        )

    for row in functions:
        net = network_map.get(row["address"])
        row["field_index"] = (
            net["field_index"]
            if net is not None
            else None
        )
        row["condition_index"] = (
            net["condition_index"]
            if net is not None
            else None
        )
        row["field_index_source"] = (
            net["source"]
            if net is not None
            else None
        )

    print(
        "\n[PROPERTIES] %d total, inherited included"
        % len(properties)
    )
    print(
        "  Off      Type               Name"
        "                              Owner"
    )
    print(
        "  -------- ------------------ -------------------------------- "
        "---------------------------------------------"
    )

    for p in properties:
        off_text = _fmt_optional_int(
            p["offset"],
            hex_mode=True,
        )

        print(
            "  %-8s %-18s %-32s %s"
            % (
                off_text,
                p["type"],
                p["name"],
                p["owner"],
            )
        )
        print(
            "           addr=0x%08X localNet=%s globalNet=%s "
            "FieldIndex=%s%s"
            % (
                p["address"],
                _fmt_optional_int(
                    p["local_netindex"],
                ),
                _fmt_optional_int(
                    p["global_netindex"],
                ),
                _fmt_optional_int(
                    p["field_index"],
                ),
                (
                    " [%s]" % p["field_index_source"]
                    if p["field_index_source"]
                    else ""
                ),
            )
        )
        print(
            "           Elem=%s Arr=%s PropSize=%s Flags=%s"
            % (
                _fmt_optional_int(
                    p["element_size"],
                    hex_mode=True,
                ),
                _fmt_optional_int(
                    p["array_dim"],
                ),
                _fmt_optional_int(
                    p["property_size"],
                    hex_mode=True,
                ),
                p["flags_text"],
            )
        )
        if p["condition_index"] is not None:
            print(
                "           ConditionIndex=%d"
                % p["condition_index"]
            )
        if p["details"]:
            print(
                "           %s"
                % p["details"]
            )

    print(
        "\n[FUNCTIONS] %d total, inherited/state overrides included"
        % len(functions)
    )

    for fn in functions:
        scope = fn["owner"]
        if fn["state"]:
            scope += " :: state " + fn["state"]

        return_text = "void"
        if fn["returns"]:
            return_text = ", ".join(
                r["type"] + " " + r["name"]
                for r in fn["returns"]
            )

        params_text = ", ".join(
            "%s %s"
            % (
                p["type"],
                p["name"],
            )
            for p in fn["params"]
        )

        print(
            "\n  %s %s(%s)"
            % (
                return_text,
                fn["name"],
                params_text,
            )
        )
        print(
            "      owner=%s"
            % scope
        )
        print(
            "      addr=0x%08X localNet=%s globalNet=%s "
            "FieldIndex=%s%s"
            % (
                fn["address"],
                _fmt_optional_int(
                    fn["local_netindex"],
                ),
                _fmt_optional_int(
                    fn["global_netindex"],
                ),
                _fmt_optional_int(
                    fn["field_index"],
                ),
                (
                    " [%s]" % fn["field_index_source"]
                    if fn["field_index_source"]
                    else ""
                ),
            )
        )
        if fn["condition_index"] is not None:
            print(
                "      ConditionIndex=%d"
                % fn["condition_index"]
            )
        print(
            "      ParamsFrame/PropertySize=%s"
            % _fmt_optional_int(
                fn["property_size"],
                hex_mode=True,
            )
        )

        for i, p in enumerate(fn["params"]):
            print(
                "      param[%02d] %-18s %-28s "
                "off=%s elem=%s arr=%s"
                % (
                    i,
                    p["type"],
                    p["name"],
                    _fmt_optional_int(
                        p["offset"],
                        hex_mode=True,
                    ),
                    _fmt_optional_int(
                        p["element_size"],
                        hex_mode=True,
                    ),
                    _fmt_optional_int(
                        p["array_dim"],
                    ),
                )
            )
            if p["details"]:
                print(
                    "                %s"
                    % p["details"]
                )

        for p in fn["returns"]:
            print(
                "      return    %-18s %-28s off=%s"
                % (
                    p["type"],
                    p["name"],
                    _fmt_optional_int(
                        p["offset"],
                        hex_mode=True,
                    ),
                )
            )
            if p["details"]:
                print(
                    "                %s"
                    % p["details"]
                )

    networked_properties = sum(
        1
        for p in properties
        if p["field_index"] is not None
    )
    networked_functions = sum(
        1
        for fn in functions
        if fn["field_index"] is not None
    )

    print("\n[SUMMARY]")
    print(
        "  Properties        : %d (%d networked)"
        % (
            len(properties),
            networked_properties,
        )
    )
    print(
        "  Functions         : %d (%d networked/RPC)"
        % (
            len(functions),
            networked_functions,
        )
    )
    print(
        "  Other UField nodes: %d"
        % len(other)
    )
    print(
        "  Network mapping   : %s"
        % network_source
    )
    print(
        "  GetMaxIndex       : %s"
        % _fmt_optional_int(get_max_index)
    )
    print(
        "\n  IMPORTANT: UObject NetIndex/global NetIndex and "
        "FClassNetCache FieldIndex are different index spaces."
    )

    report = {
        "query": query,
        "class": {
            "address": target_class,
            "path": target_path,
            "package": target_ident["package"],
            "local_netindex": target_ident["local_netindex"],
            "global_netindex": target_ident["global_netindex"],
        },
        "inheritance": [
            {
                "address": cls_obj,
                "path": objs.path(cls_obj),
                **_object_net_identity(
                    objs,
                    mem,
                    cls_obj,
                    netindex_off,
                    package_bases,
                ),
            }
            for cls_obj in chain
        ],
        "network": {
            "source": network_source,
            "get_max_index": get_max_index,
            "cache_address": (
                live_cache["cache"]["addr"]
                if live_cache is not None
                else None
            ),
        },
        "properties": properties,
        "functions": functions,
        "other_fields": other,
    }

    if json_path:
        out_path = Path(json_path)
        out_path.write_text(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
            newline="\n",
        )
        print(
            "\n[JSON] written: %s"
            % out_path
        )

    return report

# ---------------------------------------------------------------------------
# Old-CSV signature guided native struct storage discovery
# ---------------------------------------------------------------------------

def _csv_is_empty(value):
    if value is None:
        return True
    text = str(value).strip()
    if not text:
        return True
    return text.lower() in ("nan", "none", "null")


def _csv_number(value):
    if _csv_is_empty(value):
        return None
    text = str(value).strip()
    try:
        if any(c in text.lower() for c in (".", "e")):
            v = float(text)
            if not math.isfinite(v):
                return None
            return v
        return int(text, 0)
    except Exception:
        try:
            v = float(text)
            if not math.isfinite(v):
                return None
            return v
        except Exception:
            return None


def _schema_column_runtime_offset(mem, col):
    prop = col["prop"]
    off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
    elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None) or 1
    if off is None:
        return None
    return int(off) + int(col.get("element_index", 0)) * int(elem)


def _csv_supported_schema(schema):
    supported = {}
    for col in schema:
        cls = col["class"]
        if cls in (
            "BoolProperty",
            "ByteProperty",
            "IntProperty",
            "UIntProperty",
            "FloatProperty",
            "DoubleProperty",
            "StrProperty",
        ):
            supported[col["column"]] = col
    return supported


def _csv_compare_value(runtime_value, csv_value, cls):
    if _csv_is_empty(csv_value):
        return None

    if cls == "StrProperty":
        old = str(csv_value).replace("\r\n", "\n").replace("\r", "\n").strip()
        cur = "" if runtime_value is None else str(runtime_value)
        cur = cur.replace("\r\n", "\n").replace("\r", "\n").strip()
        return cur == old

    old_num = _csv_number(csv_value)
    if old_num is None or runtime_value is None:
        return None

    try:
        if cls in ("FloatProperty", "DoubleProperty"):
            cur = float(runtime_value)
            old = float(old_num)
            if not math.isfinite(cur):
                return False
            tol = max(1.0e-4, abs(old) * 2.5e-4)
            return abs(cur - old) <= tol

        return int(runtime_value) == int(old_num)
    except Exception:
        return False


def _strict_row_semantics(objs, mem, base, schema):
    """
    Independent current-build sanity checks.
    This does NOT compare against the old CSV.
    """
    checked = 0
    good = 0
    nonempty_strings = 0

    # Bool backing words: no unknown bits outside the reflected masks.
    bool_masks = defaultdict(int)
    bool_offsets = {}
    for col in schema:
        if col["class"] != "BoolProperty":
            continue
        prop = col["prop"]
        off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
        if off is None:
            continue
        mask = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, 0) or 0
        bool_masks[int(off)] |= int(mask)
        bool_offsets[int(off)] = prop

    for off, mask in bool_masks.items():
        raw = mem.try_u32(base + off, None)
        checked += 1
        if raw is not None and (raw & ~mask) == 0:
            good += 1

    # Byte enums have a real reflected cardinality in this build.
    seen_byte_props = set()
    for col in schema:
        if col["class"] != "ByteProperty":
            continue
        prop = col["prop"]
        if prop in seen_byte_props:
            continue
        seen_byte_props.add(prop)

        slot = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, None)
        if not slot:
            continue
        info = _read_enum_names(objs, mem, slot, limit=1)
        if info is None or info["num"] <= 0:
            continue

        off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
        arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
        elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None) or 1
        if off is None:
            continue

        for j in range(min(int(arrdim), 8)):
            try:
                v = mem.read(base + off + j * elem, 1)[0]
            except Exception:
                checked += 1
                continue
            checked += 1
            # Allow 0xFF as a common enum "none"/sentinel representation.
            if v == 0xFF or v < info["num"]:
                good += 1

    # FString headers and contents must be structurally valid.
    seen_string_props = set()
    for col in schema:
        if col["class"] != "StrProperty":
            continue
        prop = col["prop"]
        if prop in seen_string_props:
            continue
        seen_string_props.add(prop)

        off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
        arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
        elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None) or 12
        if off is None:
            continue

        for j in range(min(int(arrdim), 4)):
            addr = base + off + j * elem
            checked += 2
            if _validate_fstring_header(mem, addr):
                good += 2
                nr = mem.try_u32(addr + 4, None)
                if nr is not None and sgn32(nr) > 1:
                    nonempty_strings += 1

    # Float data should be finite and within a broad gameplay range.
    for col in schema:
        cls = col["class"]
        if cls not in ("FloatProperty", "DoubleProperty"):
            continue
        off = _schema_column_runtime_offset(mem, col)
        if off is None:
            continue
        checked += 1
        try:
            if cls == "DoubleProperty":
                v = struct.unpack("<d", mem.read(base + off, 8))[0]
            else:
                v = struct.unpack("<f", mem.read(base + off, 4))[0]
            if math.isfinite(v) and abs(v) <= 1.0e8:
                good += 1
        except Exception:
            pass

    # Int fields with enum-ish naming should not look like arbitrary pointers.
    for col in schema:
        if col["class"] not in ("IntProperty", "UIntProperty"):
            continue
        name = col["column"].lower()
        if not (name.startswith("m_e") or name.startswith("e")):
            continue
        off = _schema_column_runtime_offset(mem, col)
        if off is None:
            continue
        checked += 1
        try:
            raw = mem.read(base + off, 4)
            if col["class"] == "UIntProperty":
                v = struct.unpack("<I", raw)[0]
                if v <= 1_000_000:
                    good += 1
            else:
                v = struct.unpack("<i", raw)[0]
                if -1 <= v <= 1_000_000:
                    good += 1
        except Exception:
            pass

    ratio = (float(good) / checked) if checked else 1.0
    return {
        "good": good,
        "checked": checked,
        "ratio": ratio,
        "nonempty_strings": nonempty_strings,
    }


def _match_row_to_csv(objs, mem, known_objects, base, row, shared_cols):
    compared = 0
    matched = 0
    mismatches = []

    for name, col in shared_cols.items():
        old = row.get(name)
        if _csv_is_empty(old):
            continue

        cur = _sdd_scalar_at(
            objs,
            mem,
            known_objects,
            base,
            col["prop"],
            col.get("element_index", 0),
        )

        ok = _csv_compare_value(cur, old, col["class"])
        if ok is None:
            continue

        compared += 1
        if ok:
            matched += 1
        elif len(mismatches) < 8:
            mismatches.append((name, old, cur))

    ratio = (float(matched) / compared) if compared else 0.0
    return {
        "compared": compared,
        "matched": matched,
        "ratio": ratio,
        "mismatches": mismatches,
    }


def _csv_anchor_candidates(rows, shared_cols, mem, requested=None):
    """
    Return (rarity, magnitude, row_index, column_name, int_value, runtime_offset)
    tuples. Only 32-bit integer current fields are used because the existing
    process scanner can search them efficiently and exactly.
    """
    allowed = {}
    for name, col in shared_cols.items():
        if col["class"] not in ("IntProperty", "UIntProperty"):
            continue
        if requested and name.lower() != requested.lower():
            continue
        off = _schema_column_runtime_offset(mem, col)
        if off is None:
            continue
        allowed[name] = (col, off)

    if requested and not allowed:
        return []

    frequencies = {}
    for name in allowed:
        freq = defaultdict(int)
        for row in rows:
            v = _csv_number(row.get(name))
            if v is None:
                continue
            try:
                iv = int(v)
            except Exception:
                continue
            if float(v) != float(iv):
                continue
            freq[iv] += 1
        frequencies[name] = freq

    anchors = []
    for ri, row in enumerate(rows):
        for name, (col, off) in allowed.items():
            v = _csv_number(row.get(name))
            if v is None:
                continue
            try:
                iv = int(v)
            except Exception:
                continue
            if float(v) != float(iv):
                continue
            # Zero produces too many raw hits and carries little identity.
            if iv == 0:
                continue
            if col["class"] == "UIntProperty" and not (0 <= iv <= 0xFFFFFFFF):
                continue
            if col["class"] == "IntProperty" and not (-0x80000000 <= iv <= 0x7FFFFFFF):
                continue

            freq = frequencies[name].get(iv, 999999)
            # Prefer values that occur once in the old table and larger
            # magnitudes (fewer accidental occurrences in arbitrary memory).
            anchors.append(
                (
                    freq,
                    -min(abs(iv), 2_000_000_000),
                    ri,
                    name,
                    iv,
                    off,
                )
            )

    anchors.sort()
    return anchors


def scan_struct_csv_signature(
    objs,
    mem,
    groups,
    struct_query,
    csv_path,
    anchor_field=None,
    anchor_rows=8,
    min_row_match=0.70,
    min_semantic=0.85,
    max_hits=150000,
    max_results=20,
    validate_prefix=12,
):
    st = _resolve_one_struct(objs, groups, struct_query)
    if st is None:
        return None

    stride = mem.try_u32(st + 0x54, None)
    if not isinstance(stride, int) or stride <= 0:
        print("!! bad struct PropertySize/stride")
        return None

    path = Path(csv_path)
    if not path.exists():
        print("!! signature CSV not found: %s" % csv_path)
        return None

    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        csv_fields = list(reader.fieldnames or [])

    if not rows:
        print("!! signature CSV has no rows")
        return None

    schema = _sdd_expand_row_schema(objs, mem, st)
    supported = _csv_supported_schema(schema)
    shared_names = [name for name in csv_fields if name in supported]
    shared = {name: supported[name] for name in shared_names}

    print("\n============================================================")
    print("STRUCT CSV SIGNATURE SCAN: %s" % objs.path(st))
    print("============================================================")
    print("  current stride       : 0x%X (%d)" % (stride, stride))
    print("  old CSV              : %s" % csv_path)
    print("  old CSV rows         : %d" % len(rows))
    print("  old CSV columns      : %d" % len(csv_fields))
    print("  current columns      : %d" % len(schema))
    print("  exact shared columns : %d" % len(shared_names))
    if shared_names:
        print("    %s" % ", ".join(shared_names))
    print("  NOTE: CSV supplies signatures only; current reflection owns the layout.")

    if len(shared_names) < 3:
        print("!! too few exact shared columns for a useful signature scan")
        return []

    anchors = _csv_anchor_candidates(
        rows,
        shared,
        mem,
        requested=anchor_field,
    )

    if not anchors:
        print("!! no usable 32-bit integer anchor column/value found")
        if anchor_field:
            print("   requested --csv-anchor: %s" % anchor_field)
        return []

    # Keep one or a few highly distinctive anchors per old row, while
    # spreading anchors across different rows.
    chosen = []
    seen_rows = set()
    for item in anchors:
        ri = item[2]
        if ri in seen_rows:
            continue
        chosen.append(item)
        seen_rows.add(ri)
        if len(chosen) >= max(1, int(anchor_rows)):
            break

    print("\n[ANCHORS]")
    for freq, negmag, ri, name, value, off in chosen:
        print(
            "  oldRow=%-4d %-32s value=%-12d currentOff=0x%X oldFrequency=%d"
            % (ri, name, value, off, freq)
        )

    known = _known_object_addresses(groups)
    base_votes = defaultdict(list)
    raw_row_candidates = 0

    for freq, negmag, ri, name, value, off in chosen:
        hits = _scan_process_u32(mem.pid, value, max_hits=max_hits)
        print(
            "  scan %-32s=%d -> %d raw hits"
            % (name, value, len(hits))
        )

        for hit in hits:
            row_base = hit - off
            if row_base < 0x10000 or (row_base & 0x3):
                continue

            try:
                mem.read(row_base, min(stride, 16))
            except Exception:
                continue

            semantic = _strict_row_semantics(
                objs,
                mem,
                row_base,
                schema,
            )
            if semantic["ratio"] < min_semantic:
                continue

            matched = _match_row_to_csv(
                objs,
                mem,
                known,
                row_base,
                rows[ri],
                shared,
            )
            if matched["compared"] < min(4, len(shared_names)):
                continue
            if matched["ratio"] < min_row_match:
                continue

            raw_row_candidates += 1
            table_base = row_base - ri * stride
            if table_base < 0x10000:
                continue

            base_votes[table_base].append(
                {
                    "row_index": ri,
                    "row_base": row_base,
                    "anchor": name,
                    "anchor_value": value,
                    "row_match": matched,
                    "semantic": semantic,
                }
            )

    print("\n  signature-compatible row hits: %d" % raw_row_candidates)
    print("  candidate table bases        : %d" % len(base_votes))

    results = []
    prefix_n = min(len(rows), max(1, int(validate_prefix)))

    for table_base, votes in base_votes.items():
        total_compared = 0
        total_matched = 0
        good_rows = 0
        semantic_good = 0
        prefix_details = []

        for ri in range(prefix_n):
            row_base = table_base + ri * stride
            try:
                mem.read(row_base, min(stride, 16))
            except Exception:
                continue

            semantic = _strict_row_semantics(
                objs,
                mem,
                row_base,
                schema,
            )
            if semantic["ratio"] >= min_semantic:
                semantic_good += 1

            m = _match_row_to_csv(
                objs,
                mem,
                known,
                row_base,
                rows[ri],
                shared,
            )
            total_compared += m["compared"]
            total_matched += m["matched"]
            if (
                m["compared"] >= min(4, len(shared_names))
                and m["ratio"] >= min_row_match
                and semantic["ratio"] >= min_semantic
            ):
                good_rows += 1

            if ri < 5:
                prefix_details.append(
                    (ri, m["matched"], m["compared"], m["ratio"], semantic["ratio"])
                )

        field_ratio = (
            float(total_matched) / total_compared
            if total_compared
            else 0.0
        )

        # Multiple independently-found anchor rows voting for the exact same
        # base are very strong evidence.
        unique_vote_rows = len(set(v["row_index"] for v in votes))
        score = (
            field_ratio * 100.0
            + good_rows * 4.0
            + semantic_good * 1.5
            + unique_vote_rows * 12.0
        )

        results.append(
            {
                "data": table_base,
                "votes": votes,
                "vote_rows": unique_vote_rows,
                "prefix_rows": prefix_n,
                "good_rows": good_rows,
                "semantic_good": semantic_good,
                "matched": total_matched,
                "compared": total_compared,
                "field_ratio": field_ratio,
                "score": score,
                "prefix_details": prefix_details,
            }
        )

    results.sort(
        key=lambda r: (
            -r["vote_rows"],
            -r["good_rows"],
            -r["field_ratio"],
            -r["score"],
            r["data"],
        )
    )

    print("\n[CANDIDATE DATA BASES] total=%d showing<=%d" % (
        len(results), max_results
    ))

    if not results:
        print("  <none>")
        print(
            "  No old-order signature matched strongly enough. "
            "This can mean reordered rows, substantially changed values, "
            "or a non-contiguous/container layout."
        )
        return []

    for i, r in enumerate(results[:max_results]):
        print(
            "  #%02d Data=0x%08X votes=%d goodPrefix=%d/%d "
            "fieldMatch=%.1f%% semantic=%d/%d score=%.2f"
            % (
                i,
                r["data"],
                r["vote_rows"],
                r["good_rows"],
                r["prefix_rows"],
                r["field_ratio"] * 100.0,
                r["semantic_good"],
                r["prefix_rows"],
                r["score"],
            )
        )
        for ri, ma, co, ratio, sem in r["prefix_details"]:
            print(
                "       oldRow=%-3d fields=%d/%d (%.1f%%) semantic=%.1f%%"
                % (
                    ri, ma, co, ratio * 100.0, sem * 100.0
                )
            )

    print("\n  Inspect/export a DATA candidate (not a TArray header):")
    print(
        "    --dump-struct-run %s --data-address 0xADDRESS "
        "--row-count N --table-limit 8"
        % objs.path(st)
    )

    return results


def dump_struct_run(
    objs,
    mem,
    groups,
    struct_query,
    data_addr,
    row_count,
    limit=None,
    csv_path=None,
    json_path=None,
):
    st = _resolve_one_struct(objs, groups, struct_query)
    if st is None:
        return None

    stride = mem.try_u32(st + 0x54, None)
    if not isinstance(stride, int) or stride <= 0:
        print("!! bad struct stride")
        return None

    count = int(row_count)
    if count <= 0 or count > 1_000_000:
        print("!! invalid --row-count")
        return None

    try:
        mem.read(data_addr, min(stride, 16))
        mem.read(data_addr + (count - 1) * stride, min(stride, 16))
    except Exception:
        print("!! requested DATA range is not fully readable")
        return None

    schema = _sdd_expand_row_schema(objs, mem, st)
    known = _known_object_addresses(groups)
    take = count if limit is None else min(count, max(0, int(limit)))

    rows = []
    print("\n============================================================")
    print("STRUCT CONTIGUOUS RUN DUMP: %s" % objs.path(st))
    print("============================================================")
    print("  Data    : 0x%08X" % data_addr)
    print("  rows    : %d%s" % (
        take,
        " (limited from %d)" % count if take != count else "",
    ))
    print("  stride  : 0x%X" % stride)
    print("  columns : %d" % len(schema))

    for i in range(take):
        base = data_addr + i * stride
        row = {
            "__index": i,
            "__address": "0x%08X" % base,
        }
        for col in schema:
            row[col["column"]] = _sdd_scalar_at(
                objs,
                mem,
                known,
                base,
                col["prop"],
                col.get("element_index", 0),
            )
        rows.append(row)

        print("\n  [%d] @0x%08X" % (i, base))
        for col in schema:
            print(
                "      %-36s = %r"
                % (col["column"], row[col["column"]])
            )

    if csv_path:
        fields = ["__index", "__address"] + [
            c["column"] for c in schema
        ]
        with open(
            csv_path,
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        print("\nCSV saved: %s" % csv_path)

    if json_path:
        payload = {
            "struct": objs.path(st),
            "data": "0x%08X" % data_addr,
            "row_count": count,
            "stride": stride,
            "rows": rows,
        }
        Path(json_path).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print("JSON saved: %s" % json_path)

    return rows


# ---------------------------------------------------------------------------
# Generic UScriptStruct / nested-struct inspection
# ---------------------------------------------------------------------------

_STRUCT_OBJECT_CLASSES = ("ScriptStruct", "Struct")


def _resolve_struct_query(objs, groups, query):
    q = query.strip()
    qlow = q.lower()
    exact_path = []
    exact_name = []
    suffix = []
    contains = []

    for o in _iter_all_group_objects(groups):
        try:
            kind = objs.class_name(o)
            if kind not in _STRUCT_OBJECT_CLASSES:
                continue
            path = objs.path(o)
            name = objs.name(o)
        except Exception:
            continue

        plow = path.lower()
        nlow = name.lower()

        if plow == qlow:
            exact_path.append(o)
        elif nlow == qlow:
            exact_name.append(o)
        elif plow.endswith("." + qlow):
            suffix.append(o)
        elif qlow in plow:
            contains.append(o)

    for bucket in (exact_path, exact_name, suffix, contains):
        if bucket:
            return sorted(
                set(bucket),
                key=lambda o: (objs.path(o), o),
            )

    return []


def _resolve_one_struct(objs, groups, query):
    matches = _resolve_struct_query(objs, groups, query)

    if not matches:
        print("!! UScriptStruct/Struct не найден: %s" % query)
        return None

    if len(matches) != 1:
        print("!! имя struct неоднозначно: %s" % query)
        for o in matches[:100]:
            print(
                "   0x%08X %-12s %s"
                % (
                    o,
                    objs.class_name(o),
                    objs.path(o),
                )
            )
        print("   Укажи полный path, например APBGame.cWeapon.WeaponType.")
        return None

    return matches[0]


def _struct_chain_root_to_target(objs, mem, target):
    chain = []
    cur = target
    seen = set()

    while cur and cur not in seen and len(chain) < 128:
        seen.add(cur)
        chain.append(cur)
        cur = mem.try_u32(cur + 0x4C, None) or 0

    return list(reversed(chain))


def _struct_direct_properties(objs, mem, struct_obj):
    out = []

    for child in _walk_struct_children(objs, mem, struct_obj):
        if not child["class"].endswith("Property"):
            continue

        prop = child["obj"]
        flags = _try_u64(mem, prop + UPROPERTY_FLAGS)

        # Parameters are UFunction frame members, not data fields.
        if flags is not None and (flags & CPF_PARM):
            continue

        out.append(prop)

    out.sort(
        key=lambda p: (
            mem.try_u32(p + UPROPERTY_OFFSET_LIVE, 0x7FFFFFFF),
            objs.name(p),
            p,
        )
    )
    return out


def _expanded_column_count(objs, mem, props):
    count = 0
    for prop in props:
        arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
        count += max(1, int(arrdim))
    return count


def dump_struct_schema(
    objs,
    mem,
    groups,
    query,
    include_inherited=False,
):
    target = _resolve_one_struct(objs, groups, query)
    if target is None:
        return None

    chain = (
        _struct_chain_root_to_target(objs, mem, target)
        if include_inherited
        else [target]
    )

    print("\n============================================================")
    print("STRUCT DUMP: %s" % objs.path(target))
    print("============================================================")
    print("  Address      : 0x%08X" % target)
    print("  UObjectClass : %s" % objs.class_name(target))

    size = mem.try_u32(target + 0x54, None)
    super_obj = mem.try_u32(target + 0x4C, None) or 0

    print(
        "  PropertySize : %s"
        % (("0x%X" % size) if isinstance(size, int) else "?")
    )
    print(
        "  SuperStruct  : %s"
        % (
            _describe_object_ptr(objs, super_obj)
            if super_obj
            else "<null>"
        )
    )
    print(
        "  scope        : %s"
        % ("own + inherited" if include_inherited else "own only")
    )

    if include_inherited:
        print("\n[STRUCT INHERITANCE] root -> target")
        for i, st in enumerate(chain):
            st_size = mem.try_u32(st + 0x54, None)
            print(
                "  %2d 0x%08X %-70s size=%s"
                % (
                    i,
                    st,
                    objs.path(st),
                    ("0x%X" % st_size)
                    if isinstance(st_size, int)
                    else "?",
                )
            )

    rows = []

    for owner in chain:
        owner_path = objs.path(owner)
        for prop in _struct_direct_properties(objs, mem, owner):
            off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
            elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None)
            arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
            flags = _try_u64(mem, prop + UPROPERTY_FLAGS)

            rows.append(
                {
                    "prop": prop,
                    "owner": owner_path,
                    "offset": off,
                    "type": objs.class_name(prop),
                    "name": objs.name(prop),
                    "element_size": elem,
                    "array_dim": arrdim,
                    "flags": flags,
                    "details": _property_type_details(
                        objs,
                        mem,
                        prop,
                    ),
                }
            )

    rows.sort(
        key=lambda r: (
            r["offset"]
            if isinstance(r["offset"], int)
            else 0x7FFFFFFF,
            r["owner"],
            r["name"],
        )
    )

    print("\n[FIELDS]")
    if not rows:
        print("  <none>")
    else:
        print(
            "  Off      Type               Name"
            "                              Owner"
        )
        print(
            "  -------- ------------------ "
            "--------------------------------- "
            "---------------------------------------------"
        )

        for row in rows:
            off_text = (
                "0x%X" % row["offset"]
                if isinstance(row["offset"], int)
                else "?"
            )
            elem_text = (
                "0x%X" % row["element_size"]
                if isinstance(row["element_size"], int)
                else "?"
            )

            print(
                "  %-8s %-18s %-33s %s"
                % (
                    off_text,
                    row["type"],
                    row["name"],
                    row["owner"],
                )
            )
            print(
                "           addr=0x%08X Elem=%s Arr=%s Flags=%s"
                % (
                    row["prop"],
                    elem_text,
                    row["array_dim"],
                    _property_flags_full_text(row["flags"]),
                )
            )
            if row["details"]:
                print("           %s" % row["details"])

    print(
        "\n[SUMMARY] direct/included properties=%d "
        "CSV-style expanded columns=%d"
        % (
            len(rows),
            _expanded_column_count(
                objs,
                mem,
                [r["prop"] for r in rows],
            ),
        )
    )

    return {
        "struct": target,
        "path": objs.path(target),
        "size": size,
        "rows": rows,
    }


def list_nested_structs(
    objs,
    mem,
    groups,
    class_query,
    keyword_text=None,
    with_schema=False,
):
    cls_obj = _resolve_one_uclass(objs, groups, class_query)
    if cls_obj is None:
        return None

    class_path = objs.path(cls_obj)
    filters = tuple(
        part.strip().lower()
        for part in (keyword_text or "").split(",")
        if part.strip()
    )

    matches = []

    for o in _iter_all_group_objects(groups):
        try:
            kind = objs.class_name(o)
            if kind not in _STRUCT_OBJECT_CLASSES:
                continue
            path = objs.path(o)
        except Exception:
            continue

        if not path.startswith(class_path + "."):
            continue

        if filters:
            low = path.lower()
            if not any(f in low for f in filters):
                continue

        matches.append(o)

    matches.sort(key=lambda o: (objs.path(o), o))

    print("\n============================================================")
    print("NESTED STRUCTS UNDER: %s" % class_path)
    print("============================================================")
    print(
        "  filter : %s"
        % (", ".join(filters) if filters else "<none>")
    )
    print("  count  : %d" % len(matches))

    if not matches:
        print("  <none>")
        return []

    for st in matches:
        size = mem.try_u32(st + 0x54, None)
        props = _struct_direct_properties(objs, mem, st)

        print(
            "\n  0x%08X %-12s %s"
            % (
                st,
                objs.class_name(st),
                objs.path(st),
            )
        )
        print(
            "      size=%s fields=%d expandedColumns=%d"
            % (
                ("0x%X" % size)
                if isinstance(size, int)
                else "?",
                len(props),
                _expanded_column_count(objs, mem, props),
            )
        )

        if with_schema:
            for prop in props:
                off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
                elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None)
                arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
                flags = _try_u64(mem, prop + UPROPERTY_FLAGS)

                print(
                    "      +%-6s %-18s %-32s "
                    "Elem=%-6s Arr=%-3s Flags=%s"
                    % (
                        ("0x%X" % off)
                        if isinstance(off, int)
                        else "?",
                        objs.class_name(prop),
                        objs.name(prop),
                        ("0x%X" % elem)
                        if isinstance(elem, int)
                        else "?",
                        arrdim,
                        _property_flags_full_text(flags),
                    )
                )

                details = _property_type_details(objs, mem, prop)
                if details:
                    print("               %s" % details)

    return matches


def discover_sdd_classes(
    objs,
    groups,
    keyword_text="sdd",
):
    filters = tuple(
        part.strip().lower()
        for part in keyword_text.split(",")
        if part.strip()
    )

    matches = []

    for o in _iter_all_group_objects(groups):
        try:
            if objs.class_name(o) != "Class":
                continue
            path = objs.path(o)
            name = objs.name(o)
        except Exception:
            continue

        low = (name + " " + path).lower()

        if filters and not any(f in low for f in filters):
            continue

        matches.append(o)

    matches.sort(key=lambda o: (objs.path(o), o))

    print("\n============================================================")
    print("SDD / CLASS DISCOVERY")
    print("============================================================")
    print("  filters: %s" % ", ".join(filters))
    print("  count  : %d" % len(matches))

    for o in matches:
        print("  0x%08X %s" % (o, objs.path(o)))

    return matches


# ---------------------------------------------------------------------------
# Generic native TArray<UScriptStruct> storage scan / dump
# ---------------------------------------------------------------------------

def _struct_validation_plan(objs, mem, struct_obj):
    props = _struct_direct_properties(objs, mem, struct_obj)
    bool_masks = defaultdict(int)
    strings = []
    floats = []
    names = []
    objects = []
    arrays = []
    enumish = []
    keys = []

    for p in props:
        cls = objs.class_name(p)
        name = objs.name(p)
        off = mem.try_u32(p + UPROPERTY_OFFSET_LIVE, None)
        if off is None:
            continue
        arrdim = mem.try_u32(p + UPROPERTY_ARRAY_DIM, None) or 1
        elem = mem.try_u32(p + UPROPERTY_ELEMENT_SIZE, None) or 1
        if cls == 'BoolProperty':
            mask = mem.try_u32(p + UPROPERTY_TYPE_SLOT, 0) or 0
            bool_masks[off] |= mask
        elif cls == 'StrProperty':
            strings.append((p, off, arrdim, elem))
        elif cls in ('FloatProperty','DoubleProperty'):
            floats.append((p, off, arrdim, elem))
        elif cls == 'NameProperty':
            names.append((p, off, arrdim, elem))
        elif cls in ('ObjectProperty','ClassProperty','ComponentProperty'):
            objects.append((p, off, arrdim, elem))
        elif cls == 'ArrayProperty':
            arrays.append((p, off, arrdim, elem))
        elif cls in ('IntProperty','UIntProperty','ByteProperty'):
            low=name.lower()
            if low.startswith('m_e') or low.startswith('e'):
                enumish.append((p, off, arrdim, elem))
            if (
                low in ('m_eweapontype','m_einventoryitemtype','m_evehicle','m_evehiclesetuptype')
                or low.endswith('secondarykey')
                or low.endswith('type')
            ):
                keys.append((p, off, arrdim, elem))

    # prefer semantically strong ID/key fields first
    keys.sort(key=lambda x: (
        0 if objs.name(x[0]).lower() in (
            'm_eweapontype','m_einventoryitemtype','m_evehicle','m_evehiclesetuptype'
        ) else 1,
        x[1], objs.name(x[0])
    ))
    return {
        'props': props,
        'bool_masks': dict(bool_masks),
        'strings': strings,
        'floats': floats,
        'names': names,
        'objects': objects,
        'arrays': arrays,
        'enumish': enumish,
        'keys': keys,
    }


def _validate_fstring_header(mem, addr):
    data=mem.try_u32(addr,None); num=mem.try_u32(addr+4,None); maxv=mem.try_u32(addr+8,None)
    if data is None or num is None or maxv is None:
        return False
    num=sgn32(num); maxv=sgn32(maxv)
    if num < 0 or maxv < num or maxv > 1_000_000 or num > 100_000:
        return False
    if num == 0:
        return data in (0, None) or maxv >= 0
    if not data:
        return False
    try:
        raw=mem.read(data, min(num,16)*2)
        raw.decode('utf-16-le','strict')
        return True
    except Exception:
        return False


def _validate_tarray_header(mem, addr):
    data=mem.try_u32(addr,None); num=mem.try_u32(addr+4,None); maxv=mem.try_u32(addr+8,None)
    if data is None or num is None or maxv is None:
        return False
    num=sgn32(num); maxv=sgn32(maxv)
    if num < 0 or maxv < num or maxv > 1_000_000:
        return False
    if num == 0:
        return True
    if not data or (data & 0x3):
        return False
    try:
        mem.read(data,1)
        return True
    except Exception:
        return False


def _read_numeric_key(mem, objs, prop, row_addr):
    cls=objs.class_name(prop)
    off=mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
    if off is None: return None
    try:
        if cls == 'ByteProperty':
            return mem.read(row_addr+off,1)[0]
        if cls == 'IntProperty':
            return struct.unpack('<i',mem.read(row_addr+off,4))[0]
        if cls == 'UIntProperty':
            return struct.unpack('<I',mem.read(row_addr+off,4))[0]
    except Exception:
        return None
    return None


def _score_struct_rows(objs, mem, known_objects, data, num, stride, plan, sample_rows=8):
    sample=min(max(1,int(sample_rows)), num)
    if sample <= 0:
        return None
    # spread samples over the whole table instead of only its prefix
    if sample == 1:
        indices=[0]
    else:
        indices=sorted(set(int(round(i*(num-1)/(sample-1))) for i in range(sample)))

    good=0.0; checks=0.0; hard_fail=False
    key_values=defaultdict(list)

    for ri in indices:
        row=data + ri*stride
        try:
            mem.read(row, min(stride,16))
        except Exception:
            hard_fail=True; break

        for off,mask in plan['bool_masks'].items():
            raw=mem.try_u32(row+off,None)
            checks += 2
            if raw is not None and (raw & ~mask) == 0:
                good += 2

        for p,off,arrdim,elem in plan['strings']:
            for j in range(min(int(arrdim),4)):
                checks += 4
                if _validate_fstring_header(mem,row+off+j*elem):
                    good += 4

        for p,off,arrdim,elem in plan['floats']:
            cls=objs.class_name(p)
            for j in range(min(int(arrdim),8)):
                checks += 1
                try:
                    if cls == 'DoubleProperty':
                        v=struct.unpack('<d',mem.read(row+off+j*elem,8))[0]
                    else:
                        v=struct.unpack('<f',mem.read(row+off+j*elem,4))[0]
                    if math.isfinite(v) and abs(v) < 1.0e12:
                        good += 1
                except Exception:
                    pass

        for p,off,arrdim,elem in plan['names']:
            for j in range(min(int(arrdim),4)):
                checks += 2
                try:
                    idx,number=struct.unpack('<II',mem.read(row+off+j*elem,8))
                    if idx < objs.names.num and number < 1_000_000:
                        good += 2
                except Exception:
                    pass

        for p,off,arrdim,elem in plan['objects']:
            for j in range(min(int(arrdim),4)):
                checks += 2
                ptr=mem.try_u32(row+off+j*elem,None)
                if ptr is not None and (ptr == 0 or ptr in known_objects):
                    good += 2

        for p,off,arrdim,elem in plan['arrays']:
            for j in range(min(int(arrdim),4)):
                checks += 3
                if _validate_tarray_header(mem,row+off+j*elem):
                    good += 3

        for p,off,arrdim,elem in plan['enumish']:
            # Generic sanity only; many SDD enum-like fields are stored as INT IDs,
            # so do not assume UEnum cardinality unless the property is ByteProperty.
            for j in range(min(int(arrdim),8)):
                checks += 0.5
                try:
                    cls=objs.class_name(p)
                    if cls == 'ByteProperty':
                        v=mem.read(row+off+j*elem,1)[0]
                    elif cls == 'UIntProperty':
                        v=struct.unpack('<I',mem.read(row+off+j*elem,4))[0]
                    else:
                        v=struct.unpack('<i',mem.read(row+off+j*elem,4))[0]
                    if -1 <= v <= 10_000_000:
                        good += 0.5
                except Exception:
                    pass

        for p,off,arrdim,elem in plan['keys'][:4]:
            v=_read_numeric_key(mem,objs,p,row)
            if v is not None:
                key_values[objs.name(p)].append(v)

    if hard_fail or checks <= 0:
        return None

    # Distinctness of strong IDs is useful but only a bonus; tables can contain sentinels.
    distinct_bonus=0.0
    for name,vals in key_values.items():
        if len(vals) >= 2:
            distinct=len(set(vals))
            distinct_bonus += min(5.0, 5.0 * distinct / len(vals))
    score=100.0*good/checks + distinct_bonus
    return {
        'score':score,
        'base_score':100.0*good/checks,
        'checks':checks,
        'good':good,
        'sample_indices':indices,
        'key_values':dict(key_values),
    }


def scan_struct_tarrays(objs, mem, groups, struct_query, counts, sample_rows=8, max_results=30, max_hits_per_count=100000):
    st=_resolve_one_struct(objs,groups,struct_query)
    if st is None: return None
    stride=mem.try_u32(st+0x54,None)
    if not isinstance(stride,int) or stride <= 0 or stride > 1024*1024:
        print('!! invalid/unknown struct PropertySize')
        return None
    counts=sorted(set(int(x) for x in counts if int(x)>0))
    if not counts:
        print('!! --struct-counts must contain positive counts')
        return None
    plan=_struct_validation_plan(objs,mem,st)
    known=_known_object_addresses(groups)

    print('\n============================================================')
    print('STRUCT TARRAY STORAGE SCAN: %s' % objs.path(st))
    print('============================================================')
    print('  stride       : 0x%X (%d)' % (stride,stride))
    print('  count probes : %s' % ', '.join(str(x) for x in counts))
    print('  sample rows  : %d' % sample_rows)
    print('  NOTE         : count is a search heuristic, not proof of table identity.')

    results=[]; seen=set()
    for count in counts:
        print('  scanning Num=%d ...' % count)
        hits=_scan_process_u32(mem.pid,count,max_hits=max_hits_per_count)
        print('    raw aligned Num hits: %d' % len(hits))
        for hit in hits:
            hdr=hit-4
            if hdr in seen or hdr < 0x10000: continue
            seen.add(hdr)
            data=mem.try_u32(hdr,None); numraw=mem.try_u32(hdr+4,None); maxraw=mem.try_u32(hdr+8,None)
            if data is None or numraw is None or maxraw is None: continue
            num=sgn32(numraw); maxv=sgn32(maxraw)
            if num != count or maxv < num or maxv > max(num+65536, num*32): continue
            if not data or (data & 0x3): continue
            # First/last row must be readable at the proposed stride.
            try:
                mem.read(data, min(stride,16))
                mem.read(data+(num-1)*stride, min(stride,16))
            except Exception:
                continue
            scored=_score_struct_rows(objs,mem,known,data,num,stride,plan,sample_rows=sample_rows)
            if not scored: continue
            results.append({
                'header':hdr,'data':data,'num':num,'max':maxv,
                **scored,
            })

    results.sort(key=lambda r:(-r['score'], abs(r['max']-r['num']), r['header']))
    print('\n[CANDIDATES] total=%d showing<=%d' % (len(results),max_results))
    if not results:
        print('  <none>')
        print('  This only rules out obvious TArray<struct> candidates for the requested counts; storage may use another container/layout/count.')
        return []
    for i,r in enumerate(results[:max_results]):
        print('  #%02d TArray@0x%08X Data=0x%08X Num=%d Max=%d score=%.2f base=%.2f' % (
            i,r['header'],r['data'],r['num'],r['max'],r['score'],r['base_score']))
        if r['key_values']:
            for name,vals in r['key_values'].items():
                print('       %-28s %s' % (name, ', '.join(str(v) for v in vals)))
    print('\n  To inspect/export a candidate:')
    print('    --dump-struct-tarray %s --tarray-address 0xADDRESS --table-limit 8' % objs.path(st))
    return results


def dump_struct_tarray(objs, mem, groups, struct_query, tarray_addr, limit=None, csv_path=None, json_path=None):
    st=_resolve_one_struct(objs,groups,struct_query)
    if st is None: return None
    stride=mem.try_u32(st+0x54,None)
    if not isinstance(stride,int) or stride <= 0:
        print('!! bad struct stride')
        return None
    data=mem.try_u32(tarray_addr,None); nr=mem.try_u32(tarray_addr+4,None); mr=mem.try_u32(tarray_addr+8,None)
    if data is None or nr is None or mr is None:
        print('!! TArray header unreadable at 0x%08X' % tarray_addr); return None
    num=sgn32(nr); maxv=sgn32(mr)
    if num < 0 or maxv < num or num > 1_000_000 or not data:
        print('!! invalid TArray header: Data=0x%08X Num=%d Max=%d' % (data or 0,num,maxv)); return None
    schema=_sdd_expand_row_schema(objs,mem,st)
    known=_known_object_addresses(groups)
    take=num if limit is None else min(num,max(0,int(limit)))
    rows=[]
    print('\n============================================================')
    print('STRUCT TARRAY DUMP: %s' % objs.path(st))
    print('============================================================')
    print('  TArray : 0x%08X' % tarray_addr)
    print('  Data   : 0x%08X' % data)
    print('  Num/Max: %d/%d' % (num,maxv))
    print('  stride : 0x%X' % stride)
    print('  columns: %d' % len(schema))
    print('  rows   : %d%s' % (take, ' (limited)' if take != num else ''))

    for i in range(take):
        base=data+i*stride
        row={'__index':i,'__address':'0x%08X' % base}
        for col in schema:
            row[col['column']]=_sdd_scalar_at(objs,mem,known,base,col['prop'],col['element_index'])
        rows.append(row)
        print('\n  [%d] @0x%08X' % (i,base))
        for col in schema:
            print('      %-36s = %r' % (col['column'],row[col['column']]))

    if csv_path:
        fields=['__index','__address']+[c['column'] for c in schema]
        with open(csv_path,'w',newline='',encoding='utf-8-sig') as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
        print('\nCSV saved: %s' % csv_path)
    if json_path:
        payload={'struct':objs.path(st),'tarray':'0x%08X'%tarray_addr,'data':'0x%08X'%data,'num':num,'max':maxv,'stride':stride,'rows':rows}
        Path(json_path).write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding='utf-8')
        print('JSON saved: %s' % json_path)
    return rows


# ---------------------------------------------------------------------------
# cSDD reflection/native-storage discovery
# ---------------------------------------------------------------------------

def _sdd_keyword_list(raw):
    if raw is None:
        raw = "Weapon,Vehicle,Item,Ranged,Grenade,H2H,Setup"
    return tuple(
        part.strip().lower()
        for part in raw.split(",")
        if part.strip()
    )


def _sdd_name_matches(text, keywords):
    if not keywords:
        return True
    low = text.lower()
    return any(k in low for k in keywords)


def _sdd_print_struct_schema(objs, mem, struct_obj, indent="    "):
    size = mem.try_u32(struct_obj + 0x54, None)
    fields = _sdd_struct_fields(objs, mem, struct_obj)
    expanded = 0

    print(
        "%ssize=%s directProperties=%d"
        % (
            indent,
            ("0x%X" % size) if isinstance(size, int) else "?",
            len(fields),
        )
    )

    for prop in fields:
        name = objs.name(prop)
        cls = objs.class_name(prop)
        off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
        elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None)
        arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
        flags = _try_u64(mem, prop + UPROPERTY_FLAGS)
        expanded += max(1, int(arrdim))
        details = _property_type_details(objs, mem, prop)

        print(
            "%s  +%-6s %-18s %-36s Elem=%-6s Arr=%-3s Flags=%s"
            % (
                indent,
                ("0x%X" % off) if isinstance(off, int) else "?",
                cls,
                name,
                ("0x%X" % elem) if isinstance(elem, int) else "?",
                arrdim,
                _format_property_flags(flags),
            )
        )
        if details:
            print("%s           %s" % (indent, details))

    print("%sCSV-style expanded columns=%d" % (indent, expanded))


def _sdd_print_function_signature(objs, mem, fn, netindex_off, package_bases, indent="    "):
    d = _function_signature_data(
        objs,
        mem,
        fn,
        netindex_off,
        package_bases,
    )

    ret = "void"
    if d["returns"]:
        ret = d["returns"][0]["type"]

    params = ", ".join(
        "%s %s" % (p["type"], p["name"])
        for p in d["params"]
    )

    print(
        "%s%s %s(%s)"
        % (
            indent,
            ret,
            d["path"],
            params,
        )
    )
    print(
        "%s  UFunction=0x%08X localNet=%s globalNet=%s frameSize=%s"
        % (
            indent,
            d["address"],
            str(d["local_netindex"]) if d["local_netindex"] is not None else "-",
            str(d["global_netindex"]) if d["global_netindex"] is not None else "-",
            ("0x%X" % d["property_size"])
            if isinstance(d["property_size"], int)
            else "?",
        )
    )

    for p in d["params"]:
        print(
            "%s    param +%-6s %-18s %-28s %s"
            % (
                indent,
                ("0x%X" % p["offset"]) if isinstance(p["offset"], int) else "?",
                p["type"],
                p["name"],
                p["details"],
            )
        )


def sdd_discover(
    objs,
    mem,
    groups,
    netindex_off,
    class_query="cSDD",
    keyword_text=None,
    max_global_matches=300,
):
    cls_obj = _resolve_one_uclass(objs, groups, class_query)
    if cls_obj is None:
        return None

    target_path = objs.path(cls_obj)
    keywords = _sdd_keyword_list(keyword_text)
    package_bases = _active_default_package_bases(
        objs,
        mem,
        groups,
        netindex_off,
    )

    print("\n============================================================")
    print("SDD DISCOVERY: %s" % target_path)
    print("============================================================")
    print("  UClass   : 0x%08X" % cls_obj)
    print("  keywords : %s" % (", ".join(keywords) if keywords else "<all>"))

    instances = _exact_instances_of_uclass(objs, mem, groups, cls_obj)
    print("  exact instances:")
    if not instances:
        print("    <none>")
    else:
        for row in instances:
            print(
                "    0x%08X %-20s %s"
                % (row["obj"], row["package"], row["path"])
            )

    # Direct cSDD reflection tree.
    direct = _walk_struct_children(objs, mem, cls_obj)

    funcs = []
    nested_structs = []
    nested_enums = []
    direct_props = []
    other = []

    for child in direct:
        kind = child["class"]
        path = child["path"]
        if not _sdd_name_matches(path, keywords):
            continue

        if kind == "Function":
            funcs.append(child["obj"])
        elif kind in ("ScriptStruct", "Struct"):
            nested_structs.append(child["obj"])
        elif kind == "Enum":
            nested_enums.append(child["obj"])
        elif kind.endswith("Property"):
            direct_props.append(child["obj"])
        else:
            other.append(child["obj"])

    print("\n[DIRECT cSDD PROPERTIES matching keywords]")
    if not direct_props:
        print("  <none>")
    else:
        for prop in direct_props:
            print(
                "  0x%08X %-18s %s +0x%s %s"
                % (
                    prop,
                    objs.class_name(prop),
                    objs.path(prop),
                    ("%X" % mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, 0)),
                    _property_type_details(objs, mem, prop),
                )
            )

    print("\n[DIRECT cSDD FUNCTIONS matching keywords]")
    if not funcs:
        print("  <none>")
    else:
        for fn in funcs:
            _sdd_print_function_signature(
                objs,
                mem,
                fn,
                netindex_off,
                package_bases,
                indent="  ",
            )

    print("\n[NESTED cSDD STRUCTS matching keywords]")
    if not nested_structs:
        print("  <none>")
    else:
        for struct_obj in nested_structs:
            print(
                "  %s @0x%08X"
                % (
                    objs.path(struct_obj),
                    struct_obj,
                )
            )
            _sdd_print_struct_schema(
                objs,
                mem,
                struct_obj,
                indent="    ",
            )

    print("\n[NESTED cSDD ENUMS matching keywords]")
    if not nested_enums:
        print("  <none>")
    else:
        for enum_obj in nested_enums:
            info = _read_enum_names(objs, mem, enum_obj, limit=128)
            if info is None:
                print(
                    "  %s @0x%08X <unreadable>"
                    % (objs.path(enum_obj), enum_obj)
                )
                continue
            names = ", ".join(info["names"])
            if info["truncated"]:
                names += ", ..."
            print(
                "  %s @0x%08X Num=%d"
                % (
                    objs.path(enum_obj),
                    enum_obj,
                    info["num"],
                )
            )
            print("    %s" % names)

    # Some generated structs/enums are not direct Children of the class but
    # still live below cSDD in the Outer/path hierarchy.  Scan all already
    # grouped GObjects for those.
    nested_seen = set(nested_structs + nested_enums + funcs + direct_props)
    path_matches = []

    for o in _iter_all_group_objects(groups):
        if o in nested_seen:
            continue
        try:
            path = objs.path(o)
            kind = objs.class_name(o)
        except Exception:
            continue

        if not path.startswith(target_path + "."):
            continue
        if not _sdd_name_matches(path, keywords):
            continue

        if (
            kind == "Function"
            or kind == "Enum"
            or kind in ("ScriptStruct", "Struct")
            or kind.endswith("Property")
        ):
            path_matches.append(o)

    print("\n[OTHER OBJECTS UNDER cSDD matching keywords]")
    if not path_matches:
        print("  <none>")
    else:
        for o in sorted(path_matches, key=lambda x: (objs.path(x), x)):
            print(
                "  0x%08X %-18s %s"
                % (
                    o,
                    objs.class_name(o),
                    objs.path(o),
                )
            )

    # Finally search the whole object universe by keyword.  This catches
    # SDD-related generated structs whose Outer is another helper class.
    global_matches = []
    for o in _iter_all_group_objects(groups):
        try:
            name = objs.name(o)
            path = objs.path(o)
            kind = objs.class_name(o)
        except Exception:
            continue

        if not _sdd_name_matches(name + " " + path, keywords):
            continue

        if (
            kind == "Function"
            or kind == "Enum"
            or kind in ("ScriptStruct", "Struct")
            or kind.endswith("Property")
            or kind == "Class"
        ):
            global_matches.append(o)

    global_matches.sort(
        key=lambda x: (
            objs.class_name(x),
            objs.path(x),
            x,
        )
    )

    print("\n[GLOBAL REFLECTION MATCHES]")
    print("  total=%d showing<=%d" % (len(global_matches), max_global_matches))
    for o in global_matches[:max_global_matches]:
        print(
            "  0x%08X %-18s %s"
            % (
                o,
                objs.class_name(o),
                objs.path(o),
            )
        )

    print(
        "\n  NOTE: this mode discovers schemas/accessors only. "
        "If cSDD has no reflected table property, row storage must be "
        "located through a native accessor/static pointer before CSV dumping."
    )

    return {
        "class": cls_obj,
        "instances": instances,
        "functions": funcs,
        "structs": nested_structs,
        "enums": nested_enums,
        "global_matches": global_matches,
    }


# ---------------------------------------------------------------------------
# cSDD / static-data table discovery and dump
# ---------------------------------------------------------------------------

def _exact_instances_of_uclass(objs, mem, groups, cls_obj):
    out = []
    for pkg, lst in groups.items():
        for o in lst:
            if (mem.try_u32(o + UO_CLASS, None) or 0) != cls_obj:
                continue
            try:
                out.append(
                    {
                        "obj": o,
                        "package": pkg,
                        "name": objs.name(o),
                        "path": objs.path(o),
                    }
                )
            except Exception:
                out.append(
                    {
                        "obj": o,
                        "package": pkg,
                        "name": "<bad>",
                        "path": "0x%08X" % o,
                    }
                )
    out.sort(key=lambda r: (r["name"] != "Default__cSDD", r["path"], r["obj"]))
    return out


def _sdd_collect_properties(objs, mem, cls_obj, include_inherited=True):
    chain = (
        _class_chain_root_to_target(objs, mem, cls_obj)
        if include_inherited
        else [cls_obj]
    )
    out = []
    for owner in chain:
        for prop in _direct_properties_for_class(objs, mem, owner):
            out.append((owner, prop))
    return out


def _sdd_table_descriptor(objs, mem, instance, owner, prop):
    cls = objs.class_name(prop)
    name = objs.name(prop)
    off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
    elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None)
    arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None)
    flags = _try_u64(mem, prop + UPROPERTY_FLAGS)
    slot = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, None) or 0

    row = {
        "owner": objs.path(owner),
        "prop": prop,
        "name": name,
        "class": cls,
        "offset": off,
        "element_size": elem,
        "array_dim": arrdim,
        "flags": flags,
        "kind": None,
        "data": None,
        "num": None,
        "max": None,
        "inner": None,
        "inner_class": None,
        "row_struct": None,
        "row_struct_path": None,
        "stride": None,
    }

    if off is None:
        return row

    addr = instance + off

    if cls == "ArrayProperty":
        row["kind"] = "dynamic-array"
        row["inner"] = slot or None
        if slot:
            try:
                row["inner_class"] = objs.class_name(slot)
            except Exception:
                row["inner_class"] = "<bad>"

        data = mem.try_u32(addr, None)
        num = mem.try_u32(addr + 4, None)
        maxv = mem.try_u32(addr + 8, None)
        if data is not None and num is not None and maxv is not None:
            row["data"] = data or 0
            row["num"] = sgn32(num)
            row["max"] = sgn32(maxv)

        if slot:
            row["stride"] = mem.try_u32(slot + UPROPERTY_ELEMENT_SIZE, None)
            if row["inner_class"] == "StructProperty":
                struct_obj = mem.try_u32(slot + UPROPERTY_TYPE_SLOT, None) or 0
                row["row_struct"] = struct_obj or None
                if struct_obj:
                    try:
                        row["row_struct_path"] = objs.path(struct_obj)
                    except Exception:
                        row["row_struct_path"] = "0x%08X" % struct_obj

    elif cls == "StructProperty" and (arrdim or 0) > 1:
        row["kind"] = "static-struct-array"
        row["data"] = addr
        row["num"] = int(arrdim)
        row["max"] = int(arrdim)
        row["stride"] = elem
        row["row_struct"] = slot or None
        if slot:
            try:
                row["row_struct_path"] = objs.path(slot)
            except Exception:
                row["row_struct_path"] = "0x%08X" % slot

    elif (arrdim or 0) > 1:
        row["kind"] = "static-array"
        row["data"] = addr
        row["num"] = int(arrdim)
        row["max"] = int(arrdim)
        row["stride"] = elem

    return row


def _sdd_score_instance(objs, mem, cls_obj, instance):
    score = 0
    tables = []
    for owner, prop in _sdd_collect_properties(objs, mem, cls_obj, include_inherited=True):
        d = _sdd_table_descriptor(objs, mem, instance, owner, prop)
        if not d["kind"]:
            continue
        tables.append(d)
        n = d.get("num")
        m = d.get("max")
        data = d.get("data")
        if (
            isinstance(n, int)
            and isinstance(m, int)
            and 0 <= n <= m <= 1000000
            and (n == 0 or data)
        ):
            score += 1 + min(n, 1000)
    return score, tables


def _select_sdd_context(
    objs,
    mem,
    groups,
    class_query="cSDD",
    explicit_instance=None,
):
    cls_obj = _resolve_one_uclass(objs, groups, class_query)
    if cls_obj is None:
        return None

    instances = _exact_instances_of_uclass(objs, mem, groups, cls_obj)

    if explicit_instance is not None:
        for row in instances:
            if row["obj"] == explicit_instance:
                _, tables = _sdd_score_instance(objs, mem, cls_obj, explicit_instance)
                return cls_obj, row, tables
        print(
            "!! --sdd-instance 0x%08X не является exact instance %s"
            % (explicit_instance, objs.path(cls_obj))
        )
        return None

    if not instances:
        print(
            "!! live instances %s не найдены; UClass есть, но читать таблицы не из чего"
            % objs.path(cls_obj)
        )
        return None

    ranked = []
    for row in instances:
        score, tables = _sdd_score_instance(objs, mem, cls_obj, row["obj"])
        ranked.append((score, row, tables))

    ranked.sort(
        key=lambda x: (
            -x[0],
            x[1]["name"] != "Default__cSDD",
            x[1]["path"],
        )
    )

    score, row, tables = ranked[0]
    return cls_obj, row, tables


def sdd_scan(
    objs,
    mem,
    groups,
    class_query="cSDD",
    explicit_instance=None,
):
    ctx = _select_sdd_context(
        objs,
        mem,
        groups,
        class_query=class_query,
        explicit_instance=explicit_instance,
    )
    if ctx is None:
        return None

    cls_obj, chosen, tables = ctx
    instances = _exact_instances_of_uclass(objs, mem, groups, cls_obj)

    print("\n============================================================")
    print("SDD SCAN: %s" % objs.path(cls_obj))
    print("============================================================")
    print("  UClass            : 0x%08X" % cls_obj)
    print("  exact instances   : %d" % len(instances))
    for row in instances:
        score, _ = _sdd_score_instance(objs, mem, cls_obj, row["obj"])
        selected = "  <== SELECTED" if row["obj"] == chosen["obj"] else ""
        print(
            "    0x%08X score=%d %-24s %s%s"
            % (
                row["obj"],
                score,
                row["package"],
                row["path"],
                selected,
            )
        )

    print("\n[TABLE-LIKE PROPERTIES]")
    table_rows = [d for d in tables if d.get("kind")]
    table_rows.sort(
        key=lambda d: (
            d.get("offset") if d.get("offset") is not None else 0x7FFFFFFF,
            d["name"],
        )
    )

    if not table_rows:
        print("  <none>")
        print(
            "  Возможно, SDD хранится в native non-reflected memory или "
            "таблицы вложены в другой UObject."
        )
        return {
            "class": cls_obj,
            "instance": chosen["obj"],
            "tables": [],
        }

    for d in table_rows:
        num = d.get("num")
        maxv = d.get("max")
        stride = d.get("stride")
        extra = ""
        if d.get("row_struct_path"):
            extra = " row=%s" % d["row_struct_path"]
        elif d.get("inner"):
            extra = " inner=%s" % _describe_object_ptr(objs, d["inner"])
        print(
            "  +0x%04X %-34s %-20s Num=%-6s Max=%-6s stride=%-6s%s"
            % (
                d["offset"] or 0,
                d["name"],
                d["kind"],
                str(num) if num is not None else "?",
                str(maxv) if maxv is not None else "?",
                ("0x%X" % stride) if isinstance(stride, int) else "?",
                extra,
            )
        )

    return {
        "class": cls_obj,
        "instance": chosen["obj"],
        "tables": table_rows,
    }


def _sdd_struct_fields(objs, mem, struct_obj):
    fields = []
    for child in _walk_struct_children(objs, mem, struct_obj):
        if not child["class"].endswith("Property"):
            continue
        prop = child["obj"]
        flags = _try_u64(mem, prop + UPROPERTY_FLAGS)
        if flags is not None and (flags & CPF_PARM):
            continue
        fields.append(prop)
    fields.sort(
        key=lambda p: (
            mem.try_u32(p + UPROPERTY_OFFSET_LIVE, 0x7FFFFFFF),
            objs.name(p),
        )
    )
    return fields


def _sdd_scalar_at(
    objs,
    mem,
    known_objects,
    base,
    prop,
    element_index=0,
):
    cls = objs.class_name(prop)
    off = mem.try_u32(prop + UPROPERTY_OFFSET_LIVE, None)
    elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None) or 1
    if off is None:
        return None
    addr = base + off + element_index * elem

    try:
        if cls == "BoolProperty":
            mask = mem.try_u32(prop + UPROPERTY_TYPE_SLOT, 0) or 0
            raw = mem.try_u32(addr, None)
            if raw is None:
                return None
            return 1 if (raw & mask) else 0

        if cls == "ByteProperty":
            return mem.read(addr, 1)[0]

        if cls == "IntProperty":
            return struct.unpack("<i", mem.read(addr, 4))[0]

        if cls == "UIntProperty":
            return struct.unpack("<I", mem.read(addr, 4))[0]

        if cls == "FloatProperty":
            return struct.unpack("<f", mem.read(addr, 4))[0]

        if cls == "DoubleProperty":
            return struct.unpack("<d", mem.read(addr, 8))[0]

        if cls in ("QWordProperty", "UInt64Property"):
            return struct.unpack("<Q", mem.read(addr, 8))[0]

        if cls == "NameProperty":
            idx, number = struct.unpack("<II", mem.read(addr, 8))
            return objs.names.fmt(idx, number)

        if cls == "StrProperty":
            text = _read_fstring_live(mem, addr)
            # _read_fstring_live returns repr + metadata for human output.
            data = mem.try_u32(addr, None)
            num = mem.try_u32(addr + 4, None)
            maxv = mem.try_u32(addr + 8, None)
            if data is None or num is None or maxv is None:
                return text
            num = sgn32(num)
            maxv = sgn32(maxv)
            if not data or num <= 0 or maxv < num:
                return ""
            raw = mem.read(data, min(num, 1_000_000) * 2)
            return raw.decode("utf-16-le", "replace").rstrip("\x00")

        if cls in ("ObjectProperty", "ClassProperty", "ComponentProperty"):
            ptr = mem.try_u32(addr, None) or 0
            if not ptr:
                return ""
            if ptr in known_objects:
                return objs.path(ptr)
            return "0x%08X" % ptr

        if cls == "StructProperty":
            return _safe_raw_hex(mem, addr, elem, limit=min(elem, 64))

        if cls == "ArrayProperty":
            data = mem.try_u32(addr, None)
            num = mem.try_u32(addr + 4, None)
            maxv = mem.try_u32(addr + 8, None)
            if data is None or num is None or maxv is None:
                return "<bad TArray>"
            return "TArray(0x%08X,%d,%d)" % (
                data or 0, sgn32(num), sgn32(maxv)
            )

        return _safe_raw_hex(mem, addr, elem, limit=min(elem, 64))
    except Exception:
        return None


def _sdd_expand_row_schema(objs, mem, struct_obj):
    schema = []
    for prop in _sdd_struct_fields(objs, mem, struct_obj):
        name = objs.name(prop)
        arrdim = mem.try_u32(prop + UPROPERTY_ARRAY_DIM, None) or 1
        elem = mem.try_u32(prop + UPROPERTY_ELEMENT_SIZE, None) or 1
        for i in range(max(1, int(arrdim))):
            column = name if arrdim == 1 else "%s[%d]" % (name, i)
            schema.append(
                {
                    "column": column,
                    "prop": prop,
                    "element_index": i,
                    "element_size": elem,
                    "class": objs.class_name(prop),
                }
            )
    return schema


def _sdd_resolve_table(tables, query):
    q = query.lower()
    exact = [d for d in tables if d["name"].lower() == q]
    if len(exact) == 1:
        return exact[0]
    partial = [d for d in tables if q in d["name"].lower()]
    if len(partial) == 1:
        return partial[0]
    matches = exact if exact else partial
    if not matches:
        print("!! SDD table/property не найдена: %s" % query)
    else:
        print("!! имя SDD table неоднозначно: %s" % query)
        for d in matches:
            print("   %s (%s)" % (d["name"], d["kind"]))
    return None


def sdd_dump_table(
    objs,
    mem,
    groups,
    table_query,
    class_query="cSDD",
    explicit_instance=None,
    csv_path=None,
    json_path=None,
    limit=None,
):
    ctx = _select_sdd_context(
        objs,
        mem,
        groups,
        class_query=class_query,
        explicit_instance=explicit_instance,
    )
    if ctx is None:
        return None

    cls_obj, chosen, tables = ctx
    tables = [d for d in tables if d.get("kind")]
    d = _sdd_resolve_table(tables, table_query)
    if d is None:
        print("\nAvailable table-like properties:")
        for row in sorted(tables, key=lambda x: x["name"].lower()):
            print("   %s" % row["name"])
        return None

    print("\n============================================================")
    print("SDD TABLE: %s.%s" % (objs.path(cls_obj), d["name"]))
    print("============================================================")
    print("  instance   : 0x%08X %s" % (chosen["obj"], chosen["path"]))
    print("  property   : 0x%08X +0x%X %s" % (
        d["prop"], d["offset"] or 0, d["class"]
    ))
    print("  storage    : %s" % d["kind"])
    print("  Num/Max    : %s/%s" % (d.get("num"), d.get("max")))
    print("  Data       : 0x%08X" % (d.get("data") or 0))
    print("  stride     : %s" % (
        "0x%X" % d["stride"] if isinstance(d.get("stride"), int) else "?"
    ))

    known = _known_object_addresses(groups)
    rows = []
    headers = []

    if d["kind"] in ("dynamic-array", "static-struct-array") and d.get("row_struct"):
        struct_obj = d["row_struct"]
        schema = _sdd_expand_row_schema(objs, mem, struct_obj)
        headers = [x["column"] for x in schema]
        print("  row struct : %s @0x%08X" % (
            d.get("row_struct_path") or objs.path(struct_obj),
            struct_obj,
        ))
        print("  columns    : %d" % len(headers))

        num = d.get("num")
        stride = d.get("stride")
        data = d.get("data")
        if (
            not isinstance(num, int)
            or num < 0
            or num > 1_000_000
            or not isinstance(stride, int)
            or stride <= 0
            or (num and not data)
        ):
            print("!! invalid table header/stride")
            return None

        take = num if limit is None else min(num, limit)
        for i in range(take):
            base = data + i * stride
            row = {}
            for col in schema:
                row[col["column"]] = _sdd_scalar_at(
                    objs,
                    mem,
                    known,
                    base,
                    col["prop"],
                    col["element_index"],
                )
            rows.append(row)

    elif d["kind"] == "dynamic-array" and d.get("inner"):
        inner = d["inner"]
        headers = [d["name"]]
        num = d.get("num") or 0
        stride = d.get("stride") or 1
        data = d.get("data") or 0
        take = num if limit is None else min(num, limit)
        # Inner UProperty offset is normally zero for TArray element descriptors.
        for i in range(take):
            rows.append(
                {
                    d["name"]: _sdd_scalar_at(
                        objs,
                        mem,
                        known,
                        data + i * stride,
                        inner,
                        0,
                    )
                }
            )

    elif d["kind"] == "static-array":
        headers = [d["name"]]
        num = d.get("num") or 0
        stride = d.get("stride") or 1
        data = d.get("data") or 0
        take = num if limit is None else min(num, limit)
        for i in range(take):
            # direct property offset must be neutralized; use a tiny raw fallback
            rows.append(
                {
                    d["name"]: _safe_raw_hex(
                        mem,
                        data + i * stride,
                        stride,
                        limit=min(stride, 64),
                    )
                }
            )

    else:
        print(
            "!! table format пока не поддержан автоматически: %s"
            % d["kind"]
        )
        return None

    preview = rows[: min(len(rows), 20)]
    if headers:
        widths = {h: min(max(len(h), 10), 28) for h in headers}
        for row in preview:
            for h in headers:
                widths[h] = min(
                    max(widths[h], len(str(row.get(h, "")))),
                    28,
                )

        print("\n[PREVIEW]")
        print(" | ".join(h[:widths[h]].ljust(widths[h]) for h in headers))
        print("-+-".join("-" * widths[h] for h in headers))
        for row in preview:
            print(
                " | ".join(
                    str(row.get(h, ""))[:widths[h]].ljust(widths[h])
                    for h in headers
                )
            )
        if len(rows) > len(preview):
            print("... %d more rows" % (len(rows) - len(preview)))

    if csv_path:
        out = Path(csv_path)
        with out.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        print("\n[CSV] written: %s" % out)

    if json_path:
        out = Path(json_path)
        out.write_text(
            json.dumps(
                {
                    "class": objs.path(cls_obj),
                    "instance": chosen,
                    "table": {
                        "name": d["name"],
                        "kind": d["kind"],
                        "num": d.get("num"),
                        "max": d.get("max"),
                        "stride": d.get("stride"),
                        "row_struct": d.get("row_struct_path"),
                    },
                    "rows": rows,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
            newline="\n",
        )
        print("[JSON] written: %s" % out)

    return rows


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--exe", default="APB.exe")

    ap.add_argument(
        "--gnames",
        default=hex(DEFAULT_GNAMES),
        help="runtime address GNames (default: 0x%08X)" % DEFAULT_GNAMES,
    )

    ap.add_argument(
        "--gobjects",
        default=hex(DEFAULT_GOBJECTS),
        help="runtime address GObjects (default: 0x%08X)" % DEFAULT_GOBJECTS,
    )

    ap.add_argument(
        "--rebase",
        action="store_true",
        help=(
            "трактовать --gnames/--gobjects как адреса образа Ghidra "
            "и пересчитать относительно --ghidra-base; "
            "по умолчанию они считаются runtime"
        ),
    )

    ap.add_argument(
        "--ghidra-base",
        default="0x10900000",
    )

    ap.add_argument(
        "--name-number-mode",
        default="mem",
        choices=("mem", "uelib"),
    )

    ap.add_argument(
        "--expect",
        action="append",
        default=[],
        metavar="PKG=N",
    )

    ap.add_argument("--netindex-off")
    ap.add_argument("--dump-package")
    ap.add_argument("--out")
    ap.add_argument("--find")

    ap.add_argument(
        "--instances",
        metavar="CLASS",
        help=(
            "по имени класса вывести live UObject instances; "
            "по умолчанию target class + subclasses"
        ),
    )
    ap.add_argument(
        "--instances-exact",
        action="store_true",
        help="для --instances искать только exact class",
    )
    ap.add_argument(
        "--instance-fields",
        metavar="ADDRESS",
        help=(
            "по адресу live UObject instance вывести значения его "
            "reflection-visible полей"
        ),
    )
    ap.add_argument(
        "--fields-own",
        action="store_true",
        help="для --instance-fields вывести только поля фактического класса",
    )
    ap.add_argument(
        "--fields-inherited",
        action="store_true",
        help="для --instance-fields вывести поля класса + всех родителей",
    )
    ap.add_argument(
        "--class-functions",
        metavar="CLASS",
        help="по имени класса вывести функции и сигнатуры",
    )
    ap.add_argument(
        "--functions-own",
        action="store_true",
        help="для --class-functions вывести только свои функции",
    )
    ap.add_argument(
        "--functions-inherited",
        action="store_true",
        help="для --class-functions вывести свои + наследуемые функции",
    )
    ap.add_argument(
        "--class-netfields",
        metavar="CLASS",
        help=(
            "компактно вывести ClassNetCache field handles в формате "
            "base/ownSlots/fieldMax + ordinal rows"
        ),
    )
    ap.add_argument(
        "--netfields-inherited",
        action="store_true",
        help="для --class-netfields дополнительно вывести inherited handles",
    )

    ap.add_argument(
        "--scan-struct-csv",
        metavar="STRUCT",
        help=(
            "искать native contiguous STRUCT rows по сигнатурам из старого CSV; "
            "layout всегда берётся из текущего live UScriptStruct"
        ),
    )
    ap.add_argument(
        "--signature-csv",
        metavar="FILE",
        help="старый CSV для --scan-struct-csv (используется только как signature oracle)",
    )
    ap.add_argument(
        "--csv-anchor",
        metavar="COLUMN",
        help=(
            "принудительно использовать конкретную shared Int/UInt колонку как "
            "memory anchor; по умолчанию выбираются редкие значения автоматически"
        ),
    )
    ap.add_argument(
        "--csv-anchor-rows",
        default="8",
        metavar="N",
        help="сколько разных old rows использовать как independent anchors (default: 8)",
    )
    ap.add_argument(
        "--csv-min-row-match",
        default="0.70",
        metavar="RATIO",
        help="минимальная доля совпавших shared fields для anchor row (default: 0.70)",
    )
    ap.add_argument(
        "--csv-min-semantic",
        default="0.85",
        metavar="RATIO",
        help="минимальная independent live-schema sanity ratio (default: 0.85)",
    )
    ap.add_argument(
        "--csv-validate-prefix",
        default="12",
        metavar="N",
        help="сколько первых old rows проверять для inferred DATA base (default: 12)",
    )
    ap.add_argument(
        "--csv-max-hits",
        default="150000",
        metavar="N",
        help="максимум raw memory hits на один anchor value (default: 150000)",
    )
    ap.add_argument(
        "--csv-max-results",
        default="20",
        metavar="N",
        help="максимум DATA candidates в выводе (default: 20)",
    )
    ap.add_argument(
        "--dump-struct-run",
        metavar="STRUCT",
        help="dump/export contiguous STRUCT rows по DATA address без TArray header",
    )
    ap.add_argument(
        "--data-address",
        metavar="ADDRESS",
        help="DATA base для --dump-struct-run",
    )
    ap.add_argument(
        "--row-count",
        metavar="N",
        help="число contiguous rows для --dump-struct-run",
    )

    ap.add_argument(
        "--scan-struct-tarrays",
        metavar="STRUCT",
        help=(
            "сканировать live memory на TArray<STRUCT> по заданным Num; "
            "пример: APBGame.cWeapon.WeaponType"
        ),
    )
    ap.add_argument(
        "--struct-counts",
        default="",
        metavar="N[,N...]",
        help=(
            "candidate TArray.Num для --scan-struct-tarrays; старые counts можно "
            "использовать только как heuristic, например 34,35"
        ),
    )
    ap.add_argument(
        "--storage-sample-rows",
        default="8",
        metavar="N",
        help="сколько распределённых строк валидировать у каждого кандидата (default: 8)",
    )
    ap.add_argument(
        "--storage-max-results",
        default="30",
        metavar="N",
        help="максимум кандидатов в выводе (default: 30)",
    )
    ap.add_argument(
        "--storage-max-hits",
        default="100000",
        metavar="N",
        help="максимум raw Num hits на каждый count (default: 100000)",
    )
    ap.add_argument(
        "--dump-struct-tarray",
        metavar="STRUCT",
        help="прочитать/выгрузить конкретный TArray<STRUCT> по адресу его 12-byte header",
    )
    ap.add_argument(
        "--tarray-address",
        metavar="ADDRESS",
        help="адрес TArray header для --dump-struct-tarray",
    )
    ap.add_argument(
        "--table-limit",
        metavar="N",
        help="ограничить число строк --dump-struct-tarray",
    )
    ap.add_argument(
        "--table-csv",
        metavar="FILE",
        help="CSV output для --dump-struct-tarray",
    )
    ap.add_argument(
        "--table-json",
        metavar="FILE",
        help="JSON output для --dump-struct-tarray",
    )

    ap.add_argument(
        "--nested-structs",
        metavar="CLASS",
        help=(
            "перечислить все nested UScriptStruct/Struct под UClass, "
            "например cSDDWeapon или cWeapon"
        ),
    )
    ap.add_argument(
        "--struct-find",
        default="",
        metavar="TEXT[,TEXT...]",
        help=(
            "фильтр для --nested-structs по подстроке path"
        ),
    )
    ap.add_argument(
        "--structs-with-schema",
        action="store_true",
        help=(
            "для --nested-structs сразу печатать поля каждой структуры"
        ),
    )
    ap.add_argument(
        "--dump-struct",
        metavar="STRUCT",
        help=(
            "вывести точный layout UScriptStruct по имени/path, "
            "например APBGame.cWeapon.WeaponType"
        ),
    )
    ap.add_argument(
        "--struct-fields-inherited",
        action="store_true",
        help=(
            "для --dump-struct включить поля SuperStruct"
        ),
    )
    ap.add_argument(
        "--discover-classes",
        nargs="?",
        const="cSDD",
        metavar="TEXT[,TEXT...]",
        help=(
            "найти UClass по подстрокам; без значения ищет cSDD"
        ),
    )

    ap.add_argument(
        "--sdd-discover",
        nargs="?",
        const="Weapon,Vehicle,Item,Ranged,Grenade,H2H,Setup",
        metavar="KEYWORDS",
        help=(
            "исследовать reflection вокруг cSDD: функции-accessors, "
            "nested structs/enums и глобальные reflection matches; "
            "KEYWORDS — comma-list, по умолчанию Weapon,Vehicle,Item,"
            "Ranged,Grenade,H2H,Setup"
        ),
    )

    ap.add_argument(
        "--sdd-scan",
        nargs="?",
        const="cSDD",
        metavar="CLASS",
        help=(
            "найти live cSDD instance/CDO и перечислить table-like "
            "ArrayProperty/static-array properties; без аргумента использует cSDD"
        ),
    )
    ap.add_argument(
        "--sdd-class",
        default="cSDD",
        metavar="CLASS",
        help="класс SDD для --sdd-dump-table (default: cSDD)",
    )
    ap.add_argument(
        "--sdd-instance",
        metavar="ADDRESS",
        help=(
            "явно выбрать exact cSDD instance/CDO; иначе выбирается "
            "instance с наиболее правдоподобными непустыми таблицами"
        ),
    )
    ap.add_argument(
        "--sdd-dump-table",
        metavar="TABLE",
        help=(
            "выгрузить одну SDD table/property по имени/подстроке; "
            "для array<struct> автоматически строит columns из UStruct reflection"
        ),
    )
    ap.add_argument(
        "--sdd-csv",
        metavar="FILE",
        help="сохранить --sdd-dump-table в CSV",
    )
    ap.add_argument(
        "--sdd-json",
        metavar="FILE",
        help="сохранить --sdd-dump-table в JSON",
    )
    ap.add_argument(
        "--sdd-limit",
        metavar="N",
        help="ограничить число выгружаемых строк SDD (для probe/preview)",
    )

    ap.add_argument(
        "--dump-class",
        metavar="CLASS",
        help=(
            "одной командой вывести UClass: address/inheritance, "
            "properties+offsets/types, functions+signatures, "
            "UObject NetIndex/global NetIndex и FClassNetCache FieldIndex; "
            "принимает cAPBVehicle или APBGame.cAPBVehicle"
        ),
    )

    ap.add_argument(
        "--dump-class-json",
        metavar="FILE",
        help=(
            "дополнительно сохранить --dump-class в JSON"
        ),
    )

    ap.add_argument(
        "--probe-package-net",
        action="append",
        default=[],
        metavar="PKG",
        help=(
            "найти живой UPackage::NetObjects по инварианту "
            "NetObjects[UObject.NetIndex] == UObject; "
            "можно указать несколько раз"
        ),
    )

    ap.add_argument(
        "--probe-live-classnetcache",
        action="store_true",
        help=(
            "найти реальный heap FClassNetCache для "
            "cAPBPlayerController и напрямую вывести "
            "GetMaxIndex/заданные FieldNetIndex"
        ),
    )

    ap.add_argument(
        "--classnetcache-handles",
        default="80,138,139,158",
        metavar="N[,N...]",
        help=(
            "FieldNetIndex для direct FClassNetCache::GetFromIndex; "
            "decimal или 0xHEX, например 80,138,139,158,260"
        ),
    )

    ap.add_argument(
        "--classnetcache-class",
        default="APBGame.cAPBPlayerController",
        metavar="PACKAGE.CLASS",
        help=(
            "UClass для direct heap FClassNetCache probe; "
            "default: APBGame.cAPBPlayerController"
        ),
    )

    ap.add_argument(
        "--classnetcache-find",
        default="",
        metavar="TEXT[,TEXT...]",
        help=(
            "искать подстроки по Name/Path во всех live FFieldNetCache "
            "target class + super chain; например "
            "Spawn,Streaming,District,Replication"
        ),
    )

    ap.add_argument(
        "--probe-class-instances",
        metavar="PACKAGE.CLASS",
        help=(
            "найти live UObject instances указанного UClass и subclasses; "
            "вывести path/package/local NetIndex/global PackageMap index"
        ),
    )

    ap.add_argument(
        "--class-instances-exact",
        action="store_true",
        help=(
            "для --probe-class-instances искать только exact UClass, "
            "не subclasses"
        ),
    )

    ap.add_argument(
        "--class-instances-limit",
        default="200",
        help=(
            "максимум печатаемых instance rows (default: 200)"
        ),
    )

    ap.add_argument(
        "--probe-function-params",
        metavar="FUNCTION[,FUNCTION...]",
        help=(
            "вывести live UFunction::Children и параметры CPF_Parm: "
            "тип, Offset, размеры, flags и type-specific metadata; "
            "можно передать несколько имён через запятую"
        ),
    )

    ap.add_argument(
        "--probe-playercontroller-netfields",
        action="store_true",
        help=(
            "rebuild cAPBPlayerController ClassNetCache from live "
            "UClass::NetFields and resolve handles 80/138/158"
        ),
    )

    ap.add_argument(
        "--probe-playercontroller-open",
        action="store_true",
        help=(
            "найти Default__cAPBPlayerController, вычислить global "
            "archetype NetIndex и проверить bNetInitialRotation/NetPlayerIndex"
        ),
    )

    ap.add_argument(
        "--probe-package-guids",
        action="store_true",
        help=(
            "найти UPackage::Guid по известному Core GUID и "
            "вывести GUID Core/Engine/APBGame"
        ),
    )

    ap.add_argument(
        "--probe-packagemap",
        action="store_true",
        help=(
            "найти активный UPackageMap и проверить List end-to-end "
            "для Core, Engine, APBGame"
        ),
    )

    ap.add_argument(
        "--package-scan-start",
        default="0x40",
        help="начало скана UPackage для NetObjects (default: 0x40)",
    )

    ap.add_argument(
        "--package-scan-end",
        default="0x400",
        help="конец скана UPackage для NetObjects (default: 0x400)",
    )

    a = ap.parse_args()

    expects = []

    for e in a.expect:
        if "=" not in e:
            print(
                "!! --expect ждёт PKG=N, получено %r"
                % e
            )
            return 2

        k, v = e.split("=", 1)

        try:
            count = int(v, 0)
        except ValueError:
            print(
                "!! неверный NetObjectCount в --expect %r"
                % e
            )
            return 2

        expects.append((k.strip(), count))

    mem = R.LiveProcess(a.exe)

    print(
        "процесс pid=%d module=0x%08X"
        % (mem.pid, mem.module_base or 0)
    )

    gn = conv(a.gnames)
    go = conv(a.gobjects)

    if a.rebase and mem.module_base:
        delta = mem.module_base - conv(a.ghidra_base)

        gn += delta
        go += delta

        print(
            "rebase: delta=%+d (0x%08X)"
            % (delta, delta & 0xFFFFFFFF)
        )

    print(
        "GNames=0x%08X GObjects=0x%08X"
        % (gn, go)
    )

    # Names
    try:
        names = NameTable(
            mem,
            gn,
            number_mode=a.name_number_mode,
        )
    except MemErr as e:
        print("!! %s" % e)
        return 1

    print(
        "GNames.Num=%d Max=%d  "
        "FNameEntry: Flags=+0x00 Name/NamePtr=+0x10 ANSI"
        % (names.num, names.max)
    )

    ok, sample = names.selftest()

    print("   name[0]=%r" % names.raw(0))
    print("   контроль:")

    for idx, value in sample:
        print("      [%6d] %r" % (idx, value))

    if not ok:
        print(
            "!! name[0] != 'None' -- "
            "дальше идти нельзя"
        )
        return 1

    # Objects
    try:
        objs = Objects(mem, go, names)
    except MemErr as e:
        print("!! %s" % e)
        return 1

    if objs.max is None:
        print("GObjects.Num=%d" % objs.num)
    else:
        print(
            "GObjects.Num=%d Max=%d"
            % (objs.num, objs.max)
        )

    off = (
        conv(a.netindex_off)
        if a.netindex_off
        else None
    )

    internal = None

    # Phase 1
    if off is None:
        internal = phase1(objs, mem)

        if internal is None:
            print(
                "\n!! InternalIndex не определён; "
                "фаза 2 остановлена"
            )
            return 1

        if internal != UO_INDEX:
            print(
                "\n!! предупреждение: ожидался InternalIndex +0x%02X, "
                "получено +0x%02X"
                % (UO_INDEX, internal)
            )

        if not expects and not a.probe_package_net and not a.probe_packagemap and not a.probe_package_guids and not a.probe_playercontroller_open and not a.probe_playercontroller_netfields and not a.probe_function_params and not a.probe_live_classnetcache and not a.probe_class_instances and not a.dump_class and not a.instances and not a.instance_fields and not a.class_functions and not a.class_netfields and not a.sdd_scan and not a.sdd_dump_table and not a.sdd_discover and not a.nested_structs and not a.dump_struct and not a.discover_classes and not a.scan_struct_tarrays and not a.dump_struct_tarray and not a.scan_struct_csv and not a.dump_struct_run:
            print(
                "\n!! для фазы 2 нужен хотя бы "
                "один --expect PKG=N"
            )
            return 1

    # Grouping
    groups = build_groups(objs)

    # Phase 2
    if off is None:
        if expects:
            off = phase2(
                mem,
                groups,
                expects,
                internal,
            )

            if off is None:
                return 1
        elif a.probe_package_net or a.probe_packagemap or a.probe_package_guids or a.probe_playercontroller_open or a.probe_playercontroller_netfields or a.probe_function_params or a.probe_live_classnetcache or a.probe_class_instances or a.dump_class or a.instances or a.instance_fields or a.class_functions or a.class_netfields or a.sdd_scan or a.sdd_dump_table or a.sdd_discover or a.nested_structs or a.dump_struct or a.discover_classes or a.scan_struct_tarrays or a.dump_struct_tarray or a.scan_struct_csv or a.dump_struct_run:
            # InternalIndex уже подтверждён фазой 1; runtime reflection
            # подтвердил UObject::NetIndex = +0x24.
            off = 0x24
            print(
                "\nдля runtime package/map probe без --expect "
                "используем подтверждённый NetIndex +0x24"
            )
    else:
        print(
            "\noffset задан вручную: +0x%02X"
            % off
        )

    # UPackage runtime net-state probe
    if a.probe_package_net:
        scan_start = conv(a.package_scan_start)
        scan_end = conv(a.package_scan_end)

        if scan_end <= scan_start:
            print(
                "!! --package-scan-end должен быть больше "
                "--package-scan-start"
            )
            return 2

        for pkg in a.probe_package_net:
            probe_package_net(
                objs,
                mem,
                groups,
                pkg,
                off,
                scan_start=scan_start,
                scan_end=scan_end,
            )

    if a.probe_live_classnetcache:
        try:
            classnetcache_handles = tuple(
                int(part.strip(), 0)
                for part in a.classnetcache_handles.split(",")
                if part.strip()
            )
        except ValueError as exc:
            raise SystemExit(
                "bad --classnetcache-handles; use decimal/0xHEX comma list"
            ) from exc

        if not classnetcache_handles:
            raise SystemExit(
                "--classnetcache-handles must contain at least one index"
            )

        classnetcache_filters = tuple(
            part.strip()
            for part in a.classnetcache_find.split(",")
            if part.strip()
        )

        probe_live_classnetcache(
            objs,
            mem,
            groups,
            target_handles=classnetcache_handles,
            target_class_path=a.classnetcache_class,
            name_filters=classnetcache_filters,
        )

    if a.instances:
        try:
            instances_limit = int(a.class_instances_limit, 0)
        except ValueError as exc:
            raise SystemExit("bad --class-instances-limit") from exc
        command_instances(
            objs,
            mem,
            groups,
            a.instances,
            off,
            include_subclasses=not a.instances_exact,
            limit=max(1, instances_limit),
        )

    if a.instance_fields:
        if a.fields_own and a.fields_inherited:
            raise SystemExit(
                "use only one of --fields-own / --fields-inherited"
            )
        address = conv(a.instance_fields)
        dump_instance_fields(
            objs,
            mem,
            groups,
            address,
            off,
            include_inherited=bool(a.fields_inherited),
        )

    if a.class_functions:
        if a.functions_own and a.functions_inherited:
            raise SystemExit(
                "use only one of --functions-own / --functions-inherited"
            )
        list_class_functions(
            objs,
            mem,
            groups,
            a.class_functions,
            off,
            include_inherited=bool(a.functions_inherited),
        )

    if a.class_netfields:
        dump_class_netfields_compact(
            objs,
            mem,
            groups,
            a.class_netfields,
            off,
            include_inherited=bool(a.netfields_inherited),
        )

    if a.probe_class_instances:
        try:
            class_instances_limit = int(
                a.class_instances_limit,
                0,
            )
        except ValueError as exc:
            raise SystemExit(
                "bad --class-instances-limit"
            ) from exc

        probe_class_instances(
            objs,
            mem,
            groups,
            a.probe_class_instances,
            off,
            include_subclasses=not a.class_instances_exact,
            limit=max(1, class_instances_limit),
        )

    if a.probe_function_params:
        function_names = [
            part.strip()
            for part in a.probe_function_params.split(",")
            if part.strip()
        ]

        for function_name in function_names:
            probe_function_params(
                objs,
                mem,
                groups,
                function_name,
                off,
            )

    if a.probe_playercontroller_netfields:
        probe_playercontroller_netfields(
            objs,
            mem,
            groups,
            off,
        )

    if a.probe_playercontroller_open:
        probe_playercontroller_open(
            objs,
            mem,
            groups,
            off,
        )

    if a.probe_package_guids:
        probe_package_guids(
            objs,
            mem,
            groups,
        )

    if a.probe_packagemap:
        probe_packagemap(
            objs,
            mem,
            groups,
            off,
        )

    if a.scan_struct_csv:
        if not a.signature_csv:
            raise SystemExit("--scan-struct-csv requires --signature-csv FILE")
        try:
            csv_anchor_rows = max(1, int(a.csv_anchor_rows, 0))
            csv_min_row_match = float(a.csv_min_row_match)
            csv_min_semantic = float(a.csv_min_semantic)
            csv_validate_prefix = max(1, int(a.csv_validate_prefix, 0))
            csv_max_hits = max(1, int(a.csv_max_hits, 0))
            csv_max_results = max(1, int(a.csv_max_results, 0))
        except ValueError as exc:
            raise SystemExit("bad CSV signature scan numeric option") from exc

        if not (0.0 <= csv_min_row_match <= 1.0):
            raise SystemExit("--csv-min-row-match must be 0..1")
        if not (0.0 <= csv_min_semantic <= 1.0):
            raise SystemExit("--csv-min-semantic must be 0..1")

        scan_struct_csv_signature(
            objs,
            mem,
            groups,
            a.scan_struct_csv,
            a.signature_csv,
            anchor_field=a.csv_anchor,
            anchor_rows=csv_anchor_rows,
            min_row_match=csv_min_row_match,
            min_semantic=csv_min_semantic,
            max_hits=csv_max_hits,
            max_results=csv_max_results,
            validate_prefix=csv_validate_prefix,
        )

    if a.dump_struct_run:
        if not a.data_address or not a.row_count:
            raise SystemExit(
                "--dump-struct-run requires --data-address 0x... --row-count N"
            )
        try:
            run_count = int(a.row_count, 0)
            run_limit = (
                None
                if a.table_limit is None
                else int(a.table_limit, 0)
            )
        except ValueError as exc:
            raise SystemExit("bad --row-count/--table-limit") from exc

        dump_struct_run(
            objs,
            mem,
            groups,
            a.dump_struct_run,
            conv(a.data_address),
            run_count,
            limit=run_limit,
            csv_path=a.table_csv,
            json_path=a.table_json,
        )

    if a.scan_struct_tarrays:
        if not a.struct_counts.strip():
            raise SystemExit("--scan-struct-tarrays requires --struct-counts N[,N...]")
        try:
            storage_counts=[int(x.strip(),0) for x in a.struct_counts.split(',') if x.strip()]
            storage_sample_rows=max(1,int(a.storage_sample_rows,0))
            storage_max_results=max(1,int(a.storage_max_results,0))
            storage_max_hits=max(1,int(a.storage_max_hits,0))
        except ValueError as exc:
            raise SystemExit("bad storage scan numeric option") from exc
        scan_struct_tarrays(
            objs,mem,groups,a.scan_struct_tarrays,storage_counts,
            sample_rows=storage_sample_rows,max_results=storage_max_results,
            max_hits_per_count=storage_max_hits,
        )

    if a.dump_struct_tarray:
        if not a.tarray_address:
            raise SystemExit("--dump-struct-tarray requires --tarray-address 0x...")
        table_limit=None
        if a.table_limit is not None:
            try: table_limit=int(a.table_limit,0)
            except ValueError as exc: raise SystemExit("bad --table-limit") from exc
        dump_struct_tarray(
            objs,mem,groups,a.dump_struct_tarray,conv(a.tarray_address),
            limit=table_limit,csv_path=a.table_csv,json_path=a.table_json,
        )

    if a.discover_classes:
        discover_sdd_classes(
            objs,
            groups,
            keyword_text=a.discover_classes,
        )

    if a.nested_structs:
        list_nested_structs(
            objs,
            mem,
            groups,
            a.nested_structs,
            keyword_text=a.struct_find,
            with_schema=bool(a.structs_with_schema),
        )

    if a.dump_struct:
        dump_struct_schema(
            objs,
            mem,
            groups,
            a.dump_struct,
            include_inherited=bool(a.struct_fields_inherited),
        )

    sdd_instance = conv(a.sdd_instance) if a.sdd_instance else None

    if a.sdd_discover:
        sdd_discover(
            objs,
            mem,
            groups,
            off,
            class_query=a.sdd_class,
            keyword_text=a.sdd_discover,
        )

    if a.sdd_scan:
        sdd_scan(
            objs,
            mem,
            groups,
            class_query=a.sdd_scan,
            explicit_instance=sdd_instance,
        )

    if a.sdd_dump_table:
        sdd_limit = None
        if a.sdd_limit:
            try:
                sdd_limit = int(a.sdd_limit, 0)
            except ValueError as exc:
                raise SystemExit("bad --sdd-limit") from exc
            if sdd_limit < 0:
                raise SystemExit("--sdd-limit must be >= 0")

        sdd_dump_table(
            objs,
            mem,
            groups,
            a.sdd_dump_table,
            class_query=a.sdd_class,
            explicit_instance=sdd_instance,
            csv_path=a.sdd_csv,
            json_path=a.sdd_json,
            limit=sdd_limit,
        )

    if a.dump_class:
        dump_class_structured(
            objs,
            mem,
            groups,
            a.dump_class,
            off,
            json_path=a.dump_class_json,
        )

    # Diagnostics
    if a.dump_package:
        dump_package(
            objs,
            mem,
            groups,
            a.dump_package,
            off,
            a.out,
        )

    if a.find:
        find_object(
            objs,
            mem,
            groups,
            a.find,
            off,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
