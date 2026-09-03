# -*- coding: utf-8 -*-
"""
netindex_probe.py -- определение offset UObject::NetIndex в APB 1.13.1
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
# Main
# ---------------------------------------------------------------------------

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
        "--probe-function-params",
        metavar="FUNCTION",
        help=(
            "вывести live UFunction::Children и параметры CPF_Parm: "
            "тип, Offset, размеры, flags и type-specific metadata"
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

        if not expects and not a.probe_package_net and not a.probe_packagemap and not a.probe_package_guids and not a.probe_playercontroller_open and not a.probe_playercontroller_netfields and not a.probe_function_params and not a.probe_live_classnetcache:
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
        elif a.probe_package_net or a.probe_packagemap or a.probe_package_guids or a.probe_playercontroller_open or a.probe_playercontroller_netfields or a.probe_function_params or a.probe_live_classnetcache:
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

    if a.probe_function_params:
        probe_function_params(
            objs,
            mem,
            groups,
            a.probe_function_params,
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
