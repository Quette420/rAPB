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

        if not expects and not a.probe_package_net and not a.probe_packagemap:
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
        elif a.probe_package_net or a.probe_packagemap:
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
