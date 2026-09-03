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

        if not expects and not a.probe_package_net:
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
        elif a.probe_package_net:
            # InternalIndex уже подтверждён фазой 1; для package probe
            # используем наиболее вероятный/подтверждаемый NetIndex +0x24.
            off = 0x24
            print(
                "\nдля --probe-package-net без --expect "
                "используем NetIndex +0x24"
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
