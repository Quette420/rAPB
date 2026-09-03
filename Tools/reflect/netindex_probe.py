# -*- coding: utf-8 -*-
"""
netindex_probe.py -- определение offset UObject::NetIndex в APB 1.13.1
и снятие локальных NetIndex из живой памяти клиента.

Кладётся рядом с apb_reflect.py (Tools/reflect/). Из apb_reflect берётся
только доступ к памяти; таблица L оттуда НЕ используется -- она унаследована
от сборки 1.1.0.534979 и для 1.13.1 частично неверна.

Подтверждено на 1.13.1 (20000/20000 объектов):
    UObject +0x20  InternalIndex   (GObjects[i] = obj; obj->+0x20 = i)
Следовательно NetIndex -- один из +0x1C / +0x24 / +0x28.

Инвариант, разрешающий вопрос: в пределах пакета ненулевые NetIndex
попарно различны и лежат в 0..NetObjectCount-1, объекты без сетевого
индекса несут -1. Ни одно другое поле UObject так себя не ведёт.
NetObjectCount берётся из packages.csv.

Адреса GNames/GObjects по умолчанию -- RUNTIME (как в отчёте по 1.13.1),
пересчёт по базе модуля только при явном --rebase.

  python netindex_probe.py --expect Core=3 --expect Engine=3 \
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

# UObject, 1.13.1 -- из md/...UE3 reflection layout.md, статус CONFIRMED
UO_INDEX = 0x20
UO_OUTER = 0x2C
UO_NAME_INDEX = 0x30
UO_NAME_NUMBER = 0x34
UO_CLASS = 0x38

INDEX_CANDIDATES = [0x04, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28]
NET_CANDIDATES = [0x1C, 0x24, 0x28]

SANE_MAX_OBJECTS = 5000000
SANE_MAX_NAMES = 2000000


def conv(v):
    return int(str(v), 0)


def sgn32(v):
    return v - 0x100000000 if v >= 0x80000000 else v


# ---------------------------------------------------------------------------
# FNameEntry с автоопределением смещения строки
# ---------------------------------------------------------------------------

class NameTable(object):
    def __init__(self, mem, addr, name_off=None, wide=None, number_mode="mem"):
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
                % (self.data, self.num, self.max))

        if name_off is None or wide is None:
            self.off, self.wide = self._detect()
        else:
            self.off, self.wide = name_off, wide

    # -- поиск смещения строки по опорному имени GNames[0] == "None" --------
    def _detect(self):
        e0 = self.entry_addr(0)
        blob = self.mem.read(e0, 96)
        target_w = "None".encode("utf-16-le") + b"\x00\x00"
        for off in range(0, 80, 2):
            if blob[off:off + len(target_w)] == target_w:
                return off, True
        for off in range(0, 88):
            if blob[off:off + 5] == b"None\x00":
                return off, False
        raise MemErr(
            "не нашёл 'None' в GNames[0].\n"
            "  entry @ 0x%08X\n  %s\n"
            "Задайте вручную: --name-off 0xNN [--ansi-names]"
            % (e0, " ".join("%02X" % b for b in blob[:64])))

    def entry_addr(self, idx):
        return self.mem.ptr(self.data + 4 * idx)

    def raw(self, idx):
        if idx in self._cache:
            return self._cache[idx]
        try:
            a = self.entry_addr(idx) + self.off
            out = bytearray()
            if self.wide:
                while len(out) < 512:
                    ch = self.mem.read(a + len(out), 2)
                    if ch == b"\x00\x00":
                        break
                    out += ch
                s = bytes(out).decode("utf-16-le", "replace")
            else:
                while len(out) < 256:
                    ch = self.mem.read(a + len(out), 1)
                    if ch == b"\x00":
                        break
                    out += ch
                s = bytes(out).decode("latin-1", "replace")
        except MemErr:
            s = "<bad:%d>" % idx
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
        ok = self.raw(0) == "None"
        sample = [self.raw(i) for i in (1, 2, 3, 100, 1000)]
        return ok, sample


# ---------------------------------------------------------------------------

class Objects(object):
    def __init__(self, mem, addr, names):
        self.mem = mem
        self.names = names
        self.data = mem.ptr(addr + 0x00)
        self.num = mem.i32(addr + 0x04)
        self._name = {}
        if not (0 < self.num <= SANE_MAX_OBJECTS):
            raise MemErr(
                "GObjects невалиден: Data=0x%08X Num=%d. "
                "Адрес не тот или нужен/лишний --rebase."
                % (self.data, self.num))

    def slot(self, i):
        return self.mem.ptr(self.data + 4 * i)

    def name(self, o):
        if o in self._name:
            return self._name[o]
        try:
            s = self.names.fmt(self.mem.i32(o + UO_NAME_INDEX),
                               self.mem.i32(o + UO_NAME_NUMBER))
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
        cur, last, n = o, o, 0
        while cur and n < 24:
            last = cur
            try:
                cur = self.mem.ptr(cur + UO_OUTER)
            except MemErr:
                break
            n += 1
        return last

    def path(self, o):
        parts, cur, n = [], o, 0
        while cur and n < 24:
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
    print("\n== фаза 1: InternalIndex (obj[off] == slot), %d объектов ==" % total)
    best = None
    for off in sorted(hits, key=lambda k: -hits[k]):
        frac = hits[off] / float(total)
        print("  +0x%02X : %6d  (%.1f%%)" % (off, hits[off], frac * 100))
        if best is None and frac > 0.99:
            best = off
    print("  -> InternalIndex = %s"
          % ("+0x%02X" % best if best is not None else "НЕ ОПРЕДЕЛЁН"))
    return best


def build_groups(objs):
    print("\n== группировка по пакетам ==")
    groups = defaultdict(list)
    n = 0
    for _, o in objs.iter_objects():
        n += 1
        groups[objs.name(objs.outermost(o))].append(o)
    sizes = sorted(((len(v), k) for k, v in groups.items()), reverse=True)
    print("объектов %d, пакетов %d" % (n, len(groups)))
    print("крупнейшие:")
    for cnt, nm in sizes[:12]:
        print("   %8d  %s" % (cnt, nm))
    singles = sum(1 for c, _ in sizes if c == 1)
    print("пакетов ровно с одним объектом: %d" % singles)
    if singles > len(groups) * 0.5:
        print("!! больше половины 'пакетов' одиночные -- имена или Outer "
              "читаются неверно, результатам фазы 2 верить нельзя")
    return groups


def score(mem, obj_list, expected, off):
    vals = []
    for o in obj_list:
        v = mem.try_u32(o + off, None)
        if v is None:
            continue
        sv = sgn32(v)
        if sv == -1:
            continue
        if sv < 0 or sv > 0x00FFFFFF:
            return (False, 0.0, sv, 0, 0)
        vals.append(sv)
    if not vals:
        return (False, 0.0, -1, 0, 0)
    uniq = set(vals)
    dups = len(vals) - len(uniq)
    mx = max(uniq)
    return ((dups == 0 and mx < expected),
            len(uniq) / float(expected), mx, dups, len(uniq))


def phase2(mem, groups, expects, skip):
    print("\n== фаза 2: NetIndex (инвариант по пакетам) ==")
    passed = []
    for off in NET_CANDIDATES:
        if off == skip:
            continue
        rows, all_ok, cov, tested = [], True, 0.0, 0
        for pkg, cnt in expects:
            lst = groups.get(pkg)
            if not lst:
                rows.append("    %-18s НЕТ В ПАМЯТИ" % pkg)
                continue
            ok, c, mx, dups, seen = score(mem, lst, cnt, off)
            tested += 1
            cov += c
            all_ok = all_ok and ok
            rows.append("    %-18s ожид=%-5d уник=%-5d max=%-8d дублей=%-4d %s"
                        % (pkg, cnt, seen, mx, dups,
                           "OK" if ok else "НАРУШЕН"))
        if not tested:
            continue
        print("\n  +0x%02X : %s (покрытие %.0f%%)"
              % (off, "ПРОХОДИТ" if all_ok else "отвергнут",
                 100.0 * cov / tested))
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
    else:
        print("  !! прошли несколько: %s -- добавьте --expect на большой пакет"
              % ", ".join("+0x%02X" % p for p in passed))
    return None


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
        rows.append((sv, objs.path(o), objs.class_name(o), o))
    rows.sort()
    print("\n== %s: %d сетевых объектов ==" % (pkg, len(rows)))
    if rows:
        print("   индексы %d..%d" % (rows[0][0], rows[-1][0]))
    if out:
        with open(out, "w", encoding="utf-8") as f:
            for r in rows:
                f.write("%d\t%s\t%s\t0x%08X\n" % r)
        print("   записано в %s" % out)
    else:
        for r in rows[:40]:
            print("   %6d  %-58s %s" % (r[0], r[1], r[2]))
        if len(rows) > 40:
            print("   ... ещё %d" % (len(rows) - 40))


def find_object(objs, mem, groups, needle, off):
    print("\n== поиск %r ==" % needle)
    found = 0
    for pkg, lst in groups.items():
        for o in lst:
            if objs.name(o) != needle:
                continue
            v = mem.try_u32(o + off, None)
            print("   %-46s пакет=%-14s класс=%-18s NetIndex=%s addr=0x%08X"
                  % (objs.path(o), pkg, objs.class_name(o),
                     sgn32(v) if v is not None else "?", o))
            found += 1
    if not found:
        print("   не найден (объект может быть не загружен)")


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default="APB.exe")
    ap.add_argument("--gnames", default=hex(DEFAULT_GNAMES))
    ap.add_argument("--gobjects", default=hex(DEFAULT_GOBJECTS))
    ap.add_argument("--rebase", action="store_true",
                    help="трактовать адреса как Ghidra-образ и пересчитать "
                         "по --ghidra-base; по умолчанию адреса runtime")
    ap.add_argument("--ghidra-base", default="0x10900000")
    ap.add_argument("--name-off", help="смещение строки в FNameEntry вручную")
    ap.add_argument("--ansi-names", action="store_true")
    ap.add_argument("--name-number-mode", default="mem",
                    choices=("mem", "uelib"))
    ap.add_argument("--expect", action="append", default=[], metavar="PKG=N")
    ap.add_argument("--netindex-off")
    ap.add_argument("--dump-package")
    ap.add_argument("--out")
    ap.add_argument("--find")
    a = ap.parse_args()

    expects = []
    for e in a.expect:
        if "=" not in e:
            print("!! --expect ждёт PKG=N, получено %r" % e)
            return 2
        k, v = e.split("=", 1)
        expects.append((k.strip(), int(v)))

    mem = R.LiveProcess(a.exe)
    print("процесс pid=%d module=0x%08X" % (mem.pid, mem.module_base or 0))

    gn, go = conv(a.gnames), conv(a.gobjects)
    if a.rebase and mem.module_base:
        d = mem.module_base - conv(a.ghidra_base)
        gn, go = gn + d, go + d
        print("rebase: дельта 0x%08X" % (d & 0xFFFFFFFF))
    print("GNames=0x%08X GObjects=0x%08X" % (gn, go))

    try:
        names = NameTable(mem, gn,
                          conv(a.name_off) if a.name_off else None,
                          (not a.ansi_names) if a.name_off else None,
                          a.name_number_mode)
    except MemErr as e:
        print("!! %s" % e)
        return 1
    print("GNames.Num=%d  FNameEntry: строка на +0x%02X, %s"
          % (names.num, names.off, "wide" if names.wide else "ansi"))
    ok, sample = names.selftest()
    print("   name[0]=%r  контроль: %r" % (names.raw(0), sample))
    if not ok:
        print("!! name[0] != 'None' -- дальше идти нельзя")
        return 1

    try:
        objs = Objects(mem, go, names)
    except MemErr as e:
        print("!! %s" % e)
        return 1
    print("GObjects.Num=%d" % objs.num)

    off = conv(a.netindex_off) if a.netindex_off else None
    internal = None
    if off is None:
        internal = phase1(objs, mem)
        if not expects:
            print("\n!! для фазы 2 нужен хотя бы один --expect PKG=N")
            return 1

    groups = build_groups(objs)

    if off is None:
        off = phase2(mem, groups, expects, internal)
        if off is None:
            return 1
    else:
        print("\noffset задан вручную: +0x%02X" % off)

    if a.dump_package:
        dump_package(objs, mem, groups, a.dump_package, off, a.out)
    if a.find:
        find_object(objs, mem, groups, a.find, off)
    return 0


if __name__ == "__main__":
    sys.exit(main())
