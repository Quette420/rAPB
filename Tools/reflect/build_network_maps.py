# -*- coding: utf-8 -*-
"""
build_network_maps.py

Dedicated runtime generator for APB Reloaded UE3 network maps.

Produces:
    NetIndexMap.txt
    FieldIndexMap.txt

This tool is intentionally separate from netindex_probe.py.  It imports
apb_reflect only for LiveProcess memory access and does not use apb_reflect's
old-version layout tables.

Current APB 1.13.1 runtime layouts used here:
    UObject::NetIndex              +0x24
    UObject::Outer                 +0x2C
    UObject::Name.Index            +0x30
    UObject::Name.Number           +0x34
    UObject::Class                 +0x38

    UStruct::SuperField            +0x4C
    UClass::NetFields              +0xF4  TArray<UField*>

    UProperty::PropertyFlags       +0x4C  uint64
    UFunction::FunctionFlags       +0x88  uint32

    UPackage::NetObjects           +0x80  TArray<UObject*>
    UPackage::CurrentNumNetObjects +0x8C  int32
    UPackage::GenerationNetObjectCount +0x90 TArray<int32>

The generator derives FieldIndex from the live UClass::NetFields arrays and
the active package NetObjects ranges:
    FieldIndex = parent.FieldMax + position in supported own NetFields

This is a runtime-derived map.  It is stronger than rebuilding order from an
old export table, but it is still labelled DERIVED unless a separate direct
FClassNetCache probe has validated a particular class.
"""

import argparse
import ctypes
import datetime as _dt
import sys
from pathlib import Path
from collections import defaultdict

import apb_reflect as R


MemErr = R.MemoryError_

DEFAULT_GNAMES = 0x12538938
DEFAULT_GOBJECTS = 0x1259EF3C

# UObject
UO_NETINDEX = 0x24
UO_OUTER = 0x2C
UO_NAME_INDEX = 0x30
UO_NAME_NUMBER = 0x34
UO_CLASS = 0x38

# UField / UStruct / UClass
USTRUCT_SUPER = 0x4C
UCLASS_NETFIELDS = 0xF4

# UProperty / UFunction
UPROPERTY_FLAGS = 0x4C
UFUNCTION_FLAGS = 0x88

# UPackage
UPACKAGE_NETOBJECTS = 0x80
UPACKAGE_CURRENT_NUM = 0x8C
UPACKAGE_GENERATION_COUNTS = 0x90

# FNameEntry
FNE_FLAGS = 0x00
FNE_NAME = 0x10
FNE_NAMEPTR_FLAG = 0x4000

SANE_MAX_OBJECTS = 5_000_000
SANE_MAX_NAMES = 2_000_000
MAX_NAME_BYTES = 1024

DEFAULT_NETWORK_PACKAGES = ("Core", "Engine", "APBGame")


FUNCTION_FLAG_NAMES = (
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

PROPERTY_FLAG_NAMES = (
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


# Current-build calibration gathered from direct runtime probes.
NETINDEX_CALIBRATION = {
    "APBGame.cAPBPlayerController": 12772,
    "APBGame.Default__cAPBPlayerController": 12773,
    "APBGame.cAPBVehicle": 13637,
}

FIELDINDEX_CALIBRATION = (
    ("Engine.PlayerController", "ServerAcknowledgePossession", 41),
    (
        "APBGame.cHostingPlayerController",
        "Receive_GC2DS_ASK_DISTRICT_ENTER",
        138,
    ),
    (
        "APBGame.cHostingPlayerController",
        "Receive_DS2GC_ANS_DISTRICT_ENTER",
        139,
    ),
    ("APBGame.cAPBPlayerController", "OperateOnItemServer", 260),
    ("APBGame.cAPBPlayerController", "ClientGoToSpawnZoneSelectScreen", 390),
    ("APBGame.cAPBPlayerController", "ServerSelectSpawnZone", 392),
)


def conv(value):
    return int(str(value), 0)


def sgn32(value):
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def try_u64(mem, addr):
    try:
        raw = mem.read(addr, 8)
    except Exception:
        return None
    return int.from_bytes(raw, "little", signed=False)


def read_tarray_header(mem, addr):
    data = mem.ptr(addr + 0x00)
    num = mem.i32(addr + 0x04)
    maxv = mem.i32(addr + 0x08)
    return data, num, maxv


def fmt_flags(flags, table):
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


class NameTable:
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
                "invalid GNames: Data=0x%08X Num=%d Max=%d"
                % (self.data, self.num, self.max)
            )

        if self.raw(0) != "None":
            raise MemErr(
                "FNameEntry self-test failed: name[0]=%r, expected 'None'"
                % self.raw(0)
            )

    def entry_addr(self, index):
        if index < 0 or index >= self.num:
            raise MemErr("FName index out of range: %d" % index)
        entry = self.mem.ptr(self.data + index * 4)
        if not entry:
            raise MemErr("GNames[%d] == NULL" % index)
        return entry

    def _read_cstr(self, addr):
        out = bytearray()
        for i in range(MAX_NAME_BYTES):
            b = self.mem.read(addr + i, 1)
            if b == b"\x00":
                break
            out += b
        return bytes(out).decode("latin-1", "replace")

    def raw(self, index):
        if index in self._cache:
            return self._cache[index]
        if index < 0 or index >= self.num:
            return "<bad:%d>" % index

        try:
            entry = self.entry_addr(index)
            flags = self.mem.u32(entry + FNE_FLAGS)
            if flags & FNE_NAMEPTR_FLAG:
                name_addr = self.mem.ptr(entry + FNE_NAME)
            else:
                name_addr = entry + FNE_NAME
            value = self._read_cstr(name_addr)
        except Exception:
            value = "<unreadable:%d>" % index

        self._cache[index] = value
        return value

    def fmt(self, index, number):
        value = self.raw(index)
        if number is None or number <= 0:
            return value
        if self.number_mode == "uelib":
            return "%s_%d" % (value, number - 1)
        return "%s_%d" % (value, number)


class Objects:
    def __init__(self, mem, addr, names):
        self.mem = mem
        self.names = names
        self.addr = addr
        self.data = mem.ptr(addr + 0x00)
        self.num = mem.i32(addr + 0x04)
        try:
            self.max = mem.i32(addr + 0x08)
        except Exception:
            self.max = None

        if not (0 < self.num <= SANE_MAX_OBJECTS):
            raise MemErr(
                "invalid GObjects: Data=0x%08X Num=%d"
                % (self.data, self.num)
            )

        self._name = {}
        self._class_name = {}
        self._path = {}
        self._outermost = {}

    def slot(self, index):
        return self.mem.ptr(self.data + index * 4)

    def name(self, obj):
        if obj in self._name:
            return self._name[obj]
        try:
            idx = self.mem.i32(obj + UO_NAME_INDEX)
            num = self.mem.i32(obj + UO_NAME_NUMBER)
            value = self.names.fmt(idx, num)
        except Exception:
            value = "<unreadable>"
        self._name[obj] = value
        return value

    def class_ptr(self, obj):
        try:
            return self.mem.ptr(obj + UO_CLASS)
        except Exception:
            return 0

    def class_name(self, obj):
        if obj in self._class_name:
            return self._class_name[obj]
        cls = self.class_ptr(obj)
        value = self.name(cls) if cls else "<none>"
        self._class_name[obj] = value
        return value

    def outer(self, obj):
        try:
            return self.mem.ptr(obj + UO_OUTER)
        except Exception:
            return 0

    def outermost(self, obj):
        if obj in self._outermost:
            return self._outermost[obj]
        cur = obj
        last = obj
        seen = set()
        for _ in range(32):
            if not cur or cur in seen:
                break
            seen.add(cur)
            last = cur
            cur = self.outer(cur)
        self._outermost[obj] = last
        return last

    def package_name(self, obj):
        root = self.outermost(obj)
        return self.name(root) if root else None

    def path(self, obj):
        if obj in self._path:
            return self._path[obj]
        parts = []
        cur = obj
        seen = set()
        for _ in range(32):
            if not cur or cur in seen:
                break
            seen.add(cur)
            parts.append(self.name(cur))
            cur = self.outer(cur)
        value = ".".join(reversed(parts))
        self._path[obj] = value
        return value

    def iter_objects(self, progress=True):
        for i in range(self.num):
            if progress and i and i % 50000 == 0:
                print("  ... %d/%d" % (i, self.num))
            try:
                obj = self.slot(i)
            except Exception:
                continue
            if obj:
                yield i, obj


def collect_objects(objs):
    all_objects = []
    by_package = defaultdict(list)
    by_path = {}
    class_objects = []

    print("collecting GObjects...")
    for _, obj in objs.iter_objects(progress=True):
        all_objects.append(obj)
        pkg = objs.package_name(obj)
        by_package[pkg].append(obj)
        try:
            path = objs.path(obj)
            if path:
                by_path[path] = obj
        except Exception:
            pass
        if objs.class_name(obj) == "Class":
            class_objects.append(obj)

    print(
        "objects=%d packages=%d classes=%d"
        % (len(all_objects), len(by_package), len(class_objects))
    )
    return {
        "all": all_objects,
        "by_package": by_package,
        "by_path": by_path,
        "classes": class_objects,
    }


def find_package_root(objs, collected, package_name):
    candidates = []
    for obj in collected["by_package"].get(package_name, []):
        if objs.outer(obj) != 0:
            continue
        if objs.name(obj) != package_name:
            continue
        candidates.append(obj)

    for obj in candidates:
        if objs.class_name(obj) == "Package":
            return obj
    return candidates[0] if candidates else None


def read_generation_counts(mem, package_obj):
    data, num, maxv = read_tarray_header(
        mem, package_obj + UPACKAGE_GENERATION_COUNTS
    )
    if num < 0 or num > 128 or maxv < num or maxv > 512:
        return None
    if num and not data:
        return None

    values = []
    for i in range(num):
        values.append(mem.i32(data + i * 4))
    return values


def build_package_states(objs, mem, collected, package_names):
    states = {}
    object_base = 0

    for package_name in package_names:
        package_obj = find_package_root(objs, collected, package_name)
        if not package_obj:
            raise RuntimeError("UPackage not found: %s" % package_name)

        data, num, maxv = read_tarray_header(
            mem, package_obj + UPACKAGE_NETOBJECTS
        )
        if num < 0 or num > 2_000_000 or maxv < num:
            raise RuntimeError(
                "%s NetObjects header invalid: Data=0x%08X Num=%d Max=%d"
                % (package_name, data, num, maxv)
            )
        if num and not data:
            raise RuntimeError(
                "%s NetObjects.Data == NULL with Num=%d"
                % (package_name, num)
            )

        current_num = mem.i32(package_obj + UPACKAGE_CURRENT_NUM)
        generations = read_generation_counts(mem, package_obj)

        # In this APB build the latest generation count is the PackageMap
        # ObjectCount.  Fall back to NetObjects.Num only if the generation
        # array cannot be validated.
        object_count = (
            generations[-1]
            if generations
            else num
        )

        if object_count < 0 or object_count > num:
            raise RuntimeError(
                "%s bad ObjectCount: generation=%d NetObjects.Num=%d"
                % (package_name, object_count, num)
            )

        mismatches = 0
        non_null = 0
        slot_objects = []

        for local in range(object_count):
            try:
                obj = mem.ptr(data + local * 4)
            except Exception:
                obj = 0

            slot_objects.append(obj)

            if not obj:
                continue

            non_null += 1
            raw = mem.try_u32(obj + UO_NETINDEX, None)
            if raw is None or sgn32(raw) != local:
                mismatches += 1

        state = {
            "name": package_name,
            "package_obj": package_obj,
            "netobjects_data": data,
            "netobjects_num": num,
            "netobjects_max": maxv,
            "current_num": current_num,
            "generations": generations or [],
            "object_count": object_count,
            "object_base": object_base,
            "non_null": non_null,
            "mismatches": mismatches,
            "slots": slot_objects,
        }
        states[package_name] = state
        object_base += object_count

    return states


def object_local_netindex(mem, obj):
    raw = mem.try_u32(obj + UO_NETINDEX, None)
    return None if raw is None else sgn32(raw)


def object_global_netindex(objs, mem, obj, package_states):
    local = object_local_netindex(mem, obj)
    if local is None or local < 0:
        return None

    pkg = objs.package_name(obj)
    state = package_states.get(pkg)
    if not state or local >= state["object_count"]:
        return None

    return state["object_base"] + local


def class_super(objs, mem, cls_obj):
    ptr = mem.try_u32(cls_obj + USTRUCT_SUPER, None)
    if not ptr:
        return 0
    try:
        if objs.class_name(ptr) != "Class":
            return 0
    except Exception:
        return 0
    if ptr == cls_obj:
        return 0
    return ptr


def read_direct_netfields(objs, mem, cls_obj):
    try:
        data, num, maxv = read_tarray_header(
            mem, cls_obj + UCLASS_NETFIELDS
        )
    except Exception:
        return {
            "ok": False,
            "data": 0,
            "num": -1,
            "max": -1,
            "fields": [],
            "reason": "unreadable header",
        }

    if num < 0 or num > 10000 or maxv < num or maxv > 20000:
        return {
            "ok": False,
            "data": data,
            "num": num,
            "max": maxv,
            "fields": [],
            "reason": "invalid TArray header",
        }

    if num == 0:
        return {
            "ok": True,
            "data": data,
            "num": 0,
            "max": maxv,
            "fields": [],
            "reason": "",
        }

    if not data:
        return {
            "ok": False,
            "data": 0,
            "num": num,
            "max": maxv,
            "fields": [],
            "reason": "Data == NULL",
        }

    fields = []
    valid_types = 0

    for i in range(num):
        field = mem.try_u32(data + i * 4, None)
        if not field:
            continue
        fields.append(field)
        cls_name = objs.class_name(field)
        if cls_name == "Function" or cls_name.endswith("Property"):
            valid_types += 1

    # Non-empty NetFields should overwhelmingly be Functions/Properties.
    if fields and valid_types < int(len(fields) * 0.90):
        return {
            "ok": False,
            "data": data,
            "num": num,
            "max": maxv,
            "fields": fields,
            "reason": "less than 90% Function/*Property pointers",
        }

    return {
        "ok": True,
        "data": data,
        "num": num,
        "max": maxv,
        "fields": fields,
        "reason": "",
    }


def supported_netfields(objs, mem, cls_obj, package_states):
    raw = read_direct_netfields(objs, mem, cls_obj)
    if not raw["ok"]:
        return raw, []

    supported = []
    for field in raw["fields"]:
        local = object_local_netindex(mem, field)
        pkg = objs.package_name(field)
        state = package_states.get(pkg)

        if local is None or local < 0:
            continue
        if not state:
            continue
        if local >= state["object_count"]:
            continue

        supported.append(field)

    return raw, supported


def field_kind(objs, field):
    cls = objs.class_name(field)
    if cls == "Function":
        return "function"
    if cls.endswith("Property"):
        return "property"
    return cls


def field_flags(objs, mem, field):
    kind = field_kind(objs, field)
    if kind == "function":
        flags = mem.try_u32(field + UFUNCTION_FLAGS, None)
        return fmt_flags(flags, FUNCTION_FLAG_NAMES)
    if kind == "property":
        flags = try_u64(mem, field + UPROPERTY_FLAGS)
        return fmt_flags(flags, PROPERTY_FLAG_NAMES)
    return ""


def build_class_maps(objs, mem, collected, package_states, output_packages):
    class_set = set(collected["classes"])
    memo = {}
    visiting = set()
    failures = {}

    def resolve(cls_obj):
        if cls_obj in memo:
            return memo[cls_obj]
        if cls_obj in visiting:
            failures[cls_obj] = "inheritance cycle"
            return None

        visiting.add(cls_obj)
        super_cls = class_super(objs, mem, cls_obj)

        parent = None
        if super_cls:
            if super_cls not in class_set:
                failures[cls_obj] = (
                    "superclass is not a live UClass: 0x%08X"
                    % super_cls
                )
                visiting.remove(cls_obj)
                return None
            parent = resolve(super_cls)
            if parent is None:
                failures[cls_obj] = (
                    "unresolved superclass %s"
                    % objs.path(super_cls)
                )
                visiting.remove(cls_obj)
                return None

        raw, own_fields = supported_netfields(
            objs, mem, cls_obj, package_states
        )
        if not raw["ok"]:
            failures[cls_obj] = (
                "UClass::NetFields invalid: %s"
                % raw["reason"]
            )
            visiting.remove(cls_obj)
            return None

        base = parent["field_max"] if parent else 0
        entries = []
        next_index = base

        for field in own_fields:
            entries.append({
                "field_index": next_index,
                "field": field,
                "name": objs.name(field),
                "path": objs.path(field),
                "kind": field_kind(objs, field),
                "flags": field_flags(objs, mem, field),
                "package": objs.package_name(field),
                "local_netindex": object_local_netindex(mem, field),
                "global_netindex": object_global_netindex(
                    objs, mem, field, package_states
                ),
            })
            next_index += 1

        result = {
            "class": cls_obj,
            "path": objs.path(cls_obj),
            "name": objs.name(cls_obj),
            "package": objs.package_name(cls_obj),
            "super": super_cls,
            "super_path": objs.path(super_cls) if super_cls else None,
            "super_name": objs.name(super_cls) if super_cls else None,
            "base": base,
            "own_slots": len(entries),
            "field_max": next_index,
            "raw_netfields_num": raw["num"],
            "raw_netfields_max": raw["max"],
            "entries": entries,
            "parent": parent,
            "source": "DERIVED_RUNTIME_UClass::NetFields",
        }

        memo[cls_obj] = result
        visiting.remove(cls_obj)
        return result

    # Resolve every class so bases are available even when only a subset is
    # emitted.
    for cls_obj in collected["classes"]:
        resolve(cls_obj)

    emitted = []
    for cls_obj, row in memo.items():
        if row["package"] not in output_packages:
            continue
        if row["own_slots"] <= 0:
            continue
        emitted.append(row)

    emitted.sort(
        key=lambda r: (
            r["name"].lower(),
            r["package"].lower(),
            r["path"].lower(),
        )
    )

    return emitted, memo, failures


def inherited_field_lookup(class_row):
    mapping = {}
    chain = []
    cur = class_row
    while cur:
        chain.append(cur)
        cur = cur["parent"]

    for row in reversed(chain):
        for entry in row["entries"]:
            mapping[entry["name"]] = entry["field_index"]
    return mapping


def verify_field_calibration(class_memo, collected, objs):
    by_path = {
        row["path"]: row
        for row in class_memo.values()
    }
    results = []

    for class_path, field_name, expected in FIELDINDEX_CALIBRATION:
        row = by_path.get(class_path)
        if row is None:
            results.append({
                "class": class_path,
                "field": field_name,
                "expected": expected,
                "actual": None,
                "ok": False,
                "reason": "class unresolved",
            })
            continue

        fields = inherited_field_lookup(row)
        actual = fields.get(field_name)
        results.append({
            "class": class_path,
            "field": field_name,
            "expected": expected,
            "actual": actual,
            "ok": actual == expected,
            "reason": "",
        })

    return results


def verify_netindex_calibration(collected, objs, mem):
    results = []
    by_path = collected["by_path"]

    for path, expected in NETINDEX_CALIBRATION.items():
        obj = by_path.get(path)
        actual = object_local_netindex(mem, obj) if obj else None
        results.append({
            "path": path,
            "expected": expected,
            "actual": actual,
            "ok": actual == expected,
        })
    return results


def write_netindex_map(path, objs, mem, package_state, net_calibration):
    lines = []
    now = _dt.datetime.now().astimezone()

    lines.append("# Package: %s" % package_state["name"])
    lines.append("#")
    lines.append(
        "# Runtime source: live UPackage::NetObjects @ +0x%02X"
        % UPACKAGE_NETOBJECTS
    )
    lines.append(
        "# UObject::NetIndex @ +0x%02X; validated by NetObjects[index] == UObject*"
        % UO_NETINDEX
    )
    lines.append(
        "# GlobalNetIndex = Package.ObjectBase + local index"
    )
    lines.append("#")
    lines.append(
        "# generated %s"
        % now.isoformat(timespec="seconds")
    )
    lines.append(
        "# ObjectBase=%d ObjectCount=%d NetObjects.Num=%d "
        "CurrentNumNetObjects=%d nonNull=%d mismatches=%d"
        % (
            package_state["object_base"],
            package_state["object_count"],
            package_state["netobjects_num"],
            package_state["current_num"],
            package_state["non_null"],
            package_state["mismatches"],
        )
    )
    if package_state["generations"]:
        lines.append(
            "# GenerationNetObjectCount=[%s]"
            % ", ".join(str(v) for v in package_state["generations"])
        )

    lines.append("#")
    lines.append("# calibration against direct runtime knowledge:")
    for row in net_calibration:
        if not row["path"].startswith(package_state["name"] + "."):
            continue
        lines.append(
            "#   %s expected=%s actual=%s %s"
            % (
                row["path"],
                row["expected"],
                row["actual"] if row["actual"] is not None else "?",
                "OK" if row["ok"] else "FAIL",
            )
        )

    lines.append("#")
    lines.append("# index\tname")
    lines.append("")

    for local, obj in enumerate(package_state["slots"]):
        if obj:
            name = objs.name(obj)
        else:
            name = "<NULL>"
        lines.append("%d\t%s" % (local, name))

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8-sig",
    )


def write_fieldindex_map(
    path,
    rows,
    package_states,
    field_calibration,
    failures,
):
    lines = []
    now = _dt.datetime.now().astimezone()

    lines.append("# Runtime FieldIndex map")
    lines.append(
        "# generated %s"
        % now.isoformat(timespec="seconds")
    )
    lines.append("#")
    lines.append(
        "# Source: live UClass::NetFields(+0x%X) + live UPackage::NetObjects"
        % UCLASS_NETFIELDS
    )
    lines.append(
        "# Mapping confidence: DERIVED_RUNTIME unless separately validated by "
        "a direct heap FClassNetCache probe."
    )
    lines.append("#")
    lines.append(
        "# rule: index = FieldsBase(class) + position in supported own NetFields"
    )
    lines.append(
        "#       fieldMax = FieldsBase(class) + count(supported own NetFields)"
    )
    lines.append(
        "# order: exact live UClass::NetFields array order; no export-ordinal reconstruction"
    )
    lines.append("#")

    lines.append("# ---- network package bases ----")
    for pkg in DEFAULT_NETWORK_PACKAGES:
        state = package_states.get(pkg)
        if not state:
            continue
        lines.append(
            "#   %-8s ObjectBase=%-6d ObjectCount=%-6d "
            "NetObjects.Num=%-6d mismatches=%d"
            % (
                pkg,
                state["object_base"],
                state["object_count"],
                state["netobjects_num"],
                state["mismatches"],
            )
        )

    lines.append("#")
    lines.append("# ---- calibration against direct live-captured FieldIndex ----")
    calibration_ok = True
    for row in field_calibration:
        calibration_ok = calibration_ok and row["ok"]
        lines.append(
            "#   %s.%s: expected %s, computed %s  %s"
            % (
                row["class"],
                row["field"],
                row["expected"],
                row["actual"] if row["actual"] is not None else "?",
                "OK" if row["ok"] else "FAIL",
            )
        )

    lines.append("#")
    lines.append(
        "# calibration status: %s"
        % ("PASS" if calibration_ok else "FAIL - inspect before trusting map")
    )
    lines.append("#")
    lines.append("# ================================================")
    lines.append("# RESOLVED (%d network classes with own slots)" % len(rows))
    lines.append("# ================================================")
    lines.append("")

    for row in rows:
        parent = row["super_name"] or "(none)"
        lines.append(
            "class %s extends %s"
            % (row["name"], parent)
        )
        lines.append(
            "  base=%d ownSlots=%d fieldMax=%d "
            "(derived from %s) [%s] source=runtime-netfields"
            % (
                row["base"],
                row["own_slots"],
                row["field_max"],
                parent,
                row["package"],
            )
        )
        for entry in row["entries"]:
            lines.append(
                "    %d  %s  [%s] %s"
                % (
                    entry["field_index"],
                    entry["name"],
                    entry["kind"],
                    entry["flags"],
                )
            )
        lines.append("")

    if failures:
        lines.append("# ================================================")
        lines.append("# UNRESOLVED / INVALID UClass::NetFields (%d)" % len(failures))
        lines.append("# ================================================")
        for cls_obj, reason in sorted(
            failures.items(),
            key=lambda kv: kv[1],
        ):
            lines.append(
                "# 0x%08X %s"
                % (cls_obj, reason)
            )

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8-sig",
    )


def print_package_summary(states):
    print("\nnetwork packages:")
    for name in DEFAULT_NETWORK_PACKAGES:
        state = states.get(name)
        if not state:
            continue
        print(
            "  %-8s base=%-6d count=%-6d NetObjects.Num=%-6d "
            "nonNull=%-6d mismatches=%d"
            % (
                name,
                state["object_base"],
                state["object_count"],
                state["netobjects_num"],
                state["non_null"],
                state["mismatches"],
            )
        )


def print_calibration(net_rows, field_rows):
    print("\nNetIndex calibration:")
    for row in net_rows:
        print(
            "  %-50s expected=%-6s actual=%-6s %s"
            % (
                row["path"],
                row["expected"],
                row["actual"] if row["actual"] is not None else "?",
                "OK" if row["ok"] else "FAIL",
            )
        )

    print("\nFieldIndex calibration:")
    for row in field_rows:
        print(
            "  %-70s expected=%-4s actual=%-4s %s"
            % (
                row["class"] + "." + row["field"],
                row["expected"],
                row["actual"] if row["actual"] is not None else "?",
                "OK" if row["ok"] else "FAIL",
            )
        )


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Generate current-runtime NetIndexMap.txt and FieldIndexMap.txt "
            "for APB Reloaded without using netindex_probe.py."
        )
    )
    ap.add_argument("--exe", default="APB.exe")
    ap.add_argument("--gnames", default=hex(DEFAULT_GNAMES))
    ap.add_argument("--gobjects", default=hex(DEFAULT_GOBJECTS))
    ap.add_argument(
        "--ghidra-base",
        default="0x10900000",
        help="used only with --rebase",
    )
    ap.add_argument(
        "--rebase",
        action="store_true",
        help="treat --gnames/--gobjects as addresses relative to Ghidra image base",
    )
    ap.add_argument(
        "--name-number-mode",
        choices=("mem", "uelib"),
        default="mem",
    )
    ap.add_argument(
        "--out-dir",
        default="generated_maps",
        help="output directory (default: generated_maps)",
    )
    ap.add_argument(
        "--net-package",
        default="APBGame",
        choices=DEFAULT_NETWORK_PACKAGES,
        help=(
            "package written to NetIndexMap.txt; FieldIndexMap still uses "
            "Core+Engine+APBGame (default: APBGame)"
        ),
    )
    args = ap.parse_args()

    mem = R.LiveProcess(args.exe)
    print(
        "process pid=%d module=0x%08X"
        % (mem.pid, mem.module_base or 0)
    )

    gnames = conv(args.gnames)
    gobjects = conv(args.gobjects)

    if args.rebase and mem.module_base:
        delta = mem.module_base - conv(args.ghidra_base)
        gnames += delta
        gobjects += delta
        print(
            "rebase delta=%+d (0x%08X)"
            % (delta, delta & 0xFFFFFFFF)
        )

    print(
        "GNames=0x%08X GObjects=0x%08X"
        % (gnames, gobjects)
    )

    names = NameTable(
        mem,
        gnames,
        number_mode=args.name_number_mode,
    )
    objs = Objects(mem, gobjects, names)

    print(
        "GNames.Num=%d Max=%d GObjects.Num=%d"
        % (names.num, names.max, objs.num)
    )

    collected = collect_objects(objs)

    package_states = build_package_states(
        objs,
        mem,
        collected,
        DEFAULT_NETWORK_PACKAGES,
    )
    print_package_summary(package_states)

    # Hard fail on a broken NetObjects invariant.  FieldIndex SupportsObject
    # filtering depends on these maps.
    broken = [
        name
        for name, state in package_states.items()
        if state["mismatches"] != 0
    ]
    if broken:
        raise RuntimeError(
            "NetObjects[NetIndex] invariant failed for: %s"
            % ", ".join(broken)
        )

    net_calibration = verify_netindex_calibration(
        collected, objs, mem
    )

    field_rows, class_memo, failures = build_class_maps(
        objs,
        mem,
        collected,
        package_states,
        set(DEFAULT_NETWORK_PACKAGES),
    )

    field_calibration = verify_field_calibration(
        class_memo,
        collected,
        objs,
    )

    print_calibration(net_calibration, field_calibration)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    net_path = out_dir / "NetIndexMap.txt"
    field_path = out_dir / "FieldIndexMap.txt"

    write_netindex_map(
        net_path,
        objs,
        mem,
        package_states[args.net_package],
        net_calibration,
    )

    write_fieldindex_map(
        field_path,
        field_rows,
        package_states,
        field_calibration,
        failures,
    )

    print("\nwritten:")
    print("  %s" % net_path.resolve())
    print("  %s" % field_path.resolve())
    print(
        "  FieldIndex classes=%d unresolved=%d"
        % (len(field_rows), len(failures))
    )

    if not all(row["ok"] for row in field_calibration):
        print(
            "\nWARNING: one or more FieldIndex calibration checks failed. "
            "Do not treat FieldIndexMap.txt as authoritative until inspected."
        )
        return 2

    if not all(
        row["ok"]
        for row in net_calibration
        if row["path"].startswith(args.net_package + ".")
    ):
        print(
            "\nWARNING: NetIndex calibration failed for selected package."
        )
        return 2

    print("\ncalibration: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print("!! ERROR: %s" % exc)
        raise
