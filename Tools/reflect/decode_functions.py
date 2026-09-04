"""Decode UnrealScript UFunction exports from APB 1.1.0.534979 packages.

Establishes, by exact byte accounting, that compiled UnrealScript bytecode is
present and recoverable in this build's `.u` packages. The UFunction serial
layout was derived from this build's own bytes (see docs/PACKAGE_FORMAT.md and
docs/BYTECODE.md); it is validated on every function by three independent
invariants, and any violation aborts the decode for that function instead of
guessing:

  1. exact consumption: fixed-header(40) + ScriptStorageSize + script bytes +
     UFunction trailer consume the export's serial_size with zero remainder;
  2. self-describing trailer: FriendlyName resolves to a real name-table entry;
  3. adaptive RepOffset: the trailer is 15 bytes, or 17 iff FunctionFlags&0x40.

Layout (measured):
  [0x00] u32   NetIndex (0xFFFFFFFF for these objects)
  [0x04] FName None            -> empty tagged-property block (UObject)
  [0x0C] 28 bytes              -> UStruct object refs + Line/TextPos
                                  (field assignment provisional; size exact)
  [0x28] i32   ScriptStorageSize (S)
  [0x2C] S bytes               -> serialized UnrealScript bytecode
  ...    u16 iNative, u8 OperPrecedence, u32 FunctionFlags,
         [u16 RepOffset iff FunctionFlags & 0x40], FName FriendlyName

This tool never writes to the client tree. UnrealScript opcode *meanings* are
historical (well-known UE3 token tables) and labeled as such; the presence,
length, and boundaries of the bytecode are measured facts.

Usage:
  python tools/offline/decode_functions.py <package.u> [...] [--json OUT] [--sample NAME]
"""

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import upackage

FIXED_HEADER = 40           # bytes before ScriptStorageSize (measured)
FUNC_NET = 0x40             # FunctionFlags bit that adds a 2-byte RepOffset (measured)
NATIVE_STUB = bytes([0x0B, 0x53])  # EX_Nothing, EX_EndOfScript (historical opcode names)


class DecodeError(Exception):
    pass


def decode_function(pkg, export):
    b = pkg.export_bytes(export)
    n = len(b)
    if n < FIXED_HEADER + 4:
        raise DecodeError(f"{export['object_name']}: serial too short ({n})")
    script_size = struct.unpack_from("<i", b, FIXED_HEADER)[0]
    if script_size < 0 or FIXED_HEADER + 4 + script_size > n:
        raise DecodeError(f"{export['object_name']}: bad ScriptStorageSize {script_size}")
    script_start = FIXED_HEADER + 4
    script = b[script_start : script_start + script_size]
    trailer = b[script_start + script_size :]

    if len(trailer) < 15:
        raise DecodeError(f"{export['object_name']}: trailer too short ({len(trailer)})")
    i_native = struct.unpack_from("<H", trailer, 0)[0]
    oper_precedence = trailer[2]
    function_flags = struct.unpack_from("<I", trailer, 3)[0]
    replicated = bool(function_flags & FUNC_NET)
    fname_at = 9 if replicated else 7
    rep_offset = struct.unpack_from("<H", trailer, 7)[0] if replicated else None
    expected_trailer = fname_at + 8
    if len(trailer) != expected_trailer:
        raise DecodeError(
            f"{export['object_name']}: trailer {len(trailer)}B, expected {expected_trailer}"
            f" (flags=0x{function_flags:x})"
        )
    fn_index = struct.unpack_from("<i", trailer, fname_at)[0]
    fn_number = struct.unpack_from("<i", trailer, fname_at + 4)[0]
    if not 0 <= fn_index < len(pkg.names):
        raise DecodeError(f"{export['object_name']}: FriendlyName index {fn_index} out of range")
    friendly = pkg.names[fn_index]
    if fn_number:
        friendly = f"{friendly}_{fn_number - 1}"

    return {
        "object_name": export["object_name"],
        "serial_size": export["serial_size"],
        "script_size": script_size,
        "is_native_stub": script == NATIVE_STUB,
        "i_native": i_native,
        "oper_precedence": oper_precedence,
        "function_flags": function_flags,
        "replicated": replicated,
        "rep_offset": rep_offset,
        "friendly_name": friendly,
        "first_opcode": script[0] if script else None,
        "script": script,
    }


def analyze_package(path):
    pkg = upackage.Package(path)
    functions = pkg.find_exports(class_name="Function")
    decoded = []
    failures = []
    for export in functions:
        try:
            decoded.append(decode_function(pkg, export))
        except (DecodeError, upackage.ParseError) as error:
            failures.append(str(error))

    native = [d for d in decoded if d["is_native_stub"]]
    scripted = [d for d in decoded if not d["is_native_stub"] and d["script_size"] > 2]
    friendly_named = sum(1 for d in decoded if d["friendly_name"] == d["object_name"])
    operators = sum(1 for d in decoded if d["friendly_name"] != d["object_name"])
    replicated = sum(1 for d in decoded if d["replicated"])
    first_opcodes = Counter(d["first_opcode"] for d in scripted if d["first_opcode"] is not None)
    total_bytecode = sum(d["script_size"] for d in scripted)

    return pkg, {
        "package": pkg.name,
        "function_count": len(functions),
        "decoded_exactly": len(decoded),
        "decode_failures": len(failures),
        "failure_examples": failures[:5],
        "native_stub_count": len(native),
        "scripted_body_count": len(scripted),
        "total_scripted_bytecode_bytes": total_bytecode,
        "largest_bytecode_bytes": max((d["script_size"] for d in scripted), default=0),
        "replicated_function_count": replicated,
        "friendlyname_equals_export": friendly_named,
        "operator_functions": operators,
        "first_opcode_census_top": [
            {"opcode": f"0x{op:02x}", "count": count}
            for op, count in first_opcodes.most_common(12)
        ],
    }, decoded


def main():
    parser = argparse.ArgumentParser(description="APB 1.1.0.534979 UFunction bytecode decoder")
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--json", help="write combined JSON summary")
    parser.add_argument("--sample", help="print the raw bytecode of this function name if present")
    args = parser.parse_args()

    summaries = []
    for path in args.packages:
        pkg, summary, decoded = analyze_package(path)
        summaries.append(summary)
        print(f"=== {summary['package']} ===")
        print(
            f"  functions={summary['function_count']} "
            f"decoded_exactly={summary['decoded_exactly']} "
            f"failures={summary['decode_failures']}"
        )
        print(
            f"  native_stubs={summary['native_stub_count']} "
            f"scripted_bodies={summary['scripted_body_count']} "
            f"total_bytecode={summary['total_scripted_bytecode_bytes']}B "
            f"largest={summary['largest_bytecode_bytes']}B"
        )
        print(
            f"  friendlyname==export={summary['friendlyname_equals_export']} "
            f"operators={summary['operator_functions']} "
            f"replicated={summary['replicated_function_count']}"
        )
        if summary["failure_examples"]:
            for example in summary["failure_examples"]:
                print(f"  FAILURE: {example}")
        if args.sample:
            for d in decoded:
                if d["object_name"] == args.sample or d["friendly_name"] == args.sample:
                    code = " ".join(f"{x:02x}" for x in d["script"])
                    print(f"  sample {d['object_name']} ({d['script_size']}B): {code}")
                    break

    if args.json:
        Path(args.json).write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
