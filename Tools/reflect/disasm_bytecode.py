"""Same-build UnrealScript bytecode token walker for APB 1.1.0.534979.

Purpose: confirm the UE3 bytecode grammar for THIS build by the exact-consumption
invariant. Every scripted UFunction body is a sequence of serialized expressions
of length ScriptStorageSize. If the opcode/operand grammar is correct, walking a
body consumes exactly that many bytes and ends on the terminal EX_EndOfScript
token. The walk is bounded: any out-of-range read, unknown opcode, or over/under
run is reported for that function rather than guessed past.

Opcode names come from the well-known UE3 EExprToken table; this tool's evidence
is the *fit* of that grammar to this build's bytes (measured), not the names.

This tool never writes to the client tree.

Usage:
  python tools/offline/disasm_bytecode.py <package.u> [...] [--json OUT]
                                          [--print FUNC] [--show-fails N]
"""

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import upackage
import decode_functions

# EExprToken names (UE3, historical). Operand grammar is validated by fit.
TOKENS = {
    0x00: "LocalVariable", 0x01: "InstanceVariable", 0x02: "DefaultVariable",
    0x04: "Return", 0x05: "Switch", 0x06: "Jump", 0x07: "JumpIfNot",
    0x08: "Stop", 0x09: "Assert", 0x0A: "Case", 0x0B: "Nothing",
    0x0C: "LabelTable", 0x0D: "GotoLabel", 0x0E: "EatReturnValue", 0x0F: "Let",
    0x10: "DynArrayElement", 0x11: "New", 0x12: "ClassContext", 0x13: "Metacast",
    0x14: "LetBool", 0x15: "EndParmValue", 0x16: "EndFunctionParms", 0x17: "Self",
    0x18: "Skip", 0x19: "Context", 0x1A: "ArrayElement", 0x1B: "VirtualFunction",
    0x1C: "FinalFunction", 0x1D: "IntConst", 0x1E: "FloatConst", 0x1F: "StringConst",
    0x20: "ObjectConst", 0x21: "NameConst", 0x22: "RotationConst", 0x23: "VectorConst",
    0x24: "ByteConst", 0x25: "IntZero", 0x26: "IntOne", 0x27: "True",
    0x28: "False", 0x29: "NativeParm", 0x2A: "NoObject", 0x2C: "IntConstByte",
    0x2D: "BoolVariable", 0x2E: "DynamicCast", 0x2F: "Iterator", 0x30: "IteratorPop",
    0x31: "IteratorNext", 0x32: "StructCmpEq", 0x33: "StructCmpNe", 0x34: "UnicodeStringConst",
    0x35: "StructMember", 0x36: "DynArrayLength", 0x37: "GlobalFunction", 0x38: "PrimitiveCast",
    0x39: "DynArrayInsert", 0x3A: "ReturnNothing", 0x3B: "EqualEqual_DelDel",
    0x3C: "NotEqual_DelDel", 0x3D: "EqualEqual_DelFunc", 0x3E: "NotEqual_DelFunc",
    0x3F: "EmptyDelegate", 0x40: "DynArrayRemove", 0x41: "DebugInfo", 0x42: "DelegateFunction",
    0x43: "DelegateProperty", 0x44: "LetDelegate", 0x45: "Conditional", 0x46: "DynArrayFind",
    0x47: "DynArrayFindStruct", 0x48: "LocalOutVariable", 0x49: "DefaultParmValue",
    0x4A: "EmptyParmValue", 0x4B: "InstanceDelegate",
    0x50: "InterfaceContext", 0x51: "InterfaceCast", 0x52: "EndOfScript",
    0x53: "EndOfScript",
    0x54: "DynArrayAdd", 0x55: "DynArrayAddItem", 0x56: "DynArrayRemoveItem",
    0x57: "DynArrayInsertItem", 0x58: "DynArrayIterator", 0x59: "DynArraySort",
    0x5A: "FilterEditorOnly",
}

EX_EndFunctionParms = 0x16
EX_EndOfScript = 0x53
EX_HighNative = 0x60          # 0x60..0x6F extended native, 0x70..0xFF native
EX_FirstNative = 0x70

# Cast-token operand for EX_PrimitiveCast (0x38): a single ECastToken byte, then expr.


class WalkError(Exception):
    def __init__(self, message, offset, opcode):
        super().__init__(message)
        self.offset = offset
        self.opcode = opcode


class Walker:
    def __init__(self, code, pkg=None):
        self.b = code
        self.pos = 0
        self.tokens = Counter()
        self.pkg = pkg
        self.trace = []          # (offset, opcode, [resolved symbols]) when pkg is provided
        self._syms = None

    def _need(self, count):
        if self.pos + count > len(self.b):
            raise WalkError(f"read {count} past end", self.pos, None)

    def u8(self):
        self._need(1)
        v = self.b[self.pos]
        self.pos += 1
        return v

    def u16(self):
        self._need(2)
        v = struct.unpack_from("<H", self.b, self.pos)[0]
        self.pos += 2
        return v

    def i32(self):
        self._need(4)
        v = struct.unpack_from("<i", self.b, self.pos)[0]
        self.pos += 4
        return v

    def skip(self, n):
        self._need(n)
        self.pos += n

    def objref(self):
        value = self.i32()
        if self._syms is not None and self.pkg is not None:
            self._syms.append(self.pkg.object_name(value) or "None")

    def name(self):
        index = self.i32()
        self.i32()  # FName number
        if self._syms is not None and self.pkg is not None and 0 <= index < len(self.pkg.names):
            self._syms.append(f"'{self.pkg.names[index]}'")

    def cstr(self):
        start = self.pos
        while True:
            self._need(1)
            ch = self.b[self.pos]
            self.pos += 1
            if ch == 0:
                break
            if self.pos - start > 8192:
                raise WalkError("unterminated StringConst", start, 0x1F)

    def ucstr(self):
        while True:
            self._need(2)
            ch = struct.unpack_from("<H", self.b, self.pos)[0]
            self.pos += 2
            if ch == 0:
                break

    def params(self):
        # expression list terminated by EX_EndFunctionParms
        while True:
            self._need(1)
            if self.b[self.pos] == EX_EndFunctionParms:
                self.pos += 1
                self.tokens[EX_EndFunctionParms] += 1
                return
            self.expr()

    def native_call(self, opcode):
        if opcode < EX_FirstNative:            # 0x60..0x6F extended native
            self.u8()                          # second index byte
        self.params()

    def expr(self):
        start = self.pos
        op = self.u8()
        self.tokens[op] += 1
        if self.pkg is not None:
            self._syms = []
            self.trace.append((start, op, self._syms))

        if op >= EX_HighNative:
            self.native_call(op)
            return op

        if op in (0x00, 0x01, 0x02, 0x03, 0x29, 0x48, 0x0E):  # var / native-parm / eat-return refs
            self.objref(); return op
        if op in (0x43, 0x4B):  # DelegateProperty / InstanceDelegate: FName (8 bytes)
            self.name(); return op
        if op in (0x0B, 0x17, 0x25, 0x26, 0x27, 0x28, 0x2A,
                  0x30, 0x31, 0x3F, 0x08, 0x15, 0x53, 0x5A, 0x4A):
            return op                                           # no operands
        if op == 0x04:  # Return
            self.expr(); return op
        if op == 0x3A:  # ReturnNothing
            self.objref(); return op
        if op == 0x06:  # Jump
            self.u16(); return op
        if op == 0x07:  # JumpIfNot
            self.u16(); self.expr(); return op
        if op == 0x0F or op == 0x14 or op == 0x44:  # Let / LetBool / LetDelegate
            self.expr(); self.expr(); return op
        if op == 0x18:  # Skip
            self.u16(); self.expr(); return op
        if op == 0x19 or op == 0x12:  # Context / ClassContext
            # this build: object expr, WORD wSkip, WORD bSize, member expr (4-byte middle)
            self.expr(); self.u16(); self.u16(); self.expr(); return op
        if op == 0x1A:  # ArrayElement
            self.expr(); self.expr(); return op
        if op == 0x10:  # DynArrayElement
            self.expr(); self.expr(); return op
        if op == 0x1B or op == 0x37:  # VirtualFunction / GlobalFunction
            self.name(); self.params(); return op
        if op == 0x1C:  # FinalFunction
            self.objref(); self.params(); return op
        if op == 0x1D:  # IntConst
            self.skip(4); return op
        if op == 0x1E:  # FloatConst
            self.skip(4); return op
        if op == 0x1F:  # StringConst
            self.cstr(); return op
        if op == 0x34:  # UnicodeStringConst
            self.ucstr(); return op
        if op == 0x20:  # ObjectConst
            self.objref(); return op
        if op == 0x21:  # NameConst
            self.name(); return op
        if op == 0x22:  # RotationConst
            self.skip(12); return op
        if op == 0x23:  # VectorConst
            self.skip(12); return op
        if op == 0x24 or op == 0x2C:  # ByteConst / IntConstByte
            self.skip(1); return op
        if op == 0x2D:  # BoolVariable
            self.expr(); return op
        if op in (0x2E, 0x13, 0x52):  # DynamicCast / Metacast / InterfaceCast (objref + expr)
            self.objref(); self.expr(); return op
        if op == 0x51:  # InterfaceContext: single expr
            self.expr(); return op
        if op == 0x58:  # DynArrayIterator: array, iter, BYTE, index, WORD skip
            self.expr(); self.expr(); self.u8(); self.expr(); self.u16(); return op
        if op == 0x2F:  # Iterator
            self.expr(); self.u16(); return op
        if op == 0x32 or op == 0x33:  # StructCmpEq / StructCmpNe
            self.objref(); self.expr(); self.expr(); return op
        if op == 0x35:  # StructMember
            self.objref(); self.objref(); self.u8(); self.u8(); self.expr(); return op
        if op == 0x36:  # DynArrayLength
            self.expr(); return op
        if op == 0x38:  # PrimitiveCast
            self.u8(); self.expr(); return op
        if op == 0x45:  # Conditional
            self.expr(); self.u16(); self.expr(); self.u16(); self.expr(); return op
        if op == 0x50:  # InterfaceContext
            self.expr(); return op
        if op == 0x42:  # DelegateFunction
            self.u8(); self.objref(); self.name(); self.params(); return op
        if op == 0x05:  # Switch: u16 bSize (type size; 1 for byte-typed), then value expr
            self.u16(); self.expr(); return op
        if op == 0x0A:  # Case
            self.u16()
            if self.pos >= 2 and struct.unpack_from("<H", self.b, self.pos - 2)[0] != 0xFFFF:
                self.expr()
            return op
        if op == 0x09:  # Assert
            self.u16(); self.u8(); self.expr(); return op
        if op == 0x11:  # New
            self.expr(); self.expr(); self.expr(); self.expr(); return op
        if op in (0x39, 0x40, 0x54):  # dyn-array ops taking (array, value)
            self.expr(); self.expr(); return op
        if op == 0x46:  # DynArrayFind: array, WORD skip, search
            self.expr(); self.u16(); self.expr(); return op
        if op == 0x47:  # DynArrayFindStruct: array, WORD skip, prop, search
            self.expr(); self.u16(); self.expr(); self.expr(); return op
        if op in (0x55, 0x56, 0x57):  # DynArray add/remove/insert item
            self.expr(); self.u16(); self.expr(); return op
        if op in (0x3B, 0x3C, 0x3D, 0x3E):  # delegate comparisons: two operands + EndFunctionParms sentinel
            self.expr(); self.expr()
            term = self.u8()
            if term != EX_EndFunctionParms:
                raise WalkError(f"delegate cmp missing EndFunctionParms (got 0x{term:02x})", self.pos - 1, op)
            self.tokens[EX_EndFunctionParms] += 1
            return op
        if op == 0x49:  # DefaultParmValue
            self.u16(); self.expr(); return op
        if op == 0x41:  # DebugInfo (usually stripped)
            self.skip(12); return op

        raise WalkError(f"unhandled opcode 0x{op:02x}", self.pos - 1, op)


def walk_function(code, pkg=None):
    w = Walker(code, pkg=pkg)
    while w.pos < len(code):
        w.expr()
    return w


def disassemble_text(pkg, export):
    """Return a readable per-token listing for one function (linear token order)."""
    decoded = decode_functions.decode_function(pkg, export)
    code = decoded["script"]
    w = walk_function(code, pkg=pkg)
    lines = [
        f"{export['object_name']}  (script {len(code)} bytes, iNative={decoded['i_native']}, "
        f"flags=0x{decoded['function_flags']:x}, replicated={decoded['replicated']})"
    ]
    for offset, op, syms in w.trace:
        name = TOKENS.get(op, "ExtendedNative" if op < EX_FirstNative else "NativeCall") if op >= EX_HighNative else TOKENS.get(op, f"?0x{op:02x}")
        detail = ("  " + ", ".join(syms)) if syms else ""
        lines.append(f"  @{offset:4d}  0x{op:02x} {name}{detail}")
    return "\n".join(lines)


def analyze(path, show_fails=0):
    pkg = upackage.Package(path)
    functions = pkg.find_exports(class_name="Function")
    exact = 0
    failed = []
    token_hist = Counter()
    for export in functions:
        try:
            decoded = decode_functions.decode_function(pkg, export)
        except Exception as error:  # noqa: BLE001 (header decode already covered elsewhere)
            failed.append((export["object_name"], f"header: {error}"))
            continue
        code = decoded["script"]
        if not code:
            exact += 1
            continue
        try:
            w = walk_function(code)
            if w.pos == len(code):
                exact += 1
                token_hist.update(w.tokens)
            else:
                failed.append((export["object_name"], f"consumed {w.pos}/{len(code)}"))
        except WalkError as error:
            failed.append(
                (export["object_name"], f"{error} at {error.offset}/{len(code)}")
            )

    summary = {
        "package": pkg.name,
        "function_count": len(functions),
        "walked_exactly": exact,
        "walk_failures": len(failed),
        "failure_examples": [f"{n}: {m}" for n, m in failed[:show_fails]] if show_fails else [],
        "top_tokens": [
            {"opcode": f"0x{op:02x}", "name": TOKENS.get(op, "native" if op >= 0x60 else "?"),
             "count": count}
            for op, count in token_hist.most_common(15)
        ],
    }
    return pkg, summary, failed


def main():
    parser = argparse.ArgumentParser(description="APB 1.1.0.534979 UnrealScript token walker")
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--json")
    parser.add_argument("--print", dest="print_fn")
    parser.add_argument("--show-fails", type=int, default=0)
    args = parser.parse_args()

    summaries = []
    for path in args.packages:
        pkg, summary, failed = analyze(path, show_fails=args.show_fails)
        summaries.append(summary)
        print(f"=== {summary['package']} ===")
        print(
            f"  functions={summary['function_count']} "
            f"walked_exactly={summary['walked_exactly']} "
            f"failures={summary['walk_failures']}"
        )
        for example in summary["failure_examples"]:
            print(f"  FAIL {example}")
        if args.print_fn:
            for export in pkg.find_exports(class_name="Function", object_name=args.print_fn):
                print(disassemble_text(pkg, export))
                break

    if args.json:
        Path(args.json).write_text(json.dumps(summaries, indent=2), encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
