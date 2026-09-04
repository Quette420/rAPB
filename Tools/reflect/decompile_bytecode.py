#!/usr/bin/env python3
"""Decompile APB 1.1.0.534979 UnrealScript functions to readable pseudo-code.

Builds on the exact token walker (`disasm_bytecode.py`): it consumes the same
byte grammar but *renders* each expression to a string, so a scripted function's
logic comes out as readable UnrealScript-like statements instead of an opcode
trace. This is the "replicate the scripted functions" step behind
`profiles/function-replicability.json` -- the ~37% of functions with real bodies
can be lifted directly from here.

Control flow is emitted as a correct *linearization*: statements in byte order,
with `Lxxx:` labels at jump targets and explicit `goto L…` / `if (!cond) goto L…`
/ `return …`. That is faithful and never mis-nests; structuring the gotos into
if/else/loops is a later pass. Native calls render as `native_0xNN(args)` because
the engine's native-function-index → name table is not in the package (the args
and call structure are recovered; the native name is not).

Because it reuses the walker's exact consumption, it never desyncs: an opcode
whose rendering is unspecified still consumes its operands correctly and shows as
`«token»`. Coverage is reported so the honest limit is visible.

Read-only, offline. `--print Class.Func` decompiles one function; `--out` writes a
profile with a curated set of emulator-critical functions plus decompile-coverage
stats. Emits derived pseudo-code of the client's own script (names/logic), no raw
client bytes. Not inherited from any other build.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import upackage           # noqa: E402
import decode_functions   # noqa: E402

EX_EndFunctionParms = 0x16
EX_EndOfScript = 0x53
EX_HighNative = 0x60
EX_FirstNative = 0x70

# UnrealScript native operator function-name prefixes -> infix/prefix symbol.
_BINOP = {
    "Add": "+", "Subtract": "-", "Multiply": "*", "Divide": "/", "Modulo": "%", "Percent": "%",
    "EqualEqual": "==", "NotEqual": "!=", "Less": "<", "Greater": ">",
    "LessEqual": "<=", "GreaterEqual": ">=", "ComplementEqual": "~=",
    "AndAnd": "&&", "OrOr": "||", "XorXor": "^^", "And": "&", "Or": "|", "Xor": "^",
    "Concat": "$", "At": "@", "ShiftLeft": "<<", "ShiftRight": ">>",
    "AddEqual": "+=", "SubtractEqual": "-=", "MultiplyEqual": "*=", "DivideEqual": "/=",
}
_PREOP = {"Not_PreBool": "!", "Subtract_PreInt": "-", "Subtract_PreFloat": "-",
          "Complement_PreInt": "~"}
_POSTOP = {"AddAdd": "++", "SubtractSubtract": "--"}


def load_natives(package_path: Path):
    """index -> native function name, from the sibling .u packages."""
    idx = {}
    for name in ("Core.u", "Engine.u", "APBGame.u", "APBUserInterface.u", "IpDrv.u"):
        p = package_path.parent / name
        if not p.is_file():
            continue
        pkg = upackage.Package(str(p))
        for f in pkg.find_exports(class_name="Function"):
            try:
                d = decode_functions.decode_function(pkg, f)
            except Exception:   # noqa: BLE001
                continue
            ni = d["i_native"]
            if ni and ni > 0 and ni not in idx:
                idx[ni] = f["object_name"]
    return idx

# Curated emulator-critical scripted functions to decompile into the profile.
CRITICAL = [
    ("cAPBPawn", "Stun"), ("cAPBPawn", "EndArrest"), ("cAPBPawn", "BeginRespawnDeath"),
    ("cAPBPawn", "AskForRespawn"), ("cAPBPawn", "UpdateArrestTimeRemaining"),
    ("Respawning", "Tick"), ("Respawning", "BeginState"), ("DyingRespawn", "BeginState"),
    ("Dead", "ClientReceiveRespawnInfo"), ("cAPBPlayerController", "GoToSpawnZoneSelectScreen"),
    ("cHostingClient", "OnDistrictEnter"), ("cHostingGC2DS", "DistrictEnter"),
    ("cAPBPlayerController", "OnDatabaseLoadComplete"),
    ("cAPBPawnAnimation", "ReplicatedEvent"),   # a switch example
    ("cHostingLobby", "SetWorldOffline"),        # while/break search-loop example
    ("GolemSpawnerActor", "SpawnCharacterAtRandomLocation"),  # do-while + while/break
]


class Decompiler:
    def __init__(self, code, pkg, natives=None):
        self.b = code
        self.pos = 0
        self.pkg = pkg
        self.natives = natives or {}
        self.targets = set()   # jump-target byte offsets
        self.unrendered = 0

    # ---- byte readers ----
    def u8(self):
        v = self.b[self.pos]; self.pos += 1; return v

    def u16(self):
        v = struct.unpack_from("<H", self.b, self.pos)[0]; self.pos += 2; return v

    def i32(self):
        v = struct.unpack_from("<i", self.b, self.pos)[0]; self.pos += 4; return v

    def f32(self):
        v = struct.unpack_from("<f", self.b, self.pos)[0]; self.pos += 4; return v

    def obj(self):
        return self.pkg.object_name(self.i32()) or "None"

    def fname(self):
        idx = self.i32(); self.i32()
        return self.pkg.names[idx] if 0 <= idx < len(self.pkg.names) else f"name{idx}"

    def cstr(self):
        s = []
        while True:
            c = self.b[self.pos]; self.pos += 1
            if c == 0:
                break
            s.append(chr(c))
        return "".join(s)

    def ucstr(self):
        s = []
        while True:
            c = struct.unpack_from("<H", self.b, self.pos)[0]; self.pos += 2
            if c == 0:
                break
            s.append(chr(c))
        return "".join(s)

    def params_list(self):
        args = []
        while self.b[self.pos] != EX_EndFunctionParms:
            a = self.expr()
            if a != "":                     # drop omitted optional params (EmptyParmValue/Nothing)
                args.append(a)
        self.pos += 1
        return args

    def params(self):
        return "(" + ", ".join(self.params_list()) + ")"

    def native_call(self, op):
        idx = ((op & 0x0F) << 8) | self.u8() if op < EX_FirstNative else op
        name = self.natives.get(idx, f"native_{idx}")
        args = self.params_list()
        # infix/prefix/postfix operators render specially
        pre = name.split("_", 1)[0]
        if name in _PREOP and len(args) == 1:
            return f"{_PREOP[name]}{args[0]}"
        if pre in _POSTOP and len(args) == 1:
            return f"{args[0]}{_POSTOP[pre]}"
        if pre in _BINOP and len(args) == 2:
            return f"({args[0]} {_BINOP[pre]} {args[1]})"
        return name + "(" + ", ".join(args) + ")"

    # ---- expression renderer (mirrors Walker.expr consumption exactly) ----
    def expr(self):
        op = self.u8()
        if op >= EX_HighNative:
            return self.native_call(op)
        if op in (0x00, 0x01, 0x02, 0x03, 0x29, 0x48, 0x0E):
            return self.obj()
        if op in (0x43, 0x4B):
            return f"'{self.fname()}'"
        if op in (0x0B, 0x4A):
            return ""                       # Nothing / EmptyParmValue (omitted optional)
        if op == 0x17:
            return "self"
        if op == 0x25:
            return "0"
        if op == 0x26:
            return "1"
        if op == 0x27:
            return "true"
        if op == 0x28:
            return "false"
        if op == 0x2A:
            return "none"
        if op in (0x30, 0x31):
            return "0"                      # IntZero-ish placeholders
        if op in (0x3F, 0x08, 0x15, 0x5A):
            return "«nop»"
        if op == 0x04:                      # Return
            e = self.expr()
            return "return" if e in ("", "return") else "return " + e
        if op == 0x3A:                      # ReturnNothing
            self.obj(); return "return"
        if op == 0x06:                      # Jump
            t = self.u16(); self.targets.add(t); return f"goto L{t}"
        if op == 0x07:                      # JumpIfNot
            t = self.u16(); self.targets.add(t); c = self.expr(); return f"if (!({c})) goto L{t}"
        if op in (0x0F, 0x14, 0x44):        # Let / LetBool / LetDelegate
            lhs = self.expr(); rhs = self.expr(); return f"{lhs} = {rhs}"
        if op == 0x18:                      # Skip
            t = self.u16(); self.targets.add(t); return self.expr()
        if op in (0x19, 0x12):              # Context / ClassContext
            o = self.expr(); self.u16(); self.u16(); m = self.expr(); return f"{o}.{m}"
        if op in (0x1A, 0x10):              # ArrayElement / DynArrayElement
            a = self.expr(); i = self.expr(); return f"{a}[{i}]"
        if op in (0x1B, 0x37):              # VirtualFunction / GlobalFunction
            n = self.fname(); return n + self.params()
        if op == 0x1C:                      # FinalFunction
            n = self.obj(); return n + self.params()
        if op == 0x1D:                      # IntConst
            return str(self.i32())
        if op == 0x1E:                      # FloatConst
            return repr(round(self.f32(), 6))
        if op == 0x1F:                      # StringConst
            return '"' + self.cstr() + '"'
        if op == 0x34:                      # UnicodeStringConst
            return '"' + self.ucstr() + '"'
        if op == 0x20:                      # ObjectConst
            return self.obj()
        if op == 0x21:                      # NameConst
            return f"'{self.fname()}'"
        if op in (0x22, 0x23):              # Rotation/VectorConst
            self.pos += 12; return "<vec>"
        if op in (0x24, 0x2C):              # ByteConst / IntConstByte
            return str(self.u8())
        if op == 0x2D:                      # BoolVariable
            return self.expr()
        if op in (0x2E, 0x13, 0x52):        # DynamicCast / Metacast / InterfaceCast
            t = self.obj(); e = self.expr(); return f"{t}({e})"
        if op in (0x51, 0x50, 0x36):        # InterfaceContext / DynArrayLength
            return self.expr() + (".length" if op == 0x36 else "")
        if op == 0x58:                      # DynArrayIterator
            a = self.expr(); it = self.expr(); self.u8(); self.expr(); self.u16(); return f"foreach {a} ({it})"
        if op == 0x2F:                      # Iterator
            e = self.expr(); self.u16(); return f"foreach {e}"
        if op in (0x32, 0x33):              # StructCmpEq / StructCmpNe
            self.obj(); a = self.expr(); b = self.expr(); return f"({a} {'==' if op == 0x32 else '!='} {b})"
        if op == 0x35:                      # StructMember
            m = self.obj(); self.obj(); self.u8(); self.u8(); s = self.expr(); return f"{s}.{m}"
        if op == 0x38:                      # PrimitiveCast
            self.u8(); return self.expr()
        if op == 0x45:                      # Conditional
            c = self.expr(); self.u16(); a = self.expr(); self.u16(); b = self.expr(); return f"({c} ? {a} : {b})"
        if op == 0x42:                      # DelegateFunction
            self.u8(); self.obj(); n = self.fname(); return n + self.params()
        if op == 0x05:                      # Switch
            self.u16(); v = self.expr(); return f"switch ({v})"
        if op == 0x0A:                      # Case
            has = struct.unpack_from("<H", self.b, self.pos)[0] != 0xFFFF
            self.u16()
            return "case " + (self.expr() if has else "default") + ":"
        if op == 0x09:                      # Assert
            self.u16(); self.u8(); return "assert(" + self.expr() + ")"
        if op == 0x11:                      # New
            a = [self.expr() for _ in range(4)]; return "new(" + ", ".join(a) + ")"
        if op in (0x39, 0x40, 0x54):        # dyn-array ops (array, value)
            a = self.expr(); v = self.expr(); return f"{a}.op({v})"
        if op == 0x46:                      # DynArrayFind
            a = self.expr(); self.u16(); s = self.expr(); return f"{a}.find({s})"
        if op == 0x47:                      # DynArrayFindStruct
            a = self.expr(); self.u16(); p = self.expr(); s = self.expr(); return f"{a}.find({p},{s})"
        if op in (0x55, 0x56, 0x57):        # DynArray add/remove/insert
            a = self.expr(); self.u16(); v = self.expr(); return f"{a}.mod({v})"
        if op in (0x3B, 0x3C, 0x3D, 0x3E):  # delegate comparisons
            a = self.expr(); b = self.expr(); self.u8(); return f"({a} <=> {b})"
        if op == 0x49:                      # DefaultParmValue
            self.u16(); return "default=" + self.expr()
        if op == 0x41:                      # DebugInfo
            self.pos += 12; return "«dbg»"
        self.unrendered += 1
        return f"«op0x{op:02x}»"

    def decompile(self):
        """Return list of (offset, next_offset, statement)."""
        stmts = []
        while self.pos < len(self.b):
            off = self.pos
            op = self.b[self.pos]
            if op == EX_EndOfScript:
                self.pos += 1
                continue
            s = self.expr()
            if s and s != "«nop»":
                stmts.append((off, self.pos, s))
        return stmts


def structure(stmts):
    """Reconstruct if/else/while from the goto-linearised statements.

    Returns (lines, residual_gotos). If residual_gotos == 0 the control flow was
    fully reducible and the lines are clean structured code; otherwise the caller
    should fall back to the labelled-goto rendering (never a messy mix).
    """
    items = []
    for off, nxt, text in stmts:
        kind, target, cond = "stmt", None, None
        if text.startswith("if (!(") and " goto L" in text:
            kind = "if"; gpos = text.rindex(" goto L")
            target = int(text[gpos + len(" goto L"):])
            cond = text[len("if (!("):gpos]        # "<COND>))"
            if cond.endswith("))"):
                cond = cond[:-2]                    # strip the wrapping "!( … )"
        elif text.startswith("goto L"):
            kind = "goto"; target = int(text[len("goto L"):])
        elif text.startswith("return"):
            kind = "return"
        elif text.startswith("switch ("):
            kind = "switch"; cond = text[len("switch ("):-1]   # the switched value
        elif text.startswith("case ") or text == "default:":
            kind = "case"
        items.append({"off": off, "nxt": nxt, "kind": kind, "text": text,
                      "target": target, "cond": cond})
    off2idx = {it["off"]: i for i, it in enumerate(items)}
    lines, residual = [], [0]

    def idx_after(off):
        # index of first item at or after byte offset off
        for j, it in enumerate(items):
            if it["off"] >= off:
                return j
        return len(items)

    def resolve(off, depth=0):
        # follow chains of unconditional gotos (indirected break/continue)
        if depth > 8:
            return off
        j = off2idx.get(off)
        if j is not None and items[j]["kind"] == "goto":
            return resolve(items[j]["target"], depth + 1)
        return off

    def emit(i, end, indent, brk=None, cont=None):
        while i < len(items) and items[i]["off"] < end:
            it = items[i]
            # do-while: this item is the target of a backward conditional back-edge in scope
            be = None
            for j in range(i + 1, len(items)):
                if items[j]["off"] >= end:
                    break
                if items[j]["kind"] == "if" and items[j]["target"] == it["off"]:
                    be = j; break
            if be is not None and it["kind"] != "if":
                beit = items[be]
                after = items[be + 1]["off"] if be + 1 < len(items) else (1 << 30)
                lines.append(f"{indent}do {{")
                emit(i, beit["off"], indent + "  ", brk=after, cont=beit["off"])
                lines.append(f"{indent}}} while (!({beit['cond']}))")
                i = be + 1; continue
            if it["kind"] == "switch":
                # find switch end (Lend) = convergence point = max jump target in the region
                j, maxt = i + 1, 0
                while j < len(items) and items[j]["off"] < end:
                    ij = items[j]
                    if ij["kind"] in ("goto", "if") and ij["target"]:
                        maxt = max(maxt, ij["target"])
                    elif maxt and ij["off"] >= maxt:
                        break
                    j += 1
                lend = maxt
                if lend and idx_after(lend) <= len(items):
                    region_end = idx_after(lend)
                    lines.append(f"{indent}switch ({it['cond']}) {{")
                    k = i + 1
                    while k < region_end:
                        ck = items[k]
                        if ck["kind"] == "case":
                            lines.append(f"{indent}  {ck['text']}")
                            m = k + 1
                            while m < region_end and items[m]["kind"] != "case":
                                m += 1
                            body_end = m
                            if (body_end - 1 > k and items[body_end - 1]["kind"] == "goto"
                                    and items[body_end - 1]["target"] == lend):
                                body_end -= 1          # drop the trailing break
                            stop = items[body_end]["off"] if body_end < len(items) else lend
                            emit(k + 1, stop, indent + "    ", brk=lend, cont=cont)
                            k = m
                        else:
                            k += 1
                    lines.append(indent + "}")
                    i = region_end
                    continue
                # unresolved switch -> plain statement, keep goto fallback for the region
                lines.append(indent + it["text"]); i += 1; continue
            if it["kind"] == "if" and it["target"] and it["off"] < it["target"] <= end:
                t = it["target"]; tidx = idx_after(t)
                prev = items[tidx - 1] if tidx - 1 >= i + 1 else None
                if prev and prev["kind"] == "goto" and prev["target"] == it["off"]:
                    # while loop: body gets break->t (exit), continue->it.off (loop top)
                    lines.append(f"{indent}while ({it['cond']}) {{")
                    emit(i + 1, prev["off"], indent + "  ", brk=t, cont=it["off"])
                    lines.append(indent + "}")
                    i = tidx; continue
                if prev and prev["kind"] == "goto" and t < prev["target"] <= end:
                    lend = prev["target"]
                    lines.append(f"{indent}if ({it['cond']}) {{")
                    emit(i + 1, prev["off"], indent + "  ", brk=brk, cont=cont)
                    lines.append(indent + "} else {")
                    emit(tidx, lend, indent + "  ", brk=brk, cont=cont)
                    lines.append(indent + "}")
                    i = idx_after(lend); continue
                lines.append(f"{indent}if ({it['cond']}) {{")
                emit(i + 1, t, indent + "  ", brk=brk, cont=cont)
                lines.append(indent + "}")
                i = tidx; continue
            if it["kind"] == "if":
                lines.append(f"{indent}if (!({it['cond']})) goto L{it['target']}"); residual[0] += 1
            elif it["kind"] == "goto":
                rt = resolve(it["target"])
                if it["target"] == cont or rt == cont:
                    lines.append(indent + "continue")
                elif it["target"] == brk or rt == brk:
                    lines.append(indent + "break")
                else:
                    lines.append(f"{indent}goto L{it['target']}"); residual[0] += 1
            else:
                lines.append(indent + it["text"])
            i += 1

    emit(0, 1 << 30, "")
    return lines, residual[0]


def render(pkg, export, natives=None):
    d = decode_functions.decode_function(pkg, export)
    code = d["script"]
    if not code:
        return None
    dec = Decompiler(code, pkg, natives)
    try:
        stmts = dec.decompile()
    except Exception as exc:   # noqa: BLE001
        return {"error": str(exc)}
    structured_lines, residual = structure(stmts)
    if residual == 0:
        lines = structured_lines
        mode = "structured"
    else:
        lines = [f"{'L' + str(off) + ': ' if off in dec.targets else '      '}{s}"
                 for off, _nxt, s in stmts]
        mode = "goto"
    return {"lines": lines, "statements": len(stmts), "unrendered_ops": dec.unrendered,
            "control_flow": mode}


def find(pkg, owner, name):
    for f in pkg.find_exports(class_name="Function"):
        if f["object_name"] == name and pkg.object_name(f["outer_index"]) == owner:
            return f
    return None


def decompile_class(pkg, natives, class_name):
    """Decompile every scripted function of one class -> {func: lines}."""
    out = {}
    for f in pkg.find_exports(class_name="Function"):
        if pkg.object_name(f["outer_index"]) != class_name:
            continue
        d = decode_functions.decode_function(pkg, f)
        if len(d["script"]) <= 8 or (d["function_flags"] & 0x400):
            continue
        r = render(pkg, f, natives)
        if r and "lines" in r:
            out[f["object_name"]] = r["lines"]
    return out


def build_class_profile(pkg, natives, class_name) -> dict:
    funcs = decompile_class(pkg, natives, class_name)
    return {
        "client_profile": "1.1.0.534979",
        "package": pkg.name,
        "authority": "MEASURED (UnrealScript decompiled from APBGame.u)",
        "class": class_name,
        "summary": f"decompiled scripted functions of {class_name} (source-level UnrealScript)",
        "scripted_function_count": len(funcs),
        "functions": funcs,
        "caveats": [
            "Native and thin (<=8B) functions of the class are omitted (no script body to decompile).",
            "Control flow is structured where reducible, else labelled-goto; native calls are named "
            "but implemented in the engine, not here.",
            "Nothing inherited from any other build.",
        ],
    }


def build_profile(pkg, natives) -> dict:
    # coverage over all scripted bodies
    total = clean = errors = 0
    resolved_natives = unresolved_natives = 0
    structured = goto_fallback = 0
    for f in pkg.find_exports(class_name="Function"):
        d = decode_functions.decode_function(pkg, f)
        if len(d["script"]) <= 8 or (d["function_flags"] & 0x400):
            continue
        total += 1
        r = render(pkg, f, natives)
        if r is None or "error" in r:
            errors += 1
        elif r["unrendered_ops"] == 0:
            clean += 1
        if r and "lines" in r:
            for ln in r["lines"]:
                unresolved_natives += ln.count("native_")
            if r.get("control_flow") == "structured":
                structured += 1
            else:
                goto_fallback += 1
    critical = {}
    for owner, name in CRITICAL:
        f = find(pkg, owner, name)
        if f:
            r = render(pkg, f, natives)
            if r and "lines" in r:
                critical[f"{owner}.{name}"] = r["lines"]
    return {
        "client_profile": "1.1.0.534979",
        "package": pkg.name,
        "authority": "MEASURED (UnrealScript bytecode decompiled from APBGame.u)",
        "summary": "readable pseudo-code for scripted functions; control flow as labelled gotos "
                   "(faithful linearisation, structuring is a later pass)",
        "decompile_coverage": {
            "scripted_bodies": total,
            "fully_rendered": clean,
            "with_unrendered_ops_or_error": total - clean,
            "pct_fully_rendered": round(100 * clean / total, 1) if total else 0,
            "note": "fully_rendered = every opcode had a rendering; the rest still consume bytes "
                    "correctly and show unknown ops as «op0xNN» (never desyncs)",
        },
        "native_names": {
            "index_map_size": len(natives),
            "unresolved_call_sites": unresolved_natives,
            "note": "native functions resolve to real names (SetTimer, operators render infix); "
                    "unresolved ones (no i_native declaration in the scanned packages) stay native_<n>",
        },
        "control_flow_structuring": {
            "fully_structured": structured,
            "goto_fallback": goto_fallback,
            "pct_structured": round(100 * structured / total, 1) if total else 0,
            "note": "fully_structured = if/else/while reconstructed with braces and zero residual "
                    "gotos; the rest keep the faithful labelled-goto rendering (irreducible / "
                    "switch-heavy control flow) rather than risk a wrong structure",
        },
        "critical_functions": critical,
        "caveats": [
            "Control flow is a labelled-goto linearisation, not structured if/else/loops.",
            "Native-function calls render as native_0xNN(args): the engine native-index->name table is "
            "not in the package, so the name is unknown though the call/args are recovered.",
            "A rendered statement may still invoke native helpers; decompilation gives the script-level "
            "logic, not native semantics.",
            "Nothing inherited from any other build.",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", required=True, type=Path, help="path to APBGame.u")
    ap.add_argument("--print", dest="fn", help="decompile one function: Class.Func")
    ap.add_argument("--class", dest="cls", help="decompile all scripted functions of a class")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    if not args.package.is_file():
        sys.stderr.write(f"not found: {args.package}\n")
        return 2
    pkg = upackage.Package(str(args.package))
    natives = load_natives(args.package)
    if args.fn:
        owner, name = args.fn.split(".", 1)
        f = find(pkg, owner, name)
        if not f:
            sys.stderr.write(f"not found: {args.fn}\n"); return 2
        r = render(pkg, f, natives)
        print(f"// {owner}.{name}")
        for ln in (r["lines"] if r and "lines" in r else [str(r)]):
            print(ln)
        return 0
    if args.cls:
        data = build_class_profile(pkg, natives, args.cls)
        if not args.out:
            for fn, lines in data["functions"].items():
                print(f"// {args.cls}.{fn}")
                for ln in lines:
                    print(ln)
                print()
            return 0
    else:
        data = build_profile(pkg, natives)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        if "decompile_coverage" in data:
            c = data["decompile_coverage"]
            sys.stderr.write(f"wrote {args.out}: {c['pct_fully_rendered']}% fully rendered of "
                             f"{c['scripted_bodies']} scripted bodies\n")
        else:
            sys.stderr.write(f"wrote {args.out}: {data['scripted_function_count']} functions of "
                             f"{data['class']}\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
