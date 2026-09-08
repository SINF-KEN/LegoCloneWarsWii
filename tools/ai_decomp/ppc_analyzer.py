#!/usr/bin/env python3
"""PowerPC semantic analyzer for decompilation support.

Reads a function context JSON produced by tools/ghidra/ExportFunctionContext.java
and derives semantic facts that Ghidra's reference database misses:

  - register constant propagation (lis/addi/ori/oris address construction)
  - resolved memory addresses (lwz r3, 0x10(r7) with r7 known)
  - table/array accesses (lwzx with constant base + symbolic index)
  - direct and indirect calls (bl, bctr with known CTR value)
  - virtual call patterns (lwz vtable; lwz vtable+off; mtctr; bctr)
  - branch inventory

This is a linear, best-effort static analysis, not an emulator. Registers are
tracked in instruction order without basic-block merging, so values are only
trusted until a register is reassigned.

Usage:
    python3 tools/ai_decomp/ppc_analyzer.py <function_json> [--write] [--stdout]
"""

import argparse
import json
import re
import sys

MASK32 = 0xFFFFFFFF


def sext16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def parse_int(text):
    text = text.strip()
    neg = text.startswith("-")
    if neg:
        text = text[1:]
    if text.lower().startswith("0x"):
        v = int(text, 16)
    else:
        v = int(text, 10)
    return -v if neg else v


class Value:
    """Either a 32-bit constant or a symbolic expression string."""

    __slots__ = ("kind", "value", "expr")

    def __init__(self, kind, value=None, expr=None):
        self.kind = kind  # "const" | "expr" | "unknown"
        self.value = value
        self.expr = expr

    @staticmethod
    def const(v):
        return Value("const", value=v & MASK32)

    @staticmethod
    def unknown():
        return Value("unknown")

    def is_const(self):
        return self.kind == "const"

    def signed(self):
        v = self.value
        return v - 0x100000000 if v & 0x80000000 else v

    def __str__(self):
        if self.kind == "const":
            return hex(self.value)
        if self.kind == "expr":
            return self.expr
        return "?"


UNKNOWN = Value.unknown()


def expr_val(text):
    return Value("expr", expr=text)


def rlwinm_mask(mb, me):
    # PowerPC mask: ones from bit mb to bit me (bit 0 = MSB)
    if mb <= me:
        m = 0
        for i in range(mb, me + 1):
            m |= 1 << (31 - i)
        return m
    else:
        m = MASK32
        for i in range(me + 1, mb):
            m &= ~(1 << (31 - i))
        return m


def rotate_left(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & MASK32


class Instruction:
    def __init__(self, line):
        m = re.match(r"^\s*([0-9a-fA-F]+):\s*(\S+)\s*(.*)$", line)
        if not m:
            raise ValueError("unparseable instruction line: %r" % line)
        self.address = int(m.group(1), 16)
        self.mnemonic = m.group(2).lower()
        self.operand_text = m.group(3).strip()
        self.operands = self._split_operands(self.operand_text)

    @staticmethod
    def _split_operands(text):
        if not text:
            return []
        # memory operands look like "0x10(r12)" and contain no commas,
        # so a plain comma split is sufficient for PPC syntax
        return [p.strip() for p in text.split(",")]

    def __repr__(self):
        return "%08x: %s %s" % (self.address, self.mnemonic, self.operand_text)


MEM_RE = re.compile(r"^(-?(?:0x[0-9a-fA-F]+|\d+))\((\w+)\)$")


def parse_mem_operand(op):
    m = MEM_RE.match(op)
    if not m:
        return None
    return parse_int(m.group(1)), m.group(2)


class Analyzer:
    def __init__(self):
        self.regs = {}  # reg name (r3, ctr, ...) -> Value
        self.derived = {
            "register_values": [],
            "memory_accesses": [],
            "branches": [],
            "calls": [],
            "address_constructions": [],
            "indirect_calls": [],
        }
        # rolling window for virtual-call pattern matching
        self.recent = []
        # register -> index into address_constructions of an unfinished
        # (high-half only) address construction, cleared when the register
        # is overwritten or used as a source before the sequence completes
        self.pending_construction = {}

    def set_reg(self, reg, value, addr):
        self.regs[reg] = value
        if value.kind != "unknown":
            self.derived["register_values"].append(
                {
                    "address": "%08x" % addr,
                    "register": reg,
                    "value": str(value),
                    "kind": value.kind,
                }
            )
            if value.kind == "const" and value.value >= 0x80000000:
                entry = {
                    "address": "%08x" % addr,
                    "register": reg,
                    "value": hex(value.value),
                }
                constructions = self.derived["address_constructions"]
                pending = self.pending_construction.get(reg)
                if pending is not None and pending < len(constructions):
                    # completion of a lis/addi (or addis/ori) sequence:
                    # keep the start address and the completed value only
                    entry["address"] = constructions[pending]["address"]
                    constructions[pending] = entry
                else:
                    constructions.append(entry)
                    self.pending_construction[reg] = len(constructions) - 1
            else:
                self.pending_construction.pop(reg, None)

    def get_reg(self, reg):
        v = self.regs.get(reg)
        if v is None:
            # never-assigned register: treat as a named symbolic (parameter)
            return expr_val(reg)
        return v

    # ---- ALU ----

    def eval_alu(self, ins):
        mn = ins.mnemonic
        ops = ins.operands

        if mn in ("lis",):
            # lis rD, imm  ->  rD = imm << 16
            self.set_reg(ops[0], Value.const(parse_int(ops[1]) << 16), ins.address)
        elif mn == "li":
            self.set_reg(ops[0], Value.const(parse_int(ops[1])), ins.address)
        elif mn in ("addi", "addic", "addic.", "subi"):
            dst, src, imm = ops[0], ops[1], parse_int(ops[2])
            if src in ("r0",) or src == dst and False:
                pass
            if src == "r0" and mn == "addi":
                # addi rD, r0, imm is li, but r0-as-base is valid too
                pass
            src_val = self.get_reg(src)
            base = Value.const(0) if src == "r0" else src_val
            if base.is_const():
                self.set_reg(dst, Value.const(base.value + imm), ins.address)
            else:
                e = str(base)
                if imm:
                    e = "(%s + %d)" % (e, imm)
                self.set_reg(dst, expr_val(e), ins.address)
        elif mn == "addis":
            dst, src, imm = ops[0], ops[1], parse_int(ops[2])
            src_val = Value.const(0) if src == "r0" else self.get_reg(src)
            if src_val.is_const():
                self.set_reg(dst, Value.const(src_val.value + (imm << 16)),
                             ins.address)
            else:
                self.set_reg(dst, expr_val("(%s + 0x%x)" % (src_val, imm << 16 & MASK32)),
                             ins.address)
        elif mn == "ori":
            dst, src, imm = ops[0], ops[1], parse_int(ops[2])
            src_val = Value.const(0) if src == "r0" else self.get_reg(src)
            if src_val.is_const():
                self.set_reg(dst, Value.const(src_val.value | (imm & 0xFFFF)),
                             ins.address)
            else:
                self.set_reg(dst, expr_val("(%s | 0x%x)" % (src_val, imm & 0xFFFF)),
                             ins.address)
        elif mn == "oris":
            dst, src, imm = ops[0], ops[1], parse_int(ops[2])
            src_val = Value.const(0) if src == "r0" else self.get_reg(src)
            if src_val.is_const():
                self.set_reg(dst, Value.const(src_val.value | ((imm & 0xFFFF) << 16)),
                             ins.address)
            else:
                self.set_reg(dst, expr_val("(%s | 0x%x)" % (src_val, (imm & 0xFFFF) << 16)),
                             ins.address)
        elif mn in ("or", "mr"):
            if mn == "mr":
                dst, src = ops[0], ops[1]
            else:
                dst, a, b = ops[0], ops[1], ops[2]
                va = Value.const(0) if a == "r0" else self.get_reg(a)
                vb = Value.const(0) if b == "r0" else self.get_reg(b)
                if va.is_const() and vb.is_const():
                    self.set_reg(dst, Value.const(va.value | vb.value), ins.address)
                    return
                self.set_reg(dst, expr_val("(%s | %s)" % (va, vb)), ins.address)
                return
            src_val = self.get_reg(src)
            self.set_reg(dst, src_val if src_val.kind != "unknown"
                         else expr_val(src), ins.address)
        elif mn in ("add", "add."):
            dst, a, b = ops[0], ops[1], ops[2]
            va, vb = self.get_reg(a), self.get_reg(b)
            if va.is_const() and vb.is_const():
                self.set_reg(dst, Value.const(va.value + vb.value), ins.address)
            else:
                self.set_reg(dst, expr_val("(%s + %s)" % (va, vb)), ins.address)
        elif mn in ("subf", "subf."):
            dst, b, a = ops[0], ops[1], ops[2]  # subf rD, rA, rB: rD = rB - rA
            va, vb = self.get_reg(a), self.get_reg(b)
            if va.is_const() and vb.is_const():
                self.set_reg(dst, Value.const(vb.value - va.value), ins.address)
            else:
                self.set_reg(dst, expr_val("(%s - %s)" % (vb, va)), ins.address)
        elif mn in ("mullw", "mullw."):
            dst, a, b = ops[0], ops[1], ops[2]
            va, vb = self.get_reg(a), self.get_reg(b)
            if va.is_const() and vb.is_const():
                self.set_reg(dst, Value.const(va.value * vb.value), ins.address)
            else:
                self.set_reg(dst, expr_val("(%s * %s)" % (va, vb)), ins.address)
        elif mn == "mulli":
            dst, a, imm = ops[0], ops[1], parse_int(ops[2])
            va = self.get_reg(a)
            if va.is_const():
                self.set_reg(dst, Value.const(va.value * imm), ins.address)
            else:
                self.set_reg(dst, expr_val("(%s * %d)" % (va, imm)), ins.address)
        elif mn in ("slw", "slw."):
            dst, a, b = ops[0], ops[1], ops[2]
            va, vb = self.get_reg(a), self.get_reg(b)
            if va.is_const() and vb.is_const():
                self.set_reg(dst, Value.const(va.value << (vb.value & 31)), ins.address)
            else:
                self.set_reg(dst, expr_val("(%s << (%s & 31))" % (va, vb)), ins.address)
        elif mn in ("srw", "srw.", "sraw", "sraw."):
            dst, a, b = ops[0], ops[1], ops[2]
            va, vb = self.get_reg(a), self.get_reg(b)
            op = ">>" if mn.startswith("srw") else ">>a"
            if va.is_const() and vb.is_const():
                self.set_reg(dst, Value.const(va.value >> (vb.value & 31)), ins.address)
            else:
                self.set_reg(dst, expr_val("(%s %s (%s & 31))" % (va, op, vb)),
                             ins.address)
        elif mn == "rlwinm":
            dst, src = ops[0], ops[1]
            sh = parse_int(ops[2]) & 31
            mb, me = parse_int(ops[3]), parse_int(ops[4])
            mask = rlwinm_mask(mb, me)
            vs = self.get_reg(src)
            if vs.is_const():
                self.set_reg(dst, Value.const(rotate_left(vs.value, sh) & mask),
                             ins.address)
            else:
                # render the common idioms readably
                if sh:
                    m2 = mask >> sh
                    if m2 and (m2 & (m2 + 1)) == 0:
                        # mask is a low-bit mask shifted left: (v & m2) << sh
                        e = "(%s & 0x%x) << %d" % (vs, m2, sh)
                    else:
                        e = "((%s << %d) & 0x%x)" % (vs, sh, mask)
                else:
                    e = "(%s & 0x%x)" % (vs, mask)
                self.set_reg(dst, expr_val(e), ins.address)
        elif mn == "rlwimi":
            dst, src = ops[0], ops[1]
            sh = parse_int(ops[2]) & 31
            mb, me = parse_int(ops[3]), parse_int(ops[4])
            mask = rlwinm_mask(mb, me)
            vd = self.get_reg(dst) if dst in self.regs else UNKNOWN
            vs = self.get_reg(src)
            if vd.is_const() and vs.is_const():
                rot = rotate_left(vs.value, sh)
                self.set_reg(dst, Value.const((vd.value & ~mask) | (rot & mask)),
                             ins.address)
            else:
                self.set_reg(dst, expr_val("(%s | ((%s << %d) & 0x%x))"
                                           % (vd, vs, sh, mask)), ins.address)
        elif mn in ("lwzu", "stwu"):
            # update form: also writes base register with EA
            pass  # handled generically below via operand forms

    # ---- memory ----

    LOAD_SIZES = {"lwz": 4, "lwzu": 4,
                  "lbz": 1, "lhz": 2,
                  "ld": 8, "lfs": 4, "lfd": 8}
    STORE_SIZES = {"stw": 4, "stwu": 4,
                   "stb": 1, "sth": 2, "std": 8, "stfs": 4, "stfd": 8}

    def record_access(self, ins, kind, size, dst_reg, base_val, index_val,
                      base_reg, index_reg):
        entry = {
            "address": "%08x" % ins.address,
            "type": kind,
            "size": size,
        }
        if dst_reg:
            entry["register"] = dst_reg
        if base_reg:
            entry["base_register"] = base_reg
        if index_reg:
            entry["index_register"] = index_reg
        if index_val is None:
            if base_val.is_const():
                entry["effective_address"] = hex(base_val.value)
            else:
                entry["effective_address"] = str(base_val)
        else:
            # indexed: lwzx rD, rA, rB -> EA = rA + rB
            if base_val.is_const() and index_val.is_const():
                entry["effective_address"] = hex((base_val.value + index_val.value) & MASK32)
            elif base_val.is_const():
                entry.update({
                    "table_base": hex(base_val.value),
                    "index": str(index_val),
                })
                if size:
                    entry["element_size"] = size
            elif index_val.is_const():
                entry["effective_address"] = "(%s + 0x%x)" % (base_val, index_val.value)
            else:
                entry["effective_address"] = "(%s + (%s))" % (base_val, index_val)
        self.derived["memory_accesses"].append(entry)
        return entry

    def eval_memory(self, ins):
        mn = ins.mnemonic
        ops = ins.operands

        if mn in self.LOAD_SIZES or mn in self.STORE_SIZES:
            size = (self.LOAD_SIZES.get(mn) or self.STORE_SIZES.get(mn))
            mem = parse_mem_operand(ops[-1])
            if mem is None:
                return
            off, base_reg = mem
            base_val = Value.const(0) if base_reg == "r0" else self.get_reg(base_reg)
            if base_val.is_const():
                ea = Value.const(base_val.value + off)
            else:
                ea = expr_val("(%s + %d)" % (base_val, off) if off else str(base_val))
            kind = "load" if mn in self.LOAD_SIZES else "store"
            self.record_access(ins, kind, size, ops[0], ea, None, base_reg, None)
            if kind == "load":
                self.set_reg(ops[0], expr_val("*(uint%d_t*)(%s)" % (size * 8, ea)),
                             ins.address)
            return

        INDEXED = {"lwzx": (4, "load"), "lwzx.": (4, "load"), "lbzx": (1, "load"),
                   "lhzx": (2, "load"), "stwx": (4, "store"), "stbx": (1, "store"),
                   "sthx": (2, "store")}
        if mn in INDEXED:
            size, kind = INDEXED[mn]
            dst_reg, a_reg, b_reg = ops[0], ops[1], ops[2]
            base_val = Value.const(0) if a_reg == "r0" else self.get_reg(a_reg)
            idx_val = self.get_reg(b_reg)
            self.record_access(ins, kind, size, dst_reg, base_val, idx_val,
                               a_reg, b_reg)
            if kind == "load":
                ea = ("(%s + (%s))" % (base_val, idx_val))
                self.set_reg(dst_reg, expr_val("*(uint%d_t*)(%s)" % (size * 8, ea)),
                             ins.address)
            return

        if mn == "lwzu":
            pass  # already covered by LOAD_SIZES

    # ---- control flow ----

    BRANCHES = {"b", "ba", "beq", "bne", "blt", "bgt", "ble", "bge",
                "bltl", "bnel", "bgtl", "blel", "bgel", "bdnz", "bdz"}

    def eval_control(self, ins):
        mn = ins.mnemonic
        ops = ins.operands

        if mn == "bl":
            target = ops[-1]
            self.derived["calls"].append(
                {"address": "%08x" % ins.address, "target": target,
                 "type": "direct"})
        elif mn in ("b", "ba"):
            self.derived["branches"].append(
                {"address": "%08x" % ins.address, "type": "unconditional",
                 "target": ops[-1]})
        elif mn in ("blr", "blrl"):
            self.derived["branches"].append(
                {"address": "%08x" % ins.address, "type": "return"})
        elif mn in self.BRANCHES:
            self.derived["branches"].append(
                {"address": "%08x" % ins.address, "type": mn,
                 "target": ops[-1]})
        elif mn in ("bctr", "bcctr", "bctrl", "bcctrl"):
            ctr = self.get_reg("ctr")
            entry = {"address": "%08x" % ins.address,
                     "type": "call" if mn.endswith("l") else "jump"}
            if ctr.is_const():
                entry["target"] = hex(ctr.value)
            else:
                entry["target"] = "unknown(%s)" % ctr
                # look for a virtual-call pattern in the recent window
                vcall = self.match_virtual_call(ins)
                if vcall:
                    entry["virtual_call"] = vcall
            self.derived["indirect_calls"].append(entry)
        elif mn == "mtspr":
            # mtspr CTR, rX  /  mtspr LR, rX
            spr, reg = ops[0], ops[1]
            spr_l = spr.lower()
            if spr_l in ("ctr", "lr", "9", "8"):
                name = "ctr" if spr_l in ("ctr", "9") else "lr"
                self.set_reg(name, self.get_reg(reg), ins.address)

    def match_virtual_call(self, ins):
        """Detect: lwz rX, 0(rY); lwz rX, off(rX); mtspr CTR, rX; bctr."""
        window = self.recent[-4:]
        if len(window) < 3:
            return None
        strs = [(i.mnemonic, i.operands) for i in window]
        # last three before the branch
        try:
            (m1, o1), (m2, o2), (m3, o3) = strs[-3:]
        except ValueError:
            return None
        if not (m1.startswith("lwz") and m2.startswith("lwz")
                and m3 == "mtspr"):
            return None
        if o3[0].lower() != "ctr":
            return None
        mem2 = parse_mem_operand(o2[1])
        if mem2 is None:
            return None
        vtable_reg = o1[-1].split("(")[-1].rstrip(")")
        return {
            "object_register": vtable_reg,
            "vtable_offset": mem2[0],
            "pattern": "object->vtable[%d]()" % (mem2[0] // 4),
        }

    # mnemonics whose first operand is the destination GPR; for everything
    # else all register operands are treated as sources
    DEST_WRITES = {
        "add", "add.", "addc", "addc.", "adde", "adde.", "addi", "addic",
        "addic.", "addis", "addme", "addme.", "addze", "addze.",
        "subf", "subf.", "subfc", "subfc.", "subfe", "subfe.", "subfic",
        "subfme", "subfme.", "subfze", "subfze.",
        "mullw", "mullw.", "mulli", "divw", "divw.", "divwu", "divwu.",
        "or", "or.", "ori", "oris", "xor", "xor.", "xori", "xoris",
        "and", "and.", "andi.", "andis.", "nor", "nor.", "nand", "nand.",
        "eqv", "orc", "slw", "slw.", "srw", "srw.", "sraw", "sraw.",
        "srawi", "srawi.", "rlwinm", "rlwinm.", "rlwimi", "rlwimi.",
        "rlwnm", "mr", "li", "lis", "la", "neg", "neg.", "extsb", "extsb.",
        "extsh", "extsh.", "cntlzw", "cntlzw.",
        "lwz", "lwzu", "lbz", "lbzu", "lhz", "lhzu", "lha", "lhau",
        "lfs", "lfsu", "lfd", "lfdu", "lwzx", "lwzux", "lbzx", "lhzx",
        "lhax", "lfsx", "lfdx",
    }

    @staticmethod
    def _source_regs(ins):
        regs = set(re.findall(r"\br\d+\b", ins.operand_text))
        if ins.operands and ins.mnemonic in Analyzer.DEST_WRITES:
            m = re.match(r"(r\d+)", ins.operands[0])
            if m:
                regs.discard(m.group(1))
        return regs

    # ---- driver ----

    def analyze(self, instructions):
        for line in instructions:
            try:
                ins = Instruction(line)
            except ValueError:
                continue
            self.eval_alu(ins)
            self.eval_memory(ins)
            self.eval_control(ins)
            for reg in self._source_regs(ins):
                self.pending_construction.pop(reg, None)
            self.recent.append(ins)
            if len(self.recent) > 8:
                self.recent.pop(0)
        return self.derived


def analyze_file(path):
    with open(path) as f:
        data = json.load(f)
    analyzer = Analyzer()
    derived = analyzer.analyze(data.get("instructions", []))
    return data, derived


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("function_json", help="function_<addr>.json from the Ghidra exporter")
    ap.add_argument("--write", action="store_true",
                    help="write function_<addr>_analyzed.json next to the input")
    ap.add_argument("--stdout", action="store_true", help="print derived JSON")
    args = ap.parse_args()

    data, derived = analyze_file(args.function_json)
    if args.stdout:
        print(json.dumps(derived, indent=2))
    if args.write:
        out_path = args.function_json.replace(".json", "_analyzed.json")
        data["derived"] = derived

        # join derived facts with Ghidra's data model (#11/#12); degrades
        # gracefully to empty lists when the catalog has not been exported
        try:
            import data_analysis
            data_analysis.enrich(data, derived)
        except ImportError:
            data["global_references"] = []
            data["string_references"] = []
            data["data_catalog_available"] = False

        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
        print("Wrote %s" % out_path, file=sys.stderr)
    if not args.stdout:
        # friendly summary
        print("Derived facts for %s (%s):" % (data.get("name"), data.get("address")))
        print("  register values:      %d" % len(derived["register_values"]))
        print("  address constructions:%d" % len(derived["address_constructions"]))
        for a in derived["address_constructions"]:
            print("    %s: %s = %s" % (a["address"], a["register"], a["value"]))
        print("  memory accesses:      %d" % len(derived["memory_accesses"]))
        for m in derived["memory_accesses"]:
            print("    %s %s %s" % (m["address"], m["type"],
                                    m.get("effective_address") or m.get("table_base", "")))
        print("  indirect calls:       %d" % len(derived["indirect_calls"]))
        for c in derived["indirect_calls"]:
            extra = c.get("virtual_call")
            print("    %s -> %s%s" % (c["address"], c["target"],
                                     (" " + str(extra["pattern"]) if extra else "")))
        for key in ("global_references", "string_references"):
            if key in data:
                print("  %s: %d" % (key, len(data[key])) +
                      ("" if data.get("data_catalog_available", True)
                       else "  (data catalog not exported yet)"))


if __name__ == "__main__":
    main()
