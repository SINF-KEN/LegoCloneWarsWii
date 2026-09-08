#!/usr/bin/env python3
"""Conservative type / struct / vtable EVIDENCE analysis (Phase 5.4).

Everything produced here is evidence, never authoritative source-level
truth: no class names, no struct names, no field names, no confirmed
types. Reuses ppc_analyzer's instruction parser; does not duplicate the
semantic analyzer.

Recognized patterns (all conservative):

  field        D-form load/store against a base register:
               lwz r4, 0x8(r3)  ->  base r3, +0x8, read, width 4
               widths: lbz/stb 1, lhz/sth 2, lwz/stw 4, lfs/stfs 4,
               lfd/stfd 8
  vtable       lwz rA, off(rR) ; lwz rA, slot(rA) ; mtctr rA ; bctr
               -> receiver rR, vtable pointer at receiver+off,
                  virtual slot at vtable+slot (slot_index = slot/4)
               a NONZERO off is recorded as such; +0 is not assumed
  funcptr      lwz rA, off(rR) ; mtctr rA ; bctr without the second
               vtable load -> function-pointer evidence only
  table_lookup an INDEXED load (lwzx etc.) through a base register
               that the semantic analyzer resolved to a constructed
               address (e.g. a global table) — explicitly NOT treated
               as a C++ object/receiver
  receiver     registers that serve as object bases for vtable
               dispatch (role evidence only)

Aggregation helpers answer cross-function questions (which fields,
slots, receivers recur) with counts and derived evidence levels
(observed / repeated / matched via objdiff-verified functions).
"""

import re

from ppc_analyzer import Instruction, parse_mem_operand

WIDTHS = {
    "lwz": 4, "lwzu": 4, "lwzx": 4,
    "lbz": 1, "lbzu": 1, "lbzx": 1,
    "lhz": 2, "lhzu": 2, "lhzx": 2,
    "lha": 2, "lhax": 2,
    "lfs": 4, "lfd": 8,
    "stw": 4, "stwu": 4, "stwx": 4,
    "sth": 2, "sthu": 2, "sthx": 2,
    "stb": 1, "stbu": 1, "stbx": 1,
    "stfs": 4, "stfd": 8,
}
INDEXED_LOADS = {"lwzx", "lbzx", "lhzx", "lhax", "lfsx", "lfdx"}
LOADS = {"lwz", "lwzu", "lwzx", "lbz", "lbzu", "lbzx", "lhz", "lhzu",
         "lhzx", "lha", "lhax", "lfs", "lfd", "lfsx", "lfdx"}
STORES = {"stw", "stwu", "stwx", "sth", "sthu", "sthx", "stb", "stbu",
          "stbx", "stfs", "stfd"}
BRANCH_THROUGH_CTR = {"bctr", "bctrl"}

MAX_FIELD_RECORDS = 24
MAX_PATTERN_RECORDS = 32


SPR_SUBS = [
    (re.compile(r"\bmtspr\s+CTR\b\s*,\s*", re.IGNORECASE), "mtctr "),
    (re.compile(r"\bmtspr\s+LR\b\s*,\s*", re.IGNORECASE), "mtlr "),
    (re.compile(r"\bmfspr\s+(\w+)\s*,\s*CTR\b", re.IGNORECASE),
     r"mfctr \1"),
    (re.compile(r"\bmfspr\s+(\w+)\s*,\s*LR\b", re.IGNORECASE),
     r"mflr \1"),
]


def _parse(lines):
    instrs = []
    for line in lines or []:
        for pattern, replacement in SPR_SUBS:
            line = pattern.sub(replacement, line)
        try:
            instrs.append(Instruction(line))
        except ValueError:
            continue
    return instrs


def _load_store_fields(ins):
    """(dest, base, offset, width, access) for D-form loads/stores."""
    mn = ins.mnemonic
    width = WIDTHS.get(mn)
    if width is None or len(ins.operands) < 2:
        return None
    mem = parse_mem_operand(ins.operands[-1])
    if mem is None:
        return None
    offset, base = mem
    access = "write" if mn in STORES else "read"
    dest = ins.operands[0] if mn in LOADS else None
    return dict(dest=dest, base=base, offset=offset, width=width,
                access=access)


def analyze_instructions(lines):
    """Extract conservative type/vtable/field evidence patterns.

    Returns a list of pattern dicts, each carrying a `kind` field:
      field | vtable | funcptr | table_lookup | receiver
    Bounded by MAX_PATTERN_RECORDS / MAX_FIELD_RECORDS.
    """
    instrs = _parse(lines)
    if not instrs:
        return []

    patterns = []
    vtable_load_addresses = set()

    # ---- virtual dispatch windows (classic and nonzero vtable offset)
    consumed = set()
    for i in range(len(instrs) - 3):
        w = instrs[i:i + 4]
        if w[0].mnemonic not in LOADS or w[1].mnemonic not in LOADS:
            continue
        if w[2].mnemonic != "mtctr" or w[3].mnemonic not in \
                BRANCH_THROUGH_CTR:
            continue
        m0 = parse_mem_operand(w[0].operands[-1])
        m1 = parse_mem_operand(w[1].operands[-1])
        if m0 is None or m1 is None:
            continue
        off0, base = m0
        off1, base1 = m1
        dest0 = w[0].operands[0]
        dest1 = w[1].operands[0]
        if base1 != dest0 or w[2].operands[-1] != dest1:
            continue
        if off1 % 4 != 0:
            continue
        patterns.append({
            "kind": "vtable",
            "register": base,
            "offset": off0,              # vtable pointer offset
            "slot_offset": off1,
            "slot_index": off1 // 4,
            "access": "read",
            "width": 4,
            "call_site": "%08x" % w[3].address,
            "instruction_address": "%08x" % w[0].address,
            "note": "receiver %s; vtable pointer at %s+0x%x; slot at "
                    "vtable+0x%x" % (base, base, off0, off1),
        })
        vtable_load_addresses.update(
            "%08x" % w[0].address, "%08x" % w[1].address)
        consumed.update((i, i + 1, i + 2, i + 3))

    # ---- function-pointer dispatch (mtctr without vtable window)
    for i in range(2, len(instrs)):
        if instrs[i].mnemonic not in BRANCH_THROUGH_CTR:
            continue
        if instrs[i - 1].mnemonic != "mtctr" or (i - 1) in consumed:
            continue
        prev = instrs[i - 2]
        if prev.mnemonic not in LOADS or (i - 2) in consumed:
            continue
        mem = parse_mem_operand(prev.operands[-1])
        if mem is None:
            continue
        mt_src = instrs[i - 1].operands[-1] if instrs[i - 1].operands \
            else None
        if prev.operands[0] != mt_src:
            continue
        off, base = mem
        patterns.append({
            "kind": "funcptr",
            "register": base,
            "offset": off,
            "call_site": "%08x" % instrs[i].address,
            "instruction_address": "%08x" % prev.address,
            "note": "indirect call through %s+0x%x; no vtable load "
                    "pattern present" % (base, off),
        })
        consumed.update((i - 2, i - 1))

    # ---- field accesses (D-form loads/stores), excluding vtable loads
    base_uses = {}   # register -> [instruction indices using it as base]
    field_records = []
    for i, ins in enumerate(instrs):
        if i in consumed or ins.address in vtable_load_addresses:
            continue
        f = _load_store_fields(ins)
        if f is None:
            continue
        field_records.append({
            "kind": "field",
            "register": f["base"],
            "offset": f["offset"],
            "access": f["access"],
            "width": f["width"],
            "instruction_address": "%08x" % ins.address,
            "pointer_like": False,
        })
        base_uses.setdefault(f["base"], []).append(len(field_records) - 1)
        if f["dest"]:
            base_uses.setdefault(f["dest"], [])

    # pointer-like: a read whose destination later serves as a base
    for reg, uses in base_uses.items():
        if uses and reg in base_uses:
            for idx in base_uses.get(reg, []):
                if field_records[idx]["access"] == "read":
                    field_records[idx]["pointer_like"] = True

    patterns.extend(field_records[:MAX_FIELD_RECORDS])

    # ---- table lookups: indexed loads through a resolved base
    for ins in instrs:
        if ins.mnemonic in INDEXED_LOADS and len(ins.operands) >= 3:
            patterns.append({
                "kind": "table_lookup",
                "register": ins.operands[1],
                "indexed": True,
                "index_register": ins.operands[2],
                "instruction_address": "%08x" % ins.address,
                "note": "indexed load through %s; the loaded value is "
                        "NOT classified as a C++ object"
                        % ins.operands[1],
            })

    # ---- receiver role evidence from vtable patterns
    for p in patterns:
        if p["kind"] == "vtable":
            patterns.append({
                "kind": "receiver",
                "register": p["register"],
                "note": "serves as object base for virtual dispatch",
            })
            break

    return patterns[:MAX_PATTERN_RECORDS]


# ----------------------------------------------------------------
# persistence
# ----------------------------------------------------------------

def record_evidence(conn, patterns, function_address, function_name=None,
                    matched=False):
    """Persist analysis patterns via database.record_type_evidence."""
    return db_record(conn, patterns, function_address, function_name,
                     matched)


def db_record(conn, patterns, function_address, function_name=None,
              matched=False):
    import database as db
    return db.record_type_evidence(conn, patterns,
                                   function_address=function_address,
                                   function_name=function_name,
                                   matched=matched)


# ----------------------------------------------------------------
# aggregation
# ----------------------------------------------------------------

def fields_by_receiver(conn, register):
    return [dict(r) for r in conn.execute(
        """SELECT register, offset, access, width,
                  COUNT(*) AS functions,
                  SUM(matched_count) AS matched_observations
           FROM type_evidence WHERE kind='field' AND register = ?
           GROUP BY register, offset, access, width
           ORDER BY offset""", (register,))]


def vtable_slots(conn):
    return [dict(r) for r in conn.execute(
        """SELECT register, offset AS vtable_offset,
                  slot_offset, slot_index,
                  COUNT(DISTINCT function_address) AS functions,
                  SUM(observation_count) AS observations,
                  SUM(matched_count) AS matched_observations
           FROM type_evidence WHERE kind='vtable'
           GROUP BY register, offset, slot_offset, slot_index
           ORDER BY slot_offset""")]


def functions_using_slot(conn, slot_offset):
    return [dict(r) for r in conn.execute(
        """SELECT DISTINCT function_address, function_name
           FROM type_evidence
           WHERE kind='vtable' AND slot_offset = ?""",
        (slot_offset,))]


def functions_accessing_offset(conn, offset):
    return [dict(r) for r in conn.execute(
        """SELECT DISTINCT function_address, function_name, register,
                  offset, access, width
           FROM type_evidence
           WHERE kind='field' AND offset = ?""", (offset,))]


def virtual_targets(conn):
    """Virtual-call sites with known targets. None are resolvable with
    the current evidence (vtable contents are not extracted), so this
    reports sites with an explicit unknown target."""
    return [dict(r) for r in conn.execute(
        """SELECT function_address, call_site, register, slot_offset,
                  'unknown' AS target
           FROM type_evidence WHERE kind='vtable' ORDER BY call_site""")]


def register_roles(conn, address):
    roles = []
    for r in conn.execute(
            """SELECT register, kind, COUNT(DISTINCT function_address)
                  AS n
               FROM type_evidence WHERE function_address = ?
               GROUP BY register, kind""", (address,)):
        role = "object/receiver" if r["kind"] in ("vtable", "receiver") \
            else None
        roles.append({"register": r["register"],
                      "role": role or r["kind"],
                      "evidence": r["n"]})
    return roles


# ----------------------------------------------------------------
# rendering (bounded, with mandatory disclaimer)
# ----------------------------------------------------------------

DISCLAIMER = ("Type/struct/vtable information is inferred evidence, "
              "not authoritative source-level truth. Do not invent "
              "class names, field names, or signatures unsupported by "
              "evidence.")


def render_type_evidence_markdown(patterns, max_fields=12):
    if not patterns:
        return ""
    vtables = [p for p in patterns if p["kind"] == "vtable"]
    tables = [p for p in patterns if p["kind"] == "table_lookup"]
    funcptrs = [p for p in patterns if p["kind"] == "funcptr"]
    fields = [p for p in patterns if p["kind"] == "field"][:max_fields]

    lines = [DISCLAIMER, ""]
    if vtables:
        lines.append("**Virtual dispatch**")
        for v in vtables:
            lines.append("- receiver %s +0x%x -> vtable pointer; "
                         "vtable +0x%x -> virtual slot %d"
                         % (v["register"], v["offset"],
                            v["slot_offset"], v["slot_index"]))
    if funcptrs:
        lines.append("**Indirect function-pointer calls** "
                     "(no vtable pattern present)")
        for f in funcptrs:
            lines.append("- %s +0x%x (call at %s)"
                         % (f["register"], f["offset"],
                            f.get("call_site") or "?"))
    if tables:
        lines.append("**Table lookups** (loaded values are NOT "
                     "classified as C++ objects)")
        for t in tables:
            lines.append("- indexed load via %s at %s"
                         % (t["register"],
                            t.get("instruction_address") or "?"))
    if fields:
        lines.append("**Observed field accesses**")
        for f in fields:
            like = " (pointer-like)" if f.get("pointer_like") else ""
            lines.append("- %s +0x%x: %s, width %d%s"
                         % (f["register"], f["offset"], f["access"],
                            f["width"], like))
    if len([p for p in patterns if p["kind"] == "field"]) > max_fields:
        lines.append("... additional field accesses omitted (bounded)")
    return "\n".join(lines)


def main():
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--instructions",
                    help="Ghidra export JSON with instruction lines")
    args = ap.parse_args()
    with open(args.instructions) as f:
        lines = json.load(f).get("instructions", [])
    print(json.dumps(analyze_instructions(lines), indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
