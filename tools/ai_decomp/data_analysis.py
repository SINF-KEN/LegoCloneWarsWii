#!/usr/bin/env python3
"""Global/data reference analysis for decompilation support.

Joins three sources into a per-function picture of global data usage:

  1. Ghidra's reference database (direct references, from
     ExportFunctionContext.java: data_ref_details)
  2. PowerPC-derived facts (ppc_analyzer.py: address_constructions,
     memory_accesses) that catch addresses Ghidra could not resolve
  3. The data catalog (ExportDataCatalog.java: memory blocks + defined
     data + strings) used to enrich every resolved address with
     section/label/type/size/string information

Produces, per function:

  global_references: one entry per resolved address
      address, access_type (read/write/read_write/address_only),
      indexed (direct global vs table access), instruction_addresses,
      width, base_register, index_expression, resolved_base_address,
      symbolic_expression, and data-model fields (defined, label,
      data_type, data_size, section, string)

  string_references: address, contents, encoding, reference
      instruction(s), direct or derived

Unresolved addresses are preserved (defined=false, address=null) rather
than dropped. Data types are only reported when Ghidra established them;
nothing is invented here.
"""

import json
import os
from bisect import bisect_right

MASK32 = 0xFFFFFFFF

# access width by instruction mnemonic (for Ghidra direct references)
MNEMONIC_WIDTH = {
    "lwz": 4, "lwzu": 4, "lwzx": 4, "lwzux": 4, "lwa": 4, "lwax": 4,
    "lhz": 2, "lhzu": 2, "lhzx": 2, "lha": 2, "lhax": 2,
    "lbz": 1, "lbzu": 1, "lbzx": 1,
    "lfs": 4, "lfsu": 4, "lfsx": 4, "lfd": 8, "lfdu": 8, "lfdx": 8,
    "stw": 4, "stwu": 4, "stwx": 4, "stwux": 4,
    "sth": 2, "sthu": 2, "sthx": 2,
    "stb": 1, "stbu": 1, "stbx": 1,
    "stfs": 4, "stfsu": 4, "stfd": 8, "stfdu": 8,
}

DEFAULT_CATALOG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "ghidra", "output", "data_catalog.json")

DEFAULT_FUNCTIONS = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "ghidra", "output", "functions.json")


class Catalog:
    """In-memory query layer over data_catalog.json (+ functions.json)."""

    def __init__(self, catalog_path=DEFAULT_CATALOG,
                 functions_path=DEFAULT_FUNCTIONS):
        self.data_by_addr = {}
        self.data_starts = []
        self.data_entries = []  # entries sorted by start address
        self.blocks = []
        self.functions_by_addr = {}

        if os.path.exists(catalog_path):
            with open(catalog_path) as f:
                cat = json.load(f)

            for b in cat.get("memory_blocks", []):
                self.blocks.append((int(b["start"], 16), int(b["end"], 16),
                                    b["name"]))

            for entry in cat.get("data", []):
                addr_hex, size, label, dtype, value = entry
                addr = int(addr_hex, 16)
                rec = {
                    "address": addr_hex,
                    "size": size,
                    "label": label,
                    "data_type": dtype,
                    "string": value,
                }
                self.data_by_addr[addr] = rec
                self.data_entries.append((addr, rec))

            self.data_entries.sort(key=lambda t: t[0])
            self.data_starts = [a for a, _ in self.data_entries]

        if os.path.exists(functions_path):
            with open(functions_path) as f:
                funcs = json.load(f)
            for fn in funcs.get("functions", []):
                try:
                    self.functions_by_addr[int(fn["address"], 16)] = fn["name"]
                except (KeyError, ValueError):
                    continue

    # ---- queries ----

    def section_of(self, addr):
        for start, end, name in self.blocks:
            if start <= addr <= end:
                return name
        return None

    def data_at(self, addr):
        return self.data_by_addr.get(addr)

    def data_containing(self, addr):
        """Data item whose range covers addr (e.g. element inside an array)."""
        i = bisect_right(self.data_starts, addr)
        if i == 0:
            return None
        start, rec = self.data_entries[i - 1]
        if addr < start + rec["size"]:
            return rec
        return None

    def function_at(self, addr):
        return self.functions_by_addr.get(addr)


def _lookup(catalog, addr):
    """Ghidra data-model facts for an address. Never invents types."""
    info = {
        "defined": False,
        "label": None,
        "data_type": None,
        "data_size": None,
        "section": catalog.section_of(addr),
        "string": None,
    }

    rec = catalog.data_at(addr)
    if rec is None:
        rec = catalog.data_containing(addr)

    if rec is not None:
        info["defined"] = True
        info["label"] = rec["label"]
        info["data_type"] = rec["data_type"]
        info["data_size"] = rec["size"]
        info["string"] = rec["string"]
    else:
        fn = catalog.function_at(addr)
        if fn is not None:
            info["label"] = fn

    return info


def _encoding(data_type):
    if not data_type:
        return None
    t = data_type.lower()
    if "unicode" in t or "wchar16" in t or "utf16" in t:
        return "UTF-16BE"
    if "wchar" in t:
        return "UTF-32BE"
    if "string" in t or "char" in t or "sbyte" in t:
        return "ASCII"
    return data_type


def _accesses_from_derived(catalog, derived):
    """Raw (addr, kind, meta) tuples from ppc_analyzer derived facts."""
    out = []
    for m in derived.get("memory_accesses", []):
        meta = {
            "width": m.get("size"),
            "base_register": m.get("base_register"),
            "destination_register": m.get("register"),
            "indexed": "table_base" in m,
            "table_base": m.get("table_base"),
            "index_expression": m.get("index"),
        }
        if "effective_address" in m:
            try:
                addr = int(m["effective_address"], 16)
            except ValueError:
                continue
            out.append((addr, "read" if m["type"] == "load" else "write",
                        m["address"], meta, m.get("effective_address")))
        elif "table_base" in m:
            try:
                base = int(m["table_base"], 16)
            except ValueError:
                continue
            out.append((base, "read" if m["type"] == "load" else "write",
                        m["address"], meta, m["table_base"]))
    return out


def analyze_global_references(catalog, data, derived):
    """Build global_references for one function.

    Sources merged per address:
      - derived memory accesses  -> read / write
      - derived address constructions -> address_only (unless accessed)
      - Ghidra direct references -> per ref type (READ/WRITE)
    """
    # addr -> state
    refs = {}

    def touch(addr, kind, instr, meta, symbolic):
        r = refs.setdefault(addr, {
            "address": "%08x" % addr,
            "access_type": None,
            "indexed": False,
            "instruction_addresses": [],
            "width": None,
            "base_register": None,
            "index_expression": None,
            "resolved_base_address": None,
            "symbolic_expression": None,
        })
        r.setdefault("_kinds", set())
        r["_kinds"].add(kind)
        if instr and instr not in r["instruction_addresses"]:
            r["instruction_addresses"].append(instr)
        if meta.get("width") and r["width"] is None:
            r["width"] = meta["width"]
        if meta.get("indexed"):
            r["indexed"] = True
            if r["resolved_base_address"] is None:
                r["resolved_base_address"] = meta.get("table_base")
            if r["index_expression"] is None:
                r["index_expression"] = meta.get("index_expression")
        elif r["resolved_base_address"] is None and meta.get("direct_base"):
            r["resolved_base_address"] = meta["direct_base"]
        if r["base_register"] is None and meta.get("base_register"):
            r["base_register"] = meta["base_register"]
        if r["symbolic_expression"] is None and symbolic:
            r["symbolic_expression"] = symbolic

    # 1. derived memory accesses
    accesses = _accesses_from_derived(catalog, derived)
    for addr, kind, instr, meta, symbolic in accesses:
        m = dict(meta)
        if "table_base" not in m:
            # direct access: recover the base register/EA the access used
            m.setdefault("direct_base", symbolic)
        touch(addr, kind, instr, m, symbolic)

    # 2. derived address constructions not dereferenced -> address_only
    accessed = {a for a, _, _, _, _ in accesses}
    # an address counts as accessed if any dereference used it as EA or base
    for m in derived.get("memory_accesses", []):
        for key in ("effective_address", "table_base"):
            v = m.get(key)
            if v:
                try:
                    accessed.add(int(v, 16))
                except ValueError:
                    pass

    for c in derived.get("address_constructions", []):
        try:
            addr = int(c["value"], 16)
        except (KeyError, ValueError):
            continue
        if addr in accessed:
            continue
        touch(addr, "address_only", c.get("address"), {}, c["value"])

    # 3. Ghidra direct references (catches everything Ghidra resolved that
    #    our linear analyzer may have missed). When a direct read/write sits
    #    on an instruction whose derived access has an unresolved base
    #    (e.g. the r13 small-data-area register), preserve that symbolic
    #    base instead of dropping it.
    derived_by_instr = {}
    for m in derived.get("memory_accesses", []):
        derived_by_instr.setdefault(m.get("address"), []).append(m)

    for d in data.get("data_ref_details", []):
        target = d["target"]
        try:
            addr = int(target, 16)
        except ValueError:
            continue
        rt = d.get("reference_type", "")
        if "READ" in rt and "WRITE" in rt:
            kind = "read_write"
        elif "READ" in rt:
            kind = "read"
        elif "WRITE" in rt:
            kind = "write"
        else:
            kind = "address_only"

        width = None
        instruction = d.get("instruction") or ""
        mnemonic = instruction.split()[0].lower() if instruction.split() \
            else ""
        width = MNEMONIC_WIDTH.get(mnemonic)

        meta = {"indexed": False, "width": width}
        symbolic = None
        if kind != "address_only":
            for m in derived_by_instr.get(d.get("instruction_address"), []):
                ea = m.get("effective_address")
                if ea is None:
                    continue
                try:
                    int(ea, 16)
                    resolved = True
                except ValueError:
                    resolved = False
                if not resolved:
                    meta["base_register"] = m.get("base_register")
                    symbolic = ea
                break

        touch(addr, kind, d.get("instruction_address"), meta, symbolic)

    # finalize access_type + data model enrichment
    out = []
    for addr in sorted(refs):
        r = refs[addr]
        kinds = r.pop("_kinds", set())
        if kinds == {"read", "write"}:
            r["access_type"] = "read_write"
        elif "write" in kinds:
            r["access_type"] = "write"
        elif "read" in kinds:
            r["access_type"] = "read"
        else:
            r["access_type"] = "address_only"

        info = _lookup(catalog, addr)
        r.update(info)

        if r["indexed"] and r["resolved_base_address"] is None:
            r["resolved_base_address"] = r["address"]
        if r["symbolic_expression"] is None:
            r["symbolic_expression"] = r["address"]

        out.append(r)
    return out


def analyze_string_references(catalog, data, global_references):
    """Build string_references: strings this function actually reaches."""
    # instruction addresses that hit each string address
    str_addrs = {}
    for g in global_references:
        if g.get("string") is not None:
            for instr in g["instruction_addresses"]:
                str_addrs.setdefault(int(g["address"], 16), set()).add(instr)

    out = []
    for addr in sorted(str_addrs):
        g = next(x for x in global_references
                 if int(x["address"], 16) == addr)
        instrs = sorted(str_addrs[addr])
        direct = False
        for d in data.get("data_ref_details", []):
            if d["target"].lower() == g["address"].lower():
                direct = True
                break
        out.append({
            "address": g["address"],
            "contents": g["string"],
            "encoding": _encoding(g.get("data_type")),
            "data_type": g.get("data_type"),
            "length": g.get("data_size"),
            "reference_instruction": instrs[0],
            "reference_instructions": instrs,
            "reference_kind": "direct" if direct else "derived",
        })
    return out


def enrich(data, derived, catalog=None):
    """Add global_references + string_references to a function context.

    Mutates and returns `data` (the analyzed function JSON).
    """
    if catalog is None:
        catalog = Catalog()
    if not catalog.data_starts and not catalog.blocks:
        # no catalog available: preserve unresolved placeholders instead
        # of producing misleading enrichment
        data["global_references"] = []
        data["string_references"] = []
        data["data_catalog_available"] = False
        return data

    data["data_catalog_available"] = True
    refs = analyze_global_references(catalog, data, derived)
    data["global_references"] = refs
    data["string_references"] = analyze_string_references(catalog, data,
                                                          refs)
    return data


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("function_json",
                    help="function context JSON (with derived facts)")
    ap.add_argument("--catalog", default=DEFAULT_CATALOG)
    ap.add_argument("--stdout", action="store_true")
    args = ap.parse_args()

    with open(args.function_json) as f:
        data = json.load(f)

    catalog = Catalog(args.catalog)
    refs = analyze_global_references(catalog, data,
                                     data.get("derived", {}))
    strs = analyze_string_references(catalog, data, refs)

    if args.stdout:
        print(json.dumps({"global_references": refs,
                          "string_references": strs}, indent=2))
    else:
        print("global references: %d" % len(refs))
        for r in refs:
            datainfo = ""
            if r["label"]:
                datainfo = "  <%s>" % r["label"]
            elif r["defined"]:
                datainfo = "  <%s>" % r["data_type"]
            print("  %s %-11s %s%s" % (
                r["address"], r["access_type"],
                "indexed table" if r["indexed"] else "direct", datainfo))
            if r["index_expression"]:
                print("      index: %s" % r["index_expression"])
        print("string references: %d" % len(strs))
        for s in strs:
            text = s["contents"] or ""
            print("  %s (%s, %s) %r" % (s["address"], s["encoding"],
                                        s["reference_kind"], text[:60]))


if __name__ == "__main__":
    main()
