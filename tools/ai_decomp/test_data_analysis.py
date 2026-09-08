#!/usr/bin/env python3
"""Regression tests for the global/data reference + string analysis layer
(roadmap items #11 and #12).

Covers three exported functions:

  801b16b0  indexed table access through a PowerPC-constructed address
            (lis/addi) that Ghidra's reference database does not resolve
  801c2818  direct global WRITE via the r13 small-data-area register
  805b330c  function referencing a string through a pointer slot

Inputs are the git-ignored exports under tools/ghidra/output/ (the game
dump itself is never needed by this test and must never be committed).
Regenerate inputs with:

    ./tools/ghidra/export_data_catalog.sh
    ./tools/ghidra/export_function.sh 801b16b0
    ./tools/ghidra/export_function.sh 801c2818
    ./tools/ghidra/export_function.sh 805b330c

Run:  python3 tools/ai_decomp/test_data_analysis.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ppc_analyzer import Analyzer  # noqa: E402
import data_analysis  # noqa: E402

OUT = os.path.join(HERE, "..", "ghidra", "output")


def load_and_analyze(addr):
    path = os.path.join(OUT, "function_%s.json" % addr)
    if not os.path.exists(path):
        print("SKIP: %s missing; run ./tools/ghidra/export_function.sh %s"
              % (path, addr))
        return None
    with open(path) as f:
        data = json.load(f)
    derived = Analyzer().analyze(data.get("instructions", []))
    data_analysis.enrich(data, derived,
                         catalog=data_analysis.Catalog())
    return data


def by_address(records):
    return {r["address"]: r for r in records}


def main():
    catalog = data_analysis.Catalog()
    if not catalog.data_starts and not catalog.blocks:
        print("SKIP: data catalog missing; run "
              "./tools/ghidra/export_data_catalog.sh")
        return 0

    functions = {}
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    # ------------------------------------------------------------------
    # 801b16b0: indexed table access via constructed address
    # ------------------------------------------------------------------
    data = load_and_analyze("801b16b0")
    if data:
        functions["801b16b0"] = data
        refs = by_address(data["global_references"])
        check("808d7740" in refs, "801b16b0: 0x808d7740 not in global_references")

        r = refs.get("808d7740", {})
        check(r.get("access_type") == "read",
              "801b16b0: 0x808d7740 access_type should be read, got %r"
              % r.get("access_type"))
        check(r.get("indexed") is True,
              "801b16b0: 0x808d7740 should be an indexed/table access")
        check(r.get("width") == 4, "801b16b0: width should be 4")
        check(r.get("base_register") == "r7",
              "801b16b0: base_register should be r7, got %r"
              % r.get("base_register"))
        check(r.get("index_expression") == "(r3 & 0xff) << 2",
              "801b16b0: index_expression wrong: %r"
              % r.get("index_expression"))
        check(r.get("resolved_base_address") == "0x808d7740",
              "801b16b0: resolved_base_address wrong")
        check("801b16bc" in r.get("instruction_addresses", []),
              "801b16b0: instruction address 801b16bc not recorded")
        check(r.get("section") is not None,
              "801b16b0: section not resolved for 0x808d7740")
        check(r.get("defined") is False,
              "801b16b0: 0x808d7740 has no defined data; must be preserved "
              "as unresolved (defined=false), got %r" % r.get("defined"))
        check(data["string_references"] == [],
              "801b16b0: expected no string references")

    # ------------------------------------------------------------------
    # 801c2818: direct global write via r13 small data area
    # ------------------------------------------------------------------
    data = load_and_analyze("801c2818")
    if data:
        functions["801c2818"] = data
        refs = by_address(data["global_references"])
        check("808c2478" in refs,
              "801c2818: 808c2478 not in global_references")

        r = refs.get("808c2478", {})
        check(r.get("access_type") == "write",
              "801c2818: access_type should be write, got %r"
              % r.get("access_type"))
        check(r.get("indexed") is False,
              "801c2818: should be a direct (non-indexed) access")
        check(r.get("width") == 4, "801c2818: width should be 4")
        check(r.get("defined") is True and r.get("label") == "DAT_808c2478",
              "801c2818: data model enrichment failed: %r" % r)
        check(r.get("data_type") == "undefined4",
              "801c2818: data_type should be undefined4, got %r"
              % r.get("data_type"))
        check(r.get("data_size") == 4, "801c2818: data_size should be 4")
        check(r.get("section") is not None,
              "801c2818: section not resolved")
        check(r.get("base_register") == "r13"
              and r.get("symbolic_expression") == "(r13 + 1112)",
              "801c2818: unresolved r13 base not preserved: base=%r sym=%r"
              % (r.get("base_register"), r.get("symbolic_expression")))

    # ------------------------------------------------------------------
    # 805b330c: string reference through a pointer slot
    # ------------------------------------------------------------------
    data = load_and_analyze("805b330c")
    if data:
        functions["805b330c"] = data
        refs = by_address(data["global_references"])
        check("808c07bc" in refs,
              "805b330c: pointer slot 808c07bc not in global_references")
        check(refs.get("808c07bc", {}).get("access_type") == "read",
              "805b330c: pointer slot should be read")

        strs = data["string_references"]
        check(len(strs) == 1,
              "805b330c: expected exactly 1 string reference, got %d"
              % len(strs))
        if strs:
            s = strs[0]
            check(s["address"] == "8083660c",
                  "805b330c: string address wrong: %r" % s["address"])
            check(s["contents"] == "INVALID ID - OUT OF INDEX ARRAY RANGE",
                  "805b330c: string contents wrong: %r" % s["contents"])
            check(s["encoding"] == "ASCII",
                  "805b330c: encoding should be ASCII, got %r"
                  % s["encoding"])
            check(s["reference_instruction"] == "805b3320",
                  "805b330c: reference_instruction wrong: %r"
                  % s["reference_instruction"])
            check(s["reference_kind"] == "direct",
                  "805b330c: reference_kind should be direct, got %r"
                  % s["reference_kind"])

        # the string's address_only reference (pointer target) must carry
        # the data model info
        r = refs.get("8083660c", {})
        check(r.get("defined") is True and r.get("data_type") == "string",
              "805b330c: string data model enrichment failed: %r" % r)

    # ------------------------------------------------------------------
    # format sanity for all analyzed functions
    # ------------------------------------------------------------------
    for addr, data in functions.items():
        check("data_catalog_available" in data,
              "%s: data_catalog_available flag missing" % addr)
        for r in data["global_references"]:
            for key in ("address", "access_type", "indexed",
                        "instruction_addresses", "width", "base_register",
                        "index_expression", "resolved_base_address",
                        "symbolic_expression", "defined", "label",
                        "data_type", "data_size", "section", "string"):
                check(key in r,
                      "%s: global reference missing key %r" % (addr, key))
            check(r["access_type"] in
                  ("read", "write", "read_write", "address_only"),
                  "%s: bad access_type %r" % (addr, r["access_type"]))

    if functions:
        # resolved addresses must be within some memory block section
        cat_blocks = catalog.blocks
        for addr, data in functions.items():
            for r in data["global_references"]:
                a = int(r["address"], 16)
                check(any(s <= a <= e for s, e, _ in cat_blocks),
                      "%s: %s maps to no known section" % (addr, r["address"]))

    if failures:
        print("FAIL:")
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS: data_analysis meets all expectations (%d functions)"
          % len(functions))
    return 0


if __name__ == "__main__":
    sys.exit(main())
