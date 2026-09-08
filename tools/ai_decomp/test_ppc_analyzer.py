#!/usr/bin/env python3
"""Regression test for ppc_analyzer against the reference function 801b16b0.

Run:  python3 tools/ai_decomp/test_ppc_analyzer.py

Requires tools/ghidra/output/function_801b16b0.json (regenerate with
./tools/ghidra/export_function.sh 801b16b0 if missing).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ppc_analyzer import Analyzer  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "..", "ghidra", "output", "function_801b16b0.json")


def main():
    if not os.path.exists(SAMPLE):
        print("SKIP: %s missing; run ./tools/ghidra/export_function.sh 801b16b0"
              % SAMPLE)
        return 0

    with open(SAMPLE) as f:
        data = json.load(f)

    derived = Analyzer().analyze(data["instructions"])

    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    # r7 must resolve to the global table address Ghidra could not
    check(any(v["register"] == "r7" and v["value"] == "0x808d7740"
              for v in derived["register_values"]),
          "r7 = 0x808d7740 not derived")

    # index expression
    check(any(v["register"] == "r0" and v["value"] == "(r3 & 0xff) << 2"
              for v in derived["register_values"]),
          "r0 = (r3 & 0xff) << 2 not derived")

    # table access at 801b16bc
    tbl = [m for m in derived["memory_accesses"] if m["address"] == "801b16bc"]
    check(len(tbl) == 1 and tbl[0].get("table_base") == "0x808d7740"
          and tbl[0].get("index") == "(r3 & 0xff) << 2"
          and tbl[0].get("element_size") == 4,
          "table access lwzx at 801b16bc not identified")

    # virtual call through vtable offset 0x10
    ic = derived["indirect_calls"]
    check(len(ic) == 1 and ic[0].get("virtual_call", {}).get("vtable_offset") == 16
          and ic[0]["virtual_call"]["object_register"] == "r3",
          "virtual call object->vtable[4]() not identified")

    # control flow
    check(any(b["type"] == "beq" for b in derived["branches"]), "beq missing")
    check(any(b["type"] == "return" for b in derived["branches"]), "blr missing")

    if failures:
        print("FAIL:")
        for f in failures:
            print("  - " + f)
        return 1
    print("PASS: ppc_analyzer meets all 801b16b0 expectations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
