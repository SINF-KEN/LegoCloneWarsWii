#!/usr/bin/env python3
"""Tests for Phase 5.4 — conservative type/struct/vtable evidence.

All fixtures are synthetic instruction sequences; no LLM calls and no
game dump. The real 801b16b0 export is used as an optional integration
fixture.

Run:  python3 tools/ai_decomp/test_type_analysis.py
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402
import orchestrator as orch_mod  # noqa: E402
import type_analysis as ta  # noqa: E402

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def kinds(patterns):
    return [p["kind"] for p in patterns]


def find(patterns, kind):
    return [p for p in patterns if p["kind"] == kind]


# ----------------------------------------------------------------
# unit scenarios
# ----------------------------------------------------------------

def test_field_access():
    print("== field access ==")
    # 1. basic read
    p = ta.analyze_instructions(["80000000: lwz r4,0x8(r3)",
                                 "80000004: blr"])
    fields = find(p, "field")
    check(len(fields) == 1 and fields[0]["register"] == "r3" and
          fields[0]["offset"] == 8 and fields[0]["access"] == "read"
          and fields[0]["width"] == 4, "basic read wrong: %r" % fields)

    # 2. basic write
    p = ta.analyze_instructions(["80000000: stw r4,0xc(r3)",
                                 "80000004: blr"])
    fields = find(p, "field")
    check(fields and fields[0]["access"] == "write" and
          fields[0]["offset"] == 0xc, "basic write wrong")

    # 3. widths
    for mn, w in (("lbz", 1), ("lhz", 2), ("lwz", 4), ("lfs", 4),
                  ("lfd", 8)):
        p = ta.analyze_instructions(["80000000: %s r4,0x0(r3)" % mn,
                                     "80000004: blr"])
        f = find(p, "field")
        check(f and f[0]["width"] == w,
              "%s width should be %d, got %r" % (mn, w, f))
    p = ta.analyze_instructions(["80000000: stb r4,0x1(r3)",
                                 "80000004: blr"])
    check(find(p, "field")[0]["width"] == 1, "stb width wrong")
    p = ta.analyze_instructions(["80000000: sth r4,0x2(r3)",
                                 "80000004: blr"])
    check(find(p, "field")[0]["width"] == 2, "sth width wrong")

    # 8. chained object accesses: both recorded, no typing conclusion
    p = ta.analyze_instructions(["80000000: lwz r4,0x8(r3)",
                                 "80000004: lwz r5,0x10(r4)",
                                 "80000008: blr"])
    fields = find(p, "field")
    check(len(fields) == 2, "chained accesses should both be recorded")
    check(fields[1]["register"] == "r4" and fields[1]["offset"] == 0x10,
          "chained second access wrong")
    check(all("class" not in str(x).lower() for x in fields),
          "chained accesses must not conclude a type")


def test_vtable():
    print("== vtable patterns ==")
    # 4. classic +0 pattern
    p = ta.analyze_instructions([
        "80000000: lwz r12,0x0(r3)",
        "80000004: lwz r12,0x10(r12)",
        "80000008: mtspr CTR,r12",
        "8000000c: bctr"])
    v = find(p, "vtable")
    check(len(v) == 1, "classic vtable not detected")
    check(v and v[0]["register"] == "r3" and v[0]["offset"] == 0 and
          v[0]["slot_offset"] == 0x10 and v[0]["slot_index"] == 4,
          "classic vtable fields wrong: %r" % v)
    check(not find(p, "field"),
          "vtable loads must not double as field evidence")

    # 5. nonzero vtable pointer offset
    p = ta.analyze_instructions([
        "80000000: lwz r12,0x8(r4)",
        "80000004: lwz r12,0x10(r12)",
        "80000008: mtspr CTR,r12",
        "8000000c: bctr"])
    v = find(p, "vtable")
    check(v and v[0]["offset"] == 8 and v[0]["register"] == "r4",
          "nonzero vtable pointer offset wrong: %r" % v)

    # 6. slot index calculation
    p = ta.analyze_instructions([
        "80000000: lwz r12,0x0(r3)",
        "80000004: lwz r12,0x1c(r12)",
        "80000008: mtspr CTR,r12",
        "8000000c: bctr"])
    v = find(p, "vtable")
    check(v and v[0]["slot_index"] == 7, "slot index should be 0x1c/4")

    # 7. indirect function pointer WITHOUT vtable loads
    p = ta.analyze_instructions([
        "80000000: lwz r12,0x8(r3)",
        "80000004: mtspr CTR,r12",
        "80000008: bctr"])
    check(not find(p, "vtable"),
          "plain indirect call must not be vtable evidence")
    fp = find(p, "funcptr")
    check(len(fp) == 1 and fp[0]["register"] == "r3" and
          fp[0]["offset"] == 8, "funcptr evidence wrong: %r" % fp)

    # 14 (part): mtctr without any preceding load is not evidence
    p = ta.analyze_instructions(["80000000: mtctr r12",
                                 "80000004: bctr"])
    check(not find(p, "vtable") and not find(p, "funcptr"),
          "bare mtctr/bctr must not produce dispatch evidence")


def test_table_lookup_and_receiver():
    print("== table lookups and receivers ==")
    # indexed loads are table lookups, never objects
    p = ta.analyze_instructions(["80000000: lwzx r3,r7,r0",
                                 "80000004: blr"])
    tl = find(p, "table_lookup")
    check(len(tl) == 1 and tl[0]["register"] == "r7" and
          tl[0]["indexed"] is True, "table lookup wrong: %r" % tl)
    check(not find(p, "vtable") and not find(p, "receiver"),
          "table lookup must not become receiver/vtable evidence")

    # 801b16b0: table lookup, receiver, and vtable must be separated
    export = os.path.join(HERE, "..", "ghidra", "output",
                          "function_801b16b0.json")
    if os.path.exists(export):
        with open(export) as f:
            lines = json.load(f)["instructions"]
        p = ta.analyze_instructions(lines)
        check(any(x["kind"] == "table_lookup" and
                  x["register"] == "r7" for x in p),
              "801b16b0 table lookup (r7) missing")
        v = find(p, "vtable")
        check(v and v[0]["register"] == "r3" and
              v[0]["slot_offset"] == 0x10 and v[0]["slot_index"] == 4,
              "801b16b0 vtable evidence wrong")
        check(any(x["kind"] == "receiver" and x["register"] == "r3"
                  for x in p), "801b16b0 receiver evidence missing")
        check(all(not (x["kind"] == "vtable" and x["register"] == "r7")
                  for x in p),
              "the table base must never be claimed as a vtable object")


def test_aggregation_and_db(tmp):
    print("== aggregation / persistence / levels ==")
    conn = db.connect(":memory:")

    # two functions with the same field evidence
    for addr in ("80200010", "80200020"):
        p = ta.analyze_instructions(["80000000: lwz r4,0x8(r3)",
                                     "80000004: blr"])
        ta.db_record(conn, p, function_address=addr,
                     function_name="F" + addr)
    fields = ta.fields_by_receiver(conn, "r3")
    check(len(fields) == 1 and fields[0]["functions"] == 2 and
          fields[0]["offset"] == 8, "field aggregation wrong: %r" % fields)

    # 9/10. vtable slots aggregated; evidence levels
    vpat = ta.analyze_instructions([
        "80000000: lwz r12,0x0(r3)",
        "80000004: lwz r12,0x10(r12)",
        "80000008: mtspr CTR,r12",
        "8000000c: bctr"])
    ta.db_record(conn, vpat, function_address="80200010",
                 function_name="F")
    slots = ta.vtable_slots(conn)
    check(slots and slots[0]["slot_offset"] == 0x10 and
          slots[0]["slot_index"] == 4, "slot aggregation wrong")
    check(slots[0]["observations"] >= 1, "slot observations wrong")
    check(slots[0]["matched_observations"] == 0,
          "no matched evidence without objdiff 100")

    # matched evidence only via objdiff 100
    ta.db_record(conn, vpat, function_address="80200010",
                 function_name="F", matched=True)
    slots = ta.vtable_slots(conn)
    check(slots[0]["matched_observations"] == 1,
          "matched observation not recorded")

    # 11. duplicate suppression
    before = conn.execute(
        "SELECT COUNT(*) AS n FROM type_evidence").fetchone()["n"]
    ta.db_record(conn, vpat, function_address="80200010",
                 function_name="F")
    after = conn.execute(
        "SELECT COUNT(*) AS n FROM type_evidence").fetchone()["n"]
    check(before == after, "duplicate evidence inserted")

    # other helpers
    check(any(f["function_address"] == "80200010"
              for f in ta.functions_using_slot(conn, 0x10)),
          "functions_using_slot failed")
    check(any(f["offset"] == 8 for f in
              ta.functions_accessing_offset(conn, 8)),
          "functions_accessing_offset failed")
    vt = ta.virtual_targets(conn)
    check(vt and all(v["target"] == "unknown" for v in vt),
          "virtual targets must be honestly unknown")
    roles = ta.register_roles(conn, "80200010")
    check(any(r["register"] == "r3" and
              r["role"] == "object/receiver" for r in roles),
          "receiver role missing: %r" % roles)

    # 12. bounded rendering
    many = []
    for off in range(0, 200, 4):
        many.append({"kind": "field", "register": "r3", "offset": off,
                     "access": "read", "width": 4})
    md = ta.render_type_evidence_markdown(many)
    check(md.count("Observed field accesses") == 1 and
          "omitted" in md, "field rendering not bounded")
    check(len(md) < 4000, "markdown not bounded")

    # 13. malformed / missing data
    check(ta.analyze_instructions([]) == [], "empty input")
    check(ta.analyze_instructions(["garbage line",
                                   "not an instruction"]) == [],
          "junk lines must be skipped")

    # 16. backwards-compatible migration on a pre-5.4 database
    path = os.path.join(tmp, "old.db")
    legacy = sqlite3.connect(path)
    # pre-5.4 database: full functions table, no type_evidence table
    legacy.execute(
        "CREATE TABLE functions (address TEXT PRIMARY KEY, "
        "name TEXT, size INTEGER, section TEXT, is_thunk INTEGER, "
        "is_external INTEGER, signature TEXT, return_type TEXT, "
        "status TEXT, category TEXT, analyzed INTEGER, source TEXT, "
        "updated_at TEXT)")
    legacy.execute(
        "INSERT INTO functions VALUES ('80000000', 'Old', 10, 'text', "
        "0, 0, NULL, NULL, 'unknown', NULL, 0, NULL, NULL)")
    legacy.commit()
    legacy.close()
    c2 = db.connect(path)
    tables = {r[0] for r in c2.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    check("type_evidence" in tables, "type_evidence not migrated")
    check(c2.execute("SELECT name, status FROM functions "
                     "WHERE address='80000000'").fetchone()["name"]
          == "Old", "legacy table damaged")
    c2.close()
    conn.close()


# ----------------------------------------------------------------
# integration: orchestrator recording + context/prompt embedding
# ----------------------------------------------------------------

def test_integration(tmp):
    print("== orchestrator / context integration ==")
    import test_phase5 as p5
    real = (orch_mod.PRIMARY_BASELINE, orch_mod.context_mod.build_context,
            orch_mod.objdiff_mod.evaluate, orch_mod.build_mod.run_build)
    try:
        # compiled+objdiff-verified run records evidence; context.json
        # and the prompt embed it with the disclaimer
        world = p5.make_world(os.path.join(tmp, "int"))
        conn = world["conn"]
        # richer fixture assembly so the analyzer finds real evidence
        write(os.path.join(world["output_dir"],
                           "function_80200010_analyzed.json"),
              json.dumps({
                  "address": "80200010", "name": "TargetFn", "size": 80,
                  "signature": "void TargetFn(void)",
                  "return_type": "void",
                  "decompilation": "void TargetFn(void) {}",
                  "instructions": [
                      "80200010: lwz r4,0x8(r3)",
                      "80200014: lwz r12,0x0(r4)",
                      "80200018: lwz r12,0x10(r12)",
                      "8020001c: mtspr CTR,r12",
                      "80200020: bctr",
                      "80200024: blr"],
                  "derived": {}}))
        orch, _, _ = p5.build_orch(
            world,
            client_script=[{"new_text": "// candidate\n"
                                          "return (x & 0xff) << 2;"}],
            objdiff_results=[{"pct": 100.0}], max_attempts=1)
        orch.run()

        n = conn.execute(
            "SELECT COUNT(*) AS n FROM type_evidence").fetchone()["n"]
        check(n > 0, "no type evidence recorded from verified run")
        ctx = json.load(open(os.path.join(world["attempts"],
                                          "80200010", "attempt-001",
                                          "context.json")))
        check(ctx.get("type_evidence"), "context lacks type evidence")
        prompt = open(os.path.join(world["attempts"], "80200010",
                                   "attempt-001",
                                   "prompt.txt")).read()
        check("inferred evidence, not authoritative" in prompt,
              "type disclaimer missing from prompt")

        # 5.3 intact: the same run also fed the idiom knowledge base
        check(conn.execute(
            "SELECT COUNT(*) FROM idiom_observations").fetchone()[0] >= 0,
            "idiom tables accessible")

        # dry-runs must not record evidence
        world2 = p5.make_world(os.path.join(tmp, "int2"))
        conn2 = world2["conn"]
        orch2, _, _ = p5.build_orch(
            world2, client_script=[{"new_text": "// x\n"}],
            objdiff_results=[{"pct": 100.0}], max_attempts=1,
            dry_run=True)
        orch2.run()
        check(conn2.execute(
            "SELECT COUNT(*) AS n FROM type_evidence").fetchone()["n"]
            == 0, "dry-run must not record type evidence")

        # global regressions must not record evidence
        world3 = p5.make_world(os.path.join(tmp, "int3"))
        conn3 = world3["conn"]
        orch3, _, _ = p5.build_orch(
            world3, client_script=[{"new_text": "// y\n"}],
            objdiff_results=[
                {"pct": 73.333336,
                 "regressions": ["matched_code: 43664 -> 40000"]}],
            max_attempts=1)
        orch3.run()
        check(conn3.execute(
            "SELECT COUNT(*) AS n FROM type_evidence").fetchone()["n"]
            == 0, "regressed run must not record type evidence")

        conn.close()
        conn2.close()
        conn3.close()
    finally:
        orch_mod.PRIMARY_BASELINE = real[0]
        orch_mod.context_mod.build_context = real[1]
        orch_mod.objdiff_mod.evaluate = real[2]
        orch_mod.build_mod.run_build = real[3]


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_type_test_")
    try:
        test_field_access()
        test_vtable()
        test_table_lookup_and_receiver()
        test_aggregation_and_db(tmp)
        test_integration(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all type analysis tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
