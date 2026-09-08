#!/usr/bin/env python3
"""Tests for the SQLite database layer (roadmap item #13).

1. Synthetic-fixture tests: import a small functions.json, symbols.txt,
   data catalog and one analyzed function JSON into a temporary
   database; verify schema, indexes, links and idempotency. These need
   no game dump and no Ghidra exports.
2. Real-data test (skipped when tools/ghidra/output/ is absent):
   imports the current real analysis output into a temporary database
   and spot-checks known facts.

Run:  python3 tools/ai_decomp/test_database.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
REAL_OUTPUT = os.path.join(REPO, "tools", "ghidra", "output")

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f)


def run_import(db_path, tmp, extra=()):
    return subprocess.run(
        [sys.executable, os.path.join(HERE, "import_analysis.py"),
         "--db", db_path, "--output-dir", tmp,
         "--symbols", os.path.join(tmp, "symbols.txt"),
         "--report", "", "--objdiff", ""]
        + list(extra),
        capture_output=True, text=True)


def make_fixtures(tmp):
    """Small synthetic inputs covering every importer path."""
    functions = {
        "program": "synthetic.dol",
        "functions": [
            {"address": "80100000", "name": "FUN_80100000", "size": 64,
             "thunk": False, "external": False},
            {"address": "80100100", "name": "FUN_80100100", "size": 16,
             "thunk": True, "external": False},
            {"address": "80100200", "name": "external_hook", "size": 0,
             "thunk": False, "external": True},
        ],
    }
    write_json(os.path.join(tmp, "functions.json"), functions)

    # dtk-style symbol map at original addresses; GameInit/GameTick must
    # replace the generic FUN_ names, 80100200 stays unnamed here
    with open(os.path.join(tmp, "symbols.txt"), "w") as f:
        f.write("GameInit = .text:0x80100000; "
                "// type:function size:0x40 scope:global align:16\n")
        f.write("GameTick = .text:0x80100100; "
                "// type:function size:0x10 scope:global align:16\n")
        f.write("g_score = .data:0x80700400; "
                "// type:data size:0x4 scope:global align:4\n")

    catalog = {
        "program": "synthetic.dol",
        "memory_blocks": [
            {"name": ".text", "start": "80006040", "end": "80700000",
             "size": 0x6FF9C0, "initialized": True},
            {"name": ".data", "start": "80700040", "end": "80800000",
             "size": 0xFFC0, "initialized": True},
            {"name": ".bss", "start": "80800040", "end": "80808000",
             "size": 0x7FC0, "initialized": False},
        ],
        "data": [
            ["80800100", 4, "DAT_80800100", "undefined4", None],
            ["80700200", 38, "s_hello", "string", "hello world"],
            ["80700300", 4, "PTR_s_hello", "undefined *", None],
        ],
        "data_count": 3,
    }
    write_json(os.path.join(tmp, "data_catalog.json"), catalog)

    analyzed = {
        "program": "synthetic.dol",
        "address": "80100000",
        "name": "FUN_80100000",
        "size": 64,
        "signature": "undefined FUN_80100000(uint param_1)",
        "return_type": "undefined",
        "instructions": [
            "80100000: lis r7,-0x7f80",
            "80100004: addi r7,r7,0x100",
            "80100008: lwzx r3,r7,r0",
            "8010000c: blr",
        ],
        "callers": [{"address": "80100100", "name": "FUN_80100100",
                     "size": 16}],
        "callees": [],
        "data_references": [],
        "strings": [],
        "derived": {
            "register_values": [],
            "memory_accesses": [
                {"address": "80100008", "type": "load", "size": 4,
                 "register": "r3", "base_register": "r7",
                 "table_base": "0x80800100", "index": "(r3 & 0xff) << 2",
                 "element_size": 4},
            ],
            "branches": [{"address": "8010000c", "type": "return"}],
            "calls": [],
            "address_constructions": [
                {"address": "80100000", "register": "r7",
                 "value": "0x80800100"},
            ],
            "indirect_calls": [],
        },
        "global_references": [
            {"address": "80800100", "access_type": "read", "indexed": True,
             "instruction_addresses": ["80100008"], "width": 4,
             "base_register": "r7", "index_expression": "(r3 & 0xff) << 2",
             "resolved_base_address": "0x80800100",
             "symbolic_expression": "0x80800100", "defined": True,
             "label": "DAT_80800100", "data_type": "undefined4",
             "data_size": 4, "section": ".bss", "string": None},
        ],
        "string_references": [],
    }
    write_json(os.path.join(tmp, "function_80100000_analyzed.json"),
               analyzed)


def test_synthetic(tmp):
    print("== synthetic import ==")
    db_path = os.path.join(tmp, "synthetic.db")
    rc = run_import(db_path, tmp)
    check(rc.returncode == 0, "importer failed: %s" % rc.stderr)

    conn = db.connect(db_path)

    # --- function rows ---
    rows = {r["address"]: r for r in conn.execute("SELECT * FROM functions")}
    check(set(rows) == {"80100000", "80100100", "80100200"},
          "unexpected function set: %s" % sorted(rows))
    a = rows["80100000"]
    check(a["name"] == "GameInit",
          "symbol name should replace FUN_ name, got %r" % a["name"])
    check(a["size"] == 0x40, "symbol size should win, got %r" % a["size"])
    check(a["section"] == "text",
          "80100000 section should be text, got %r" % a["section"])
    check(a["signature"] == "undefined FUN_80100000(uint param_1)",
          "signature missing after analyzed import: %r" % a["signature"])
    check(a["analyzed"] == 1, "analyzed flag not set")
    check(rows["80100100"]["is_thunk"] == 1, "thunk flag lost")
    check(rows["80100100"]["name"] == "GameTick", "thunk name not replaced")
    check(rows["80100200"]["is_external"] == 1, "external flag lost")
    check(rows["80100200"]["name"] == "external_hook",
          "un-symbolized name should be kept")
    check(a["status"] == "unknown", "default status should be unknown")

    # --- links ---
    callers = [r["caller_address"] for r in conn.execute(
        "SELECT caller_address FROM function_callers "
        "WHERE function_address='80100000'")]
    check(callers == ["80100100"], "callers wrong: %r" % callers)
    callees = [r["callee_address"] for r in conn.execute(
        "SELECT callee_address FROM function_callees "
        "WHERE function_address='80100000'")]
    check(callees == [], "callees should be empty, got %r" % callees)

    # --- instructions ---
    n = conn.execute(
        "SELECT COUNT(*) AS n FROM instructions "
        "WHERE function_address='80100000'").fetchone()["n"]
    check(n == 4, "expected 4 instructions, got %d" % n)
    op = conn.execute(
        "SELECT mnemonic, operands FROM instructions "
        "WHERE function_address='80100000' AND address='80100004'"
        ).fetchone()
    check(op["mnemonic"] == "addi" and op["operands"] == "r7,r7,0x100",
          "instruction not structured: %r" % dict(op))

    # --- globals / strings / label priority ---
    g = conn.execute("SELECT * FROM globals WHERE address='80800100'"
                     ).fetchone()
    check(g is not None and g["data_type"] == "undefined4"
          and g["section"] == ".bss",
          "global 80800100 wrong: %r" % (dict(g) if g else None))
    s = conn.execute("SELECT * FROM strings WHERE address='80700200'"
                     ).fetchone()
    check(s is not None and s["contents"] == "hello world"
          and s["encoding"] == "ASCII",
          "string 80700200 wrong: %r" % (dict(s) if s else None))
    # symbols.txt label must win over the catalog's auto label
    sp = conn.execute("SELECT * FROM globals WHERE address='80700200'"
                      ).fetchone()
    check(sp is not None and sp["label"] == "s_hello",
          "catalog label should survive when symbols.txt has no entry: %r"
          % (dict(sp) if sp else None))
    gd = conn.execute("SELECT * FROM globals WHERE address='80700400'"
                      ).fetchone()
    check(gd is not None and gd["label"] == "g_score"
          and gd["section"] == "data",
          "symbols.txt data label missing: %r" % (dict(gd) if gd else None))
    fg = conn.execute(
        "SELECT * FROM function_globals "
        "WHERE function_address='80100000' AND global_address='80800100'"
        ).fetchone()
    check(fg is not None and fg["indexed"] == 1
          and fg["access_type"] == "read"
          and fg["index_expression"] == "(r3 & 0xff) << 2",
          "function_globals link wrong: %r" % (dict(fg) if fg else None))

    # --- status helpers + set_status ---
    db.set_status(conn, "80100000", "candidate")
    check(db.status_counts(conn).get("candidate") == 1,
          "set_status/candidate failed")
    try:
        db.set_status(conn, "80100000", "bogus")
        check(False, "set_status accepted invalid status")
    except ValueError:
        pass

    # --- idempotency: run the importer again ---
    before = db.total_counts(conn)
    runs_before = before["runs"]
    conn.close()

    rc = run_import(db_path, tmp)
    check(rc.returncode == 0, "second import failed: %s" % rc.stderr)

    conn = db.connect(db_path)
    after = db.total_counts(conn)
    for key in ("functions", "globals", "strings", "instructions",
                "caller_edges"):
        check(before[key] == after[key],
              "idempotency broken for %s: %d -> %d"
              % (key, before[key], after[key]))
    check(after["runs"] == runs_before + 1,
          "analysis_runs should grow by exactly one log entry")
    a2 = conn.execute("SELECT name, size FROM functions "
                      "WHERE address='80100000'").fetchone()
    check(a2["name"] == "GameInit" and a2["size"] == 0x40,
          "re-import clobbered symbol name/size: %r" % dict(a2))

    # --- indexes exist ---
    idx = {r["name"] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    for expected in ("idx_functions_status", "idx_functions_section",
                     "idx_functions_category", "idx_callers_caller",
                     "idx_callees_callee", "idx_globals_section",
                     "idx_fg_global", "idx_fs_string"):
        check(expected in idx, "missing index %s" % expected)
    conn.close()


def test_status_cli(tmp):
    print("== status CLI ==")
    db_path = os.path.join(tmp, "synthetic.db")
    rc = subprocess.run(
        [sys.executable, os.path.join(HERE, "status.py"),
         "--db", db_path, "--json"],
        capture_output=True, text=True)
    check(rc.returncode == 0, "status.py failed: %s" % rc.stderr)
    info = json.loads(rc.stdout)
    f = info["functions"]
    check(f["total"] == 3, "status total wrong: %r" % f["total"])
    check(f["matched"] == 0 and f["unknown"] == 3,
          "status matched/unknown wrong: %r" % f)
    check(info["coverage"]["functions_with_globals"] == 1,
          "functions_with_globals wrong")
    check(info["coverage"]["functions_with_strings"] == 0,
          "functions_with_strings wrong")
    check(info["coverage"]["functions_with_indirect_calls"] == 0,
          "functions_with_indirect_calls wrong")

    rc = subprocess.run(
        [sys.executable, os.path.join(HERE, "status.py"), "--db", db_path],
        capture_output=True, text=True)
    check(rc.returncode == 0 and "total:" in rc.stdout,
          "human-readable status output broken")


def test_real():
    print("== real analysis output ==")
    if not os.path.exists(os.path.join(REAL_OUTPUT, "functions.json")):
        print("  SKIP: %s/functions.json missing" % REAL_OUTPUT)
        return
    tmp = tempfile.mkdtemp(prefix="decomp_db_real_")
    try:
        db_path = os.path.join(tmp, "real.db")
        rc = subprocess.run(
            [sys.executable, os.path.join(HERE, "import_analysis.py"),
             "--db", db_path, "--quiet"],
            capture_output=True, text=True)
        check(rc.returncode == 0, "real import failed: %s" % rc.stderr)

        conn = db.connect(db_path)
        totals = db.total_counts(conn)
        print("  functions=%d globals=%d strings=%d instructions=%d" % (
            totals["functions"], totals["globals"], totals["strings"],
            totals["instructions"]))

        check(totals["functions"] >= 28000,
              "expected >=28000 functions (Ghidra + symbols.txt), got %d"
              % totals["functions"])
        check(totals["globals"] >= 80000,
              "expected >=80000 globals, got %d" % totals["globals"])
        check(totals["strings"] >= 15000,
              "expected >=15000 strings, got %d" % totals["strings"])

        # 801b16b0 was analyzed in previous phases: full chain must exist
        row = conn.execute(
            "SELECT * FROM functions WHERE address='801b16b0'").fetchone()
        check(row is not None, "801b16b0 missing")
        check(row["name"] == "NuFileRead__FiPvii",
              "801b16b0 should carry its symbols.txt name, got %r"
              % (row["name"] if row else None))
        check(row["analyzed"] == 1, "801b16b0 not marked analyzed")
        check(row["section"] == "text", "801b16b0 section should be 'text',"
              " got %r" % (row["section"] if row else None))

        fg = conn.execute(
            "SELECT * FROM function_globals WHERE function_address='801b16b0'"
            " AND global_address='808d7740'").fetchone()
        check(fg is not None and fg["indexed"] == 1,
              "801b16b0 -> 0x808d7740 table link missing")

        fs = conn.execute(
            "SELECT * FROM function_strings WHERE function_address='805b330c'"
            ).fetchone()
        check(fs is not None and fs["string_address"] == "8083660c",
              "805b330c string reference missing")

        ic = conn.execute(
            "SELECT * FROM indirect_calls WHERE function_address='801b16b0'"
            ).fetchone()
        check(ic is not None and ic["virtual_call"] is not None,
              "801b16b0 virtual call record missing")

        # symbol coverage from symbols.txt
        named = conn.execute(
            """SELECT COUNT(*) AS n FROM functions
               WHERE name IS NOT NULL
                 AND name NOT LIKE 'FUN\\_%' ESCAPE '\\'
                 AND name NOT LIKE 'thunk\\_FUN\\_%' ESCAPE '\\'"""
            ).fetchone()["n"]
        print("  named functions: %d" % named)
        check(named >= 28000,
              "symbol import too weak: only %d named functions" % named)

        # category seeding from objdiff report
        stats = {r["category"]: r for r in conn.execute(
            "SELECT * FROM category_stats")}
        known = sum(s["matched_functions"] for s in stats.values())
        check(known == 308,
              "category matched sum should be 308, got %d" % known)
        matched = db.status_counts(conn).get("matched", 0)
        print("  seeded matched: %d (fully-matched categories)" % matched)
        check(matched >= 38,
              "expected >=38 seeded matches (runtime+trk+msl), got %d"
              % matched)

        # idempotency on real data
        before = db.total_counts(conn)
        conn.close()
        rc = subprocess.run(
            [sys.executable, os.path.join(HERE, "import_analysis.py"),
             "--db", db_path, "--quiet"],
            capture_output=True, text=True)
        check(rc.returncode == 0, "second real import failed: %s" % rc.stderr)
        conn = db.connect(db_path)
        after = db.total_counts(conn)
        for key in ("functions", "globals", "strings", "instructions",
                    "caller_edges"):
            check(before[key] == after[key],
                  "real idempotency broken for %s: %d -> %d"
                  % (key, before[key], after[key]))
        conn.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_db_test_")
    try:
        make_fixtures(tmp)
        test_synthetic(tmp)
        test_status_cli(tmp)
        test_real()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all database tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
