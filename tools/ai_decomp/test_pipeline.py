#!/usr/bin/env python3
"""Tests for discovery (#14), prioritization (#15) and the dependency
graph (#16).

Synthetic tests build a small database directly with database.py, so
they need no game dump and no Ghidra exports. A real-database test
runs the CLIs against tools/ai_decomp/decomp.db when it exists.

Run:  python3 tools/ai_decomp/test_pipeline.py
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
from dependencies import DependencyGraph  # noqa: E402
from discover import Discovery  # noqa: E402
from prioritize import Scorer, size_band  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
REAL_DB = db.DB_PATH

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def add_function(conn, address, name=None, size=100, section="text",
                 thunk=False, external=False, status="unknown",
                 category="game"):
    db.upsert_function(conn, address, name=name, size=size,
                       section=section, is_thunk=thunk,
                       is_external=external, status=status,
                       category=category)


def link(conn, table, column, src, dsts):
    db.set_function_links(conn, table, column, src, dsts)


def make_db(path):
    """Synthetic world:

    G1 (game, unknown) <- M1(matched), G2 ; calls M2(matched)   -> top rank
    LEAF (game)            no edges
    A -> B -> C            all unknown game, same size: B must beat A
    CY1 -> CY2 -> CY3 -> CY1   cycle
    M1, M2 matched; RT runtime; NK sdk; TH thunk; EX external
    """
    conn = db.connect(path)

    add_function(conn, "80200010", "G1", 300)
    add_function(conn, "80200020", "M1", 200, status="matched")
    add_function(conn, "80200030", "M2", 200, status="matched")
    add_function(conn, "80200040", "G2", 100)
    add_function(conn, "80200050", "RT_big", 5000, category="runtime")
    add_function(conn, "80200060", "NK_big", 4000, category="sdk")
    add_function(conn, "80200070", "TH", 8, thunk=True)
    add_function(conn, "80200080", "EX", 0, external=True)
    add_function(conn, "80200090", "LEAF", 200)
    add_function(conn, "802000a0", "A", 200)
    add_function(conn, "802000b0", "B", 200)
    add_function(conn, "802000c0", "C", 200)
    add_function(conn, "802000d0", "CY1", 100)
    add_function(conn, "802000e0", "CY2", 100)
    add_function(conn, "802000f0", "CY3", 100)

    # G1 is called by M1 (matched) and G2; calls M2 (matched)
    link(conn, "function_callers", "caller_address", "80200010",
         ["80200020", "80200040"])
    link(conn, "function_callees", "callee_address", "80200010",
         ["80200030"])

    link(conn, "function_callees", "callee_address", "802000a0",
         ["802000b0"])
    link(conn, "function_callees", "callee_address", "802000b0",
         ["802000c0"])
    link(conn, "function_callers", "caller_address", "802000b0",
         ["802000a0"])
    link(conn, "function_callers", "caller_address", "802000c0",
         ["802000b0"])

    link(conn, "function_callees", "callee_address", "802000d0",
         ["802000e0"])
    link(conn, "function_callees", "callee_address", "802000e0",
         ["802000f0"])
    link(conn, "function_callees", "callee_address", "802000f0",
         ["802000d0"])
    link(conn, "function_callers", "caller_address", "802000e0",
         ["802000d0"])
    link(conn, "function_callers", "caller_address", "802000f0",
         ["802000e0"])
    link(conn, "function_callers", "caller_address", "802000d0",
         ["802000f0"])
    conn.commit()
    return conn


def test_scorer_rules(conn):
    print("== scorer rules ==")
    scorer = Scorer(conn)
    scorer.discovery.symbol_units["SrcFn"] = {"main/fake.master/fake_unit"}
    scorer.discovery.unit_source["main/fake.master/fake_unit"] = \
        "/tmp/fake.cpp"
    scorer.functions["80200100"] = {
        "address": "80200100", "name": "SrcFn", "size": 300,
        "section": "text", "is_thunk": 0, "is_external": 0,
        "signature": None, "return_type": None, "status": "unknown",
        "category": "game", "analyzed": 0, "source": None}
    scorer.callees["80200100"] = []
    result = scorer.score("80200100", include_library=True)
    check(result["score"] == 30 + 15 + 8 + 8,
          "source-unit score expected 61, got %d (%s)"
          % (result["score"], result["reasons"]))
    check(any("unit has source" in r for r in result["reasons"]),
          "has_source reason missing")

    # size bands are transparent and non-monotonic in raw size
    check(size_band(24)[0] == 0, "trivial band should score 0")
    check(size_band(200)[0] > size_band(24)[0], "medium > trivial")
    check(size_band(1000)[0] > size_band(100)[0], "large > small")
    check(size_band(9000)[0] < size_band(1000)[0],
          "very large should score below large (diminishing)")


def test_ranking(conn):
    print("== ranking ==")
    scorer = Scorer(conn)

    ranked = scorer.rank(limit=50)
    addresses = [r["address"] for r in ranked]
    ids = {r["address"]: r["name"] for r in ranked}

    # exclusions
    for name in ("M1", "M2", "RT_big", "NK_big", "TH", "EX"):
        check(name not in ids.values(), "%s must be excluded" % name)

    # dependency readiness: G1 (matched caller + matched callee) is #1
    check(ids.get(addresses[0]) == "G1",
          "G1 should rank first, got %s" % ids.get(addresses[0]))

    # A -> B -> C: B (one unknown callee) outranks A (two unknowns)
    check(addresses.index("802000b0") < addresses.index("802000a0"),
          "B should outrank A (dependency readiness)")

    # matched callees make G1 strictly better than the same-size LEAF
    g1 = next(r for r in ranked if r["address"] == "80200010")
    leaf = next(r for r in ranked if r["address"] == "80200090")
    check(g1["score"] > leaf["score"], "G1 should outscore LEAF")

    # determinism
    again = scorer.rank(limit=50)
    check([r["address"] for r in again] == addresses,
          "ranking must be deterministic")

    # include-library: runtime appears but sinks to the bottom
    ranked_lib = scorer.rank(limit=50, include_library=True)
    lib_ids = [r["address"] for r in ranked_lib]
    check("80200050" in lib_ids, "runtime should appear with flag")
    rt_names = {r["address"]: r["name"] for r in ranked_lib}
    check(rt_names.get("80200050") == "RT_big", "runtime row wrong")
    check(lib_ids.index("80200050") > lib_ids.index("80200010"),
          "runtime should rank below game code even when included")

    # category filter
    ranked_game = scorer.rank(limit=50, category="game")
    check(all(r["category"] == "game" for r in ranked_game),
          "category filter leaked")

    # min/max size filters
    ranked_small = scorer.rank(limit=50, max_size=150)
    check(all((r["size"] or 0) <= 150 for r in ranked_small),
          "max_size filter leaked")


def test_traversal(conn):
    print("== traversal ==")
    g = DependencyGraph(conn)

    # bounded BFS
    check(set(g.callees_up_to("802000a0", 1)) == {"802000b0"},
          "callees depth 1 wrong")
    check(set(g.callees_up_to("802000a0", 2)) == {"802000b0", "802000c0"},
          "callees depth 2 wrong")
    check(set(g.callers_up_to("802000c0", 1)) == {"802000b0"},
          "callers depth 1 wrong")
    check(set(g.callers_up_to("802000c0", 2)) == {"802000b0", "802000a0"},
          "callers depth 2 wrong")

    # closures
    check(set(g.dependency_closure("802000a0")) == {"802000b0",
                                                    "802000c0"},
          "dependency closure wrong")
    check(g.reverse_dependency_closure("802000a0") == {},
          "nobody calls A; reverse closure should be empty")
    check(set(g.reverse_dependency_closure("802000c0")) == {"802000b0",
                                                            "802000a0"},
          "reverse closure of C wrong")

    # direct edge helpers
    check([c["address"] for c in g.direct_callees("802000a0")]
          == ["802000b0"], "direct callees wrong")
    check(len(g.direct_callers("80200010")) == 2, "direct callers wrong")

    # cycles: closure terminates and SCC is detected
    closure = g.dependency_closure("802000d0")
    check(set(closure) == {"802000e0", "802000f0"},
          "cycle closure wrong: %r" % closure)
    sccs = g.sccs_from("802000d0")
    check(any(set(c) == {"802000d0", "802000e0", "802000f0"}
              for c in sccs), "3-cycle not detected: %r" % sccs)
    check(g.sccs_from("802000a0") == [], "acyclic chain has no cycles")

    # unimported addresses get placeholders, not crashes
    info = g.function("fffffff9")
    check(info["address"] == "fffffff9" and info["name"] is None,
          "placeholder for unimported address wrong")

    # summary report runs
    report = g.summary("80200010", depth=1)
    check(report is not None and len(report["direct_callers"]) == 2
          and report["dependency_depth"] == 1,
          "summary report wrong")


def test_discovery(conn):
    print("== discovery ==")
    d = Discovery(conn, report_path="/nonexistent",
                  objdiff_path="/nonexistent", src_root="/nonexistent")
    d.symbol_units["G1"] = {"main/fake.master/fake_unit"}
    d.unit_source["main/fake.master/fake_unit"] = "/tmp/fake.cpp"

    g1 = d.one("80200010")
    check(g1["unmatched"] and not g1["matched"],
          "G1 match state wrong")
    check(g1["game_candidate"], "G1 should be a game candidate")
    check(g1["has_source"] and g1["partially_implemented"],
          "G1 should be partially implemented via its unit")
    check(g1["has_symbol"], "G1 should have a symbol")
    m1 = d.one("80200020")
    check(m1["matched"] and not m1["unmatched"],
          "matched detection wrong")
    rt = d.one("80200050")
    check(rt["library_candidate"] and not rt["game_candidate"],
          "runtime classification wrong")
    th = d.one("80200070")
    check(th["has_unknown_name"] is False or th["has_symbol"],
          "thunk name handling wrong")

    summary = d.summary()
    check(summary["total"] == 15, "summary total wrong: %r" % summary)
    check(summary["matched"] == 2, "summary matched wrong")
    check(summary["library"] == 2, "summary library count wrong")


def test_real_db():
    print("== real database ==")
    if not os.path.exists(REAL_DB):
        print("  SKIP: %s missing" % REAL_DB)
        return
    py = sys.executable
    prior = os.path.join(HERE, "prioritize.py")
    deps = os.path.join(HERE, "dependencies.py")
    disc = os.path.join(HERE, "discover.py")

    rc = subprocess.run(
        [py, prior, "--json", "--limit", "25"],
        capture_output=True, text=True)
    check(rc.returncode == 0, "prioritize --json failed: %s" % rc.stderr)
    rows = json.loads(rc.stdout)
    check(len(rows) == 25, "expected 25 ranked rows, got %d" % len(rows))
    check(len({r["address"] for r in rows}) == 25, "duplicate addresses")
    check(all(r["status"] != "matched" for r in rows),
          "matched function in default ranking")
    check(all(r["category"] not in ("runtime", "sdk", "msl", "trk",
                                    "nulib") for r in rows),
          "library function in default ranking")
    check(rows == sorted(rows, key=lambda r: (-r["score"], -r["callers"],
                                              -(r["size"] or 0),
                                              r["address"])),
          "json ranking not sorted")

    rc = subprocess.run([py, deps, "801b16b0", "--json"],
                        capture_output=True, text=True)
    check(rc.returncode == 0, "dependencies --json failed: %s" % rc.stderr)
    report = json.loads(rc.stdout)
    check(len(report["direct_callers"]) == 31,
          "expected 31 direct callers for 801b16b0, got %d"
          % len(report["direct_callers"]))
    check(report["function"]["name"] == "NuFileRead__FiPvii",
          "801b16b0 name wrong")

    rc = subprocess.run([py, disc], capture_output=True, text=True)
    check(rc.returncode == 0 and "functions:" in rc.stdout,
          "discover summary failed: %s" % rc.stderr)


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_pipeline_test_")
    try:
        conn = make_db(os.path.join(tmp, "synthetic.db"))
        test_scorer_rules(conn)
        test_ranking(conn)
        test_traversal(conn)
        test_discovery(conn)
        conn.close()
        test_real_db()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all pipeline tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
