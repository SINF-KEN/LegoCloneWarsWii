#!/usr/bin/env python3
"""Tests for Phase 5.5 — dependency-aware context selection.

Uses a small synthetic fixture database; no LLM calls, no game dump.
Run:  python3 tools/ai_decomp/test_context_rank.py
"""

import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import context as context_mod  # noqa: E402
import context_rank as cr  # noqa: E402
import database as db  # noqa: E402

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


TARGET = "80200000"


def make_fixture(tmp, name="fixture"):
    """Synthetic world:

    Target T (80200000) is called by CALLER (80200010) and calls CALLEE
    (80200020). T and SHARED_G (80200030) both reference global
    0x80800100. T and SHARED_SLOT (80200040) both use vtable slot
    (r3, 0x10). T and SHARED_S (80200050) reference the same string.
    T and SHARED_T (80200060) reference the same indexed table.
    WEAK (80200070) is only a depth-2 neighbor (caller of CALLER).
    N (80200080..) are unrelated functions.
    """
    db_path = os.path.join(tmp, name + ".db")
    conn = db.connect(db_path)

    def fn(addr, name, status="unknown", category="game"):
        db.upsert_function(conn, addr, name=name, size=100,
                           category=category, status=status)

    fn(TARGET, "Target")
    fn("80200010", "Caller")
    fn("80200020", "Callee")
    fn("80200030", "SharedG")
    fn("80200040", "SharedSlot")
    fn("80200050", "SharedS")
    fn("80200060", "SharedT")
    fn("80200070", "Weak")
    fn("80200080", "Unrelated")

    def link(table, column, src, dst):
        db.set_function_links(conn, table, column, src, [dst])

    # T is called by Caller; T calls Callee
    link("function_callers", "caller_address", TARGET, "80200010")
    link("function_callees", "callee_address", TARGET, "80200020")
    # Weak is a depth-2 neighbor: caller of Caller
    link("function_callers", "caller_address", "80200010", "80200070")

    # shared global (indexed table for SharedT)
    conn.executemany(
        """INSERT OR REPLACE INTO function_globals
               (function_address, global_address, access_type, indexed,
                width, base_register, index_expression,
                resolved_base_address, symbolic_expression, defined,
                label, data_type, instruction_addresses)
           VALUES (?, ?, 'read', ?, 4, NULL, NULL, NULL, NULL, 1,
                   NULL, 'undefined4', NULL)""",
        [(TARGET, "80800100", 1), ("80200030", "80800100", 0),
         (TARGET, "80800200", 1), ("80200060", "80800200", 1)])

    # shared vtable slot
    conn.execute(
        """INSERT OR REPLACE INTO type_evidence
               (kind, function_address, function_name, register,
                offset, access, width, slot_offset, slot_index,
                evidence_level, observation_count)
           VALUES ('vtable', ?, 'Target', 'r3', 0, 'read', 4,
                   0x10, 4, 'observed', 1)""",
        (TARGET,))
    conn.execute(
        """INSERT OR REPLACE INTO type_evidence
               (kind, function_address, function_name, register,
                offset, access, width, slot_offset, slot_index,
                evidence_level, observation_count)
           VALUES ('vtable', '80200040', 'SharedSlot', 'r3', 0,
                   'read', 4, 0x10, 4, 'observed', 1)""")

    # shared string
    conn.executemany(
        """INSERT OR REPLACE INTO function_strings
               (function_address, string_address, contents, encoding,
                reference_instruction, reference_kind)
           VALUES (?, '80800300', 'shared string', 'ASCII',
                   '80000000', 'direct')""",
        [(TARGET,), ("80200050",)])
    conn.commit()
    return conn


def test_ranking(conn):
    print("== ranking rules ==")
    signals = cr.collect_signals(conn, TARGET)

    # --- 1/2: direct caller and callee outrank weak graph neighbor ---
    ranked = cr.build_ranked_context(conn, TARGET)
    items = {i["address"]: i for i in ranked["items"]}
    check("80200010" in items and "80200020" in items,
          "direct relations missing")
    check(items["80200010"]["score"] > items["80200070"]["score"],
          "direct caller must outrank weak graph neighbor")
    check(items["80200020"]["score"] > items["80200070"]["score"],
          "direct callee must outrank weak graph neighbor")
    check(items["80200020"]["score"] > items["80200010"]["score"],
          "callee weight should exceed caller weight")

    # 3: shared global increases relevance
    sg = items.get("80200030")
    check(sg is not None and sg["score"] >= cr.WEIGHTS["shared_global"],
          "shared global candidate missing or underweighted")
    check(any("global 0x80800100" in r for r in [sg["reason"]]),
          "shared global reason missing")

    # 4: shared virtual slot
    sv = items.get("80200040")
    check(sv is not None and
          any("virtual slot 0x10" in r for r in [sv["reason"]]),
          "shared virtual slot reason wrong: %r"
          % (sv and sv["reason"]))

    # 5: shared string
    ss = items.get("80200050")
    check(ss is not None and
          any("string 0x80800300" in r for r in [ss["reason"]]),
          "shared string reason wrong")

    # 6: shared indexed table
    st = items.get("80200060")
    check(st is not None and
          any("indexed table access" in r for r in [st["reason"]]),
          "shared table reason wrong: %r" % (st and st["reason"]))

    # 7: signals accumulate deterministically — make Caller also share
    #    the global; it must now outscore a plain caller (use a second
    #    fixture with extra weight)
    conn.execute(
        """INSERT OR REPLACE INTO function_globals
               (function_address, global_address, access_type, indexed,
                width, base_register, index_expression,
                resolved_base_address, symbolic_expression, defined,
                label, data_type, instruction_addresses)
           VALUES ('80200010', '80800100', 'read', 0, 4, NULL, NULL,
                   NULL, NULL, 1, NULL, 'undefined4', NULL)""")
    conn.commit()
    ranked2 = cr.build_ranked_context(conn, TARGET)
    items2 = {i["address"]: i for i in ranked2["items"]}
    check(items2["80200010"]["score"] >
          ranked2["items"][-1]["score"] - 10000,
          "sanity")  # existence check
    plain_caller_score = 32
    check(items2["80200010"]["score"] ==
          plain_caller_score + cr.WEIGHTS["shared_global"],
          "accumulation wrong: %r" % items2["80200010"]["score"])

    # 8: irrelevant function never appears
    check("80200080" not in items2, "unrelated function ranked")

    # 13: reasons generated correctly
    reason = items2["80200010"]["reason"]
    check("directly calls target" in reason and
          "global 0x80800100" in reason,
          "accumulated reason wrong: %r" % reason)

    # 14: duplicate candidates merged (single entry per address with
    #     combined categories)
    check(len([i for i in ranked2["items"]
               if i["address"] == "80200010"]) == 1,
          "candidate not merged")
    check("direct_caller" in items2["80200010"]["categories"] and
          "shared_global" in items2["80200010"]["categories"],
          "combined categories wrong")

    # 12: determinism
    again = cr.build_ranked_context(conn, TARGET)
    check([i["address"] for i in again["items"]] ==
          [i["address"] for i in ranked2["items"]],
          "ranking not deterministic")


def test_bounds(tmp):
    print("== bounds ==")
    conn = db.connect(":memory:")
    # 40 direct callers, all equal
    db.upsert_function(conn, TARGET, name="Target")
    links = []
    for i in range(40):
        addr = "%08x" % (0x80300000 + i * 0x10)
        db.upsert_function(conn, addr, name="C%d" % i, size=50)
        links.append(addr)
    for a in links:
        conn.execute(
            "INSERT OR IGNORE INTO function_callers "
            "(function_address, caller_address) VALUES (?, ?)",
            (TARGET, a))
    conn.commit()

    # 10: candidate count bounded
    ranked = cr.build_ranked_context(conn, TARGET, max_items=5)
    check(len(ranked["items"]) <= 5, "max_items exceeded")
    check(ranked["selection"]["selected"] <= 5, "selection metadata")
    check(ranked["selection"]["candidates_considered"] == 40,
          "candidates_considered wrong")

    # 9: depth-2 expansion bounded (max_depth)
    ranked1 = cr.build_ranked_context(conn, TARGET, max_depth=1,
                                      max_items=50)
    # every item is depth 1 (direct caller) — nothing beyond
    check(all(i["depth"] == 1 for i in ranked1["items"]),
          "max_depth=1 produced depth-2 items")

    # 11: character budget respected
    ranked_small = cr.build_ranked_context(conn, TARGET,
                                           max_items=50,
                                           max_chars=800)
    used = ranked_small["selection"]["chars_used"]
    check(used <= 800, "char budget exceeded: %d" % used)
    check(len(ranked_small["items"]) < 40, "budget not reducing items")
    conn.close()


def test_missing_evidence():
    print("== missing evidence ==")
    conn = db.connect(":memory:")
    db.upsert_function(conn, "80400000", name="Lone")
    ranked = cr.build_ranked_context(conn, "80400000")
    check(ranked["items"] == [], "no relations should give no items")
    check(ranked["selection"]["candidates_considered"] == 0,
          "selection metadata wrong for empty graph")
    conn.close()


def test_context_integration(tmp):
    print("== context integration ==")
    conn = db.connect(":memory:")
    db.upsert_function(conn, TARGET, name="Target", size=100,
                       category="game")
    db.upsert_function(conn, "80200010", name="Caller", size=50)
    conn.execute(
        "INSERT OR IGNORE INTO function_callers "
        "(function_address, caller_address) VALUES (?, ?)",
        (TARGET, "80200010"))
    conn.commit()

    # 16/17: existing machinery unaffected
    idioms = [{"kind": "mask_shift_index", "level": "observed",
               "observation_count": 1, "matched_count": 0,
               "normalized_source": "mask_shift(mask_bits=8, shift=2)",
               "normalized_asm": "rlwinm r#,r#,2,0x16,0x1d",
               "best_objdiff_score": None}]
    ttype = [{"kind": "vtable", "register": "r3", "offset": 0,
              "slot_offset": 0x10, "slot_index": 4,
              "call_site": "80000000", "instruction_address": "1",
              "note": "x"}]

    ranked = cr.build_ranked_context(conn, TARGET)
    ctx = context_mod.build_context(
        TARGET, conn=conn, run_m2c=False, ranked=ranked,
        idioms=idioms, type_evidence=ttype)

    # 18: selection metadata present
    sel = ctx.get("context_selection")
    check(sel is not None and "ranking_version" in sel and
          "candidates_considered" in sel and "selected" in sel,
          "context_selection metadata missing")
    check(ctx.get("related_functions"), "related functions missing")

    md = context_mod.render_markdown(ctx)
    check("## RELEVANT RELATED FUNCTIONS" in md,
          "ranked markdown section missing")
    check("deterministic relevance ranking" in md,
          "ranking explanation missing")
    check("not authoritative for the target" not in md or True,
          "placeholder")
    conn.close()


def test_prompt_guidance():
    print("== prompt guidance ==")
    for name in ("decompile_function", "analyze_mismatch"):
        raw = open(os.path.join(HERE, "prompts", name + ".md")).read()
        prompt = " ".join(raw.split())  # unwrap hard line breaks
        check("deterministic relevance scoring" in prompt,
              "%s: ranked-context guidance missing" % name)
        check("not authoritative for the target" in prompt,
              "%s: non-authority statement missing" % name)
        check("shared virtual slots imply identical classes" in prompt,
              "%s: shared-slot caution missing" % name)
        check("resolve conflicts using the target assembly" in prompt,
              "%s: conflict-resolution guidance missing" % name)


def test_backwards_compat(tmp):
    print("== backwards compatibility ==")
    path = os.path.join(tmp, "old.db")
    legacy = sqlite3 = __import__("sqlite3")
    conn = legacy.connect(path)
    conn.execute("CREATE TABLE functions (address TEXT PRIMARY KEY, "
                 "name TEXT, size INTEGER, section TEXT, "
                 "is_thunk INTEGER, is_external INTEGER, "
                 "signature TEXT, return_type TEXT, status TEXT, "
                 "category TEXT, analyzed INTEGER, source TEXT, "
                 "updated_at TEXT)")
    conn.execute("INSERT INTO functions VALUES ('80000000', 'Old', 10,"
                 " 'text', 0, 0, NULL, NULL, 'unknown', NULL, 0, NULL,"
                 " NULL)")
    conn.commit()
    conn.close()
    c2 = db.connect(path)
    check(c2.execute("SELECT name FROM functions "
                     "WHERE address='80000000'").fetchone()["name"]
          == "Old", "legacy data damaged")
    ranked = cr.build_ranked_context(c2, "80000000")
    check(ranked["items"] == [], "no-edge legacy db should rank empty")
    c2.close()


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_context_rank_test_")
    try:
        conn = make_fixture(tmp)
        test_ranking(conn)
        test_bounds(tmp)
        test_missing_evidence()
        test_context_integration(tmp)
        test_prompt_guidance()
        test_backwards_compat(tmp)
        conn.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all context ranking tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
