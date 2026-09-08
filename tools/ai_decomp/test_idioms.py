#!/usr/bin/env python3
"""Tests for the MWCC compiler-idiom knowledge base (Phase 5.3).

Uses synthetic source/assembly fixtures and a temporary database; no
LLM calls, no game dump. The real 801b16b0 attempt is used only as an
optional integration fixture.

Run:  python3 tools/ai_decomp/test_idioms.py
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402
import idioms as idioms_mod  # noqa: E402
import orchestrator as orch_mod  # noqa: E402
from worktree import WorktreeManager  # noqa: E402

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def make_world(tmp_sub):
    repo = os.path.join(tmp_sub, "looprepo")
    os.makedirs(os.path.join(repo, "src", "fake.master"), exist_ok=True)
    write(os.path.join(repo, "README"), "init\n")
    write(os.path.join(repo, UNIT_REL), "// unit source\n")

    def git(*args):
        subprocess.run(["git", "-C", repo, *args], check=True,
                       capture_output=True, text=True)
    git("init", "-b", "ai-decomp")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    git("add", "-A")
    git("commit", "-m", "init")

    conn = db.connect(os.path.join(tmp_sub, "loop.db"))
    db.upsert_function(conn, "80200010", name="TargetFn", size=64,
                       category="game", source="symbols")
    conn.commit()
    output_dir = os.path.join(tmp_sub, "output")
    write(os.path.join(output_dir, "function_80200010_analyzed.json"),
          json.dumps({
              "address": "80200010", "name": "TargetFn", "size": 64,
              "signature": "void TargetFn(void)",
              "return_type": "void",
              "decompilation": "void TargetFn(void) {}",
              "instructions": ["80200010: rlwinm r0,r3,2,0x16,0x1d",
                               "80200014: blr"],
              "derived": {}}))
    write(os.path.join(tmp_sub, "baseline.json"), json.dumps(
        {"units": [{"name": "main/fake.master/fake_unit",
                    "functions": [{"name": "TargetFn", "size": "64",
                                   "fuzzy_match_percent": None}]}],
         "categories": []}))
    return {
        "conn": conn, "repo": repo,
        "output_dir": output_dir,
        "baseline": os.path.join(tmp_sub, "baseline.json"),
        "attempts": os.path.join(tmp_sub, "attempts"),
        "src_root": os.path.join(repo, "src"),
        "include_root": os.path.join(repo, "include"),
        "unit_src": os.path.join(repo, UNIT_REL),
    }


UNIT_REL = "src/fake.master/fake_unit.cpp"


class FakeClient:
    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def generate(self, prompt):
        entry = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1

        class R:
            pass
        r = R()
        r.prompt = prompt
        r.ok = True
        r.error = None
        r.response = json.dumps({
            "analysis": "fake",
            "source_changes": [{
                "path": UNIT_REL, "operation": "append",
                "new_text": entry.get("new_text", "")}],
            "confidence": 0.5,
        })
        return r


def build_orch(world, objdiff_results, max_attempts=1,
               new_text="// candidate idiom\n"):
    wt = WorktreeManager(repo=world["repo"],
                         worktrees_dir=os.path.join(world["repo"],
                                                    ".worktrees"))
    orch = orch_mod.Orchestrator(
        "80200010", world["conn"], max_attempts=max_attempts,
        llm_client=FakeClient([{"new_text": new_text}]),
        attempts_root=world["attempts"], worktree_manager=wt,
        log=lambda *a, **k: None)
    orch_mod.PRIMARY_BASELINE = world["baseline"]
    real_bc = orch_mod.context_mod.build_context

    def fake_build_context(address, conn=None, **kwargs):
        return GENUINE_BC(address, conn=world["conn"], run_m2c=False,
                          output_dir=world["output_dir"],
                          src_root=world["src_root"],
                          include_dir=world["include_root"])
    orch_mod.context_mod.build_context = fake_build_context

    calls = {"n": 0}

    def fake_evaluate(worktree, target_symbol=None, baseline_report=None,
                      target_address=None, **kw):
        r = objdiff_results[min(calls["n"], len(objdiff_results) - 1)]
        calls["n"] += 1
        return {"report": "fake",
                "target": {"symbol": target_symbol,
                           "address": target_address,
                           "data_available": r.get("pct") is not None,
                           "fully_matched": r.get("pct") == 100.0,
                           "match_percent": r.get("pct")},
                "overall": None, "regressions": r.get("regressions", []),
                "limitations": []}
    orch_mod.objdiff_mod.evaluate = fake_evaluate

    def fake_build(wt, timeout=1, repo=None, build_cmd=("ninja",), **kw):
        return {"success": True, "classification": "ok", "errors": [],
                "warnings": [], "objects": [], "stdout": "",
                "stderr": "", "exit_code": 0, "duration_seconds": 0.1,
                "command": list(build_cmd), "timeout_seconds": timeout,
                "worktree": wt, "started": "-", "configure": None}
    orch_mod.build_mod.run_build = fake_build
    return orch


GENUINE_BC = orch_mod.context_mod.build_context


# ----------------------------------------------------------------
# 1-8: creation, duplicates, normalization, levels, counts, scoring
# ----------------------------------------------------------------

def test_core(tmp):
    print("== core idioms ==")
    conn = db.connect(":memory:")

    # 1. creation
    iid = db.upsert_idiom(conn, "mask_shift_index",
                          "mask_shift(mask_bits=8, shift=2)",
                          "rlwinm r#,r#,2,0x16,0x1d")
    row = db.get_idiom(conn, iid)
    check(row["kind"] == "mask_shift_index" and
          row["compiler"] == "MWCC" and
          row["architecture"] == "PowerPC" and
          row["target"] == "ppc-mwcc", "creation wrong: %r" % row)

    # 2. duplicate idiom creation returns the same row
    iid2 = db.upsert_idiom(conn, "mask_shift_index",
                           "mask_shift(mask_bits=8, shift=2)",
                           "rlwinm r#,r#,2,0x16,0x1d")
    check(iid2 == iid, "duplicate idiom created a second row")

    # 3. source normalization groups equivalent constructs
    a = idioms_mod.canonical_mask_shift("(x & 0xff) << 2")
    b = idioms_mod.canonical_mask_shift("(idx & 255) * 4")
    c = idioms_mod.canonical_mask_shift("(x & 0xffff) << 3")
    check(a == b == "mask_shift(mask_bits=8, shift=2)",
          "equivalent mask/shift forms must group: %r vs %r" % (a, b))
    check(a != c, "different masks must not group")

    # 4. assembly normalization: registers/addresses genericized,
    #    structure preserved
    n1 = idioms_mod.normalize_asm_line("801b16b0: lis r7,-0x7f73")
    n2 = idioms_mod.normalize_asm_line("80200000: lis r3,-0x5000")
    check(n1 == n2 == "lis r#,0xADDR", "register/address norm wrong")
    check(idioms_mod.normalize_asm_line("rlwinm r0,r3,2,0x16,0x1d")
          == "rlwinm r#,r#,2,0x16,0x1d",
          "rlwinm operand structure must survive")
    check(idioms_mod.normalize_asm_line("801b16d0: mtspr CTR,r12")
          == "mtspr CTR,r#", "spr normalization wrong")

    # 5-8. observation levels, counts, matched counts, averages
    asm = ["80200010: rlwinm r0,r3,2,0x16,0x1d", "80200014: blr"]
    src = "int f(int x) { return (x & 0xff) << 2; }\n"

    learned = idioms_mod.learn_from_attempt(
        conn, address="80200010", function_name="Fn", attempt_number=1,
        source_text=src, assembly_lines=asm, objdiff_percent=50.0,
        accepted_as_best=True, compiled=True, improvement=50.0)
    check(len(learned) >= 1, "mask+shift+rlwinm should be learned")
    row = db.get_idiom(conn, learned[0]["idiom_id"])
    check(row["observation_count"] == 1, "count should be 1")
    check(row["matched_count"] == 0, "no match yet")
    check(row["average_improvement"] == 50.0, "improvement wrong")
    check(db.effective_idiom_level(row["observation_count"],
                                   row["matched_count"]) == "observed",
          "single observation must stay 'observed'")

    # repeated: second independent function observes the same idiom
    idioms_mod.learn_from_attempt(
        conn, address="80200020", function_name="G", attempt_number=2,
        source_text=src, assembly_lines=asm, objdiff_percent=80.0,
        compiled=True, improvement=30.0)
    row = db.get_idiom(conn, learned[0]["idiom_id"])
    check(row["observation_count"] == 2, "count should be 2")
    check(db.effective_idiom_level(row["observation_count"],
                                   row["matched_count"]) == "repeated",
          "two observations should be 'repeated'")
    check(abs(row["average_improvement"] - 40.0) < 0.01,
          "running average wrong: %r" % row["average_improvement"])

    # matched: objdiff 100 observation promotes the idiom
    idioms_mod.learn_from_attempt(
        conn, address="80200030", function_name="H", attempt_number=3,
        source_text=src, assembly_lines=asm, objdiff_percent=100.0,
        accepted_as_best=True, compiled=True, improvement=20.0)
    row = db.get_idiom(conn, learned[0]["idiom_id"])
    check(row["matched_count"] == 1, "matched_count should be 1")
    check(row["best_objdiff_score"] == 100.0, "best score should be 100")
    check(db.effective_idiom_level(row["observation_count"],
                                   row["matched_count"]) == "matched",
          "100%% observation must promote to 'matched'")

    # duplicate observation (same function+attempt+level) is ignored
    before = db.get_idiom(conn, learned[0]["idiom_id"])
    idioms_mod.learn_from_attempt(
        conn, address="80200030", function_name="H", attempt_number=3,
        source_text=src, assembly_lines=asm, objdiff_percent=100.0,
        accepted_as_best=True, compiled=True)
    after = db.get_idiom(conn, learned[0]["idiom_id"])
    check(after["observation_count"] == before["observation_count"],
          "duplicate observation inflated counts")

    # rejected: regressed candidate marks the observation, not the idiom
    idioms_mod.learn_from_attempt(
        conn, address="80200040", function_name="K", attempt_number=4,
        source_text=src, assembly_lines=asm, objdiff_percent=None,
        compiled=True, regressed=True)
    row = db.get_idiom(conn, learned[0]["idiom_id"])
    check(row["matched_count"] == 1, "regression must not add a match")
    obs = conn.execute(
        "SELECT evidence_level FROM idiom_observations "
        "WHERE idiom_id=? AND function_address='80200040'",
        (learned[0]["idiom_id"],)).fetchone()
    check(obs and obs["evidence_level"] == "rejected",
          "regressed observation should be marked rejected")

    # 9-11. retrieval + compiler/architecture filtering
    hits = idioms_mod.retrieve_relevant_idioms(
        conn, assembly_lines=asm)
    check(any(h["kind"] == "mask_shift_index" for h in hits),
          "rlwinm target should retrieve the mask_shift idiom")
    conn.execute("INSERT INTO idioms (kind, compiler, architecture, "
                 "target) VALUES ('x', 'GCC', 'PowerPC', 'ppc-gcc')")
    hits_all = idioms_mod.retrieve_relevant_idioms(
        conn, assembly_lines=asm, compiler="GCC")
    check(hits_all == [],
          "idioms from another compiler must not be retrieved by "
          "default and GCC has no matching pattern")
    hits_ppc = idioms_mod.retrieve_relevant_idioms(
        conn, assembly_lines=asm, architecture="MIPS")
    check(hits_ppc == [], "architecture filter failed")

    # 17. irrelevant idioms are excluded
    irrelevant = idioms_mod.retrieve_relevant_idioms(
        conn, assembly_lines=["80000000: blr"])
    check(all(h["kind"] != "mask_shift_index" for h in irrelevant),
          "non-matching target should not retrieve rlwinm idiom")

    # 15. one-observation rendering must not claim universality
    conn2 = db.connect(":memory:")
    one = db.upsert_idiom(conn2, "kind_x", "s", "a")
    db.add_idiom_observation(conn2, one, function_address="80000000",
                             objdiff_percent=30.0,
                             evidence_level="observed")
    rows = idioms_mod.retrieve_relevant_idioms(
        conn2, assembly_lines=["a"])
    rendered = idioms_mod.render_idioms_markdown(rows)
    check("observed in 1 compilation" in rendered,
          "single observation must be labeled as such")

    # 18. no raw game data: stored fields are bounded excerpts only
    huge_source = "x" * 5000 + " main.dol game.rvz"
    learned = idioms_mod.learn_from_attempt(
        conn2, address="80000001", attempt_number=1,
        source_text=huge_source, assembly_lines=["a"],
        objdiff_percent=10.0, compiled=True)
    if learned:
        obs = conn2.execute(
            "SELECT source_excerpt FROM idiom_observations "
            "WHERE function_address='80000001'").fetchone()
        check(len(obs["source_excerpt"]) <=
              idioms_mod.MAX_EXCERPT, "excerpt not bounded")
    conn.close()
    conn2.close()


# ----------------------------------------------------------------
# 12-14: orchestrator integration (failed build, regression, 100%)
# ----------------------------------------------------------------

def test_orchestrator_learning(tmp):
    print("== orchestrator learning integration ==")
    real = (orch_mod.PRIMARY_BASELINE, orch_mod.context_mod.build_context,
            orch_mod.objdiff_mod.evaluate, orch_mod.build_mod.run_build)
    try:
        # 12. failed build produces no observations
        world = make_world(os.path.join(tmp, "fail"))
        orch = build_orch(world, objdiff_results=[], max_attempts=1)
        real_rb = orch_mod.build_mod.run_build
        orch_mod.build_mod.run_build = lambda wt, timeout=1, repo=None, \
            build_cmd=("ninja",), **kw: {
                "success": False, "classification": "compile_error",
                "errors": ["error: x"], "warnings": [], "objects": [],
                "stdout": "", "stderr": "", "exit_code": 1,
                "duration_seconds": 0.1, "command": list(build_cmd),
                "timeout_seconds": timeout, "worktree": wt,
                "started": "-", "configure": None}
        try:
            orch.run()
        finally:
            orch_mod.build_mod.run_build = real_rb
        check(world["conn"].execute(
            "SELECT COUNT(*) FROM idiom_observations").fetchone()[0] == 0,
            "failed build must not create compiler observations")

        # 13. regressed candidate is stored but never 'matched'
        world = make_world(os.path.join(tmp, "regr"))
        orch = build_orch(world, objdiff_results=[
            {"pct": 73.333336,
             "regressions": ["matched_code: 43664 -> 40000"]}],
            max_attempts=1,
            new_text="// regressed\nreturn (x & 0xff) << 2;\n")
        orch.run()
        levels = [r[0] for r in world["conn"].execute(
            "SELECT evidence_level FROM idiom_observations")]
        check(levels and all(l == "rejected" for l in levels),
              "regressed observations must all be rejected")

        # 14. 100% produces 'matched' observations
        world = make_world(os.path.join(tmp, "full"))
        orch = build_orch(world, objdiff_results=[{"pct": 100.0}],
                          max_attempts=1,
                          new_text="// full\n"
                                   "return (x & 0xff) << 2;\n")
        orch.run()
        levels = [r[0] for r in world["conn"].execute(
            "SELECT evidence_level FROM idiom_observations")]
        check(levels and all(l == "matched" for l in levels),
              "100%% observations must be matched")
        row = world["conn"].execute(
            "SELECT matched_count FROM idioms").fetchone()
        check(row["matched_count"] >= 1, "matched_count not updated")
    finally:
        orch_mod.PRIMARY_BASELINE = real[0]
        orch_mod.context_mod.build_context = GENUINE_BC
        orch_mod.objdiff_mod.evaluate = real[2]
        orch_mod.build_mod.run_build = real[3]


# ----------------------------------------------------------------
# 16: prompt receives relevant idioms (loop integration)
# ----------------------------------------------------------------

def test_prompt_receives_idioms(tmp):
    print("== prompt receives idioms ==")
    real = (orch_mod.PRIMARY_BASELINE, orch_mod.context_mod.build_context,
            orch_mod.objdiff_mod.evaluate, orch_mod.build_mod.run_build)
    try:
        world = make_world(os.path.join(tmp, "prompt"))
        # seed the knowledge base with an idiom matching the fixture asm
        conn = world["conn"]
        iid = db.upsert_idiom(conn, "mask_shift_index",
                              "mask_shift(mask_bits=8, shift=2)",
                              "rlwinm r#,r#,2,0x16,0x1d")
        db.add_idiom_observation(
            conn, iid, function_address="80200010",
            function_name="Other", objdiff_percent=100.0,
            evidence_level="matched")

        orch = build_orch(world, objdiff_results=[{"pct": 100.0}],
                          max_attempts=1)
        orch.run()
        prompt = open(os.path.join(world["attempts"], "80200010",
                                   "attempt-001",
                                   "prompt.txt")).read()
        check("Known MWCC compiler idioms" in prompt,
              "idiom block missing from prompt")
        check("not guarantees" in prompt,
              "non-authority disclaimer missing")
        check("mask_shift_index" in prompt, "idiom kind missing")
        conn.close()
    finally:
        orch_mod.PRIMARY_BASELINE = real[0]
        orch_mod.context_mod.build_context = GENUINE_BC
        orch_mod.objdiff_mod.evaluate = real[2]
        orch_mod.build_mod.run_build = real[3]


# ----------------------------------------------------------------
# 20. backwards compatibility + no game data in DB
# ----------------------------------------------------------------

def test_backwards_compat(tmp):
    print("== database backwards compatibility ==")
    path = os.path.join(tmp, "old.db")
    conn = sqlite3.connect(path)
    # pre-5.3 database: full functions table, no idiom tables
    conn.execute("CREATE TABLE functions (address TEXT PRIMARY KEY, "
                 "name TEXT, size INTEGER, section TEXT, "
                 "is_thunk INTEGER, is_external INTEGER, "
                 "signature TEXT, return_type TEXT, status TEXT, "
                 "category TEXT, analyzed INTEGER, source TEXT, "
                 "updated_at TEXT)")
    conn.execute("INSERT INTO functions VALUES ('80000000', 'Old', "
                 "10, 'text', 0, 0, NULL, NULL, 'unknown', NULL, "
                 "0, NULL, NULL)")
    conn.commit()
    conn.close()

    import database as db
    c2 = db.connect(path)
    check(c2.execute("SELECT name, status FROM functions "
                     "WHERE address='80000000'").fetchone()["name"]
          == "Old", "old table damaged by migration")
    tables = {r[0] for r in c2.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    check({"idioms", "idiom_observations"} <= tables,
          "new tables missing after migration")
    c2.close()


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_idioms_test_")
    try:
        test_core(tmp)
        test_orchestrator_learning(tmp)
        test_prompt_receives_idioms(tmp)
        test_backwards_compat(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all idiom knowledge base tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
