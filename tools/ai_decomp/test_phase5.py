#!/usr/bin/env python3
"""Tests for Phase 5.1 — best-so-far retry continuity.

Every external system (LLM, compiler, objdiff) is faked; nothing here
touches the network, the real repository, or the game dump. Worktrees
run against tiny synthetic git repositories.

Run:  python3 tools/ai_decomp/test_phase5.py
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
import mismatch as mismatch_mod  # noqa: E402
import orchestrator as orch_mod  # noqa: E402
from worktree import WorktreeManager  # noqa: E402

failures = []

# capture the genuine functions before any test patches module attributes
GENUINE_BUILD_CONTEXT = orch_mod.context_mod.build_context
GENUINE_EVALUATE = orch_mod.objdiff_mod.evaluate
GENUINE_RUN_BUILD = orch_mod.build_mod.run_build


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def make_git_repo(path):
    os.makedirs(path)
    write(os.path.join(path, "README"), "init\n")
    write(os.path.join(path, "src", "fake.master", "fake_unit.cpp"),
          "// unit source\n")

    def git(*args):
        subprocess.run(["git", "-C", path, *args], check=True,
                       capture_output=True, text=True)
    git("init", "-b", "ai-decomp")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    git("add", "-A")
    git("commit", "-m", "init")
    return path


BASELINE_FIXTURE = {
    "units": [{"name": "main/fake.master/fake_unit",
               "functions": [{"name": "TargetFn", "size": "64",
                              "fuzzy_match_percent": None}]}],
    "categories": [],
}

UNIT_REL = "src/fake.master/fake_unit.cpp"


class FakeClient:
    """Returns scripted structured responses in order."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        entry = self.script[min(self.calls - 1, len(self.script) - 1)]

        class R:
            pass
        r = R()
        r.prompt = prompt
        if entry.get("behavior") == "llm_error":
            r.ok = False
            r.error = "HTTP 500"
            return r
        r.ok = True
        r.error = None
        if entry.get("behavior") == "malformed":
            r.response = "not json"
        else:
            r.response = json.dumps({
                "analysis": "fake",
                "hypotheses": ["h%d" % self.calls],
                "unknowns": ["u%d" % self.calls],
                "proposed_source": "fake",
                "source_changes": [{
                    "path": UNIT_REL,
                    "operation": "append",
                    "new_text": entry.get("new_text", ""),
                }],
                "confidence": 0.5,
            })
        return r


def make_world(tmp_sub):
    repo = make_git_repo(os.path.join(tmp_sub, "looprepo"))
    conn = db.connect(os.path.join(tmp_sub, "loop.db"))
    db.upsert_function(conn, "80200010", name="TargetFn", size=64,
                       category="nulib", source="symbols")
    conn.commit()

    output_dir = os.path.join(tmp_sub, "output")
    write(os.path.join(output_dir, "function_80200010_analyzed.json"),
          json.dumps({
              "address": "80200010", "name": "TargetFn", "size": 64,
              "signature": "void TargetFn(void)",
              "return_type": "void",
              "decompilation": "void TargetFn(void) {}",
              "instructions": ["80200010: blr"],
              "derived": {}}))
    write(os.path.join(tmp_sub, "baseline.json"),
          json.dumps(BASELINE_FIXTURE))
    return {
        "conn": conn, "repo": repo, "output_dir": output_dir,
        "baseline": os.path.join(tmp_sub, "baseline.json"),
        "attempts": os.path.join(tmp_sub, "attempts"),
        "src_root": os.path.join(repo, "src"),
        "include_root": os.path.join(repo, "include"),
        "unit_src": os.path.join(repo, UNIT_REL),
        "tmp_sub": tmp_sub,
    }


def build_orch(world, client_script, objdiff_results, max_attempts=3,
               dry_run=False):
    wt = WorktreeManager(repo=world["repo"],
                         worktrees_dir=os.path.join(world["repo"],
                                                    ".worktrees"))
    orch = orch_mod.Orchestrator(
        "80200010", world["conn"], max_attempts=max_attempts,
        dry_run=dry_run, llm_client=FakeClient(client_script),
        attempts_root=world["attempts"], worktree_manager=wt,
        log=lambda *a, **k: None)
    orch_mod.PRIMARY_BASELINE = world["baseline"]

    def fake_build_context(address, conn=None, **kwargs):
        ctx = GENUINE_BUILD_CONTEXT(address, conn=world["conn"], run_m2c=False,
                      output_dir=world["output_dir"],
                      src_root=world["src_root"],
                      include_dir=world["include_root"])
        ctx["source"]["path"] = world["unit_src"]
        return ctx
    orch_mod.context_mod.build_context = fake_build_context

    seen_worktrees = []
    unit_contents = []
    calls = {"n": 0}

    def fake_build(wt, timeout=1, repo=None, build_cmd=("ninja",), **kw):
        unit_path = os.path.join(wt, UNIT_REL)
        unit_contents.append(
            open(unit_path).read() if os.path.exists(unit_path) else None)
        seen_worktrees.append(wt)
        return {"success": True, "classification": "ok", "errors": [],
                "warnings": [], "objects": [], "stdout": "",
                "stderr": "", "exit_code": 0, "duration_seconds": 0.1,
                "command": list(build_cmd), "timeout_seconds": timeout,
                "worktree": wt, "started": "-", "configure": None}

    def fake_evaluate(worktree, target_symbol=None, baseline_report=None,
                      target_address=None, **kwargs):
        r = objdiff_results[min(calls["n"], len(objdiff_results) - 1)]
        calls["n"] += 1
        return {
            "report": "fake",
            "target": {"symbol": target_symbol,
                       "address": target_address,
                       "data_available": r.get("pct") is not None,
                       "fully_matched": r.get("pct") == 100.0,
                       "match_percent": r.get("pct")},
            "overall": {
                "from": {"matched_code": 43664, "matched_functions": 308},
                "to": {"matched_code": r.get("global_code", 43664),
                       "matched_functions": r.get("global_fn", 308)},
            },
            "regressions": r.get("regressions", []),
            "limitations": [],
        }

    orch_mod.build_mod.run_build = fake_build
    orch_mod.objdiff_mod.evaluate = fake_evaluate
    return orch, unit_contents, calls


def best_of(world):
    path = os.path.join(world["attempts"], "80200010", "best.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def test_retry_continuity(tmp):
    print("== retry continuity ==")
    real = (orch_mod.PRIMARY_BASELINE, orch_mod.context_mod.build_context,
            orch_mod.objdiff_mod.evaluate, orch_mod.build_mod.run_build)
    try:
        # --- 1+2+11: inheritance and lineage across attempts ---
        world = make_world(os.path.join(tmp, "w1"))
        conn, repo = world["conn"], world["repo"]
        orch, contents, _ = build_orch(
            world,
            client_script=[{"new_text": "// attempt-one\n"},
                           {"new_text": "// attempt-two\n"},
                           {"new_text": "// attempt-three\n"}],
            objdiff_results=[{"pct": 60.0}, {"pct": 70.0},
                             {"pct": 80.0}],
            max_attempts=3)
        outcome = orch.run()
        check(len(outcome["attempts"]) == 3, "3 attempts expected")
        check(all(a["classification"] == "matching"
                  for a in outcome["attempts"]),
              "ascending improvements should all be matching")
        best = best_of(world)
        check(best["best_attempt"] == 3 and best["parent_attempt"] == 2,
              "best lineage wrong: %r" % best)
        check(best["target_match_percent"] == 80.0, "best pct wrong")
        check(best["base_commit"], "base_commit missing")
        # attempt 2 inherited attempt 1's applied candidate
        check("// attempt-one" in contents[1] and
              "// attempt-two" in contents[1],
              "attempt 2 worktree did not inherit attempt 1 state")
        check("// attempt-two" in contents[2] and
              "// attempt-one" in contents[2],
              "attempt 3 worktree did not inherit attempt 2 state")
        a2meta = json.load(open(os.path.join(
            world["attempts"], "80200010", "attempt-002",
            "metadata.json")))
        check(a2meta["parent_attempt"] == 1 and
              a2meta["target_match_before"] == 60.0 and
              a2meta["target_match_after"] == 70.0 and
              a2meta["accepted_as_best"] is True and
              a2meta["base_commit"],
              "attempt 2 lineage metadata wrong: %r" % a2meta)
        check(db.status_counts(conn).get("matching") == 1,
              "verified best should leave status matching")
        conn.close()

        # --- 3+4: worse and equal candidates never replace best ---
        world = make_world(os.path.join(tmp, "w2"))
        conn = world["conn"]
        orch, _, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"}, {"new_text": "// a2\n"},
                           {"new_text": "// a3\n"}],
            objdiff_results=[{"pct": 73.33}, {"pct": 60.0},
                             {"pct": 73.33}],
            max_attempts=3)
        outcome = orch.run()
        best = best_of(world)
        check(best["best_attempt"] == 1 and
              best["target_match_percent"] == 73.33,
              "worse/equal candidates must not replace best: %r" % best)
        check(outcome["attempts"][1]["accepted_as_best"] is False and
              outcome["attempts"][2]["accepted_as_best"] is False,
              "worse/equal must not be accepted")
        check(outcome["attempts"][1]["classification"] ==
              "objdiff_no_improvement" and
              outcome["attempts"][2]["classification"] ==
              "objdiff_no_improvement",
              "worse/equal should classify as no_improvement")
        check(outcome["attempts"][1]["target_match_before"] == 73.33,
              "attempt 2 should report the inherited best as before")
        conn.close()

        # --- 5: target improvement + global regression rejected ---
        world = make_world(os.path.join(tmp, "w3"))
        conn, repo = world["conn"], world["repo"]
        orch, contents, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2-bad\n"}],
            objdiff_results=[
                {"pct": 73.33},
                {"pct": 85.0, "regressions":
                    ["matched_code: 43664 -> 40000"]}],
            max_attempts=2)
        outcome = orch.run()
        best = best_of(world)
        check(best["best_attempt"] == 1 and
              best["target_match_percent"] == 73.33,
              "regressing candidate must not become best")
        check(outcome["attempts"][1]["classification"]
              == "objdiff_regression", "regression classification wrong")
        best_patch = open(os.path.join(world["attempts"], "80200010",
                                       "best.patch")).read()
        check("// a2-bad" not in best_patch,
              "rejected candidate state leaked into best.patch")
        m = json.load(open(os.path.join(world["attempts"], "80200010",
                                        "attempt-002", "metadata.json")))
        check(m["regression"] is True and m["accepted_as_best"] is False,
              "regression metadata wrong")
        conn.close()

        # --- 6 covered above; 7: compiler failure keeps best ---
        world = make_world(os.path.join(tmp, "w4"))
        conn = world["conn"]
        conn = world["conn"]
        orch, _, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2\n"}],
            objdiff_results=[{"pct": 73.33}],
            max_attempts=2)
        real_rb = orch_mod.build_mod.run_build

        def _ok_build(wt, build_cmd):
            return {"success": True, "classification": "ok",
                    "errors": [], "warnings": [], "objects": [],
                    "stdout": "", "stderr": "", "exit_code": 0,
                    "duration_seconds": 0.1,
                    "command": list(build_cmd), "timeout_seconds": 1,
                    "worktree": wt, "started": "-", "configure": None}

        flip2 = {"n": 0}

        def build_seq(wt, timeout=1, repo=None, build_cmd=("ninja",),
                      **kw):
            flip2["n"] += 1
            if flip2["n"] == 2:
                return {"success": False,
                        "classification": "compile_error",
                        "errors": ["error: x"], "warnings": [],
                        "objects": [], "stdout": "", "stderr": "",
                        "exit_code": 1, "duration_seconds": 0.1,
                        "command": list(build_cmd),
                        "timeout_seconds": timeout, "worktree": wt,
                        "started": "-", "configure": None}
            return _ok_build(wt, build_cmd)
        orch_mod.build_mod.run_build = build_seq
        try:
            outcome = orch.run()
        finally:
            orch_mod.build_mod.run_build = real_rb
        best = best_of(world)
        check(best["best_attempt"] == 1 and
              best["target_match_percent"] == 73.33,
              "compile failure must not replace best")
        check(outcome["attempts"][1]["classification"]
              == "compile_error", "compile classification wrong")
        conn.close()

        # --- 8: unavailable target objdiff never replaces best ---
        world = make_world(os.path.join(tmp, "w5"))
        conn = world["conn"]
        orch, _, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2\n"}],
            objdiff_results=[{"pct": 73.33}, {"pct": None}],
            max_attempts=2)
        outcome = orch.run()
        best = best_of(world)
        check(best["best_attempt"] == 1,
              "unavailable target data must not replace verified best")
        check(outcome["attempts"][1]["classification"]
              == "objdiff_no_improvement",
              "unavailable target data classification wrong")
        conn.close()

        # --- 8b: no data with no best -> still no best ---
        world = make_world(os.path.join(tmp, "w6"))
        conn = world["conn"]
        orch, _, _ = build_orch(
            world, client_script=[{"new_text": "// a1\n"}],
            objdiff_results=[{"pct": None}], max_attempts=1)
        outcome = orch.run()
        check(best_of(world) is None,
              "candidate without target data must not create a best")
        check(db.status_counts(conn).get("blocked") == 1,
              "no best -> blocked")
        conn.close()

        # --- 9: 100% terminates immediately ---
        world = make_world(os.path.join(tmp, "w7"))
        conn = world["conn"]
        orch, _, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2\n"}],
            objdiff_results=[{"pct": 73.33}, {"pct": 100.0}],
            max_attempts=5)
        outcome = orch.run()
        check(outcome["status"] == "ok" and
              len(outcome["attempts"]) == 2,
              "100%% should terminate at attempt 2 (got %s after %d)"
              % (outcome["status"], len(outcome["attempts"])))
        best = best_of(world)
        check(best["best_attempt"] == 2 and
              best["target_match_percent"] == 100.0,
              "100% candidate must become best")
        check(db.status_counts(conn).get("matched") == 1,
              "objdiff-verified 100% must set matched")
        conn.close()

        # --- 10+11: metadata survives across invocations ---
        world = make_world(os.path.join(tmp, "w8"))
        conn = world["conn"]
        orch, _, _ = build_orch(
            world, client_script=[{"new_text": "// a1\n"}],
            objdiff_results=[{"pct": 60.0}], max_attempts=1)
        orch.run()
        check(best_of(world)["best_attempt"] == 1, "best after run 1")
        # a NEW orchestrator instance continues from the persisted best
        orch2, contents2, _ = build_orch(
            world, client_script=[{"new_text": "// a2\n"}],
            objdiff_results=[{"pct": 75.0}], max_attempts=1)
        outcome = orch2.run()
        check(outcome["attempts"][0]["attempt_number"] == 2,
              "attempt numbering must continue across invocations")
        check(outcome["attempts"][0]["target_match_before"] == 60.0,
              "invocation 2 must inherit the persisted best")
        check("// a1" in (contents2[0] or ""),
              "invocation 2 must replay the persisted best patch")
        best = best_of(world)
        check(best["best_attempt"] == 2 and best["parent_attempt"] == 1,
              "cross-invocation lineage wrong: %r" % best)
        conn.close()

        # --- 12: failed attempts cannot corrupt the best patch ---
        world = make_world(os.path.join(tmp, "w9"))
        conn = world["conn"]
        orch, _, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2-worse\n"}],
            objdiff_results=[{"pct": 73.33}, {"pct": 50.0}],
            max_attempts=2)
        orch.run()
        patch_before = open(os.path.join(world["attempts"], "80200010",
                                         "best.patch")).read()
        check("// a1" in patch_before and
              "// a2-worse" not in patch_before,
              "best.patch must contain only the best candidate")
        conn.close()

        # --- 13: primary tree untouched ---
        status = subprocess.run(
            ["git", "-C", world["repo"], "status", "--porcelain",
             "--untracked-files=no"],
            capture_output=True, text=True).stdout
        check(status.strip() == "", "primary tree modified: %r" % status)
        check("// a1" not in open(world["unit_src"]).read(),
              "AI source leaked into the primary checkout")
    finally:
        orch_mod.PRIMARY_BASELINE = real[0]
        orch_mod.context_mod.build_context = GENUINE_BUILD_CONTEXT
        orch_mod.objdiff_mod.evaluate = GENUINE_EVALUATE
        orch_mod.build_mod.run_build = GENUINE_RUN_BUILD


def test_real_dry_run():
    print("== real 801b16b0 dry-run ==")
    if not os.path.exists(db.DB_PATH):
        print("  SKIP: real database missing")
        return
    env = dict(os.environ)
    env.pop("LLM_API_KEY", None)
    # isolated attempts root so the dry-run can never clobber the real
    # attempt records (the same attempt number would be reused)
    import tempfile as _tf
    isolated_root = _tf.mkdtemp(prefix="phase5_dryrun_")
    rc = subprocess.run(
        [sys.executable, os.path.join(HERE, "orchestrator.py"),
         "--address", "801b16b0", "--max-attempts", "2", "--dry-run",
         "--dry-run-build", "--allow-dirty",
         "--attempts-root", isolated_root],
        capture_output=True, text=True, env=env, timeout=1800)
    shutil.rmtree(isolated_root, ignore_errors=True)
    check(rc.returncode == 0, "dry-run failed: %s" % rc.stderr[-400:])
    check('"dry_run"' in rc.stdout or '"objdiff_no_improvement"'
          in rc.stdout, "unexpected dry-run status")


# ----------------------------------------------------------------
# mismatch evidence (5.2)
# ----------------------------------------------------------------

def make_elf(path, symbols):
    """Minimal ELF32 big-endian relocatable object: .text + .symtab +
    .strtab + .shstrtab, with one FUNC symbol per entry."""
    import struct

    names = list(symbols.keys())
    strtab = b"\0"
    name_off = {}
    for name in names:
        name_off[name] = len(strtab)
        strtab += name.encode() + b"\0"

    text = bytearray()
    entries = [struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0)]
    for name in names:
        code = symbols[name]
        pad = (4 - len(text) % 4) % 4
        text += b"\0" * pad
        entries.append(struct.pack(">IIIBBH", name_off[name],
                                   len(text), len(code), 0x12, 0, 1))
        text += code
    sym_entries = b"".join(entries)

    shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    n = lambda s: shstrtab.index(s.encode() + b"\0")

    e_ehsize = 52
    text_off = e_ehsize
    symtab_off = text_off + len(text)
    strtab_off = symtab_off + len(sym_entries)
    shstr_off = strtab_off + len(strtab)
    sh_off = (shstr_off + len(shstrtab) + 3) & ~3

    out = bytearray()
    out += b"\x7fELF" + bytes([1, 2, 1, 0, 0]) + b"\0" * 7
    out += struct.pack(">HHIIIIIHHHHHH",
                       1,        # e_type: REL
                       17,       # e_machine: PPC
                       1,        # e_version
                       0,        # e_entry
                       0,        # e_phoff
                       sh_off,   # e_shoff
                       0,        # e_flags
                       e_ehsize, 0, 0, 40, 4, 3)
    out += text
    out += b"\0" * (symtab_off - len(out))
    out += sym_entries
    out += strtab
    out += shstrtab
    out += b"\0" * (sh_off - len(out))

    def shdr(name, typ, off, size, link, entsize):
        return struct.pack(">10I", n(name), typ, 0, 0, off, size,
                           link, 0, 4, entsize)

    # standard null section header first, so symbol st_shndx indexes
    # line up with the ELF convention (real objects have one too)
    out += b"\0" * 40
    out += shdr(".text", 1, text_off, len(text), 0, 0)
    out += shdr(".symtab", 2, symtab_off, len(sym_entries), 3, 16)
    out += shdr(".strtab", 3, strtab_off, len(strtab), 0, 0)
    out += shdr(".shstrtab", 3, shstr_off, len(shstrtab), 0, 0)
    struct.pack_into(">I", out, 0x20, sh_off)
    struct.pack_into(">H", out, 0x30, 5)
    open(path, "wb").write(bytes(out))


def test_mismatch_extraction(tmp):
    print("== mismatch extraction ==")
    target_o = os.path.join(tmp, "target.o")
    base_o = os.path.join(tmp, "base.o")
    expected = bytes.fromhex(
        "3c808d7738c0000038840000") + b"\x00" * 4  # 3 words + pad word
    actual = bytes.fromhex(
        "3c6000003884000038c00000") + b"\x00" * 4
    make_elf(target_o, {"Fn__Fv": expected})
    make_elf(base_o, {"Fn__Fv": actual})

    res = mismatch_mod.collect_mismatch(
        tmp, "Fn__Fv", address="80000000",
        target_path=target_o, base_path=base_o,
        instruction_lines=["80000000: lis r7,-0x7f73",
                           "80000004: addi r7,r7,0",
                           "80000008: addi r4,0,0",
                           "8000000c: blr"])
    check(res["available"] is True, "mismatch should be available")
    check(res["expected_size"] == 16 and res["actual_size"] == 16,
          "sizes wrong")
    check(res["differing_words"] == 3,
          "expected 3 differing words, got %s" % res["differing_words"])
    d0 = res["differences"][0]
    check(d0["expected"] == "3c808d77" and d0["actual"] == "3c600000"
          and d0["kind"] == "instruction"
          and d0.get("expected_mnemonic") == "lis r7,-0x7f73",
          "difference record wrong: %r" % d0)
    md = mismatch_mod.render_mismatch_markdown(res)
    check("3c808d77" in md and len(md) < 6200, "markdown render wrong")

    # bounded output
    many = mismatch_mod.collect_mismatch(
        tmp, "Fn__Fv", target_path=target_o, base_path=base_o,
        max_differences=2)
    check(len(many["differences"]) == 2 and many["truncated"] is True,
          "bounding wrong: %r" % many["differences"])

    # unavailable: symbol missing from base object
    res = mismatch_mod.collect_mismatch(
        tmp, "Missing__Fv", target_path=target_o, base_path=base_o)
    check(res["available"] is False and res["reason"],
          "missing symbol should be unavailable with reason")

    # malformed inputs do not crash
    res = mismatch_mod.collect_mismatch(
        tmp, "Fn__Fv", target_path=os.path.join(tmp, "nope.o"),
        base_path=base_o)
    check(res["available"] is False, "missing file should be unavailable")


def test_mismatch_plumbing(tmp):
    print("== mismatch plumbing into prompts ==")
    real = (orch_mod.PRIMARY_BASELINE, orch_mod.context_mod.build_context,
            orch_mod.objdiff_mod.evaluate, orch_mod.build_mod.run_build,
            orch_mod.mismatch_mod.collect_mismatch)
    try:
        world = make_world(os.path.join(tmp, "m1"))
        conn, repo, attempts = world["conn"], world["repo"], \
            world["attempts"]

        fake_mismatch = {
            "target": "80200010", "symbol": "TargetFn",
            "available": True, "match_percent": 73.333336,
            "expected_size": 48, "actual_size": 44,
            "size_matches": False, "differing_words": 2,
            "differences": [
                {"offset": 0, "kind": "instruction",
                 "expected": "3c808d77", "actual": "3c600000",
                 "expected_mnemonic": "lis r7,-0x7f73"},
                {"offset": 44, "kind": "function_size",
                 "expected": "48 bytes", "actual": "44 bytes"},
            ],
            "truncated": False,
        }

        def scripted_mismatch(worktree, symbol, address=None, **kw):
            return dict(fake_mismatch)

        orch, contents, _ = build_orch(
            world,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2\n"}],
            objdiff_results=[{"pct": 73.333336}, {"pct": 73.333336}],
            max_attempts=2)
        orch_mod.mismatch_mod.collect_mismatch = scripted_mismatch
        try:
            outcome = orch.run()
        finally:
            orch_mod.mismatch_mod.collect_mismatch = real[4]

        # mismatch.json artifact recorded for the accepted best attempt
        mpath = os.path.join(attempts, "80200010", "attempt-001",
                             "mismatch.json")
        check(os.path.exists(mpath), "mismatch.json artifact missing")
        saved = json.load(open(mpath))
        check(saved["available"] is True and
              saved["differences"][0]["expected"] == "3c808d77",
              "mismatch artifact wrong")

        # next prompt contains: best score, patch (previous source),
        # mismatch evidence, improve-not-restart instruction
        prompt2 = open(os.path.join(attempts, "80200010",
                                    "attempt-002",
                                    "prompt.txt")).read()
        check("73.333336" in prompt2, "best score missing from prompt")
        check("// a1" in prompt2, "previous source/patch missing")
        check("3c808d77" in prompt2 and "Objective mismatch evidence"
              in prompt2, "mismatch evidence missing from prompt")
        check("Improve it" in prompt2 and
              "rather than starting over" in prompt2,
              "improve-not-restart instruction missing")
        # bounded: prompt stays well under the cap despite evidence
        check(len(prompt2) < 40000, "prompt not bounded")

        # equal percent -> attempt 2 not accepted as best
        check(outcome["attempts"][1]["accepted_as_best"] is False,
              "equal candidate must not replace best")
        best = best_of(world)
        check(best["best_attempt"] == 1, "best changed unexpectedly")

        # compiler errors reach the NEXT attempt's prompt
        world2 = make_world(os.path.join(tmp, "m2"))
        conn2 = world2["conn"]
        real_rb = orch_mod.build_mod.run_build
        flips = {"n": 0}

        def build_seq(wt, timeout=1, repo=None, build_cmd=("ninja",),
                      **kw):
            flips["n"] += 1
            if flips["n"] == 2:  # attempt 2 fails to compile
                return {"success": False,
                        "classification": "compile_error",
                        "errors": ["error: SYNTAX_ERROR_XYZ at "
                                   "foo.cpp:1"],
                        "warnings": ["warning: something"],
                        "objects": [], "stdout": "", "stderr": "",
                        "exit_code": 1, "duration_seconds": 0.1,
                        "command": list(build_cmd),
                        "timeout_seconds": timeout, "worktree": wt,
                        "started": "-", "configure": None}
            return {"success": True, "classification": "ok",
                    "errors": [], "warnings": [], "objects": [],
                    "stdout": "", "stderr": "", "exit_code": 0,
                    "duration_seconds": 0.1,
                    "command": list(build_cmd),
                    "timeout_seconds": timeout, "worktree": wt,
                    "started": "-", "configure": None}
        orch, _, _ = build_orch(
            world2,
            client_script=[{"new_text": "// a1\n"},
                           {"new_text": "// a2\n"},
                           {"new_text": "// a3\n"}],
            objdiff_results=[{"pct": 73.333336},
                             {"pct": 73.333336},
                             {"pct": 73.333336}],
            max_attempts=3)
        orch_mod.build_mod.run_build = build_seq
        try:
            outcome = orch.run()
        finally:
            orch_mod.build_mod.run_build = real_rb
        check(outcome["attempts"][1]["classification"]
              == "compile_error", "compile classification wrong")
        # attempt 3's prompt (written before its build) must carry the
        # compiler error, the warnings, the best score and the best
        # candidate source
        prompt3 = open(os.path.join(world2["attempts"], "80200010",
                                    "attempt-003",
                                    "prompt.txt")).read()
        check("SYNTAX_ERROR_XYZ" in prompt3,
              "compiler error missing from retry prompt")
        check("warning: something" in prompt3,
              "compiler warning missing from retry prompt")
        check("73.333336" in prompt3,
              "best score missing from compile-error retry prompt")
        check("// a1" in prompt3,
              "previous source missing from compile-error retry prompt")
        check(conn.execute(
            "SELECT status FROM functions WHERE address='80200010'"
        ).fetchone()[0] == "matching",
            "verified best should keep status matching")
        conn.close()
        conn.close()
    finally:
        orch_mod.PRIMARY_BASELINE = real[0]
        orch_mod.context_mod.build_context = GENUINE_BUILD_CONTEXT
        orch_mod.objdiff_mod.evaluate = GENUINE_EVALUATE
        orch_mod.build_mod.run_build = GENUINE_RUN_BUILD
        orch_mod.mismatch_mod.collect_mismatch = real[4]


def test_no_game_data_in_prompts(tmp):
    print("== no raw game data in context ==")
    world = make_world(os.path.join(tmp, "m3"))
    conn = world["conn"]
    orch, _, _ = build_orch(
        world, client_script=[{"new_text": "// a1\n"}],
        objdiff_results=[{"pct": 73.333336}], max_attempts=1)
    outcome = orch.run()
    prompt = open(os.path.join(world["attempts"], "80200010",
                               "attempt-001", "prompt.txt")).read()
    for marker in ("main.dol", "game.rvz", "orig/", "SC4P64/sys"):
        check(marker not in prompt,
              "raw game reference %r leaked into prompt" % marker)
    check(conn.execute(
        "SELECT status FROM functions WHERE address='80200010'"
    ).fetchone()[0] == "matching", "status should be matching")
    conn.close()


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_phase5_test_")
    try:
        test_mismatch_extraction(tmp)
        test_retry_continuity(tmp)
        test_mismatch_plumbing(tmp)
        test_no_game_data_in_prompts(tmp)
        test_real_dry_run()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all phase 5.1 tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
