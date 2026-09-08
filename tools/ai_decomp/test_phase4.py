#!/usr/bin/env python3
"""Tests for Phase 4: editor (#21), worktrees (#22), build (#23),
objdiff (#24) and the match/retry loop (#25).

External systems (LLM, compiler, objdiff) are faked; nothing here
touches the network or the real build. The worktree tests run against a
tiny synthetic git repository. A real-repo worktree test is skipped
unless the primary tree is clean.

Run:  python3 tools/ai_decomp/test_phase4.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build as build_mod  # noqa: E402
import database as db  # noqa: E402
import editor as editor_mod  # noqa: E402
import objdiff as objdiff_mod  # noqa: E402
import orchestrator as orch_mod  # noqa: E402
from worktree import WorktreeError, WorktreeManager  # noqa: E402

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("  FAIL: " + msg)


def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# ----------------------------------------------------------------
# editor (#21)
# ----------------------------------------------------------------

def test_editor(tmp):
    print("== editor ==")
    repo = os.path.join(tmp, "repo")
    write(os.path.join(repo, "src", "foo.cpp"), "int main() { return 0; }\n")
    write(os.path.join(repo, "include", "foo.h"), "#pragma once\n")

    good = {"path": "src/foo.cpp", "operation": "replace",
            "old_text": "return 0;", "new_text": "return 42;"}

    # dry-run: validation + patch, no modification
    result = editor_mod.apply_changes([good], repo_root=repo,
                                      dry_run=True)
    check("return 42;" in result["patch"], "dry-run patch missing")
    with open(os.path.join(repo, "src", "foo.cpp")) as f:
        check("return 0;" in f.read(), "dry-run modified the file")

    # real apply + rollback
    result = editor_mod.apply_changes([good], repo_root=repo)
    with open(os.path.join(repo, "src", "foo.cpp")) as f:
        check("return 42;" in f.read(), "apply did not modify the file")
    restored = editor_mod.rollback(result["originals"], repo_root=repo)
    with open(os.path.join(repo, "src", "foo.cpp")) as f:
        check("return 0;" in f.read(), "rollback failed")

    # refusals: every one of these must raise without touching files
    refusals = [
        ({"path": "/etc/passwd", "operation": "create", "new_text": "x"},
         "absolute"),
        ({"path": "src/../../evil.h", "operation": "create",
          "new_text": "x"}, "traversal"),
        ({"path": "orig/SC4P64/sys/main.dol", "operation": "create",
          "new_text": "x"}, "protected"),
        ({"path": "build/SC4P64/x.o", "operation": "create",
          "new_text": "x"}, "protected"),
        ({"path": ".git/config", "operation": "replace",
          "old_text": "a", "new_text": "b"}, "protected"),
        ({"path": "tools/ghidra/output/functions.json",
          "operation": "replace", "old_text": "a", "new_text": "b"},
         "protected"),
        ({"path": "src/other.cpp", "operation": "replace",
          "old_text": "nope", "new_text": "x"}, "missing old_text"),
        ({"path": "src/foo.cpp", "operation": "frobnicate",
          "new_text": "x"}, "bad operation"),
        ({"path": "src/foo.cpp", "operation": "create", "new_text": "x"},
         "create over existing"),
        ({"path": "src/missing.cpp", "operation": "append",
          "new_text": "x"}, "append to missing"),
        ("not-an-object", "non-object change"),
    ]
    before = open(os.path.join(repo, "src", "foo.cpp")).read()
    for change, why in refusals:
        try:
            editor_mod.apply_changes([change] if isinstance(change, dict)
                                     else [change], repo_root=repo)
            check(False, "should refuse (%s)" % why)
        except editor_mod.EditError:
            pass
    after = open(os.path.join(repo, "src", "foo.cpp")).read()
    check(before == after, "refused attempts modified the file")

    # ambiguity: old_text matching twice
    write(os.path.join(repo, "src", "dup.cpp"), "x = 1;\nx = 1;\n")
    try:
        editor_mod.apply_changes(
            [{"path": "src/dup.cpp", "operation": "replace",
              "old_text": "x = 1;", "new_text": "y = 2;"}],
            repo_root=repo)
        check(False, "ambiguous patch should be refused")
    except editor_mod.EditError as exc:
        check("ambiguous" in str(exc), "ambiguity not named in refusal")

    # create + append + restrict_to
    editor_mod.apply_changes(
        [{"path": "src/new.cpp", "operation": "create",
          "new_text": "int a;\n"}], repo_root=repo)
    check(os.path.exists(os.path.join(repo, "src", "new.cpp")),
          "create failed")
    editor_mod.apply_changes(
        [{"path": "src/new.cpp", "operation": "append",
          "new_text": "int b;\n"}], repo_root=repo)
    with open(os.path.join(repo, "src", "new.cpp")) as f:
        check(f.read() == "int a;\nint b;\n", "append failed")

    try:
        editor_mod.restrict_to(
            [{"path": "src/unrelated.cpp", "operation": "create",
              "new_text": "x"}], ["src/new.cpp"])
        check(False, "restrict_to should refuse unrelated files")
    except editor_mod.EditError:
        pass

    # unified diff path validation
    bad_diff = "--- a/orig/x\n+++ b/orig/x\n@@ -1 +1 @@\n-a\n+b\n"
    try:
        editor_mod.apply_unified_diff(bad_diff, repo_root=repo,
                                      dry_run=True)
        check(False, "diff into orig/ should be refused")
    except editor_mod.EditError:
        pass


# ----------------------------------------------------------------
# worktrees (#22)
# ----------------------------------------------------------------

def make_git_repo(path, extra_files=None):
    os.makedirs(path)
    write(os.path.join(path, "README"), "init\n")
    for rel, content in (extra_files or {}).items():
        write(os.path.join(path, rel), content)
    def git(*args):
        subprocess.run(["git", "-C", path, *args], check=True,
                       capture_output=True, text=True)
    git("init", "-b", "ai-decomp")
    git("config", "user.email", "t@t")
    git("config", "user.name", "t")
    git("add", "-A")
    git("commit", "-m", "init")
    return path


def test_worktrees(tmp):
    print("== worktrees ==")
    repo = make_git_repo(os.path.join(tmp, "wtrepo"))
    mgr = WorktreeManager(repo=repo,
                          worktrees_dir=os.path.join(repo, ".worktrees"))

    info = mgr.create_worktree("801b16b0", attempt=1)
    check(os.path.isdir(info["path"]), "worktree dir missing")
    check(info["branch"] == "ai-attempt/801b16b0-attempt-001",
          "branch name wrong")
    check(os.path.exists(os.path.join(info["path"], "README")),
          "worktree is not a checkout")

    # duplicate creation refused
    try:
        mgr.create_worktree("801b16b0", attempt=1)
        check(False, "duplicate worktree should be refused")
    except WorktreeError:
        pass

    # dirty primary tree refuses creation unless overridden
    write(os.path.join(repo, "dirty.txt"), "uncommitted\n")
    try:
        mgr.create_worktree("801b16b0", attempt=2)
        check(False, "dirty tree should refuse")
    except WorktreeError as exc:
        check("dirty" in str(exc).lower(), "dirty refusal not explained")
    info2 = mgr.create_worktree("801b16b0", attempt=2, allow_dirty=True)
    check(os.path.isdir(info2["path"]), "allow_dirty create failed")

    # removal + branch deletion; user branches are never touched
    removed = mgr.remove_worktree("801b16b0", attempt=2, force=True)
    check(removed["branch_deleted"], "attempt branch should be deleted")
    branches = subprocess.run(
        ["git", "-C", repo, "branch", "--list",
         "ai-attempt/*"], capture_output=True, text=True).stdout
    check("attempt-002" not in branches, "attempt-002 branch survived")
    check(os.path.exists(os.path.join(repo, "dirty.txt")),
          "primary tree files must survive")

    # the never-delete-user-branches rule: a user branch with the same
    # base name cannot exist under the ai-attempt/ prefix, so create a
    # user branch and make sure removal of attempts leaves it alone
    subprocess.run(["git", "-C", repo, "branch", "user-feature"],
                   check=True, capture_output=True)
    mgr.remove_worktree("801b16b0", attempt=1, force=True)
    branches = subprocess.run(
        ["git", "-C", repo, "branch", "--list"],
        capture_output=True, text=True).stdout
    check("user-feature" in branches, "user branch was deleted")

    # remove nonexistent is an explicit error
    try:
        mgr.remove_worktree("801b16b0", attempt=9)
        check(False, "removing nonexistent worktree should fail")
    except WorktreeError:
        pass


# ----------------------------------------------------------------
# build (#23)
# ----------------------------------------------------------------

def test_build(tmp):
    print("== build orchestrator ==")
    worktree = os.path.join(tmp, "buildtree")
    os.makedirs(worktree)
    write(os.path.join(worktree, "build.ninja"), "# fake\n")

    # success with warnings (warnings are not failures)
    ok_script = os.path.join(tmp, "fake_ninja_ok")
    write(ok_script, "#!/usr/bin/env python3\n"
                     "import sys\n"
                     "print('build/SC4P64/src/foo.o: warning: unused')\n"
                     "print('[1/1] CC src/foo.cpp')\n")
    os.chmod(ok_script, 0o755)
    record = build_mod.run_build(worktree, timeout=30,
                                 build_cmd=[sys.executable, ok_script])
    check(record["success"], "fake build should succeed")
    check(record["classification"] == "ok", "classification wrong")
    check(len(record["warnings"]) == 1, "warning not captured")
    check(record["objects"], "object mentions not captured")

    # failure classification
    fail_script = os.path.join(tmp, "fake_ninja_fail")
    write(fail_script, "#!/usr/bin/env python3\n"
                       "import sys\n"
                       "print('FAILED: src/foo.cpp error: bad syntax')\n"
                       "sys.exit(1)\n")
    os.chmod(fail_script, 0o755)
    record = build_mod.run_build(worktree, timeout=30,
                                 build_cmd=[sys.executable, fail_script])
    check(not record["success"], "failing build should not succeed")
    check(record["classification"] == "compile_error",
          "should classify as compile_error")

    # timeout classification
    slow_script = os.path.join(tmp, "fake_ninja_slow")
    write(slow_script, "#!/usr/bin/env python3\n"
                       "import time\n"
                       "time.sleep(10)\n")
    os.chmod(slow_script, 0o755)
    record = build_mod.run_build(worktree, timeout=1,
                                 build_cmd=[sys.executable, slow_script])
    check(record["classification"] == "timeout", "timeout not detected")
    check(not record["success"], "timeout must not succeed")


# ----------------------------------------------------------------
# objdiff (#24)
# ----------------------------------------------------------------

def test_objdiff(tmp):
    print("== objdiff parsing ==")
    baseline = {
        "from": {"matched_code": 100, "matched_functions": 4,
                 "complete_code": 50, "complete_units": 2},
        "to": {"matched_code": 100, "matched_functions": 4,
               "complete_code": 50, "complete_units": 2},
    }
    regressions = objdiff_mod.detect_regressions({
        "from": {"matched_code": 120, "matched_functions": 6,
                 "complete_code": 60, "complete_units": 3},
        "to": {"matched_code": 100, "matched_functions": 5,
               "complete_code": 59, "complete_units": 2},
    })
    check(len(regressions) == 4, "regression detection incomplete: %r"
          % regressions)
    check(objdiff_mod.detect_regressions(baseline) == [],
          "no-change must not be a regression")

    # per-function parsing + limitation reporting
    report = {"units": [{
        "name": "main/nufile.master/nufile_Lump",
        "functions": [
            {"name": "Other__Fv", "size": "32",
             "fuzzy_match_percent": 100.0},
            {"name": "Partial__Fv", "size": "48",
             "fuzzy_match_percent": 45.5},
            {"name": "NoData__Fv", "size": "16",
             "fuzzy_match_percent": None},
        ]}]}
    unit, entry = objdiff_mod.find_function_entry(report, "Partial__Fv")
    check(unit == "main/nufile.master/nufile_Lump" and entry,
          "function lookup failed")
    check(entry["fuzzy_match_percent"] == 45.5, "percent wrong")
    check(entry["fuzzy_match_percent"] != 100.0,
          "partial must not read as fully matched")
    unit, entry = objdiff_mod.find_function_entry(report, "Missing__Fv")
    check(entry is None, "missing function should return None")


# ----------------------------------------------------------------
# the loop (#25) with fakes
# ----------------------------------------------------------------

BASELINE_FIXTURE = {
    "units": [{
        "name": "main/fake.master/fake_unit",
        "functions": [
            {"name": "TargetFn", "size": "64",
             "fuzzy_match_percent": None},
        ]}],
    "categories": [],
}


class FakeClient:
    def __init__(self, behavior):
        self.behavior = behavior  # "ok" | "llm_error" | "malformed"
        self.calls = 0

    def generate(self, prompt):
        self.calls += 1
        class R:
            pass
        r = R()
        r.prompt = prompt
        if self.behavior == "llm_error":
            r.ok = False
            r.error = "HTTP 500: boom"
            return r
        r.ok = True
        r.error = None
        if self.behavior == "malformed":
            r.response = "I think the function adds numbers. Nice!"
        else:
            r.response = json.dumps({
                "analysis": "fake",
                "source_changes": [{
                    "path": "src/fake.master/fake_unit.cpp",
                    "operation": "append",
                    "new_text": "// attempt\n"}],
                "confidence": 0.5,
            })
        return r


def make_loop_world(tmp_sub):
    """Synthetic git repo + DB + exports + baseline fixture."""
    repo = make_git_repo(os.path.join(tmp_sub, "looprepo"), extra_files={
        "src/fake.master/fake_unit.cpp": "// unit source\n"})

    db_path = os.path.join(tmp_sub, "loop.db")
    conn = db.connect(db_path)
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
    unit_src = os.path.join(repo, "src", "fake.master", "fake_unit.cpp")

    baseline_path = os.path.join(tmp_sub, "baseline.json")
    write(baseline_path, json.dumps(BASELINE_FIXTURE))

    src_root = os.path.join(repo, "src")
    include_root = os.path.join(repo, "include")
    attempts = os.path.join(tmp_sub, "attempts")
    return conn, repo, output_dir, baseline_path, attempts, src_root, \
        include_root


def build_orchestrator(conn, repo, output_dir, baseline_path, attempts,
                       src_root, include_root, client_behavior="ok",
                       objdiff_behavior=None, max_attempts=3,
                       dry_run=False):
    """Wire an Orchestrator to synthetic infrastructure + fakes."""
    wt = WorktreeManager(repo=repo,
                         worktrees_dir=os.path.join(repo, ".worktrees"))
    orch = orch_mod.Orchestrator(
        "80200010", conn, max_attempts=max_attempts, dry_run=dry_run,
        llm_client=FakeClient(client_behavior),
        attempts_root=attempts, worktree_manager=wt,
        log=lambda *a, **k: None)

    # inject the synthetic world
    orch_mod.PRIMARY_BASELINE = baseline_path

    real_build_context = orch_mod.context_mod.build_context

    def fake_build_context(address, conn=None, **kwargs):
        ctx = real_build_context(address, conn=conn, run_m2c=False,
                                 output_dir=output_dir,
                                 src_root=src_root,
                                 include_dir=include_root)
        # unit source discovery (synthetic names are unknown to the
        # real objdiff config)
        ctx["source"]["path"] = os.path.join(src_root, "fake.master",
                                             "fake_unit.cpp")
        return ctx

    orch_mod.context_mod.build_context = fake_build_context

    def fake_evaluate(worktree, target_symbol=None, baseline_report=None,
                      target_address=None, **kwargs):
        behavior = objdiff_behavior
        if callable(behavior):
            behavior = behavior(fake_evaluate.calls)
        fake_evaluate.calls += 1
        behavior = behavior or {}
        return {
            "report": "fake",
            "target": {"symbol": target_symbol,
                       "address": target_address,
                       "data_available": True,
                       "fully_matched": behavior.get("full", False),
                       "match_percent": behavior.get("pct", 50.0)},
            "overall": None,
            "regressions": behavior.get("regressions", []),
            "limitations": [],
        }

    fake_evaluate.calls = 0
    orch_mod.objdiff_mod.evaluate = fake_evaluate
    return orch


def test_loop(tmp):
    print("== match/retry loop ==")
    real_baseline = orch_mod.PRIMARY_BASELINE
    real_bc = orch_mod.context_mod.build_context
    real_eval = orch_mod.objdiff_mod.evaluate
    real_run_build = orch_mod.build_mod.run_build

    def fake_build_ok(wt, timeout=1, repo=None, build_cmd=("ninja",),
                      **kw):
        return {"success": True, "classification": "ok", "errors": [],
                "warnings": [], "objects": ["build/SC4P64/src/x.o"],
                "stdout": "", "stderr": "", "exit_code": 0,
                "duration_seconds": 0.1, "command": list(build_cmd),
                "timeout_seconds": timeout, "worktree": wt,
                "started": "-", "configure": None}

    orch_mod.build_mod.run_build = fake_build_ok
    try:
        # --- scenario 1: successful match terminates, db=matched ---
        world = make_loop_world(os.path.join(tmp, "w1"))
        conn, repo = world[0], world[1]
        orch = build_orchestrator(
            *world, objdiff_behavior={"pct": 100.0, "full": True},
            max_attempts=3)
        outcome = orch.run()
        check(outcome["status"] == "ok", "full match should end the "
              "loop, got %r" % outcome["status"])
        check(len(outcome["attempts"]) == 1,
              "loop must stop at the first 100% match")
        check(db.status_counts(conn).get("matched") == 1,
              "matched status must be set on objective 100%")
        kept = WorktreeManager(
            repo=repo,
            worktrees_dir=os.path.join(repo, ".worktrees")).list()
        check(len(kept) == 1, "matched attempt keeps its worktree")
        a1 = orch.attempt_dir(1)
        for artifact in ("context.json", "prompt.txt", "response.json",
                         "patch.diff", "build.log", "objdiff.json",
                         "result.json"):
            check(os.path.exists(os.path.join(a1, artifact)),
                  "attempt artifact missing: %s" % artifact)
        conn.close()

        # --- scenario 2: improvement without 100%, max attempts ---
        world = make_loop_world(os.path.join(tmp, "w2"))
        conn, repo = world[0], world[1]
        orch = build_orchestrator(
            *world, objdiff_behavior={"pct": 50.0, "full": False},
            max_attempts=2)
        outcome = orch.run()
        check(len(outcome["attempts"]) == 2,
              "max_attempts not enforced")
        check(all(a["classification"] == "matching"
                  for a in outcome["attempts"]),
              "improvement attempts should classify as matching")
        check(db.status_counts(conn).get("matching") == 1,
              "improvement should set matching status")
        left = WorktreeManager(
            repo=repo,
            worktrees_dir=os.path.join(repo, ".worktrees")).list()
        check(not left, "non-final attempt worktrees should be cleaned "
              "up: %r" % left)
        conn.close()

        # --- scenario 3: global regression is rejected ---
        world = make_loop_world(os.path.join(tmp, "w3"))
        conn, repo = world[0], world[1]
        orch = build_orchestrator(
            *world, objdiff_behavior={
                "pct": 100.0, "full": True,
                "regressions": ["matched_code: 43664 -> 40000"]},
            max_attempts=1)
        outcome = orch.run()
        check(outcome["attempts"][0]["classification"]
              == "objdiff_regression",
              "regression must be classified as such")
        check(db.status_counts(conn).get("matched") is None,
              "regression must never set matched")
        left = WorktreeManager(
            repo=repo,
            worktrees_dir=os.path.join(repo, ".worktrees")).list()
        check(not left, "rejected attempt worktree should be removed: %r"
              % left)
        check(os.path.exists(os.path.join(
            repo, ".worktrees") ) is False or not os.listdir(
            os.path.join(repo, ".worktrees", "80200010")) if os.path.isdir(
            os.path.join(repo, ".worktrees", "80200010")) else True,
            "worktree dir leftovers")
        conn.close()

        # --- scenario 4: compile error classification ---
        world = make_loop_world(os.path.join(tmp, "w4"))
        conn = world[0]
        orch_mod.build_mod.run_build = (
            lambda wt, timeout=1, repo=None, build_cmd=("ninja",), **kw: {
                "success": False, "classification": "compile_error",
                "errors": ["error: expected ';'"], "warnings": [],
                "objects": [], "stdout": "", "stderr": "",
                "exit_code": 1, "duration_seconds": 0.1,
                "command": list(build_cmd), "timeout_seconds": timeout,
                "worktree": wt, "started": "-", "configure": None})
        orch = build_orchestrator(*world, max_attempts=1)
        outcome = orch.run()
        check(outcome["attempts"][0]["classification"]
              == "compile_error", "compile error not classified")
        check(os.path.exists(os.path.join(orch.attempt_dir(1),
                                          "build.log")),
              "build log missing")
        conn.close()

        # --- scenario 5: llm error, malformed response, dry-run ---
        world = make_loop_world(os.path.join(tmp, "w5"))
        conn = world[0]
        orch = build_orchestrator(*world, client_behavior="llm_error",
                                  max_attempts=1)
        outcome = orch.run()
        check(outcome["attempts"][0]["classification"] == "llm_error",
              "llm error not classified")

        orch = build_orchestrator(*world, client_behavior="malformed",
                                  max_attempts=1)
        outcome = orch.run()
        check(outcome["attempts"][0]["classification"]
              == "malformed_response", "malformed response not classified")

        unit_src = os.path.join(world[1], "src", "fake.master",
                                "fake_unit.cpp")
        unit_before = open(unit_src).read()
        orch = build_orchestrator(*world, max_attempts=1, dry_run=True)
        outcome = orch.run()
        check(outcome["attempts"][0]["classification"] == "dry_run",
              "dry-run classification wrong")
        check(open(unit_src).read() == unit_before,
              "dry-run modified source outside the worktree")
        conn.close()
    finally:
        orch_mod.PRIMARY_BASELINE = real_baseline
        orch_mod.context_mod.build_context = real_bc
        orch_mod.objdiff_mod.evaluate = real_eval
        orch_mod.build_mod.run_build = real_run_build


def test_real_orchestrator_dry_run():
    print("== real orchestrator dry-run (801b16b0) ==")
    if not os.path.exists(db.DB_PATH):
        print("  SKIP: real database missing")
        return
    env = dict(os.environ)
    env.pop("LLM_API_KEY", None)
    rc = subprocess.run(
        [sys.executable, os.path.join(HERE, "orchestrator.py"),
         "--address", "801b16b0", "--max-attempts", "1", "--dry-run",
         "--allow-dirty", "--skip-build"],
        capture_output=True, text=True, env=env)
    check(rc.returncode == 0, "dry-run orchestrator failed: %s"
          % rc.stderr[-500:])
    check('"dry_run"' in rc.stdout, "dry-run status missing from output")


def main():
    tmp = tempfile.mkdtemp(prefix="decomp_phase4_test_")
    try:
        test_editor(tmp)
        test_worktrees(tmp)
        test_build(tmp)
        test_objdiff(tmp)
        test_loop(tmp)
        test_real_orchestrator_dry_run()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if failures:
        print("\nFAILED: %d check(s)" % len(failures))
        return 1
    print("\nPASS: all phase 4 tests")
    return 0


if __name__ == "__main__":
    sys.exit(main())
