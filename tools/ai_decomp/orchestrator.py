#!/usr/bin/env python3
"""Single-function, single-worker autonomous decompilation loop
(roadmap item #25).

    python3 tools/ai_decomp/orchestrator.py --address 801b16b0 \
        --max-attempts 5

Flow per attempt:

    context -> prompt -> LLM -> structured edits -> isolated worktree
      -> editor -> ninja -> objdiff -> classify -> retry or finish

Every attempt is recorded under attempts/<address>/attempt-NNN/ with
context.json, prompt.txt, response.json, patch.diff, build.log,
objdiff.json and result.json.

Objective verdicts only:

  - a function is "matched" when and only when objdiff reports 100.0
    for its symbol; LLM claims never set database status
  - an attempt is rejected when the objdiff `report changes` comparison
    against the pre-run baseline shows ANY global regression
    (matched_code / matched_functions / complete_code / complete_units)

Classifications:

  ok                    target fully matched (loop stops)
  matching              improved but not yet 100% (retry with feedback)
  objdiff_no_improvement  compiled but no improvement (retry)
  objdiff_regression    global regression; attempt rejected
  compile_error         build failed; compiler errors fed back
  llm_error             API call failed
  malformed_response    response was not the required JSON structure
  no_edits              response contained no applicable source changes
  timeout               build timed out

Safety (enforced by the components this orchestrator calls):

  - the primary working tree is never modified; attempts run in
    .worktrees/<address>/attempt-NNN (editor.py validates every path
    against src/include and rejects traversal/protected dirs)
  - the game dump is never read, sent anywhere, committed or pushed
  - nothing is committed or pushed automatically, ever
  - --dry-run runs the whole pipeline but performs no source
    modification, no external LLM request, and no commit

Database: status transitions (in_progress / matching / matched /
blocked) are written only after objectively verified results.
"""

import argparse
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build as build_mod  # noqa: E402
import context as context_mod  # noqa: E402
import database as db  # noqa: E402
import editor as editor_mod  # noqa: E402
import llm as llm_mod  # noqa: E402
import objdiff as objdiff_mod  # noqa: E402
from worktree import WorktreeError, WorktreeManager  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
ATTEMPTS_ROOT = os.path.join(HERE, "attempts")
PRIMARY_BASELINE = os.path.join(REPO, "build", "SC4P64", "baseline.json")
PRIMARY_REPORT = os.path.join(REPO, "build", "SC4P64", "report.json")


class Orchestrator:
    """One target function, one worker, bounded attempts.

    `llm_client` is injectable for tests; a fake only needs
    .generate(prompt) -> object with .response (str) and .ok/.error.
    """

    def __init__(self, address, conn, max_attempts=5,
                 build_timeout=build_mod.DEFAULT_TIMEOUT,
                 dry_run=False, dry_run_build=False, allow_dirty=False,
                 skip_build=False, llm_client=None,
                 attempts_root=ATTEMPTS_ROOT, worktree_manager=None,
                 log=print):
        self.address = str(address).strip().lower()
        self.conn = conn
        self.max_attempts = max_attempts
        self.build_timeout = build_timeout
        self.dry_run = dry_run
        self.dry_run_build = dry_run_build
        self.allow_dirty = allow_dirty
        self.skip_build = skip_build
        self.llm_client = llm_client
        self.attempts_root = attempts_root
        self.worktrees = worktree_manager or WorktreeManager()
        self.log = log

        self.symbol = None
        self.unit_source_path = None
        self.baseline = None

    # ----------------------------------------------------------------
    # recording
    # ----------------------------------------------------------------

    def attempt_dir(self, attempt):
        return os.path.join(self.attempts_root, self.address,
                            "attempt-%03d" % attempt)

    def _write(self, attempt, name, content):
        path = os.path.join(self.attempt_dir(attempt), name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    # ----------------------------------------------------------------
    # baseline
    # ----------------------------------------------------------------

    def establish_baseline(self):
        """Baseline build/objdiff of the primary tree, stored once."""
        base_dir = os.path.join(self.attempts_root, self.address,
                                "baseline")
        os.makedirs(base_dir, exist_ok=True)

        have_baseline = os.path.exists(PRIMARY_BASELINE)
        have_report = os.path.exists(PRIMARY_REPORT)
        if not have_report or not have_baseline:
            if self.dry_run or not have_report:
                self.log("generating primary baseline report "
                         "(ninja baseline)...")
                proc = build_mod.run_build(REPO, build_cmd=("ninja",
                                                            "baseline"))
                if not proc["success"]:
                    raise RuntimeError("baseline build failed; fix the "
                                       "primary tree first")
            else:
                self.log("generating baseline report from current "
                         "objects...")
                objdiff_mod.generate_report(REPO,
                                            output=PRIMARY_BASELINE)

        baseline_report = objdiff_mod.load_json(PRIMARY_BASELINE)
        unit_name, entry = objdiff_mod.find_function_entry(
            baseline_report, self.symbol)

        baseline = {
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "baseline_report": PRIMARY_BASELINE,
            "target": {
                "symbol": self.symbol,
                "address": self.address,
                "unit": unit_name,
                "data_available": entry is not None
                    and entry.get("fuzzy_match_percent") is not None,
                "match_percent": (entry or {}).get("fuzzy_match_percent"),
            },
        }
        if entry is None:
            baseline["limitations"] = [
                "target symbol has no baseline entry (not implemented "
                "in its unit source yet); improvement is measured "
                "against 'no data'"]

        with open(os.path.join(base_dir, "objdiff.json"), "w") as f:
            json.dump(baseline, f, indent=2)
        self.baseline = baseline
        return baseline

    # ----------------------------------------------------------------
    # LLM step (injectable / dry-run)
    # ----------------------------------------------------------------

    def canned_response(self, prompt, unit_rel):
        """Deterministic stand-in for the LLM in --dry-run mode.

        Carries a valid but conservative edit (a comment appended to the
        unit's source) so the editor's validation and patch generation
        are exercised. The editor runs in dry-run, so nothing is written.
        """
        changes = []
        if unit_rel:
            changes = [{
                "path": unit_rel,
                "operation": "append",
                "new_text": "\n/* dry-run: candidate edit (never "
                            "applied) */\n",
            }]
        return llm_mod.LLMResponse(
            prompt=prompt,
            model="dry-run-canned",
            response=json.dumps({
                "analysis": "DRY-RUN: canned response; no API call was "
                            "made. The editor below ran in dry-run mode.",
                "hypotheses": [],
                "proposed_source": None,
                "source_changes": changes,
                "confidence": 0.0,
                "unknowns": ["dry-run mode never consults a model"],
                "additional_context_needed": [],
            }, indent=2),
            request_id="dry-run",
            usage={"prompt_tokens": len(prompt) // 4,
                   "completion_tokens": 0},
            latency_seconds=0.0,
        )

    def call_llm(self, prompt, unit_rel=None):
        if self.dry_run:
            return self.canned_response(prompt, unit_rel)
        client = self.llm_client or llm_mod.LLMClient()
        return client.generate(prompt)

    # ----------------------------------------------------------------
    # the loop
    # ----------------------------------------------------------------

    def run(self):
        fn = self.conn.execute(
            "SELECT * FROM functions WHERE address = ?",
            (self.address,)).fetchone()
        if fn is None:
            raise RuntimeError("function %s not in database" % self.address)
        self.symbol = fn["name"]
        if not self.symbol:
            raise RuntimeError("function %s has no symbol; export the "
                               "context first" % self.address)
        if fn["status"] == "matched":
            self.log("%s is already objectively matched; refusing to "
                     "touch it" % self.address)
            return {"status": "already_matched", "attempts": []}

        if self.primary_is_dirty() and not self.allow_dirty:
            raise RuntimeError(
                "primary working tree is dirty; refusing to start "
                "(use --allow-dirty to override)")

        self.establish_baseline()
        if not self.dry_run:
            db.set_status(self.conn, self.address, "in_progress")
        self.conn.commit()

        results = []
        feedback = None
        final = None
        for attempt in range(1, self.max_attempts + 1):
            self.log("=== attempt %d/%d ===" % (attempt, self.max_attempts))
            try:
                result = self.run_attempt(attempt, feedback)
            except (editor_mod.EditError,
                    objdiff_mod.ObjdiffError,
                    build_mod.BuildError,
                    WorktreeError) as exc:
                result = {"classification": "internal_error",
                          "error": str(exc)}
            self._write(attempt, "result.json",
                        json.dumps(result, indent=2, default=str))
            results.append(result)
            final = result
            if result["classification"] in ("ok", "already_matched"):
                break
            feedback = result.get("feedback")

        # final database status: only objective results count
        if not self.dry_run:
            if final and final["classification"] == "ok":
                db.set_status(self.conn, self.address, "matched")
            elif final and final["classification"] == "matching":
                db.set_status(self.conn, self.address, "matching")
            else:
                db.set_status(self.conn, self.address, "blocked")
            self.conn.commit()

        return {"status": final["classification"] if final else "unknown",
                "attempts": results}

    def primary_is_dirty(self):
        return self.worktrees.primary_is_dirty()

    def run_attempt(self, attempt, feedback):
        record_dir = self.attempt_dir(attempt)
        os.makedirs(record_dir, exist_ok=True)
        result = {"attempt": attempt, "classification": "unknown"}

        # 1. context
        ctx = context_mod.build_context(self.address, conn=self.conn)
        self._write(attempt, "context.json", json.dumps(ctx, indent=2))
        self.unit_source_path = ctx["source"]["path"]

        # 2. prompt (+ feedback from the previous attempt)
        if feedback:
            template = llm_mod.load_prompt("analyze_mismatch")
            feedback_block = "\n\n## Previous attempt feedback\n" + feedback
        else:
            template = llm_mod.load_prompt("decompile_function")
            feedback_block = ""
        prompt = llm_mod.render_prompt(template, context_mod
                                       .render_markdown(ctx))
        prompt = prompt + feedback_block
        self._write(attempt, "prompt.txt", prompt)

        # 3. LLM
        unit_rel = editor_mod.rel_form(self.unit_source_path) \
            if self.unit_source_path else None
        response = self.call_llm(prompt, unit_rel=unit_rel)
        self._write(attempt, "response.json", json.dumps(
            response.to_dict() if hasattr(response, "to_dict")
            else {"response": str(response)}, indent=2))
        if not getattr(response, "ok", True) or response.error:
            result["classification"] = "llm_error"
            result["error"] = getattr(response, "error", "llm failed")
            return result
        try:
            structured = llm_mod.parse_structured(response.response)
        except llm_mod.LLMResponseError as exc:
            result["classification"] = "malformed_response"
            result["error"] = str(exc)
            return result
        result["confidence"] = structured.get("confidence")

        # 4. edits (validated against the unit's source file only)
        changes = structured.get("source_changes") or []
        if not changes:
            result["classification"] = "no_edits"
            result["error"] = "response contained no source_changes"
            return result
        try:
            if self.unit_source_path:
                editor_mod.restrict_to(changes, [self.unit_source_path])
        except editor_mod.EditError as exc:
            result["classification"] = "no_edits"
            result["error"] = str(exc)
            return result
        try:
            worktree_info = self.worktrees.create_worktree(
                self.address, attempt, allow_dirty=True)
        except WorktreeError as exc:
            result["classification"] = "internal_error"
            result["error"] = str(exc)
            return result

        try:
            worktree_path = worktree_info["path"]
            self._write(attempt, "worktree.json",
                        json.dumps(worktree_info, indent=2))

            # 5. editor (dry-run never writes)
            edit_result = editor_mod.apply_changes(
                changes, repo_root=worktree_path,
                dry_run=self.dry_run)
            self._write(attempt, "patch.diff",
                        edit_result["patch"] or "(no changes)\n")
            result["patch"] = edit_result["patch"]

            if self.dry_run and not self.dry_run_build:
                result["classification"] = "dry_run"
                result["note"] = ("dry-run: changes validated but not "
                                  "applied; use --dry-run-build to also "
                                  "run build+objdiff on the unmodified "
                                  "worktree")
                return result

            # 6. build
            build_record = build_mod.run_build(
                worktree_path, timeout=self.build_timeout)
            self._write(attempt, "build.log", json.dumps(build_record,
                                                         indent=2))
            if not build_record["success"]:
                result["classification"] = (
                    "timeout" if build_record["classification"] ==
                    "timeout" else "compile_error")
                result["feedback"] = (
                    "The previous attempt failed to compile:\n"
                    + "\n".join(build_record["errors"][:30]))
                return result

            # 7. objdiff
            od = objdiff_mod.evaluate(
                worktree_path, target_symbol=self.symbol,
                baseline_report=PRIMARY_BASELINE,
                target_address=self.address)
            self._write(attempt, "objdiff.json", json.dumps(od, indent=2))
            result["objdiff"] = {
                "match_percent": (od["target"] or {}).get("match_percent"),
                "fully_matched": (od["target"] or {}).get(
                    "fully_matched", False),
                "regressions": od["regressions"],
                "limitations": od["limitations"],
            }

            # 8. classify — objective verdicts only
            if od["regressions"]:
                result["classification"] = "objdiff_regression"
                result["feedback"] = (
                    "The previous attempt regressed the global match:\n"
                    + "\n".join(od["regressions"])
                    + "\nIt was rejected; do not repeat that change.")
                return result
            if od["target"] and od["target"]["fully_matched"]:
                result["classification"] = "ok"
                result["note"] = ("objdiff confirms 100%% for %s"
                                  % self.symbol)
                if not self.dry_run:
                    result["database_status"] = "matched"
                return result

            baseline_pct = (self.baseline["target"] or {}).get(
                "match_percent")
            now_pct = (od["target"] or {}).get("match_percent")
            improved = (now_pct is not None
                        and (baseline_pct is None or now_pct > baseline_pct))
            if improved:
                result["classification"] = "matching"
                result["feedback"] = (
                    "The previous attempt improved the target to %s%% "
                    "but it is not fully matched yet. objdiff target "
                    "data: %s\nKeep improving; the function must reach "
                    "exactly 100%%." % (now_pct,
                                        json.dumps(result["objdiff"])))
            else:
                result["classification"] = "objdiff_no_improvement"
                result["feedback"] = (
                    "The previous attempt compiled but did not improve "
                    "the target function's match. objdiff target data: "
                    + json.dumps(result["objdiff"]))
            return result
        finally:
            # keep the worktree only when the function is fully matched
            # (for human review); everything else is cleaned up
            if result["classification"] != "ok" \
                    and os.path.exists(worktree_info["path"]):
                try:
                    self.worktrees.remove_worktree(
                        self.address, attempt, force=True)
                except Exception:
                    pass  # cleanup must never mask the attempt result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--address", required=True)
    ap.add_argument("--max-attempts", type=int, default=5)
    ap.add_argument("--db", default=db.DB_PATH)
    ap.add_argument("--dry-run", action="store_true",
                    help="full pipeline without source modification, "
                         "external LLM requests, or commits")
    ap.add_argument("--dry-run-build", action="store_true",
                    help="with --dry-run: continue through build and "
                         "objdiff on the unmodified worktree")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="start even if the primary tree is dirty")
    ap.add_argument("--build-timeout", type=int,
                    default=build_mod.DEFAULT_TIMEOUT)
    ap.add_argument("--skip-build", action="store_true",
                    help=argparse.SUPPRESS)  # test hook
    args = ap.parse_args(argv)

    conn = db.connect(args.db)
    orch = Orchestrator(
        args.address, conn, max_attempts=args.max_attempts,
        build_timeout=args.build_timeout, dry_run=args.dry_run,
        dry_run_build=args.dry_run_build,
        allow_dirty=args.allow_dirty, skip_build=args.skip_build)
    try:
        outcome = orch.run()
    finally:
        conn.close()
    print(json.dumps({"status": outcome["status"],
                      "attempts": len(outcome["attempts"]),
                      "results": [
                          {k: v for k, v in r.items()
                           if k in ("attempt", "classification",
                                    "error", "confidence",
                                    "objdiff")} for r in
                          outcome["attempts"]]}, indent=2))
    return 0 if outcome["status"] in ("ok", "dry_run",
                                      "already_matched") else 1


if __name__ == "__main__":
    sys.exit(main())
