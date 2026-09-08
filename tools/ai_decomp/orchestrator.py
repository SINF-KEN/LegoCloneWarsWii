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
import idioms as idioms_mod  # noqa: E402
import llm as llm_mod  # noqa: E402
import mismatch as mismatch_mod  # noqa: E402
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
        self.best = None  # best objectively verified candidate so far

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
    # best-candidate persistence (objective objdiff results only)
    # ----------------------------------------------------------------

    def best_json_path(self):
        return os.path.join(self.attempts_root, self.address, "best.json")

    def best_patch_path(self):
        return os.path.join(self.attempts_root, self.address, "best.patch")

    def load_best(self):
        """Continue from a previously verified best candidate."""
        path = self.best_json_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                best = json.load(f)
            patch_file = self.best_patch_path()
            if best.get("accepted") and os.path.exists(patch_file):
                with open(patch_file) as f:
                    best["patch"] = f.read()
                self.best = best
                self.log("continuing from verified best candidate: "
                         "attempt %d at %s%%"
                         % (best.get("best_attempt"),
                            best.get("target_match_percent")))
                return self.best
        except (OSError, ValueError) as exc:
            self.log("ignoring unreadable best.json: %s" % exc)
        return None

    def save_best(self, patch_text):
        self.best["patch"] = patch_text
        self.best["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        os.makedirs(os.path.dirname(self.best_json_path()), exist_ok=True)
        with open(self.best_patch_path(), "w") as f:
            f.write(patch_text)
        meta = {k: v for k, v in self.best.items() if k != "patch"}
        with open(self.best_json_path(), "w") as f:
            json.dump(meta, f, indent=2)

    def capture_best_patch(self, worktree_path, base_commit):
        """Capture the accumulated candidate diff (objective state)."""
        return self.worktrees.diff_against(worktree_path, base_commit)

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

    def _accept_best(self, attempt, worktree_path, base_commit,
                     target_pct, result):
        """Record an objectively better candidate as the new best.

        The accumulated worktree diff (best patch + this attempt's edit)
        is captured from the disposable worktree; nothing is committed.
        """
        patch_text = self.capture_best_patch(worktree_path, base_commit)
        self.best = {
            "address": self.address,
            "best_attempt": attempt,
            "target_match_percent": target_pct,
            "parent_attempt": result.get("parent_attempt"),
            "base_commit": base_commit,
            "base_branch": self.worktrees.base_branch,
            "global_regression": False,
            "accepted": True,
            "captured": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "dry_run": self.dry_run,
        }
        if not self.dry_run:
            self.save_best(patch_text)
            self.log("new best candidate: attempt %d at %s%%"
                     % (attempt, target_pct))

    def _best_mismatch(self, up_to_attempt):
        """Most recent mismatch evidence available before this attempt.

        Prefers the best attempt's evidence; falls back to the most
        recent measured attempt (the best candidate may predate
        mismatch capture).
        """
        candidates = []
        best_attempt = (self.best or {}).get("best_attempt")
        if best_attempt is not None:
            candidates.append(self.attempt_dir(best_attempt))
        for a in range(up_to_attempt - 1, 0, -1):
            candidates.append(self.attempt_dir(a))
        for d in candidates:
            path = os.path.join(d, "mismatch.json")
            if not os.path.exists(path):
                continue
            try:
                with open(path) as f:
                    evidence = json.load(f)
                if isinstance(evidence, dict):
                    return evidence
            except (OSError, ValueError):
                continue
        return None

    def _previous_attempt_summary(self):
        """Hypotheses/unknowns/classification of the best attempt."""
        best_attempt = (self.best or {}).get("best_attempt")
        if best_attempt is None:
            return ""
        path = os.path.join(self.attempt_dir(best_attempt),
                            "response.json")
        lines = []
        try:
            with open(path) as f:
                structured = (json.load(f) or {}).get("structured") or {}
            for key in ("hypotheses", "unknowns",
                        "additional_context_needed"):
                if structured.get(key):
                    lines.append("- %s: %s" % (
                        key, "; ".join(map(str, structured[key]))))
        except (OSError, ValueError):
            pass
        result_path = os.path.join(self.attempt_dir(best_attempt),
                                   "result.json")
        try:
            with open(result_path) as f:
                prev = json.load(f)
            lines.append("- previous classification: %s"
                         % prev.get("classification"))
            if prev.get("objdiff"):
                lines.append("- previous objdiff: %s"
                             % json.dumps(prev["objdiff"]))
        except (OSError, ValueError):
            pass
        return ("\n### Known hypotheses / unknowns from the best "
                "attempt\n" + "\n".join(lines)) if lines else ""

    def call_llm(self, prompt, unit_rel=None):
        if self.dry_run:
            return self.canned_response(prompt, unit_rel)
        try:
            client = self.llm_client or llm_mod.LLMClient()
        except llm_mod.LLMConfigError as exc:
            response = llm_mod.LLMResponse(prompt=prompt,
                                           error=str(exc))
            response.fatal = True
            return response
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

        previous_status = fn["status"]
        self.establish_baseline()
        self.load_best()
        if not self.dry_run:
            db.set_status(self.conn, self.address, "in_progress")
        self.conn.commit()

        results = []
        feedback = None
        final = None
        # attempt numbers continue from a loaded best candidate so
        # lineage stays monotonic across orchestrator invocations
        start = (self.best or {}).get("best_attempt") or 0
        for attempt in range(start + 1, start + 1 + self.max_attempts):
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
            self._write(attempt, "metadata.json", json.dumps({
                "attempt_number": attempt,
                "parent_attempt": result.get("parent_attempt"),
                "base_commit": result.get("base_commit"),
                "target_match_before": result.get("target_match_before"),
                "target_match_after": result.get("target_match_after"),
                "global_match_before": result.get("global_match_before"),
                "global_match_after": result.get("global_match_after"),
                "regression": result.get("regression"),
                "accepted_as_best": result.get("accepted_as_best"),
                "best_attempt_now": (self.best or {}).get("best_attempt"),
                "classification": result.get("classification"),
            }, indent=2, default=str))
            results.append(result)
            final = result
            if result.get("fatal"):
                self.log("fatal error, aborting the loop: %s"
                         % result.get("error"))
                break
            if result["classification"] in ("ok", "already_matched"):
                break
            feedback = result.get("feedback")

        # fatal aborts never produce a verdict: restore prior status
        if final and final.get("fatal") and not self.dry_run:
            db.set_status(self.conn, self.address, previous_status)
            self.conn.commit()

        # final database status: only objective results count.
        # matched requires objdiff fuzzy_match_percent == 100.0 (ok);
        # a verified best candidate (any confirmed percent) is matching;
        # everything else is blocked.
        elif not self.dry_run:
            if final and final["classification"] == "ok":
                db.set_status(self.conn, self.address, "matched")
            elif self.best and self.best.get("target_match_percent") \
                    is not None:
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
        if os.path.isdir(record_dir):
            # re-running the same attempt number must never mix old
            # artifacts (e.g. a stale build.log from a dry-run) with
            # this attempt's records
            shutil.rmtree(record_dir)
        os.makedirs(record_dir, exist_ok=True)
        result = {
            "attempt": attempt,
            "classification": "unknown",
            "attempt_number": attempt,
            "parent_attempt": (self.best or {}).get("best_attempt"),
            "target_match_before": (self.best or {}).get(
                "target_match_percent"),
        }

        # 1. context (+ relevant known idioms retrieved against the
        #    target's actual assembly and the m2c candidate source)
        ctx = context_mod.build_context(self.address, conn=self.conn)
        relevant_idioms = idioms_mod.retrieve_relevant_idioms(
            self.conn, assembly_lines=ctx.get("assembly"),
            source_text=(ctx.get("m2c") or {}).get("candidate_c"),
            limit=idioms_mod.DEFAULT_RETRIEVE_LIMIT)
        ctx["idioms"] = relevant_idioms
        idioms_block = idioms_mod.render_idioms_markdown(relevant_idioms)
        self._write(attempt, "context.json", json.dumps(ctx, indent=2))
        self.unit_source_path = ctx["source"]["path"]

        # 2. prompt (+ feedback from the previous attempt). When a best
        # candidate exists, the model must improve it, not start over.
        if feedback or self.best:
            template = llm_mod.load_prompt("analyze_mismatch")
        else:
            template = llm_mod.load_prompt("decompile_function")
        feedback_block = "\n\n## Previous attempt feedback\n" + \
            (feedback or "")
        if self.best:
            prev = self._previous_attempt_summary()
            mismatch_block = ""
            best_mismatch = self._best_mismatch(attempt)
            if best_mismatch:
                mismatch_block = (
                    "\n### Objective mismatch evidence\n"
                    "Byte-level comparison of the extracted original "
                    "object vs the built candidate object for %s. "
                    "Prioritize: exact instruction mismatches, then "
                    "instruction ordering, register, load/store, "
                    "branch, immediate/address, call/return, and "
                    "function-size differences.\n%s\n"
                    % (self.symbol,
                       mismatch_mod.render_mismatch_markdown(
                           best_mismatch)))
            feedback_block += (
                "\n\n## Current best verified candidate\n"
                "The previous candidate below is the current best "
                "verified candidate (target objdiff %s%%). **Improve it "
                "rather than starting over. Do not throw it away "
                "unnecessarily.**\n"
                "Its changes are ALREADY APPLIED to the file you are "
                "editing: the current file content is the existing "
                "source plus this patch. Craft `old_text` against that "
                "combined content.\n"
                "\n### Accumulated best patch\n"
                "```diff\n%s\n```\n%s%s"
                % (self.best.get("target_match_percent"),
                   self.best.get("patch", "").strip(),
                   mismatch_block,
                   prev))
        prompt = llm_mod.render_prompt(template, context_mod
                                       .render_markdown(ctx))
        prompt = prompt + feedback_block
        if idioms_block:
            prompt += "\n\n" + idioms_block + "\n"
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
            result["fatal"] = getattr(response, "fatal", False)
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

        compiled_ok = False
        now_pct = None
        regressed = False
        accepted_flag = None
        try:
            worktree_path = worktree_info["path"]
            base_commit = self.worktrees.head(worktree_path)
            worktree_info["base_commit"] = base_commit
            result["base_commit"] = base_commit
            worktree_info["best_replayed"] = False

            # retry continuity: rebuild the best verified candidate in
            # this disposable worktree before applying new edits
            if self.best and self.best.get("patch"):
                try:
                    editor_mod.apply_unified_diff(
                        self.best["patch"], repo_root=worktree_path)
                    worktree_info["best_replayed"] = True
                except editor_mod.EditError as exc:
                    result["classification"] = "best_replay_failed"
                    result["error"] = (
                        "best candidate patch no longer applies to %s: "
                        "%s" % (base_commit, exc))
                    result["fatal"] = True
                    return result
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
                error_text = "\n".join(
                    build_record["errors"][:15])[:4000]
                warn_text = "\n".join(
                    build_record["warnings"][:5])
                result["feedback"] = (
                    "The previous attempt failed to compile:\n"
                    + error_text
                    + ("\n\nCompiler warnings (context only):\n"
                       + warn_text if warn_text else ""))
                return result

            # 7. objdiff
            od = objdiff_mod.evaluate(
                worktree_path, target_symbol=self.symbol,
                baseline_report=PRIMARY_BASELINE,
                target_address=self.address)
            self._write(attempt, "objdiff.json", json.dumps(od, indent=2))

            # objective mismatch evidence for the next attempt (5.2)
            mismatch_evidence = None
            if od.get("target") and od["target"].get("data_available"):
                try:
                    t_path, b_path = mismatch_mod.unit_object_paths(
                        worktree_path, od["target"].get("unit"))
                    mismatch_evidence = mismatch_mod.collect_mismatch(
                        worktree_path, self.symbol,
                        address=self.address,
                        unit_name=od["target"].get("unit"),
                        target_path=t_path, base_path=b_path,
                        instruction_lines=ctx.get("assembly"))
                    mismatch_evidence["match_percent"] = \
                        od["target"].get("match_percent")
                    self._write(attempt, "mismatch.json", json.dumps(
                        mismatch_evidence, indent=2))
                except (OSError, ValueError) as exc:
                    mismatch_evidence = {
                        "available": False,
                        "reason": "mismatch extraction failed: %s" % exc,
                    }
                    self._write(attempt, "mismatch.json", json.dumps(
                        mismatch_evidence, indent=2))
            result["mismatch_available"] = bool(
                mismatch_evidence and mismatch_evidence.get("available"))

            result["objdiff"] = {
                "match_percent": (od["target"] or {}).get("match_percent"),
                "fully_matched": (od["target"] or {}).get(
                    "fully_matched", False),
                "regressions": od["regressions"],
                "limitations": od["limitations"],
            }

            # 8. classify + best-candidate acceptance — objective
            #    verdicts only (objdiff numbers, never LLM claims)
            overall = od.get("overall") or {}
            result["global_match_before"] = {
                k: overall.get("from", {}).get(k)
                for k in ("matched_code", "matched_functions")}
            result["global_match_after"] = {
                k: overall.get("to", {}).get(k)
                for k in ("matched_code", "matched_functions")}
            result["regression"] = bool(od.get("regressions"))
            regressed = bool(od.get("regressions"))
            now_pct = (od.get("target") or {}).get("match_percent")
            result["target_match_after"] = now_pct
            compiled_ok = True
            best_pct = (self.best or {}).get("target_match_percent") \
                if self.best else None

            if od["regressions"]:
                result["classification"] = "objdiff_regression"
                result["accepted_as_best"] = False
                result["feedback"] = (
                    "The previous attempt regressed the global match:\n"
                    + "\n".join(od["regressions"])
                    + "\nIt was rejected; do not repeat that change.")
                return result

            if od["target"] and od["target"]["fully_matched"]:
                result["accepted_as_best"] = now_pct is not None and (
                    best_pct is None or now_pct > best_pct)
                accepted_flag = result["accepted_as_best"]
                if result["accepted_as_best"]:
                    self._accept_best(attempt, worktree_path, base_commit,
                                      now_pct, result)
                result["classification"] = "ok"
                result["note"] = ("objdiff confirms 100%% for %s"
                                  % self.symbol)
                return result

            # exact function-level data required to become the new best;
            # unavailable data never replaces a verified best candidate
            if now_pct is None:
                result["classification"] = "objdiff_no_improvement"
                result["accepted_as_best"] = False
                result["feedback"] = (
                    "The previous attempt compiled but objdiff has no "
                    "match data for the target symbol (%s). A candidate "
                    "without measurable target data cannot become the "
                    "best candidate. objdiff: %s"
                    % (self.symbol, json.dumps(result["objdiff"])))
                return result

            if best_pct is None or now_pct > best_pct:
                result["accepted_as_best"] = True
                accepted_flag = True
                self._accept_best(attempt, worktree_path, base_commit,
                                  now_pct, result)
                result["classification"] = "matching"
                result["feedback"] = (
                    "The previous attempt is the new best verified "
                    "candidate: target objdiff improved to %s%% (was "
                    "%s%%). It is not fully matched yet; it must reach "
                    "exactly 100%%. objdiff: %s"
                    % (now_pct, best_pct, json.dumps(result["objdiff"])))
                return result

            result["classification"] = "objdiff_no_improvement"
            result["accepted_as_best"] = False
            if now_pct < best_pct:
                result["feedback"] = (
                    "The previous attempt made the target WORSE "
                    "(%s%% < best %s%%). It was rejected; the best "
                    "candidate is preserved and its patch is already "
                    "applied in your working file. Do not repeat that "
                    "change. objdiff: %s"
                    % (now_pct, best_pct, json.dumps(result["objdiff"])))
            else:
                result["feedback"] = (
                    "The previous attempt compiled but did not improve "
                    "the target (equal to best %s%%); the best "
                    "candidate is preserved and already applied. "
                    "objdiff: %s"
                    % (best_pct, json.dumps(result["objdiff"])))
            return result
        finally:
            # 5.3: learn compiler idioms from real compiled+objdiff
            # outcomes only (never from dry-runs or failed builds)
            if compiled_ok and not self.dry_run and result.get("patch"):
                try:
                    learned = idioms_mod.learn_from_attempt(
                        self.conn, address=self.address,
                        function_name=self.symbol,
                        attempt_number=attempt,
                        source_text=result.get("patch") or "",
                        assembly_lines=ctx.get("assembly") or [],
                        objdiff_percent=now_pct,
                        accepted_as_best=accepted_flag,
                        regressed=regressed, compiled=True,
                        improvement=(now_pct -
                                     result.get("target_match_before"))
                        if now_pct is not None and
                        result.get("target_match_before") is not None
                        else None)
                    if learned:
                        result["idioms_learned"] = len(learned)
                except Exception as exc:  # learning must never break
                    self.log("idiom learning failed: %s" % exc)

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
    ap.add_argument("--attempts-root", default=ATTEMPTS_ROOT,
                    help="attempt records directory (default: "
                         "tools/ai_decomp/attempts)")
    ap.add_argument("--skip-build", action="store_true",
                    help=argparse.SUPPRESS)  # test hook
    args = ap.parse_args(argv)

    conn = db.connect(args.db)
    orch = Orchestrator(
        args.address, conn, max_attempts=args.max_attempts,
        build_timeout=args.build_timeout, dry_run=args.dry_run,
        dry_run_build=args.dry_run_build,
        allow_dirty=args.allow_dirty, skip_build=args.skip_build,
        attempts_root=args.attempts_root)
    try:
        outcome = orch.run()
    except (RuntimeError, llm_mod.LLMConfigError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
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
    if outcome["status"] in ("ok", "dry_run", "already_matched"):
        return 0
    if args.dry_run:
        # a completed dry-run is a successful validation even when the
        # measured classification is not an improvement
        return 0 if outcome["status"] not in (
            "internal_error", "best_replay_failed") else 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
