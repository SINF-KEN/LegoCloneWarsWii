#!/usr/bin/env python3
"""objdiff integration: objective match evaluation (roadmap item #24).

Uses the project's own tooling, never a reimplementation:

  - the objdiff-cli binary the project downloads (build/tools/objdiff-cli)
  - the project's objdiff.json unit configuration
  - `objdiff-cli report generate` for the candidate tree
  - `objdiff-cli report changes` against a baseline report for global
    regression detection

What counts as objective truth here:

  - a function is FULLY MATCHED only when its unit's report entry shows
    fuzzy_match_percent == 100.0 (objdiff compares the built object
    against the extracted original object byte-for-byte per symbol)
  - global regression = any decrease in matched_code bytes or
    matched_functions count between baseline and candidate

objdiff limitations are reported as such: when a function has no report
entry (its unit has no built object, or the symbol is not implemented in
the unit's source), data_available is False and no match verdict is
produced. Approximate similarity is never seeded into the database as a
match.

API:

    from objdiff import Objdiff
    od = Objdiff()
    result = od.evaluate(worktree, target_symbol="NuFileRead__FiPvii",
                         baseline_report="build/SC4P64/baseline.json")

CLI:
    python3 tools/ai_decomp/objdiff.py --worktree W --symbol SYM \
        --baseline build/SC4P64/baseline.json
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
PRIMARY_OBJDIFF = os.path.join(REPO, "build", "tools", "objdiff-cli")
PRIMARY_REPORT = os.path.join(REPO, "build", "SC4P64", "report.json")
PRIMARY_BASELINE = os.path.join(REPO, "build", "SC4P64", "baseline.json")

FULL_MATCH_PERCENT = 100.0

# aggregate fields used for regression detection (objdiff report changes)
REGRESSION_FIELDS = ("matched_code", "matched_functions",
                     "complete_code", "complete_units")


class ObjdiffError(Exception):
    pass


def find_objdiff(worktree=None):
    """The project's objdiff-cli binary: worktree first, then primary."""
    candidates = []
    if worktree:
        candidates.append(os.path.join(worktree, "build", "tools",
                                       "objdiff-cli"))
    candidates.append(PRIMARY_OBJDIFF)
    for path in candidates:
        if os.path.exists(path):
            return path
    raise ObjdiffError(
        "objdiff-cli not found (looked in %s). Run `ninja tools` in the "
        "repository first." % ", ".join(candidates))


def _run(binary, args, cwd, timeout=600):
    proc = subprocess.run([binary, *args], cwd=cwd,
                          capture_output=True, text=True,
                          timeout=timeout)
    return proc


def generate_report(worktree, binary=None, output=None, timeout=600):
    """Generate the progress report for a built tree."""
    binary = binary or find_objdiff(worktree)
    output = output or os.path.join(worktree, "build", "SC4P64",
                                    "report.json")
    proc = _run(binary, ["report", "generate", "-o", output],
                cwd=worktree, timeout=timeout)
    if proc.returncode != 0:
        raise ObjdiffError("report generate failed: %s"
                           % proc.stderr.strip()[-2000:])
    if not os.path.exists(output):
        raise ObjdiffError("report generate produced no output")
    return output


def changes_report(baseline_path, candidate_path, worktree, binary=None,
                   output=None, timeout=300):
    """objdiff report changes: baseline vs candidate."""
    binary = binary or find_objdiff(worktree)
    output = output or os.path.join(
        os.path.dirname(candidate_path), "report_changes.json")
    proc = _run(binary, ["report", "changes", "-f", "json",
                         baseline_path, candidate_path],
                cwd=worktree, timeout=timeout)
    if proc.returncode != 0:
        raise ObjdiffError("report changes failed: %s"
                           % proc.stderr.strip()[-2000:])
    if output:
        with open(output, "w") as f:
            f.write(proc.stdout)
    return json.loads(proc.stdout)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def overall_totals(changes):
    """Normalize the from/to aggregate blocks."""
    out = {}
    for side in ("from", "to"):
        block = changes.get(side, {})
        out[side] = {field: block.get(field) for field in
                     ("total_code", "matched_code", "total_functions",
                      "matched_functions", "complete_code",
                      "complete_units")}
    return out


def detect_regressions(changes):
    """True when any aggregate metric decreased from baseline."""
    regressions = []
    for field in REGRESSION_FIELDS:
        before = changes.get("from", {}).get(field)
        after = changes.get("to", {}).get(field)
        if before is None or after is None:
            continue
        try:
            b, a = int(before), int(after)
        except (TypeError, ValueError):
            continue
        if a < b:
            regressions.append("%s: %d -> %d" % (field, b, a))
    return regressions


def find_function_entry(report, symbol):
    """Locate a symbol's unit entry in a report.

    Returns (unit_name, entry|None). Limitation-aware: a missing entry
    means objdiff has no data for that symbol (typically: the unit has
    no built object, or the unit's source does not implement it).
    """
    for unit in report.get("units", []):
        for fn in unit.get("functions", []):
            if fn.get("name") == symbol:
                return unit["name"], fn
    return None, None


def evaluate(worktree, target_symbol=None, baseline_report=None,
             binary=None, target_address=None):
    """Full objdiff evaluation of a built worktree vs a baseline.

    Returns a result dict; `target.fully_matched` is True only when
    objdiff objectively reports 100.0 for the target symbol.
    """
    if not os.path.isdir(worktree):
        raise ObjdiffError("worktree does not exist: %s" % worktree)

    report_path = generate_report(worktree, binary=binary)
    report = load_json(report_path)

    result = {
        "report": report_path,
        "target": None,
        "overall": None,
        "regressions": [],
        "limitations": [],
    }

    # ---- global regression detection against the baseline ----
    if baseline_report and os.path.exists(baseline_report):
        changes = changes_report(baseline_report, report_path, worktree,
                                 binary=binary)
        result["overall"] = overall_totals(changes)
        result["regressions"] = detect_regressions(changes)
    else:
        result["limitations"].append(
            "no baseline report available; global regression detection "
            "skipped (provide build/SC4P64/baseline.json)")

    # ---- target function ----
    if target_symbol:
        unit_name, entry = find_function_entry(report, target_symbol)
        if entry is None:
            result["target"] = {
                "symbol": target_symbol,
                "address": target_address,
                "unit": unit_name,
                "data_available": False,
                "fully_matched": False,
                "match_percent": None,
            }
            reason = ("objdiff has no entry for symbol %r" % target_symbol)
            if unit_name is None:
                reason += " (symbol not found in any unit report)"
            else:
                reason += (" (unit %s builds the symbol but reports no "
                           "match data; is it implemented in the unit "
                           "source?)" % unit_name)
            result["limitations"].append(reason)
        else:
            percent = entry.get("fuzzy_match_percent")
            fully_matched = percent is not None \
                and float(percent) == FULL_MATCH_PERCENT
            result["target"] = {
                "symbol": target_symbol,
                "address": target_address,
                "unit": unit_name,
                "data_available": percent is not None,
                "match_percent": percent,
                "size": entry.get("size"),
                "demangled": (entry.get("metadata") or {})
                    .get("demangled_name"),
                "fully_matched": fully_matched,
            }
            if percent is None:
                result["limitations"].append(
                    "unit %s has no match percent for %r; the symbol may "
                    "not be implemented in the unit source yet"
                    % (unit_name, target_symbol))
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worktree", default=REPO,
                    help="built tree to evaluate (default: primary)")
    ap.add_argument("--symbol", help="target function symbol")
    ap.add_argument("--address", help="target function address (label)")
    ap.add_argument("--baseline", default=PRIMARY_BASELINE,
                    help="baseline report for regression detection")
    ap.add_argument("--out", help="write the JSON result to a file")
    args = ap.parse_args(argv)

    try:
        result = evaluate(args.worktree, target_symbol=args.symbol,
                          baseline_report=args.baseline,
                          target_address=args.address)
    except (ObjdiffError, subprocess.TimeoutExpired) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, "w") as f:
            json.dump(result, f, indent=2)

    t = result.get("target")
    if t:
        print("target %s (%s): %s" % (
            t["symbol"], t.get("address") or "-",
            ("%.4f%%" % t["match_percent"])
            if t["match_percent"] is not None else "no data"))
        print("fully matched: %s" % t["fully_matched"])
    overall = result.get("overall")
    if overall:
        print("overall matched_functions: %s -> %s" % (
            overall["from"]["matched_functions"],
            overall["to"]["matched_functions"]))
        print("overall matched_code: %s -> %s" % (
            overall["from"]["matched_code"],
            overall["to"]["matched_code"]))
    for r in result["regressions"]:
        print("REGRESSION: %s" % r)
    for note in result["limitations"]:
        print("limitation: %s" % note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
