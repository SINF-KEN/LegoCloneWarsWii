#!/usr/bin/env python3
"""Reporting for the 10-function pipeline benchmark (Phase 5.6).

Consumes a benchmark results JSON (the collected per-function records
from tools/ai_decomp/output/benchmark_10_results.json), prints a
concise table plus aggregate metrics, and can render the human-readable
markdown report.

Null/unavailable objdiff values are never treated as zero: averages and
improvements are computed only over functions with measurable data, and
the sample counts are reported alongside.

Usage:
    python3 tools/ai_decomp/benchmark_report.py \
        --results tools/ai_decomp/output/benchmark_10_results.json \
        --markdown tools/ai_decomp/output/benchmark_10_report.md
"""

import argparse
import json
import os
import sys
from statistics import median

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RESULTS = os.path.join(HERE, "output",
                               "benchmark_10_results.json")
DEFAULT_MARKDOWN = os.path.join(HERE, "output",
                                "benchmark_10_report.md")


def improvement(baseline, best):
    """Improvement in percentage points; None unless BOTH measurable."""
    if baseline is None or best is None:
        return None
    return round(best - baseline, 4)


def _measurable(values):
    return [v for v in values if v is not None]


def aggregate(results):
    """Aggregate metrics over per-function result records."""
    baselines = _measurable([r.get("baseline") for r in results])
    bests = _measurable([r.get("best") for r in results])
    deltas = _measurable([r.get("delta") for r in results])

    def count(pred):
        return sum(1 for r in results if pred(r))

    improvements = [r.get("delta") for r in results
                    if r.get("delta") is not None]

    return {
        "functions": len(results),
        "already_matched": count(
            lambda r: r.get("classification") == "already_matched"),
        "improved": count(
            lambda r: r.get("classification") in
            ("matching", "improved", "ok")),
        "unchanged": count(
            lambda r: r.get("classification") in
            ("objdiff_no_improvement", "unchanged")),
        "reached_100": count(lambda r: r.get("reached_100") is True),
        "build_failures": count(
            lambda r: r.get("build") not in ("OK", None)
            or r.get("build_success") is False),
        "llm_failures": count(
            lambda r: r.get("classification") in
            ("llm_error", "malformed_response")),
        "regressions_rejected": count(
            lambda r: r.get("classification") == "objdiff_regression"
            or (r.get("regressions") or 0) > 0),
        "average_baseline": (round(sum(baselines) / len(baselines), 4)
                             if baselines else None),
        "average_best": (round(sum(bests) / len(bests), 4)
                         if bests else None),
        "average_improvement": (round(sum(deltas) / len(deltas), 4)
                                if deltas else None),
        "median_improvement": (round(median(deltas), 4)
                               if deltas else None),
        "improvement_samples": len(improvements),
        "total_attempts": sum(r.get("attempts") or 0
                              for r in results),
        "successful_builds": count(
            lambda r: r.get("build") == "OK"
            or r.get("build_success") is True),
        "regressions_rejected_count": sum(
            r.get("regressions") or 0 for r in results),
        "total_runtime_seconds": round(sum(
            r.get("duration_seconds") or 0 for r in results), 1),
    }


def format_table(results):
    header = ("%-9s %-42s %-10s %-8s %-7s %-8s %-6s %s"
              % ("ADDRESS", "NAME", "BASELINE", "BEST", "DELTA",
                 "ATTEMPTS", "BUILD", "RESULT"))
    lines = [header, "-" * len(header)]
    for r in results:
        fmt = lambda v: ("n/a" if v is None
                         else "%.2f" % v if isinstance(v, float)
                         else str(v))
        lines.append("%-9s %-42s %-10s %-8s %-7s %-8s %-6s %s" % (
            r.get("address") or "-",
            (r.get("name") or "-")[:42],
            fmt(r.get("baseline")),
            fmt(r.get("best")),
            fmt(r.get("delta")),
            r.get("attempts") if r.get("attempts") is not None else "-",
            r.get("build") or "-",
            r.get("classification") or "-"))
    return "\n".join(lines)


def render_markdown(results, environment=None):
    agg = aggregate(results)
    lines = ["# Phase 5.6 — 10 Function Benchmark", ""]

    lines.append("## Environment")
    for key, value in (environment or {}).items():
        lines.append("- %s: %s" % (key, value))
    lines.append("")

    lines.append("## Benchmark Functions")
    lines.append("```")
    lines.append(format_table(results))
    lines.append("```")
    lines.append("")

    lines.append("## Aggregate Metrics")
    for key, value in agg.items():
        lines.append("- %s: %s" % (key, value))
    lines.append("")

    lines.append("## Failures")
    failures = [r for r in results
                if r.get("classification") in
                ("llm_error", "malformed_response", "compile_error",
                 "timeout", "best_replay_failed", "internal_error",
                 "objdiff_regression")]
    if not failures:
        lines.append("- none recorded")
    for r in failures:
        lines.append("- %s (%s): %s" % (
            r.get("address"), r.get("classification"),
            (r.get("error") or "")[:200]))
    lines.append("")

    lines.append("## Observations")
    if agg["reached_100"]:
        lines.append("- %d function(s) reached an objdiff-verified "
                     "100%% match." % agg["reached_100"])
    if agg["improved"]:
        lines.append("- %d function(s) measurably improved over their "
                     "baseline." % agg["improved"])
    lines.append("- All match figures come from objdiff; compilation "
                 "success alone was never treated as matching.")
    lines.append("")

    lines.append("## Limitations")
    lines.append("- only 10 functions; not representative of the "
                 "~28k-function binary")
    lines.append("- sequential execution, single worker")
    lines.append("- analysis graph is still sparse (edges exist only "
                 "around analyzed functions)")
    lines.append("- m2c cannot represent PPC virtual calls; candidate "
                 "C for such functions is approximate")
    lines.append("- the installed objdiff-cli beta exposes no "
                 "instruction-level diffs; actual-side bytes are not "
                 "disassembled")
    lines.append("- benchmark retry depth was fixed at 1 attempt per "
                 "function for reproducibility")
    lines.append("")
    return "\n".join(lines)


def load_results(path):
    with open(path) as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        return payload.get("results", []), payload.get("environment", {})
    return payload, {}


def per_function(a_results, b_results):
    """Re-exported from benchmark_compare for test convenience."""
    import benchmark_compare as bc
    return bc.per_function(a_results, b_results)


def summarize(a_results, b_results, rows):
    import benchmark_compare as bc
    return bc.summarize(a_results, b_results, rows)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default=DEFAULT_RESULTS)
    ap.add_argument("--markdown", default=None)
    args = ap.parse_args(argv)

    if not os.path.exists(args.results):
        print("results file %s not found" % args.results,
              file=sys.stderr)
        return 1

    results, environment = load_results(args.results)
    print(format_table(results))
    print("")
    agg = aggregate(results)
    for key, value in agg.items():
        print("%s: %s" % (key, value))

    if args.markdown:
        os.makedirs(os.path.dirname(os.path.abspath(args.markdown)),
                    exist_ok=True)
        with open(args.markdown, "w") as f:
            f.write(render_markdown(results, environment) + "\n")
        print("\nmarkdown report written to %s" % args.markdown,
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
