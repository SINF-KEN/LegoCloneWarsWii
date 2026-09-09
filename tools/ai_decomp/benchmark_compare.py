#!/usr/bin/env python3
"""Compare two benchmark result files (A/B model qualification).

Both inputs are benchmark results JSON files as produced by the
benchmark collection (a payload with "model"/"provider" metadata and a
"results" list, or a bare results list).

Usage:
    python3 tools/ai_decomp/benchmark_compare.py \
        --a tools/ai_decomp/output/benchmark_10_results_nex25mini.json \
        --b tools/ai_decomp/output/benchmark_10_results_deepseekchat.json

Treats unavailable objdiff data as unavailable (never zero). Per
function, emits a verdict: better / equal / worse / both-unavailable /
a-vs-b-failure.
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    with open(path) as f:
        payload = json.load(f)
    if isinstance(payload, dict):
        return payload.get("results", []), payload
    return payload, {}


def hostname(url):
    try:
        return urlparse(url).netloc or url
    except (TypeError, ValueError):
        return url or "unknown"


def provider_of(payload, results_path):
    meta_model = payload.get("model")
    if meta_model:
        prov = payload.get("provider") or hostname(
            (payload.get("base_url") or ""))
        return "%s (%s)" % (meta_model, prov) if prov else str(meta_model)
    return os.path.basename(results_path)


def per_function(a_results, b_results):
    a_by = {r.get("address"): r for r in a_results}
    b_by = {r.get("address"): r for r in b_results}
    rows = []
    for addr in sorted(set(a_by) | set(b_by)):
        a, b = a_by.get(addr), b_by.get(addr)
        a_pct = (a or {}).get("best_match")
        b_pct = (b or {}).get("best_match")
        FAILURE_CLASSES = ("compile_error", "llm_error",
                           "malformed_response", "malformed_edit",
                           "timeout", "best_replay_failed",
                           "internal_error", "no_edits")
        a_failed = bool(a and a.get("classification") in FAILURE_CLASSES)
        b_failed = bool(b and b.get("classification") in FAILURE_CLASSES)
        if a_pct is not None and b_pct is not None:
            if b_pct > a_pct:
                verdict = "b_better"
            elif b_pct < a_pct:
                verdict = "b_worse"
            else:
                verdict = "equal"
        elif b_pct is not None:
            verdict = "b_better"      # b measurable, a not
        elif a_pct is not None:
            verdict = "b_worse"       # b produced nothing measurable
        else:
            verdict = ("both_failed" if (a_failed or b_failed)
                       else "both_unavailable")
        rows.append({
            "address": addr,
            "name": ((b or a) or {}).get("name"),
            "a_match": a_pct,
            "b_match": b_pct,
            "a_classification": (a or {}).get("classification"),
            "b_classification": (b or {}).get("classification"),
            "verdict": verdict,
        })
    return rows


def summarize(a_results, b_results, rows):
    def count(results, pred):
        return sum(1 for r in results if pred(r))

    def compile_ok(results):
        return count(results, lambda r: r.get("build_success") is True)

    def cls_count(results, *cls):
        return count(results, lambda r: r.get("classification") in cls)

    def matches(results):
        return _measurable([r.get("best_match") for r in results])

    a_m, b_m = matches(a_results), matches(b_results)
    avg = lambda v: round(sum(v) / len(v), 4) if v else None

    verdicts = [r["verdict"] for r in rows]
    return {
        "functions": len(rows),
        "attempts": {
            "a": sum(r.get("attempts") or 0 for r in a_results),
            "b": sum(r.get("attempts") or 0 for r in b_results),
        },
        "successful_builds": {"a": compile_ok(a_results),
                              "b": compile_ok(b_results)},
        "compile_success_rate": {
            "a": round(compile_ok(a_results) / max(len(a_results), 1), 2),
            "b": round(compile_ok(b_results) / max(len(b_results), 1), 2),
        },
        "no_edit_responses": {"a": cls_count(a_results, "no_edits"),
                              "b": cls_count(b_results, "no_edits")},
        "malformed_or_internal": {
            "a": cls_count(a_results, "malformed_edit", "internal_error"),
            "b": cls_count(b_results, "malformed_edit",
                           "internal_error")},
        "llm_failures": {"a": cls_count(a_results, "llm_error",
                                        "malformed_response"),
                         "b": cls_count(b_results, "llm_error",
                                        "malformed_response")},
        "compile_failures": {"a": cls_count(a_results, "compile_error"),
                             "b": cls_count(b_results, "compile_error")},
        "regressions": {
            "a": sum((r.get("regressions") or 0) for r in a_results),
            "b": sum((r.get("regressions") or 0) for r in b_results)},
        "reached_100": {"a": count(a_results,
                                   lambda r: r.get("reached_100") is True),
                        "b": count(b_results,
                                   lambda r: r.get("reached_100") is True)},
        "functions_with_objdiff_data": {"a": len(a_m), "b": len(b_m)},
        "average_best_match": {"a": avg(a_m), "b": avg(b_m)},
        "average_improvement": {"a": None, "b": None},
        "verdicts": {
            "b_better": verdicts.count("b_better"),
            "equal": verdicts.count("equal"),
            "b_worse": verdicts.count("b_worse"),
            "both_failed": verdicts.count("both_failed"),
            "both_unavailable": verdicts.count("both_unavailable"),
        },
    }


def _measurable(values):
    return [v for v in values if v is not None]


def format_comparison(summary, rows, a_name, b_name):
    lines = []
    lines.append("Metric                         %-28s %s"
                 % (a_name[:28], b_name[:28]))
    lines.append("-" * 70)
    for key in ("functions", "attempts", "successful_builds",
                "compile_success_rate", "no_edit_responses",
                "malformed_or_internal", "llm_failures",
                "compile_failures", "reached_100",
                "functions_with_objdiff_data", "average_best_match"):
        value = summary.get(key)
        if isinstance(value, dict):
            lines.append("%-30s %-28s %s" % (key, value.get("a"),
                                             value.get("b")))
        else:
            lines.append("%-30s %s" % (key, value))
    lines.append("")
    lines.append("Per-function verdicts:")
    for r in rows:
        lines.append("  %s %-36s a=%-8s b=%-8s %s"
                     % (r["address"], (r["name"] or "?")[:36],
                        r["a_match"] if r["a_match"] is not None
                        else "n/a",
                        r["b_match"] if r["b_match"] is not None
                        else "n/a",
                        r["verdict"]))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a", required=True, help="model A results JSON")
    ap.add_argument("--b", required=True, help="model B results JSON")
    ap.add_argument("--out", help="write comparison JSON here")
    args = ap.parse_args(argv)

    a_results, a_payload = load(args.a)
    b_results, b_payload = load(args.b)
    a_name = provider_of(a_payload, args.a)
    b_name = provider_of(b_payload, args.b)

    rows = per_function(a_results, b_results)
    summary = summarize(a_results, b_results, rows)
    summary["models"] = {"a": a_name, "b": b_name}

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"summary": summary, "per_function": rows},
                      f, indent=2)
    print(format_comparison(summary, rows, a_name, b_name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
