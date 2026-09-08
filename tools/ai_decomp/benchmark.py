#!/usr/bin/env python3
"""Deterministic 10-function benchmark selection for Phase 5.6."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database


REPO = os.path.abspath(os.path.join(HERE, "..", ".."))


def unit_source_map(report_path=None, objdiff_path=None, src_root=None):
    """Unit name -> existing source path (only source-backed units)."""
    report_path = report_path or os.path.join(
        REPO, "build", "SC4P64", "report.json")
    objdiff_path = objdiff_path or os.path.join(REPO, "objdiff.json")
    src_root = src_root or os.path.join(REPO, "src")
    mapping = {}
    try:
        with open(objdiff_path) as f:
            config = json.load(f)
        for unit in config.get("units", []):
            name = unit["name"]
            parts = name.split("/", 1)
            rel = parts[1] if len(parts) > 1 else parts[0]
            for ext in (".cpp", ".c", ".cxx", ".cc", ".s"):
                candidate = os.path.join(src_root, rel + ext)
                if os.path.exists(candidate):
                    mapping[name] = candidate
                    break
    except OSError:
        pass
    return mapping


def symbol_units(report_path):
    """symbol name -> set of unit names, from the objdiff report."""
    try:
        with open(report_path) as f:
            report = json.load(f)
    except OSError:
        return {}
    out = {}
    for unit in report.get("units", []):
        for fn in unit.get("functions", []):
            out.setdefault(fn["name"], set()).add(unit["name"])
    return out


def is_real_name(name: str | None) -> bool:
    if not name:
        return False
    return not name.startswith(("FUN_", "thunk_FUN_", "fcn_"))


def load_functions(conn):
    rows = conn.execute("""
        SELECT address, name, size, section, is_thunk, is_external,
               signature, return_type, status, category, analyzed
        FROM functions
        WHERE is_external = 0
          AND is_thunk = 0
          AND size IS NOT NULL
          AND size > 0
        ORDER BY address
    """).fetchall()
    return {r["address"]: dict(r) for r in rows}


def evidence_counts(conn):
    tables = {
        "callers": "SELECT function_address, COUNT(*) n FROM function_callers GROUP BY function_address",
        "globals": "SELECT function_address, COUNT(*) n FROM function_globals GROUP BY function_address",
        "strings": "SELECT function_address, COUNT(*) n FROM function_strings GROUP BY function_address",
        "indirect_calls": "SELECT function_address, COUNT(*) n FROM indirect_calls GROUP BY function_address",
        "instructions": "SELECT function_address, COUNT(*) n FROM instructions GROUP BY function_address",
        "type_evidence": "SELECT function_address, COUNT(*) n FROM type_evidence GROUP BY function_address",
    }

    result = defaultdict(lambda: defaultdict(int))

    for kind, sql in tables.items():
        for row in conn.execute(sql):
            result[row["function_address"]][kind] = row["n"]

    return result


def classify(row, evidence):
    size = row["size"] or 0
    e = evidence.get(row["address"], {})

    if e.get("indirect_calls", 0):
        return "virtual_or_indirect"

    if e.get("strings", 0):
        return "string_reference"

    if e.get("globals", 0):
        return "global_access"

    if e.get("type_evidence", 0):
        return "type_or_struct_evidence"

    if e.get("callers", 0):
        return "call_graph"

    if size <= 32:
        return "small_leaf"

    if size <= 256:
        return "medium_function"

    if size >= 8000:
        return "large_function"

    if size >= 2000:
        return "complex_function"

    return "general_function"


def score(row, archetype, evidence):
    """Deterministic quality score within an archetype."""
    size = row["size"] or 0
    e = evidence.get(row["address"], {})

    score = 0

    if is_real_name(row["name"]):
        score += 100

    if row["status"] == "matched":
        score -= 1000  # benchmark should test decompilation, not known matches

    if row["status"] == "matching":
        score -= 500

    # Prefer functions with actual available analysis evidence.
    score += min(e.get("callers", 0), 20) * 4
    score += min(e.get("globals", 0), 10) * 8
    score += min(e.get("strings", 0), 5) * 10
    score += min(e.get("indirect_calls", 0), 4) * 20
    score += min(e.get("type_evidence", 0), 5) * 10
    score += min(e.get("instructions", 0), 100) // 10

    # Avoid enormous functions for categories where size is not the point.
    if archetype in {"small_leaf", "medium_function"}:
        score -= max(0, size - 1000) // 100

    return score


ARCHETYPES = [
    "small_leaf",
    "medium_function",
    "global_access",
    "string_reference",
    "virtual_or_indirect",
    "type_or_struct_evidence",
    "call_graph",
    "complex_function",
    "large_function",
    "general_function",
]


def select(conn, count=10, require_unit_source=True):
    functions = load_functions(conn)
    evidence = evidence_counts(conn)
    report_path = os.path.join(REPO, "build", "SC4P64", "report.json")
    sym_units = symbol_units(report_path)
    unit_sources = unit_source_map() if require_unit_source else {}

    def has_unit_source(row):
        if not require_unit_source:
            return True
        for unit in sym_units.get(row["name"] or "", set()):
            if unit_sources.get(unit):
                return True
        return False

    def eligible(row):
        name = row["name"] or ""
        if row["status"] in {"matched", "matching"}:
            return False
        if row["is_thunk"] or row["is_external"]:
            return False
        if name.startswith("__"):
            return False
        if not has_unit_source(row):
            return False
        return True

    candidates = []

    for address, row in functions.items():
        if not eligible(row):
            continue

        e = evidence.get(address, {})
        size = row["size"] or 0

        signals = {
            "callers": e.get("callers", 0),
            "globals": e.get("globals", 0),
            "strings": e.get("strings", 0),
            "indirect_calls": e.get("indirect_calls", 0),
            "type_evidence": e.get("type_evidence", 0),
            "instructions": e.get("instructions", 0),
        }

        # Evidence-first archetype assignment. Size is only used when
        # there is no stronger observed semantic signal.
        if signals["indirect_calls"]:
            archetype = "virtual_or_indirect"
        elif signals["strings"]:
            archetype = "string_reference"
        elif signals["globals"]:
            archetype = "global_access"
        elif signals["type_evidence"]:
            archetype = "type_or_struct_evidence"
        elif signals["callers"] >= 5:
            archetype = "call_graph"
        elif size <= 32:
            archetype = "small_leaf"
        elif size <= 256:
            archetype = "medium_function"
        elif size < 2048:
            archetype = "1_2kb_function"
        elif size < 8000:
            archetype = "complex_function"
        else:
            archetype = "large_function"

        # Prefer real symbols, useful evidence, and moderate sizes.
        score = 0
        if is_real_name(row["name"]):
            score += 100

        score += min(signals["callers"], 20) * 5
        score += min(signals["globals"], 10) * 12
        score += min(signals["strings"], 5) * 15
        score += min(signals["indirect_calls"], 4) * 25
        score += min(signals["type_evidence"], 5) * 12
        score += min(signals["instructions"], 100) // 10

        # Avoid choosing enormous outliers when a category has alternatives.
        if archetype == "large_function":
            score -= max(0, size - 10000) // 500

        candidates.append(
            (archetype, score, address, row, signals)
        )

    # Required coverage. Evidence-backed categories are preferred first;
    # metadata/size categories fill the remaining slots.
    preferred = [
        "small_leaf",
        "medium_function",
        "global_access",
        "string_reference",
        "virtual_or_indirect",
        "type_or_struct_evidence",
        "call_graph",
        "1_2kb_function",
        "complex_function",
        "large_function",
    ]

    selected = []
    used = set()

    for archetype in preferred:
        pool = [
            item for item in candidates
            if item[0] == archetype and item[2] not in used
        ]

        if not pool:
            continue

        pool.sort(key=lambda x: (-x[1], x[2]))
        archetype_name, score_value, address, row, signals = pool[0]

        selected.append({
            "rank": len(selected) + 1,
            "address": address,
            "name": row["name"],
            "size": row["size"],
            "section": row["section"],
            "status_at_selection": row["status"],
            "unit": sorted(sym_units.get(row["name"] or "", set()))[0]
                    if sym_units.get(row["name"] or "") else None,
            "unit_source": sorted(
                unit_sources.get(u) for u in
                sym_units.get(row["name"] or "", set())
                if unit_sources.get(u))[0]
                if any(unit_sources.get(u) for u in
                       sym_units.get(row["name"] or "", set()))
                else None,
            "archetype": archetype_name,
            "score": score_value,
            "evidence": dict(signals),
        })
        used.add(address)

    # Fill any remaining slots deterministically from the strongest
    # unused candidates, preferring category diversity: at most two
    # functions per archetype in the filled slots.
    archetype_fill = {}
    for item in selected:
        archetype_fill[item["archetype"]] = \
            archetype_fill.get(item["archetype"], 0) + 1
    remaining = [
        item for item in candidates
        if item[2] not in used
    ]
    remaining.sort(key=lambda x: (-x[1], x[2]))

    for archetype_name, score_value, address, row, signals in remaining:
        if len(selected) >= count:
            break
        if archetype_fill.get(archetype_name, 0) >= 3:
            continue
        archetype_fill[archetype_name] = \
            archetype_fill.get(archetype_name, 0) + 1

        unit_list = sorted(sym_units.get(row["name"] or "", set()))
        source_list = sorted(unit_sources.get(u) for u in unit_list
                             if unit_sources.get(u))
        selected.append({
            "rank": len(selected) + 1,
            "address": address,
            "name": row["name"],
            "size": row["size"],
            "section": row["section"],
            "status_at_selection": row["status"],
            "unit": unit_list[0] if unit_list else None,
            "unit_source": source_list[0] if source_list else None,
            "archetype": archetype_name,
            "score": score_value,
            "evidence": dict(signals),
        })
        used.add(address)

    return selected[:count]


REQUIRED_FIELDS = ("rank", "address", "name", "size", "archetype",
                   "status_at_selection")
KNOWN_ARCHETYPES = {
    "small_leaf", "medium_function", "global_access",
    "string_reference", "virtual_or_indirect",
    "type_or_struct_evidence", "call_graph", "1_2kb_function",
    "complex_function", "large_function", "general_function",
}


class ManifestError(ValueError):
    pass


def load_manifest(path):
    with open(path) as f:
        return json.load(f)


def validate_manifest(manifest, conn, count=10):
    """Validate a benchmark manifest against the analyzed function set.

    Raises ManifestError with a precise reason on any violation.
    """
    if not isinstance(manifest, dict):
        raise ManifestError("manifest must be an object")
    functions = manifest.get("functions")
    if not isinstance(functions, list):
        raise ManifestError("manifest.functions must be a list")
    if len(functions) != count:
        raise ManifestError("expected %d functions, got %d"
                            % (count, len(functions)))

    seen = set()
    for item in functions:
        if not isinstance(item, dict):
            raise ManifestError("function entries must be objects")
        for field in REQUIRED_FIELDS:
            if field not in item:
                raise ManifestError("missing required field %r in %r"
                                    % (field, item))
        address = str(item["address"]).strip().lower()
        if address in seen:
            raise ManifestError("duplicate address %s" % address)
        seen.add(address)
        if item["archetype"] not in KNOWN_ARCHETYPES:
            raise ManifestError("malformed archetype %r for %s"
                                % (item["archetype"], address))
        if not isinstance(item["size"], int) or item["size"] <= 0:
            raise ManifestError("invalid size for %s" % address)

        row = conn.execute(
            "SELECT name FROM functions WHERE address = ?",
            (address,)).fetchone()
        if row is None:
            raise ManifestError("address %s not present in the "
                                "analyzed function set" % address)
        if (row["name"] or "") != (item["name"] or ""):
            raise ManifestError("name mismatch for %s: manifest %r vs "
                                "database %r"
                                % (address, item["name"], row["name"]))
    return True


def print_benchmark(manifest, conn=None):
    functions = manifest.get("functions", [])
    print("Benchmark functions (%d):" % len(functions))
    for item in functions:
        verified = ""
        if conn is not None:
            row = conn.execute(
                "SELECT name FROM functions WHERE address = ?",
                (item["address"],)).fetchone()
            if row and row["name"] != item["name"]:
                verified = "  [name mismatch vs database!]"
        print("%2d %-9s size=%-6d %-14s %s%s" % (
            item["rank"], item["address"], item["size"],
            item["archetype"], item["name"] or "?", verified))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument(
        "--output",
        default="tools/ai_decomp/benchmark_10.json",
    )
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()

    conn = database.connect()
    selected = select(conn, args.count)
    conn.close()

    payload = {
        "version": 1,
        "phase": "5.6",
        "count": len(selected),
        "selection": "frozen_deterministic",
        "functions": selected,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print(f"selected {len(selected)} functions")
    print(f"wrote {args.output}")

    for item in selected:
        print(
            f'{item["rank"]:2d} '
            f'{item["address"]} '
            f'{item["name"] or "?"} '
            f'size={item["size"]} '
            f'archetype={item["archetype"]} '
            f'score={item["score"]}'
        )


if __name__ == "__main__":
    main()
