#!/usr/bin/env python3
"""Deterministic function prioritization for AI decompilation
(roadmap item #15).

Scores are additive with fixed, documented weights — no ML, fully
reproducible, and every point is explained in the `reasons` column.

    python3 tools/ai_decomp/prioritize.py --limit 25
    python3 tools/ai_decomp/prioritize.py --json --limit 25
    python3 tools/ai_decomp/prioritize.py --address 801b16b0   # breakdown
    python3 tools/ai_decomp/prioritize.py --include-library --include-matched

Weights
-------
category      game +30 | uncategorized +20 | library categories -100
              (runtime/sdk/msl/trk/nulib are excluded entirely unless
              --include-library, in which case they carry the -100)
size band     <32: +0 (trivial)   32-127: +5     128-511: +15
              512-2047: +20       >=2048: +10 (large but diminishing)
callers       +2 per distinct caller, capped at +20
caller state  +6 * (matched callers / known callers)
callee state  +15 * (ready callees / known callees)
              ready = matched, or has repository source, or analyzed
leaf bonus    +8 when the function has no known callees
unknown deps  -3 per unknown direct callee (cap 5), -1 per unknown
              second-level callee (cap 10): A -> B -> C with B and C
              unknown keeps A below B
globals       +2 each, cap +10
strings       +3 each, cap +9
indirect      +4 each (virtual calls), cap +12
analyzed      +5 (Ghidra analysis already imported)
has_source    +8 (existing source to repair beats a cold start)
known caller  +3 (calls into already-analyzed code; it is load-bearing)

Determinism: ties break by caller count desc, size desc, address asc.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402
from dependencies import DependencyGraph  # noqa: E402
from discover import (Discovery, LIBRARY_CATEGORIES,  # noqa: E402
                      DEFAULT_DB, REPO, DEFAULT_REPORT, DEFAULT_OBJDIFF)

DEFAULT_LIMIT = 25


def size_band(size):
    if size is None:
        return 0, "size unknown"
    if size < 32:
        return 0, "trivial (<32 bytes)"
    if size < 128:
        return 5, "small function"
    if size < 512:
        return 15, "medium function"
    if size < 2048:
        return 20, "large function"
    return 10, "very large function (diminishing)"


class Scorer:
    def __init__(self, conn, discovery=None):
        self.conn = conn
        self.discovery = discovery or Discovery(conn)
        self.graph = DependencyGraph(conn)

        # ---- load graph evidence once ----
        self.callers = {}   # addr -> [caller addr]
        self.callees = {}   # addr -> [callee addr]
        for row in conn.execute(
                "SELECT function_address, caller_address "
                "FROM function_callers"):
            self.callers.setdefault(row[0], []).append(row[1])
        for row in conn.execute(
                "SELECT function_address, callee_address "
                "FROM function_callees"):
            self.callees.setdefault(row[0], []).append(row[1])

        self.functions = {db.normalize_address(r["address"]): dict(r)
                          for r in conn.execute("SELECT * FROM functions")}
        self.analyzed_callers = {db.normalize_address(r[0]) for r in
                                 conn.execute(
                                     "SELECT DISTINCT caller_address "
                                     "FROM function_callers")}

    # ---- readiness ----

    def _ready(self, address):
        fn = self.functions.get(address)
        if fn is None:
            return False
        if fn["status"] == "matched":
            return True
        if fn["analyzed"]:
            return True
        return self.discovery.has_source(fn["name"])

    def score(self, address, include_library=False):
        fn = self.functions[address]
        status = fn["status"]
        category = fn["category"]
        reasons = []
        score = 0

        # ---- category ----
        if category == "game":
            score += 30
            reasons.append("+30 game code")
        elif category is None:
            score += 20
            reasons.append("+20 uncategorized module code")
        elif category in LIBRARY_CATEGORIES:
            score += -100 if include_library else 0
            reasons.append("%d %s library code" % (
                -100 if include_library else 0, category))

        # ---- size ----
        band, band_reason = size_band(fn["size"])
        if band:
            score += band
            reasons.append("+%d %s" % (band, band_reason))
        elif fn["size"] is not None:
            reasons.append(band_reason)

        # ---- callers ----
        callers = self.callers.get(address, [])
        if callers:
            score += 2 * min(len(callers), 10)
            reasons.append("+%d %d caller(s)" % (
                2 * min(len(callers), 10), len(callers)))
            matched = sum(1 for c in callers
                          if self.functions.get(c, {}).get("status")
                          == "matched")
            if matched:
                ratio = matched / len(callers)
                pts = int(round(6 * ratio))
                score += pts
                reasons.append("+%d %d/%d callers matched" % (
                    pts, matched, len(callers)))

        # ---- callees / dependency readiness ----
        callees = self.callees.get(address, [])
        if callees:
            ready = [c for c in callees if self._ready(c)]
            if ready:
                pts = int(round(15 * len(ready) / len(callees)))
                score += pts
                reasons.append("+%d %d/%d callees ready" % (
                    pts, len(ready), len(callees)))
            unknown_direct = [c for c in callees if not self._ready(c)]
            if unknown_direct:
                pts = -3 * min(len(unknown_direct), 5)
                score += pts
                reasons.append("%d %d unknown callee(s)" % (
                    pts, len(unknown_direct)))
                # second-level unknowns: chains A->B->C keep A below B
                unknown_deep = 0
                for c in unknown_direct:
                    deep = [d for d in self.callees.get(c, [])
                            if not self._ready(d)]
                    unknown_deep += len(deep)
                if unknown_deep:
                    pts = -1 * min(unknown_deep, 10)
                    score += pts
                    reasons.append("%d %d unknown 2nd-level callee(s)"
                                   % (pts, unknown_deep))
        else:
            score += 8
            reasons.append("+8 leaf (no known callees)")

        # ---- analysis evidence ----
        globals_n = self.conn.execute(
            "SELECT COUNT(*) FROM function_globals WHERE function_address=?",
            (address,)).fetchone()[0]
        strings_n = self.conn.execute(
            "SELECT COUNT(*) FROM function_strings WHERE function_address=?",
            (address,)).fetchone()[0]
        indirect_n = self.conn.execute(
            "SELECT COUNT(*) FROM indirect_calls WHERE function_address=?",
            (address,)).fetchone()[0]

        if globals_n:
            pts = 2 * min(globals_n, 5)
            score += pts
            reasons.append("+%d %d global ref(s)" % (pts, globals_n))
        if strings_n:
            pts = 3 * min(strings_n, 3)
            score += pts
            reasons.append("+%d %d string ref(s)" % (pts, strings_n))
        if indirect_n:
            pts = 4 * min(indirect_n, 3)
            score += pts
            reasons.append("+%d %d indirect call(s)" % (pts, indirect_n))
        if fn["analyzed"]:
            score += 5
            reasons.append("+5 analyzed")

        # ---- source evidence ----
        if self.discovery.has_source(fn["name"]):
            score += 8
            reasons.append("+8 unit has source")

        if address in self.analyzed_callers:
            score += 3
            reasons.append("+3 calls analyzed code")

        return {
            "address": address,
            "name": fn["name"],
            "size": fn["size"],
            "score": score,
            "category": category or "uncategorized",
            "status": status,
            "callers": len(callers),
            "callees": len(callees),
            "globals": globals_n,
            "strings": strings_n,
            "indirect": indirect_n,
            "reasons": reasons,
        }

    # ---- candidate selection ----

    def candidates(self, include_library=False, include_matched=False,
                   include_thunks=False, include_externals=False,
                   category=None, min_size=None, max_size=None):
        """Gate functions, returning addresses eligible for ranking."""
        out = []
        for address, fn in self.functions.items():
            if not include_matched and fn["status"] == "matched":
                continue
            if not include_thunks and fn["is_thunk"]:
                continue
            if not include_externals and fn["is_external"]:
                continue
            if not include_library and fn["category"] in LIBRARY_CATEGORIES:
                continue
            if category and fn["category"] != category:
                continue
            if min_size is not None and (fn["size"] or 0) < min_size:
                continue
            if max_size is not None and (fn["size"] or 0) > max_size:
                continue
            out.append(address)
        return out

    def rank(self, limit=DEFAULT_LIMIT, **kwargs):
        addresses = self.candidates(**kwargs)
        scored = [self.score(a, include_library=kwargs.get(
            "include_library", False)) for a in addresses]
        scored.sort(key=lambda r: (-r["score"], -r["callers"],
                                   -(r["size"] or 0), r["address"]))
        return scored[:limit]


# ----------------------------------------------------------------
# CLI
# ----------------------------------------------------------------

def print_table(rows):
    header = ("%-5s %-9s %-34s %6s %5s %-13s %4s %4s %4s %4s %-9s %s"
              % ("rank", "address", "name", "size", "score", "category",
                 "cal", "cld", "glb", "str", "status", "reasons"))
    print(header)
    print("-" * len(header))
    for i, r in enumerate(rows, 1):
        print("%-5d %-9s %-34s %6s %5d %-13s %4d %4d %4d %4d %-9s %s" % (
            i, r["address"], (r["name"] or "?")[:34],
            r["size"] if r["size"] is not None else "-",
            r["score"], r["category"][:13], r["callers"], r["callees"],
            r["globals"], r["strings"], r["status"] or "-",
            "; ".join(r["reasons"])[:80]))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--address",
                    help="score a single function and show its breakdown")
    ap.add_argument("--include-library", action="store_true",
                    help="rank runtime/sdk/msl/trk/nulib functions too")
    ap.add_argument("--include-matched", action="store_true")
    ap.add_argument("--include-thunks", action="store_true")
    ap.add_argument("--include-externals", action="store_true")
    ap.add_argument("--category",
                    help="only this objdiff category (e.g. game)")
    ap.add_argument("--min-size", type=int)
    ap.add_argument("--max-size", type=int)
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print("Database %s not found. Run:" % args.db)
        print("  python3 tools/ai_decomp/import_analysis.py")
        return 1

    conn = db.connect(args.db)
    scorer = Scorer(conn)

    if args.address:
        address = db.normalize_address(args.address)
        if address not in scorer.functions:
            print("Function %s not in database" % address, file=sys.stderr)
            return 1
        result = scorer.score(address, include_library=True)
        conn.close()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("Score for %s (%s): %d" % (address, result["name"],
                                             result["score"]))
            for reason in result["reasons"]:
                print("  %s" % reason)
        return 0

    rows = scorer.rank(
        limit=args.limit,
        include_library=args.include_library,
        include_matched=args.include_matched,
        include_thunks=args.include_thunks,
        include_externals=args.include_externals,
        category=args.category,
        min_size=args.min_size,
        max_size=args.max_size)
    conn.close()

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print_table(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
