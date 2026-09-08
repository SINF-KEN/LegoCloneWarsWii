#!/usr/bin/env python3
"""Progress dashboard for the AI decompilation pipeline.

Usage:

    python3 tools/ai_decomp/status.py            # human-readable report
    python3 tools/ai_decomp/status.py --json     # machine-readable
    python3 tools/ai_decomp/status.py --db PATH
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402

GAME_CATEGORIES = {"game"}


def gather(conn):
    totals = db.total_counts(conn)
    statuses = db.status_counts(conn)
    categories = db.category_counts(conn)

    game = sum(n for cat, n in categories.items() if cat in GAME_CATEGORIES)
    library = sum(n for cat, n in categories.items()
                  if cat not in GAME_CATEGORIES and cat != "uncategorized")
    uncategorized = categories.get("uncategorized", 0)

    matched = statuses.get("matched", 0)
    known_matches = 0  # objdiff-known matches (incl. unseeded partial cats)
    for row in conn.execute(
            "SELECT COALESCE(SUM(matched_functions), 0) AS n "
            "FROM category_stats"):
        known_matches = row["n"]

    return {
        "database": {
            "path": None,  # filled by main()
            "functions": totals["functions"],
            "globals": totals["globals"],
            "strings": totals["strings"],
            "instructions": totals["instructions"],
            "caller_edges": totals["caller_edges"],
            "analysis_runs": totals["runs"],
        },
        "functions": {
            "total": totals["functions"],
            "game": game,
            "library_runtime": library,
            "uncategorized": uncategorized,
            "matched": matched,
            "unmatched": totals["functions"] - matched,
            "unknown": statuses.get("unknown", 0),
            "by_status": statuses,
        },
        "known_matches_objdiff": known_matches,
        "coverage": {
            "functions_with_globals": db.functions_with_globals(conn),
            "functions_with_strings": db.functions_with_strings(conn),
            "functions_with_indirect_calls":
                db.functions_with_indirect_calls(conn),
        },
    }


def print_report(info, db_path):
    f = info["functions"]

    print("Database: %s" % db_path)
    print("")
    print("Functions:")
    print("  total:            %d" % f["total"])
    print("  game:             %d" % f["game"])
    print("  library/runtime:  %d" % f["library_runtime"])
    print("  uncategorized:    %d" % f["uncategorized"])
    print("")
    print("Status:")
    print("  matched:          %d" % f["matched"])
    print("  unmatched:        %d" % f["unmatched"])
    print("  unknown:          %d" % f["unknown"])
    other = {k: v for k, v in f["by_status"].items()
             if k not in ("matched", "unknown")}
    if other:
        print("  other:            %s" % ", ".join(
            "%s=%d" % kv for kv in sorted(other.items())))
    print("  (objdiff report knows %d matched functions overall; "
          "per-function status fills in as the pipeline confirms them)"
          % info["known_matches_objdiff"])
    print("")
    print("Content:")
    print("  with globals:       %d" % info["coverage"]["functions_with_globals"])
    print("  with strings:       %d" % info["coverage"]["functions_with_strings"])
    print("  with indirect calls:%d"
          % info["coverage"]["functions_with_indirect_calls"])
    print("")
    print("Storage:")
    print("  globals:          %d" % info["database"]["globals"])
    print("  strings:          %d" % info["database"]["strings"])
    print("  instructions:     %d" % info["database"]["instructions"])
    print("  caller edges:     %d" % info["database"]["caller_edges"])
    print("  analysis runs:    %d" % info["database"]["analysis_runs"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=db.DB_PATH, help="database path")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of a human-readable report")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print("Database %s not found. Run:" % args.db)
        print("  python3 tools/ai_decomp/import_analysis.py")
        return 1

    conn = db.connect(args.db)
    info = gather(conn)
    conn.close()
    info["database"]["path"] = args.db

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print_report(info, args.db)
    return 0


if __name__ == "__main__":
    sys.exit(main())
