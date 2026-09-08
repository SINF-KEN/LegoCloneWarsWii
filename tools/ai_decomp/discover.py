#!/usr/bin/env python3
"""Function discovery: classify decompilation state from the local
database plus repository evidence (roadmap item #14).

Per function it determines:

  unmatched            status != 'matched' (match status is only ever set
                       from objective objdiff evidence in the database;
                       discovery never guesses matches)
  partially_implemented the function's unit has source that does not
                       (yet) fully match
  has_symbol           a real DTK symbol name (not a Ghidra placeholder)
  has_unknown_name     no symbol or a Ghidra-generated name
  game_candidate       objdiff category 'game' or uncategorized module code
  library_candidate    category runtime/sdk/msl/trk/nulib
  has_source           the function's unit is compiled from repository
                       source (src/<unit>.cpp/.c exists)
  without_source       no source unit
  has_analysis         useful Ghidra analysis: analyzed JSON imported,
                       or global/string/indirect-call facts present

Sources used:
  - the SQLite database (authoritative; no Ghidra rescan)
  - objdiff.json + build/SC4P64/report.json for the symbol -> unit map
  - the src/ tree on disk for unit-level source presence

CLI:

    python3 tools/ai_decomp/discover.py            # summary
    python3 tools/ai_decomp/discover.py --json
    python3 tools/ai_decomp/discover.py 801b16b0   # classify one function
"""

import argparse
import json
import os
import sys
from bisect import bisect_left

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_DB = db.DB_PATH
DEFAULT_REPORT = os.path.join(REPO, "build", "SC4P64", "report.json")
DEFAULT_OBJDIFF = os.path.join(REPO, "objdiff.json")
DEFAULT_SRC = os.path.join(REPO, "src")

LIBRARY_CATEGORIES = {"runtime", "sdk", "msl", "trk", "nulib"}
GAME_CATEGORIES = {"game"}
SOURCE_EXTENSIONS = (".cpp", ".c", ".cxx", ".cc", ".s")


def load_json(path):
    with open(path) as f:
        return json.load(f)


def unit_source_path(unit_name, src_root=DEFAULT_SRC):
    """Filesystem path of a unit's source file, if it exists.

    Unit names look like 'main/nufile.master/nufile_Lump'; the leading
    component is the DOL/REL module and the rest maps into src/.
    """
    parts = unit_name.split("/", 1)
    rel = parts[1] if len(parts) > 1 else parts[0]
    for ext in SOURCE_EXTENSIONS:
        candidate = os.path.join(src_root, rel + ext)
        if os.path.exists(candidate):
            return candidate
    return None


class Discovery:
    """Classification layer over the database + repo evidence."""

    def __init__(self, conn, report_path=DEFAULT_REPORT,
                 objdiff_path=DEFAULT_OBJDIFF, src_root=DEFAULT_SRC):
        self.conn = conn
        self.src_root = src_root

        # symbol name -> set of unit names (static names can repeat)
        self.symbol_units = {}
        self.unit_source = {}
        self._load_units(report_path, objdiff_path)

        # addresses of functions with per-function analysis facts
        self.with_globals = self._addresses(
            "SELECT DISTINCT function_address FROM function_globals")
        self.with_strings = self._addresses(
            "SELECT DISTINCT function_address FROM function_strings")
        self.with_indirect = self._addresses(
            "SELECT DISTINCT function_address FROM indirect_calls")

    # -- setup ------------------------------------------------------

    def _load_units(self, report_path, objdiff_path):
        unit_names = []
        if os.path.exists(objdiff_path):
            unit_names = [u["name"] for u in load_json(objdiff_path)
                          .get("units", [])]
        elif os.path.exists(report_path):
            unit_names = [u["name"] for u in load_json(report_path)
                          .get("units", [])]

        for unit in unit_names:
            self.unit_source[unit] = unit_source_path(unit, self.src_root)

        if os.path.exists(report_path):
            report = load_json(report_path)
            for unit in report.get("units", []):
                name = unit["name"]
                for fn in unit.get("functions", []):
                    self.symbol_units.setdefault(fn["name"], set()) \
                        .add(name)

    def _addresses(self, sql):
        return {db.normalize_address(r[0])
                for r in self.conn.execute(sql)}

    # -- classification ---------------------------------------------

    def units_of(self, name):
        return self.symbol_units.get(name or "", set())

    def has_source(self, name):
        units = self.units_of(name)
        if not units:
            return False
        return any(self.unit_source.get(u) for u in units)

    def classify(self, row):
        """Classify one functions-table row (sqlite3.Row or dict)."""
        address = db.normalize_address(row["address"])
        name = row["name"]
        category = row["category"]
        generic = (not name or name.startswith(("FUN_", "thunk_FUN_",
                                                "fcn_", "??")))
        analyzed = bool(row["analyzed"])
        has_analysis = (analyzed or address in self.with_globals
                        or address in self.with_strings
                        or address in self.with_indirect)

        return {
            "address": address,
            "name": name,
            "size": row["size"],
            "section": row["section"],
            "status": row["status"],
            "category": category,
            "matched": row["status"] == "matched",
            "unmatched": row["status"] != "matched",
            "partially_implemented": (row["status"] != "matched"
                                      and self.has_source(name)),
            "has_symbol": bool(name) and not generic,
            "has_unknown_name": generic,
            "game_candidate": (category in GAME_CATEGORIES
                               or (category is None and not analyzed)),
            "library_candidate": category in LIBRARY_CATEGORIES,
            "has_source": self.has_source(name),
            "source_units": sorted(u for u in self.units_of(name)
                                   if self.unit_source.get(u)),
            "analyzed": analyzed,
            "has_analysis": has_analysis,
            "has_globals": address in self.with_globals,
            "has_strings": address in self.with_strings,
            "has_indirect_calls": address in self.with_indirect,
        }

    def all_classified(self):
        for row in self.conn.execute(
                "SELECT * FROM functions ORDER BY address"):
            yield self.classify(row)

    def one(self, address):
        row = self.conn.execute(
            "SELECT * FROM functions WHERE address = ?",
            (db.normalize_address(address),)).fetchone()
        return self.classify(row) if row else None

    # -- summary ----------------------------------------------------

    def summary(self):
        counts = {
            "total": 0, "matched": 0, "unmatched": 0,
            "partially_implemented": 0, "with_symbol": 0,
            "unknown_name": 0, "game": 0, "library": 0,
            "with_source": 0, "without_source": 0, "with_analysis": 0,
            "with_globals": len(self.with_globals),
            "with_strings": len(self.with_strings),
            "with_indirect": len(self.with_indirect),
        }
        for c in self.all_classified():
            counts["total"] += 1
            counts["matched"] += c["matched"]
            counts["unmatched"] += c["unmatched"]
            counts["partially_implemented"] += c["partially_implemented"]
            counts["with_symbol"] += c["has_symbol"]
            counts["unknown_name"] += c["has_unknown_name"]
            counts["game"] += (c["category"] in GAME_CATEGORIES
                               or c["category"] is None)
            counts["library"] += c["library_candidate"]
            counts["with_source"] += c["has_source"]
            counts["without_source"] += not c["has_source"]
            counts["with_analysis"] += c["has_analysis"]
        # source units known to the build
        counts["source_files"] = sum(
            1 for v in self.unit_source.values() if v)
        return counts


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("address", nargs="?", help="classify one function")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=25,
                    help="list size for the unmatched-source sample")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print("Database %s not found. Run:" % args.db)
        print("  python3 tools/ai_decomp/import_analysis.py")
        return 1

    conn = db.connect(args.db)
    discovery = Discovery(conn)

    if args.address:
        result = discovery.one(args.address)
        conn.close()
        if result is None:
            print("Function %s not in database" % args.address,
                  file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            for key, value in result.items():
                print("%-24s %s" % (key + ":", value))
        return 0

    summary = discovery.summary()
    conn.close()

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print("Discovery summary")
    print("  functions:               %d" % summary["total"])
    print("  matched:                 %d" % summary["matched"])
    print("  unmatched:               %d" % summary["unmatched"])
    print("  partially implemented:   %d"
          % summary["partially_implemented"])
    print("  with DTK symbol:         %d" % summary["with_symbol"])
    print("  unknown name:            %d" % summary["unknown_name"])
    print("  game candidates:         %d" % summary["game"])
    print("  library candidates:      %d" % summary["library"])
    print("  unit has source:         %d" % summary["with_source"])
    print("  without source:          %d" % summary["without_source"])
    print("  with useful analysis:    %d" % summary["with_analysis"])
    print("    ...with globals:       %d" % summary["with_globals"])
    print("    ...with strings:       %d" % summary["with_strings"])
    print("    ...with indirect:      %d" % summary["with_indirect"])
    print("  source files in src/:    %d" % summary["source_files"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
