#!/usr/bin/env python3
"""Import existing analysis output into the local SQLite database.

Inputs (all auto-detected, none required):

  tools/ghidra/output/functions.json        Ghidra function list
  tools/ghidra/output/data_catalog.json     memory blocks + defined data
  tools/ghidra/output/function_*_analyzed.json
                                            per-function analysis (#9-#12)
  config/SC4E64/symbols.txt                 DTK symbol map (original
                                            layout: real names + sizes
                                            for functions and data)
  build/SC4P64/report.json + objdiff.json   objdiff units/categories and
                                            per-category match aggregates

Usage:

    python3 tools/ai_decomp/import_analysis.py                 # import all
    python3 tools/ai_decomp/import_analysis.py --function 801b16b0
    python3 tools/ai_decomp/import_analysis.py --db /tmp/test.db --...

The import is idempotent: running it twice produces the same database
(apart from appended analysis_runs log entries).

Note: build/SC4P64/main.elf is deliberately NOT used as a symbol source.
It is the rebuilt link, whose symbol addresses only match the original
DOL where code already matches (~3%); symbols.txt is the authoritative
original-layout map.
"""

import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_OUTPUT_DIR = os.path.join(REPO, "tools", "ghidra", "output")
DEFAULT_DB = db.DB_PATH
DEFAULT_CONFIG = os.path.join(REPO, "config", "SC4P64", "config.yml")
DEFAULT_REPORT = os.path.join(REPO, "build", "SC4P64", "report.json")
DEFAULT_OBJDIFF = os.path.join(REPO, "objdiff.json")

SYMBOLS_RE = re.compile(
    r"^(\S+) = \.([\w.]+):0x([0-9A-Fa-f]+); "
    r"// type:(\w+) size:0x([0-9A-Fa-f]+)")


# ----------------------------------------------------------------
# input readers
# ----------------------------------------------------------------

def load_json(path):
    with open(path) as f:
        return json.load(f)


def resolve_symbols_path(config_path=DEFAULT_CONFIG):
    """Read the symbols map path from the DTK build config (config.yml)."""
    try:
        with open(config_path) as f:
            for line in f:
                m = re.match(r"^symbols:\s*(\S+)\s*$", line)
                if m:
                    path = m.group(1)
                    if not os.path.isabs(path):
                        path = os.path.join(REPO, path)
                    return path
    except OSError:
        pass
    return os.path.join(REPO, "config", "SC4E64", "symbols.txt")


def parse_symbols_txt(path):
    """Parse a dtk symbols.txt into (functions, data):

    functions: {addr_int: (name, size, section)}
    data:      [(addr_int, name, size, section)]
    """
    functions = {}
    data = []
    with open(path) as f:
        for line in f:
            m = SYMBOLS_RE.match(line.strip())
            if not m:
                continue
            name, section, addr, typ, size = (
                m.group(1), m.group(2), int(m.group(3), 16), m.group(4),
                int(m.group(5), 16))
            if typ == "function":
                functions[addr] = (name, size, section)
            else:
                data.append((addr, name, size, section))
    return functions, data


def build_category_map(report_path, objdiff_path):
    """symbol name -> progress category, from objdiff config + report.

    Only unambiguous mappings are returned: if the same symbol name
    appears in units with different categories it is skipped (common
    with static function names).
    """
    config = load_json(objdiff_path)
    unit_categories = {}
    for unit in config.get("units", []):
        cats = tuple(unit.get("metadata", {}).get("progress_categories",
                                                  ()))
        unit_categories[unit["name"]] = cats

    report = load_json(report_path)
    name_cats = {}
    for unit in report.get("units", []):
        cats = unit_categories.get(unit["name"], ())
        if not cats:
            continue
        for fn in unit.get("functions", []):
            name_cats.setdefault(fn["name"], set()).update(cats)

    return {n: next(iter(c)) for n, c in name_cats.items() if len(c) == 1}


def category_aggregates(report_path):
    """Per-category (total, matched) function counts from the report."""
    report = load_json(report_path)
    stats = []
    for cat in report.get("categories", []):
        measures = cat.get("measures", {})
        stats.append({
            "category": cat["id"],
            "total_functions": int(measures.get("total_functions") or 0),
            "matched_functions":
                int(measures.get("matched_functions") or 0),
        })
    return stats


# ----------------------------------------------------------------
# importers
# ----------------------------------------------------------------

class Importer:
    def __init__(self, conn, catalog=None):
        self.conn = conn
        self.catalog = catalog  # data_analysis.Catalog for sections
        self.stats = {}

    def section_of(self, address_int):
        if self.catalog is None:
            return None
        return self.catalog.section_of(address_int)

    # -- Ghidra function list --

    def import_functions_json(self, path):
        data = load_json(path)
        functions = data.get("functions", [])
        for fn in functions:
            addr = int(fn["address"], 16)
            db.upsert_function(
                self.conn, fn["address"], name=fn.get("name"),
                size=fn.get("size"), section=self.section_of(addr),
                is_thunk=1 if fn.get("thunk") else 0,
                is_external=1 if fn.get("external") else 0,
                source="ghidra")
        self.conn.commit()
        self.stats["functions.json"] = len(functions)

    # -- DTK symbols.txt (original layout, authoritative names/sizes) --

    def import_symbols(self, path):
        functions, data = parse_symbols_txt(path)

        existing = {r["address"]: r["name"] for r in
                    self.conn.execute("SELECT address, name FROM functions")}
        renamed = added = 0
        for addr, (name, size, section) in functions.items():
            hexaddr = "%08x" % addr
            current = existing.get(hexaddr)
            db.upsert_function(
                self.conn, hexaddr, name=name, size=size, section=section,
                priority="high", source="symbols")
            if current is None:
                added += 1
            elif current != name:
                renamed += 1

        db.upsert_globals(
            self.conn,
            [{"address": "%08x" % addr, "label": name, "section": section}
             for addr, name, _size, section in data],
            source="symbols", priority="high")
        self.conn.commit()
        self.stats["symbols"] = {
            "functions": len(functions), "added": added,
            "renamed": renamed, "data_labels": len(data)}

    # -- data catalog --

    def import_catalog(self, path):
        data = load_json(path)

        blocks = [(int(b["start"], 16), int(b["end"], 16), b["name"])
                  for b in data.get("memory_blocks", [])]

        def section_of(addr_int):
            for start, end, name in blocks:
                if start <= addr_int <= end:
                    return name
            return None

        globals_rows = []
        string_rows = []
        for entry in data.get("data", []):
            addr_hex, size, label, dtype, value = entry
            addr_int = int(addr_hex, 16)
            section = section_of(addr_int)
            globals_rows.append({
                "address": addr_hex, "section": section, "label": label,
                "data_type": dtype, "data_size": size, "string": value,
            })
            if value is not None:
                encoding = "UTF-16BE" if ("unicode" in (dtype or ""
                                                     ).lower()) else "ASCII"
                string_rows.append({
                    "address": addr_hex, "contents": value,
                    "encoding": encoding, "data_type": dtype,
                    "length": size, "section": section,
                })

        db.upsert_globals(self.conn, globals_rows, source="catalog")
        db.upsert_strings(self.conn, string_rows)
        self.conn.commit()
        self.stats["catalog"] = {
            "globals": len(globals_rows), "strings": len(string_rows)}

    # -- objdiff categories + match aggregates --

    def import_report(self, report_path, objdiff_path):
        name_cat = build_category_map(report_path, objdiff_path)
        aggregates = category_aggregates(report_path)
        fully_matched = {s["category"] for s in aggregates
                         if s["matched_functions"]
                         and s["matched_functions"] == s["total_functions"]}

        renamed = 0
        for row in self.conn.execute(
                "SELECT address, name, status FROM functions "
                "WHERE category IS NULL OR status = 'unknown'").fetchall():
            if row["name"] is None:
                continue
            category = name_cat.get(row["name"])
            status = ("matched"
                      if category in fully_matched
                      and row["status"] == "unknown" else None)
            if category or status:
                db.upsert_function(self.conn, row["address"],
                                   category=category, status=status)
                renamed += 1
        db.upsert_category_stats(self.conn, aggregates)
        self.conn.commit()
        self.stats["report"] = {
            "categorized_or_matched": renamed,
            "categories": {s["category"]: s for s in aggregates}}

    # -- per-function analyzed JSON --

    def import_analyzed_file(self, path):
        data = load_json(path)
        address = db.normalize_address(data.get("address"))
        if not address:
            raise ValueError("%s has no address" % path)

        derived = data.get("derived", {})
        db.upsert_function(
            self.conn, address,
            name=data.get("name"),
            size=data.get("size"),
            signature=data.get("signature"),
            return_type=data.get("return_type"),
            analyzed=1, source="ghidra")

        if self.catalog is not None and data.get("size"):
            entry = int(address, 16)
            section = self.section_of(entry)
            if section:
                db.upsert_function(self.conn, address, section=section)

        callers = [c["address"] for c in data.get("callers", [])]
        callees = [c["address"] for c in data.get("callees", [])]
        db.set_function_links(self.conn, "function_callers", "caller_address",
                              address, callers)
        db.set_function_links(self.conn, "function_callees", "callee_address",
                              address, callees)

        n_instr = db.replace_instructions(
            self.conn, address, data.get("instructions", []))
        n_indirect = db.record_indirect_calls(
            self.conn, address, derived.get("indirect_calls", []))
        n_globals = db.link_function_globals(
            self.conn, address, data.get("global_references", []))
        n_strings = db.link_function_strings(
            self.conn, address, data.get("string_references", []))
        self.conn.commit()

        self.stats.setdefault("analyzed", {})[address] = {
            "instructions": n_instr, "indirect_calls": n_indirect,
            "globals": n_globals, "strings": n_strings,
            "callers": len(callers), "callees": len(callees)}

    def import_analyzed_dir(self, directory):
        paths = sorted(glob.glob(
            os.path.join(directory, "function_*_analyzed.json")))
        for path in paths:
            self.import_analyzed_file(path)
        return len(paths)


# ----------------------------------------------------------------
# CLI
# ----------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DEFAULT_DB, help="database path")
    ap.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                    help="Ghidra output directory")
    ap.add_argument("--functions", help="functions.json (default: <output-dir>/functions.json)")
    ap.add_argument("--catalog", help="data_catalog.json (default: <output-dir>/data_catalog.json)")
    ap.add_argument("--analyzed-dir", help="directory with function_*_analyzed.json (default: <output-dir>)")
    ap.add_argument("--function", metavar="ADDR",
                    help="import a single function_<ADDR>_analyzed.json")
    ap.add_argument("--elf", default=None,
                    help=argparse.SUPPRESS)  # deprecated, unused
    ap.add_argument("--symbols", default=None,
                    help="dtk symbols.txt (default: resolved from "
                         "config/SC4P64/config.yml; empty to skip)")
    ap.add_argument("--report", default=DEFAULT_REPORT,
                    help="objdiff report.json (empty to skip)")
    ap.add_argument("--objdiff", default=DEFAULT_OBJDIFF,
                    help="objdiff.json config (empty to skip)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    functions_path = args.functions or os.path.join(
        args.output_dir, "functions.json")
    catalog_path = args.catalog or os.path.join(
        args.output_dir, "data_catalog.json")
    analyzed_dir = args.analyzed_dir or args.output_dir
    symbols_path = args.symbols
    if symbols_path is None:
        symbols_path = resolve_symbols_path()

    # catalog is needed for section lookups even when --function is used
    catalog = None
    if os.path.exists(catalog_path):
        sys.path.insert(0, HERE)
        import data_analysis
        catalog = data_analysis.Catalog(catalog_path)

    conn = db.connect(args.db)
    importer = Importer(conn, catalog=catalog)

    sources = []
    if os.path.exists(functions_path):
        importer.import_functions_json(functions_path)
        sources.append("functions.json")
    if os.path.exists(catalog_path):
        importer.import_catalog(catalog_path)
        sources.append("data_catalog.json")
    if symbols_path and os.path.exists(symbols_path):
        importer.import_symbols(symbols_path)
        sources.append(os.path.basename(symbols_path))
    if args.report and args.objdiff and os.path.exists(args.report) \
            and os.path.exists(args.objdiff):
        importer.import_report(args.report, args.objdiff)
        sources.append("report.json")

    if args.function:
        path = os.path.join(analyzed_dir,
                            "function_%s_analyzed.json" % args.function)
        if not os.path.exists(path):
            path = os.path.join(analyzed_dir,
                                "function_%s.json" % args.function)
        importer.import_analyzed_file(path)
        sources.append(path)
    else:
        n = importer.import_analyzed_dir(analyzed_dir)
        if n:
            sources.append("%d analyzed function files" % n)

    db.record_analysis_run(conn, "import", ", ".join(sources),
                           importer.stats)
    conn.commit()
    conn.close()

    if not args.quiet:
        totals = importer.stats
        print("Imported into %s from: %s" % (args.db, ", ".join(sources)))
        for key, value in totals.items():
            print("  %s: %s" % (key, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
