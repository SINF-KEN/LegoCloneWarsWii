#!/usr/bin/env python3
"""Focused context packages for AI decompilation (roadmap item #18).

Given a function address, assembles everything relevant for producing
matching C — and nothing else:

  function identity     address, name, size, category, status, section,
                        signature, return type
  assembly              authoritative observed machine code (from the
                        Ghidra export)
  decompilation         Ghidra's C (evidence, not ground truth)
  derived facts         ppc_analyzer output: register values, memory
                        accesses, address constructions, virtual calls
  callers / callees     direct relations with match state, plus bounded
                        graph statistics (depth-limited, count-capped)
  globals / strings     this function's data references (#11/#12)
  indirect calls        mtctr/bctr dispatch sites
  dependency info       closures, cycles (from dependencies.py)
  existing source       the unit's source file excerpt when present
  headers               include/ files matching the symbol
  m2c candidate C       via m2c.py (candidate only, never authoritative)
  match information     database status + objdiff category aggregates

The SQLite database is the primary query layer; raw exports are read
only for assembly/decompilation/derived facts. Everything is size- and
relevance-capped so the package can be fed to an LLM directly.

CLI:
    python3 tools/ai_decomp/context.py 801b16b0
    python3 tools/ai_decomp/context.py 801b16b0 --format markdown
    python3 tools/ai_decomp/context.py 801b16b0 --json-out ctx.json
"""

import argparse
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402
import m2c as m2c_mod  # noqa: E402
from dependencies import DependencyGraph  # noqa: E402
from discover import (Discovery, GAME_CATEGORIES,  # noqa: E402
                      LIBRARY_CATEGORIES)

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT_DIR = os.path.join(REPO, "tools", "ghidra", "output")
INCLUDE_DIR = os.path.join(REPO, "include")
SRC_DIR = os.path.join(REPO, "src")

SCHEMA = "context/v1"

# relevance limits (tuned for LLM context windows)
DEFAULT_MAX_RELATIONS = 20
DEFAULT_DEPTH = 2
MAX_SOURCE_CHARS = 12000
MAX_DECOMP_CHARS = 24000
MAX_ASSEMBLY_LINES = 400
MAX_HEADER_LINES = 80
MAX_HEADERS = 2


def load_json(path):
    with open(path) as f:
        return json.load(f)


def truncate(text, limit, note):
    if text is None or len(text) <= limit:
        return text, False
    return text[:limit] + "\n/* ...truncated... */", True


def symbol_tokens(name):
    """Plausible identifiers inside a (possibly mangled) symbol."""
    if not name:
        return []
    tokens = []
    base = name.split("__")[0]
    if base and not base[0].isdigit():
        tokens.append(base)
    # class names in MWCC mangling: __ct__10NuFilePipeFib -> NuFilePipe
    for m in re.finditer(r"(\d+)([A-Za-z_]\w*)", name):
        tokens.append(m.group(2))
    return sorted(set(tokens), key=len, reverse=True)


def find_unit_source(name, discovery):
    """The unit's source file for a symbol, if it exists."""
    units = discovery.units_of(name)
    for unit in sorted(units):
        path = discovery.unit_source.get(unit)
        if path:
            return unit, path
    return None, None


def excerpt_source(path, name, limit=MAX_SOURCE_CHARS):
    """Read a source file, centered on the function when findable."""
    try:
        with open(path, errors="replace") as f:
            text = f.read()
    except OSError as exc:
        return None, str(exc), False

    token = None
    if name:
        token = name.split("__")[0]
    excerpt = text
    truncated = False
    if token and len(text) > limit:
        idx = text.find(token)
        if idx >= 0:
            start = max(0, idx - 2000)
            excerpt = text[start:start + limit]
            truncated = True
    if len(excerpt) > limit:
        excerpt, truncated = truncate(excerpt, limit,
                                      "source truncated")
    return excerpt, None, truncated or len(text) > len(excerpt)


def find_headers(name, max_headers=MAX_HEADERS,
                 max_lines=MAX_HEADER_LINES):
    """include/ files whose name matches a symbol token."""
    if not name or not os.path.isdir(INCLUDE_DIR):
        return []
    matches = []
    for token in symbol_tokens(name):
        if len(token) < 5:
            continue
        for root, _dirs, files in os.walk(INCLUDE_DIR):
            for fname in files:
                if token.lower() in fname.lower():
                    path = os.path.join(root, fname)
                    if path not in [m[0] for m in matches]:
                        matches.append((path, token))
        if matches:
            break
    out = []
    for path, token in matches[:max_headers]:
        try:
            with open(path, errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    lines.append(line.rstrip("\n"))
            out.append({"path": os.path.relpath(path, REPO),
                        "matched_token": token,
                        "excerpt": "\n".join(lines),
                        "truncated": len(lines) >= max_lines})
        except OSError:
            continue
    return out


def build_context(address, conn=None, max_relations=DEFAULT_MAX_RELATIONS,
                  depth=DEFAULT_DEPTH, run_m2c=True,
                  output_dir=OUTPUT_DIR, src_root=SRC_DIR,
                  include_dir=INCLUDE_DIR, mismatch=None):
    """Assemble the context package for one function."""
    address = db.normalize_address(address)
    own_conn = conn is None
    if own_conn:
        conn = db.connect()

    fn = conn.execute("SELECT * FROM functions WHERE address = ?",
                      (address,)).fetchone()
    if fn is None:
        if own_conn:
            conn.close()
        raise ValueError("function %s not in database" % address)
    fn = dict(fn)

    # ---- raw exports: assembly, decompilation, derived facts ----
    raw = None
    raw_path = None
    for candidate in ("function_%s_analyzed.json" % address,
                      "function_%s.json" % address):
        path = os.path.join(output_dir, candidate)
        if os.path.exists(path):
            raw = load_json(path)
            raw_path = path
            break

    assembly = []
    decompilation = None
    derived = {}
    if raw:
        assembly = raw.get("instructions", [])
        decompilation = raw.get("decompilation")
        derived = raw.get("derived", {})

    graph = DependencyGraph(conn)
    discovery = Discovery(conn, src_root=src_root)

    # ---- relations, capped ----
    def relations(addresses):
        rows = []
        for rel_addr in addresses:
            info = graph.function(rel_addr)
            rows.append({
                "address": info["address"],
                "name": info.get("name"),
                "status": info.get("status") or "unimported",
                "category": info.get("category"),
                "size": info.get("size"),
                "matched": info.get("status") == "matched",
            })
        rows.sort(key=lambda r: (not r["matched"], r["address"]))
        return rows[:max_relations], len(rows)

    callers, callers_total = relations(
        [c["address"] for c in graph.direct_callers(address)])
    callees, callees_total = relations(
        [c["address"] for c in graph.direct_callees(address)])

    callers_deep = graph.callers_up_to(address, depth)
    callees_deep = graph.callees_up_to(address, depth)
    reverse_closure = graph.reverse_dependency_closure(address)
    dependency_closure = graph.dependency_closure(address)
    cycles = [sorted(c) for c in graph.sccs_from(address)]

    globals_rows = [dict(r) for r in conn.execute(
        "SELECT * FROM function_globals WHERE function_address = ?",
        (address,))]
    strings_rows = [dict(r) for r in conn.execute(
        "SELECT * FROM function_strings WHERE function_address = ?",
        (address,))]
    indirect_rows = [dict(r) for r in conn.execute(
        "SELECT * FROM indirect_calls WHERE function_address = ?",
        (address,))]

    # ---- existing source / headers ----
    unit, unit_src = find_unit_source(fn["name"], discovery)
    source_excerpt = None
    source_error = None
    source_truncated = False
    if unit_src:
        source_excerpt, source_error, source_truncated = excerpt_source(
            unit_src, fn["name"])
    headers = find_headers(fn["name"])

    # ---- m2c candidate ----
    m2c_info = None
    if run_m2c:
        cached_meta = os.path.join(m2c_mod.ATTEMPTS_DIR, address, "m2c",
                                   "meta.json")
        if os.path.exists(cached_meta):
            m2c_info = load_json(cached_meta)
        else:
            m2c_info = m2c_mod.decompile(address, write=True)

    # ---- match info ----
    category_stats = [dict(r) for r in conn.execute(
        "SELECT * FROM category_stats")]
    match_info = {
        "status": fn["status"],
        "note": ("matched means objdiff-confirmed 100% for this function; "
                 "anything else is unmatched"),
        "objdiff_category_totals": {s["category"]: {
            "total": s["total_functions"],
            "matched": s["matched_functions"]} for s in category_stats},
    }

    # ---- evidence quality ----
    evidence = {
        "assembly_available": bool(assembly),
        "assembly_lines": len(assembly),
        "has_ghidra_decompilation": bool(decompilation),
        "analyzed": bool(fn["analyzed"]),
        "derived_fact_count": sum(
            len(v) for v in derived.values() if isinstance(v, list)),
        "has_m2c_candidate": bool(m2c_info
                                  and m2c_info.get("candidate_c")),
        "call_graph_sparse": (callers_total == 0 and callees_total == 0),
        "confidence_notes": [],
    }
    if not assembly:
        evidence["confidence_notes"].append(
            "no assembly export; context is weak")
    if callers_total == 0 and callees_total == 0:
        evidence["confidence_notes"].append(
            "no call-graph edges known for this function yet")
    if m2c_info and m2c_info.get("status") != "ok":
        evidence["confidence_notes"].append("m2c failed on this function")

    context = {
        "schema": SCHEMA,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "function": {
            "address": address,
            "name": fn["name"],
            "size": fn["size"],
            "category": fn["category"] or "uncategorized",
            "status": fn["status"],
            "section": fn["section"],
            "signature": fn["signature"] or (raw or {}).get("signature"),
            "return_type": fn["return_type"]
                or (raw or {}).get("return_type"),
            "is_thunk": bool(fn["is_thunk"]),
            "is_external": bool(fn["is_external"]),
            "analyzed": bool(fn["analyzed"]) or raw is not None,
        },
        "assembly": assembly[:MAX_ASSEMBLY_LINES],
        "assembly_truncated": len(assembly) > MAX_ASSEMBLY_LINES,
        "decompilation": None,
        "callers": callers,
        "callers_total": callers_total,
        "callees": callees,
        "callees_total": callees_total,
        "graph": {
            "depth_limit": depth,
            "callers_within_depth": len(callers_deep),
            "callees_within_depth": len(callees_deep),
            "reverse_closure_size": len(reverse_closure),
            "dependency_closure_size": len(dependency_closure),
            "cycles": cycles,
        },
        "globals": globals_rows,
        "strings": strings_rows,
        "indirect_calls": indirect_rows,
        "derived": derived,
        "source": {
            "unit": unit,
            "path": unit_src,
            "excerpt": source_excerpt,
            "error": source_error,
            "truncated": source_truncated,
        },
        "headers": headers,
        "mismatch": mismatch,
        "m2c": None,
        "match_info": match_info,
        "evidence": evidence,
        "limits": {
            "max_relations": max_relations,
            "depth": depth,
            "max_source_chars": MAX_SOURCE_CHARS,
            "max_decomp_chars": MAX_DECOMP_CHARS,
        },
    }

    decompilation, decomp_truncated = truncate(
        decompilation, MAX_DECOMP_CHARS, "decompilation truncated")
    context["decompilation"] = decompilation
    context["decompilation_truncated"] = decomp_truncated

    if m2c_info:
        candidate, cand_truncated = truncate(
            m2c_info.get("candidate_c"), 12000, "m2c output truncated")
        context["m2c"] = {
            "status": m2c_info.get("status"),
            "version": m2c_info.get("m2c_version"),
            "candidate_c": candidate,
            "warnings": m2c_info.get("warnings", []),
            "errors": m2c_info.get("errors", []),
            "truncated": cand_truncated,
        }

    if own_conn:
        conn.close()
    return context


# ----------------------------------------------------------------
# Markdown rendering
# ----------------------------------------------------------------

def _render_mismatch_lines(mismatch):
    import json as _json
    text = _json.dumps(mismatch, indent=2)
    if len(text) > 6000:
        text = text[:6000] + "\n/* ...truncated... */"
    return "```json\n" + text + "\n```"


def render_markdown(ctx):
    f = ctx["function"]
    lines = []
    lines.append("# Decompilation context: %s (%s)" % (
        f["name"] or "unknown", f["address"]))
    lines.append("")
    lines.append("## Function")
    lines.append("- address: `%s`" % f["address"])
    lines.append("- name: %s" % (f["name"] or "(unknown)"))
    lines.append("- size: %s bytes" % f["size"])
    lines.append("- category: %s" % f["category"])
    lines.append("- status: %s (%s)" % (f["status"],
                                        ctx["match_info"]["note"]))
    lines.append("- section: %s" % f["section"])
    lines.append("- signature: %s" % (f["signature"] or "(unknown)"))
    lines.append("- return type: %s" % (f["return_type"] or "(unknown)"))
    lines.append("- thunk: %s, external: %s" % (
        f["is_thunk"], f["is_external"]))

    if ctx["assembly"]:
        lines.append("")
        lines.append("## Assembly (authoritative observed machine code)")
        lines.append("```asm")
        lines.extend(ctx["assembly"])
        lines.append("```")

    if ctx["decompilation"]:
        lines.append("")
        lines.append("## Ghidra decompilation (evidence, not ground truth)")
        lines.append("```c")
        lines.append(ctx["decompilation"])
        lines.append("```")

    if ctx["derived"]:
        lines.append("")
        lines.append("## Derived PowerPC facts (ppc_analyzer)")
        lines.append("```json")
        lines.append(json.dumps(ctx["derived"], indent=2))
        lines.append("```")

    lines.append("")
    lines.append("## Callers (%d known%s)" % (
        ctx["callers_total"],
        ", showing %d" % len(ctx["callers"])
        if len(ctx["callers"]) < ctx["callers_total"] else ""))
    for c in ctx["callers"]:
        lines.append("- `%s` %s — status %s%s" % (
            c["address"], c["name"] or "?", c["status"],
            " [matched]" if c["matched"] else ""))
    lines.append("")
    lines.append("## Callees (%d known)" % ctx["callees_total"])
    for c in ctx["callees"]:
        lines.append("- `%s` %s — status %s%s" % (
            c["address"], c["name"] or "?", c["status"],
            " [matched]" if c["matched"] else ""))
    g = ctx["graph"]
    lines.append("")
    lines.append("## Graph (depth limit %d)" % g["depth_limit"])
    lines.append("- callers within depth: %d" % g["callers_within_depth"])
    lines.append("- callees within depth: %d" % g["callees_within_depth"])
    lines.append("- reverse closure size: %d" % g["reverse_closure_size"])
    lines.append("- dependency closure size: %d"
                 % g["dependency_closure_size"])
    lines.append("- cycles: %s" % (g["cycles"] or "none known"))

    if ctx["globals"]:
        lines.append("")
        lines.append("## Globals")
        for r in ctx["globals"]:
            lines.append("- `%s` %s %s index=%s label=%s type=%s "
                         "defined=%s" % (
                             r["global_address"], r["access_type"],
                             "table" if r["indexed"] else "direct",
                             r["index_expression"], r["label"],
                             r["data_type"], r["defined"]))
    if ctx["strings"]:
        lines.append("")
        lines.append("## Strings")
        for s in ctx["strings"]:
            lines.append("- `%s` (%s, %s) %r" % (
                s["string_address"], s["encoding"], s["reference_kind"],
                s["contents"]))
    if ctx["indirect_calls"]:
        lines.append("")
        lines.append("## Indirect calls")
        for i in ctx["indirect_calls"]:
            virtual = json.loads(i["virtual_call"]) \
                if i["virtual_call"] else None
            lines.append("- `%s` %s%s" % (
                i["instruction_address"], i["target"] or "?",
                " — " + virtual["pattern"] if virtual else ""))

    if ctx.get("mismatch"):
        lines.append("")
        lines.append("## Objective mismatch evidence "
                     "(extracted original .o vs built candidate .o)")
        lines.append(_render_mismatch_lines(ctx["mismatch"]))

    if ctx["m2c"]:
        lines.append("")
        lines.append("## m2c candidate C (%s — candidate only)"
                     % (ctx["m2c"]["version"] or "m2c"))
        for w in ctx["m2c"]["warnings"]:
            lines.append("> warning: %s" % w)
        lines.append("```c")
        lines.append(ctx["m2c"]["candidate_c"] or "(m2c failed)")
        lines.append("```")

    if ctx["source"]["path"]:
        lines.append("")
        lines.append("## Existing source (unit %s)" % ctx["source"]["unit"])
        lines.append("path: `%s`%s" % (
            ctx["source"]["path"],
            " (truncated)" if ctx["source"]["truncated"] else ""))
        if ctx["source"]["excerpt"]:
            lines.append("```cpp")
            lines.append(ctx["source"]["excerpt"])
            lines.append("```")
    if ctx["headers"]:
        lines.append("")
        lines.append("## Possibly relevant headers")
        for h in ctx["headers"]:
            lines.append("### %s (matched %s)" % (h["path"],
                                                  h["matched_token"]))
            lines.append("```c")
            lines.append(h["excerpt"])
            lines.append("```")

    lines.append("")
    lines.append("## Evidence quality")
    for key, value in ctx["evidence"].items():
        if key != "confidence_notes":
            lines.append("- %s: %s" % (key, value))
    for note in ctx["evidence"]["confidence_notes"]:
        lines.append("- NOTE: %s" % note)
    lines.append("")
    return "\n".join(lines)


# ----------------------------------------------------------------
# CLI
# ----------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("address", help="function address")
    ap.add_argument("--format", choices=("json", "markdown"),
                    default="json")
    ap.add_argument("--json", action="store_true",
                    help="alias for --format json")
    ap.add_argument("--db", default=db.DB_PATH)
    ap.add_argument("--out", help="write to file instead of stdout")
    ap.add_argument("--max-relations", type=int,
                    default=DEFAULT_MAX_RELATIONS)
    ap.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    ap.add_argument("--no-m2c", action="store_true",
                    help="skip the m2c candidate step")
    args = ap.parse_args(argv)

    try:
        conn = db.connect(args.db)
        ctx = build_context(args.address, conn=conn,
                            max_relations=args.max_relations,
                            depth=args.depth, run_m2c=not args.no_m2c)
        conn.close()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.format == "markdown" and not args.json:
        output = render_markdown(ctx)
    else:
        output = json.dumps(ctx, indent=2)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)),
                    exist_ok=True)
        with open(args.out, "w") as f:
            f.write(output + "\n")
        print("wrote %s (%d bytes)" % (args.out, len(output)),
              file=sys.stderr)
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
