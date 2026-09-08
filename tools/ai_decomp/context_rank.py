#!/usr/bin/env python3
"""Dependency-aware relevance ranking for context selection
(roadmap Phase 5.5).

Goal: MORE RELEVANT context, not more context. Given a target function,
a bounded set of related functions/evidence items is selected by a
deterministic, explainable scorer and handed to the context builder.

Deterministic additive scoring — no embeddings, no LLM:

    direct_callee         +40   directly called by the target
    direct_caller         +32   directly calls the target
    shared_global         +20   references a global the target also
                                references (capped at 2 globals)
    shared_virtual_slot   +18   uses the same receiver+virtual slot
    shared_string         +14   references the same string
    shared_table          +14   references the same indexed table
    compiler_idiom        +10   shares an observed compiler idiom
                                (capped at 2)
    type_evidence          +8   shares a field-offset/receiver pattern
    graph_neighbor         +6   second-degree dependency (depth 2)

Signals accumulate: a function that both calls the target AND shares a
global outscores one that only calls it. Ties break deterministically
by (-score, -signal_count, address).

Budgets (hard limits):
    max_items      maximum related items selected
    max_chars      maximum characters of rendered related context
    max_depth      bounded graph expansion (default 2)
    depth-2 expansion is only computed for the strongest depth-1
    candidates (max_depth1_expansion)

Every item carries its categories, a human-readable reason and the
shared evidence addresses, so the ranking is inspectable.
"""

import sys

import database as db

RANKING_VERSION = 1

DEFAULT_MAX_ITEMS = 12
DEFAULT_MAX_CHARS = 12000
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_DEPTH1_EXPANSION = 8
MAX_DEPTH = 3

WEIGHTS = {
    "direct_callee": 40,
    "direct_caller": 32,
    "shared_global": 20,
    "shared_virtual_slot": 18,
    "shared_string": 14,
    "shared_table": 14,
    "compiler_idiom": 10,
    "type_evidence": 8,
    "graph_neighbor": 6,
}

# drop-order when the budget is exceeded: weakest categories first
DROP_ORDER = ("graph_neighbor", "compiler_idiom", "type_evidence",
              "shared_string", "shared_table", "shared_virtual_slot",
              "shared_global", "direct_caller", "direct_callee")

MAX_SHARED_LISTED = 3  # shared addresses listed per reason
MAX_REASON_CHARS = 220


def _norm(address):
    return db.normalize_address(address)


# ----------------------------------------------------------------
# target signals
# ----------------------------------------------------------------

def collect_signals(conn, address):
    """Compact, bounded signal set for the target function."""
    address = _norm(address)
    globals_ = {}
    for row in conn.execute(
            """SELECT global_address, access_type, indexed, label
               FROM function_globals WHERE function_address = ?""",
            (address,)):
        globals_[_norm(row["global_address"])] = {
            "access": row["access_type"],
            "indexed": bool(row["indexed"]),
            "label": row["label"],
        }

    strings = {}
    for row in conn.execute(
            """SELECT string_address, contents FROM function_strings
               WHERE function_address = ?""", (address,)):
        strings[_norm(row["string_address"])] = row["contents"]

    slots = set()
    for row in conn.execute(
            """SELECT register, slot_offset FROM type_evidence
               WHERE function_address = ? AND kind = 'vtable'""",
            (address,)):
        slots.add((row["register"], row["slot_offset"]))

    fields = set()
    tables = set()
    for row in conn.execute(
            """SELECT kind, register, offset FROM type_evidence
               WHERE function_address = ?
                 AND kind IN ('field', 'table_lookup')""", (address,)):
        if row["kind"] == "field":
            fields.add((row["register"], row["offset"]))
        else:
            tables.add(row["register"])

    idiom_kinds = {r[0] for r in conn.execute(
        """SELECT DISTINCT i.kind FROM idiom_observations o
           JOIN idioms i ON i.id = o.idiom_id
           WHERE o.function_address = ?""", (address,))}

    return {
        "address": address,
        "globals": globals_,
        "strings": strings,
        "slots": slots,
        "fields": fields,
        "tables": tables,
        "idiom_kinds": idiom_kinds,
    }


# ----------------------------------------------------------------
# candidate discovery (bounded)
# ----------------------------------------------------------------

def discover_candidates(conn, address, signals, max_depth=2,
                        max_depth1_expansion=8):
    """Direct relations, shared-evidence functions and bounded
    depth-2 neighbors. Returns (candidates, meta)."""
    address = _norm(address)
    candidates = {}   # address -> set of relationship tags
    considered = 0

    def add(addr, tag):
        nonlocal considered
        addr = _norm(addr)
        if addr == address:
            return
        considered += 1
        candidates.setdefault(addr, set()).add(tag)

    direct_callers = set()
    direct_callees = set()
    for row in conn.execute(
            "SELECT caller_address FROM function_callers "
            "WHERE function_address = ?", (address,)):
        direct_callers.add(_norm(row[0]))
    for row in conn.execute(
            "SELECT callee_address FROM function_callees "
            "WHERE function_address = ?", (address,)):
        direct_callees.add(_norm(row[0]))
    for a in direct_callers:
        add(a, "direct_caller")
    for a in direct_callees:
        add(a, "direct_callee")

    # shared globals / indexed tables
    shared_g, shared_t = set(), set()
    for g in signals["globals"]:
        if signals["globals"][g]["indexed"]:
            shared_t.add(g)
        for row in conn.execute(
                """SELECT function_address FROM function_globals
                   WHERE global_address = ? AND function_address != ?
                   LIMIT 32""", (g, address)):
            shared_g.add(_norm(row[0]))
    for a in shared_g:
        add(a, "shared_global")
    for a in shared_t:
        add(a, "shared_table")

    # shared strings
    shared_s = set()
    for s in signals["strings"]:
        for row in conn.execute(
                """SELECT function_address FROM function_strings
                   WHERE string_address = ? AND function_address != ?
                   LIMIT 16""", (s, address)):
            shared_s.add(_norm(row[0]))
    for a in shared_s:
        add(a, "shared_string")

    # shared virtual slots
    shared_v = set()
    for (register, slot_offset) in signals["slots"]:
        for row in conn.execute(
                """SELECT DISTINCT function_address FROM type_evidence
                   WHERE kind = 'vtable' AND register = ?
                     AND slot_offset = ? AND function_address != ?
                   LIMIT 16""", (register, slot_offset, address)):
            shared_v.add(_norm(row[0]))
    for a in shared_v:
        add(a, "shared_virtual_slot")

    # shared compiler idioms
    if signals["idiom_kinds"]:
        placeholders = ",".join("?" for _ in signals["idiom_kinds"])
        for row in conn.execute(
                """SELECT DISTINCT o.function_address
                   FROM idiom_observations o
                   JOIN idioms i ON i.id = o.idiom_id
                   WHERE i.kind IN (%s) AND o.function_address != ?
                   LIMIT 32""" % placeholders,
                tuple(signals["idiom_kinds"]) + (address,)):
            add(_norm(row[0]), "compiler_idiom")

    # bounded depth-2 expansion from the strongest depth-1 nodes
    depth2 = set()
    if max_depth >= 2:
        depth1 = (direct_callers | direct_callees)
        strong = sorted(depth1)[:max_depth1_expansion]
        for node in strong:
            for row in conn.execute(
                    "SELECT caller_address FROM function_callers "
                    "WHERE function_address = ?", (node,)):
                a = _norm(row[0])
                if a != address and a not in direct_callers \
                        and a not in direct_callees:
                    depth2.add(a)
            for row in conn.execute(
                    "SELECT callee_address FROM function_callees "
                    "WHERE function_address = ?", (node,)):
                a = _norm(row[0])
                if a != address and a not in direct_callers \
                        and a not in direct_callees:
                    depth2.add(a)
    for a in depth2:
        add(a, "graph_neighbor")

    meta = {
        "direct_callers": len(direct_callers),
        "direct_callees": len(direct_callees),
        "shared_global_functions": len(shared_g),
        "shared_string_functions": len(shared_s),
        "shared_slot_functions": len(shared_v),
        "depth2_neighbors": len(depth2),
    }
    return candidates, meta


# ----------------------------------------------------------------
# scoring
# ----------------------------------------------------------------

def _shared_globals(conn, candidate, signals):
    rows = conn.execute(
        """SELECT global_address, access_type AS access, indexed, label
           FROM function_globals WHERE function_address = ?""",
        (_norm(candidate),)).fetchall()
    shared = []
    for row in rows:
        g = _norm(row["global_address"])
        if g in signals["globals"]:
            shared.append((g, row["indexed"], row["label"]))
    return shared


def _shared_strings(conn, candidate, signals):
    shared = []
    for row in conn.execute(
            """SELECT string_address FROM function_strings
               WHERE function_address = ?""", (_norm(candidate),)):
        s = _norm(row["string_address"])
        if s in signals["strings"]:
            shared.append(s)
    return shared


def _shared_slots(conn, candidate, signals):
    shared = []
    for row in conn.execute(
            """SELECT register, slot_offset FROM type_evidence
               WHERE function_address = ? AND kind = 'vtable'""",
            (_norm(candidate),)):
        key = (row["register"], row["slot_offset"])
        if key in signals["slots"]:
            shared.append(key)
    return shared


def _shared_idioms(conn, candidate, signals):
    if not signals["idiom_kinds"]:
        return []
    placeholders = ",".join("?" for _ in signals["idiom_kinds"])
    rows = conn.execute(
        """SELECT DISTINCT i.kind FROM idiom_observations o
           JOIN idioms i ON i.id = o.idiom_id
           WHERE o.function_address = ? AND i.kind IN (%s)"""
        % placeholders, (_norm(candidate),)
        + tuple(signals["idiom_kinds"])).fetchall()
    return [r[0] for r in rows]


def score_candidate(conn, candidate, signals, relations, depth,
                    max_items=None):
    """Deterministic additive score with reasons. Returns an item dict
    or None when the candidate has no relevant relationship."""
    score = 0
    categories = []
    reasons = []
    evidence = []

    is_caller = "direct_caller" in relations
    is_callee = "direct_callee" in relations

    if is_callee:
        score += WEIGHTS["direct_callee"]
        categories.append("direct_callee")
        reasons.append("directly called by target")
    if is_caller:
        score += WEIGHTS["direct_caller"]
        categories.append("direct_caller")
        reasons.append("directly calls target")

    shared_g = _shared_globals(conn, candidate, signals)
    for g, indexed, label in shared_g[:2]:
        score += WEIGHTS["shared_global"]
        categories.append("shared_global")
        desc = "references global 0x%s also used by target" % g
        if indexed:
            desc += " (indexed table access)"
            score += WEIGHTS["shared_table"]
            categories.append("shared_table")
        if label:
            desc += " [%s]" % label
        reasons.append(desc)
        evidence.append("global 0x%s" % g)

    shared_v = _shared_slots(conn, candidate, signals)
    for (register, slot_offset) in shared_v[:2]:
        score += WEIGHTS["shared_virtual_slot"]
        categories.append("shared_virtual_slot")
        reasons.append("uses virtual slot 0x%x with receiver %s"
                       % (slot_offset, register))
        evidence.append("slot 0x%x" % slot_offset)

    shared_s = _shared_strings(conn, candidate, signals)
    for s in shared_s[:1]:
        score += WEIGHTS["shared_string"]
        categories.append("shared_string")
        reasons.append("references string 0x%s also used by target" % s)
        evidence.append("string 0x%s" % s)

    shared_i = _shared_idioms(conn, candidate, signals)
    for kind in shared_i[:2]:
        score += WEIGHTS["compiler_idiom"]
        categories.append("compiler_idiom")
        reasons.append("shares observed compiler idiom '%s'" % kind)
        evidence.append("idiom %s" % kind)

    # register/field overlap counts as direct type evidence
    if "type_evidence" not in categories:
        shared_f = []
        for row in conn.execute(
                """SELECT register, offset FROM type_evidence
                   WHERE function_address = ? AND kind = 'field'""",
                (_norm(candidate),)):
            key = (row["register"], row["offset"])
            if key in signals["fields"]:
                shared_f.append(key)
        if shared_f:
            score += WEIGHTS["type_evidence"]
            categories.append("type_evidence")
            reasons.append("shares field access %s+0x%x with target"
                           % shared_f[0])
            evidence.append("field %s+0x%x" % shared_f[0])

    if not categories:
        if depth >= 2:
            score += WEIGHTS["graph_neighbor"]
            categories.append("graph_neighbor")
            reasons.append("second-degree dependency of the target")
        else:
            return None

    return {
        "address": _norm(candidate),
        "score": score,
        "primary_category": categories[0],
        "categories": sorted(set(categories)),
        "reason": "; ".join(reasons)[:MAX_REASON_CHARS],
        "evidence": evidence[:MAX_SHARED_LISTED],
        "depth": depth,
        "signal_count": len(categories),
    }


# ----------------------------------------------------------------
# budget
# ----------------------------------------------------------------

def enforce_budget(items, max_items, max_chars):
    """Select items within budgets, dropping weakest categories first."""
    def item_chars(item):
        return len(item.get("reason", "")) + \
            sum(len(e) for e in item.get("evidence", [])) + 40

    selected = []
    used = 0
    remaining = list(items)
    while remaining and len(selected) < max_items:
        candidate = remaining[0]
        cost = item_chars(candidate)
        if used + cost > max_chars and selected:
            # try to keep smaller lower-priority items that still fit
            remaining.sort(key=lambda i: (
                DROP_ORDER.index(next(
                    (c for c in DROP_ORDER
                     if c in i["categories"]),
                    DROP_ORDER[0])),
                item_chars(i)))
            swapped = False
            for alt in list(remaining[1:]):
                if used + item_chars(alt) <= max_chars:
                    remaining.remove(alt)
                    selected.append(alt)
                    used += item_chars(alt)
                    swapped = True
                    break
            if not swapped:
                break
            continue
        remaining.pop(0)
        selected.append(candidate)
        used += cost
    return selected, used


# ----------------------------------------------------------------
# public entry point
# ----------------------------------------------------------------

def build_ranked_context(conn, address, max_items=DEFAULT_MAX_ITEMS,
                         max_chars=DEFAULT_MAX_CHARS,
                         max_depth=DEFAULT_MAX_DEPTH,
                         max_depth1_expansion=8,
                         source_text=None):
    """Rank related functions/evidence for a target. Returns
    {"items": [...], "selection": {...}} — deterministic."""
    address = _norm(address)
    max_depth = min(max_depth, MAX_DEPTH)
    signals = collect_signals(conn, address)

    candidates, discovery_meta = discover_candidates(
        conn, address, signals, max_depth=max_depth,
        max_depth1_expansion=max_depth1_expansion)

    items = []
    for candidate in sorted(candidates):
        relations = candidates[candidate]
        depth = 1 if (relations & {"direct_caller", "direct_callee"}) \
            else 2
        item = score_candidate(conn, candidate, signals, relations,
                               depth)
        if item is not None:
            items.append(item)

    items.sort(key=lambda i: (-i["score"], -i["signal_count"],
                              i["address"]))
    selected, used = enforce_budget(list(items), max_items, max_chars)

    # attach identity + match status for the selected items
    for item in selected:
        row = conn.execute(
            "SELECT name, status FROM functions WHERE address = ?",
            (item["address"],)).fetchone()
        item["name"] = row["name"] if row else None
        item["status"] = row["status"] if row else "unimported"
    for rank, item in enumerate(selected, 1):
        item["rank"] = rank

    selection = {
        "ranking_version": RANKING_VERSION,
        "max_items": max_items,
        "max_chars": max_chars,
        "max_depth": max_depth,
        "candidates_considered": len(items),
        "discovery": discovery_meta,
        "selected": len(selected),
        "chars_used": used,
    }
    return {"items": selected, "selection": selection}


def main():
    import argparse
    import json
    import os
    import database as database_mod
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("address")
    ap.add_argument("--db", default=database_mod.DB_PATH)
    ap.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    ap.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    args = ap.parse_args()
    if not os.path.exists(args.db):
        print("database %s not found" % args.db, file=sys.stderr)
        return 1
    conn = database_mod.connect(args.db)
    result = build_ranked_context(conn, args.address,
                                  max_items=args.max_items,
                                  max_chars=args.max_chars)
    conn.close()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
