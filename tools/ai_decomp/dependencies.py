#!/usr/bin/env python3
"""Dependency/call-graph operations over the local decompilation database
(roadmap item #16).

Built directly on the function_callers / function_callees tables. All
traversals carry a visited set, so cycles in the call graph cannot cause
infinite recursion, and SCCs are detected with Tarjan's algorithm.

Library use:

    from dependencies import DependencyGraph
    g = DependencyGraph(conn)
    g.direct_callers("801b16b0")
    g.callees_up_to(addr, depth=3)          # BFS, bounded
    g.callers_up_to(addr, depth=2)
    g.dependency_closure(addr)              # transitive callees
    g.reverse_dependency_closure(addr)      # transitive callers
    g.sccs_from(addr)                       # cycles reachable from addr

CLI:

    python3 tools/ai_decomp/dependencies.py 801b16b0
    python3 tools/ai_decomp/dependencies.py 801b16b0 --depth 3 --json
"""

import argparse
import json
import os
import sys
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import database as db  # noqa: E402

DEFAULT_DB = db.DB_PATH

MAX_DEPTH = 25  # hard bound for traversal requests


def _normalize(address):
    return db.normalize_address(address)


class DependencyGraph:
    def __init__(self, conn):
        self.conn = conn
        self._function_cache = {}

    # ----------------------------------------------------------------
    # node info
    # ----------------------------------------------------------------

    def function(self, address):
        """Function row dict or a placeholder for unimported addresses."""
        address = _normalize(address)
        if address not in self._function_cache:
            row = self.conn.execute(
                "SELECT address, name, size, status, category, analyzed "
                "FROM functions WHERE address = ?", (address,)).fetchone()
            self._function_cache[address] = dict(row) if row else {
                "address": address, "name": None, "size": None,
                "status": None, "category": None, "analyzed": 0,
            }
        return self._function_cache[address]

    @staticmethod
    def is_matched(info):
        return info.get("status") == "matched"

    @staticmethod
    def label(info):
        name = info.get("name") or "?"
        return "%s (%s)" % (info["address"], name)

    # ----------------------------------------------------------------
    # direct edges
    # ----------------------------------------------------------------

    def direct_callers(self, address):
        return [dict(r) for r in self.conn.execute(
            "SELECT caller_address AS address FROM function_callers "
            "WHERE function_address = ?",
            (_normalize(address),))]

    def direct_callees(self, address):
        return [dict(r) for r in self.conn.execute(
            "SELECT callee_address AS address FROM function_callees "
            "WHERE function_address = ?",
            (_normalize(address),))]

    # ----------------------------------------------------------------
    # bounded BFS traversals
    # ----------------------------------------------------------------

    def _bfs(self, address, depth, edge_sql):
        """BFS returning {address: min_depth}; cycle-safe via visited set."""
        address = _normalize(address)
        depth = min(depth, MAX_DEPTH)
        seen = {address: 0}
        frontier = deque([address])
        level = 0
        while frontier and level < depth:
            level += 1
            nxt = deque()
            for node in frontier:
                for row in self.conn.execute(edge_sql, (node,)):
                    other = row[0]
                    if other not in seen:
                        seen[other] = level
                        nxt.append(other)
            frontier = nxt
        seen.pop(address, None)
        return seen

    def callers_up_to(self, address, depth=1):
        return self._bfs(address, depth,
                         "SELECT caller_address FROM function_callers "
                         "WHERE function_address = ?")

    def callees_up_to(self, address, depth=1):
        return self._bfs(address, depth,
                         "SELECT callee_address FROM function_callees "
                         "WHERE function_address = ?")

    def dependency_closure(self, address):
        """Everything this function (transitively) calls."""
        return self._bfs(address, MAX_DEPTH,
                         "SELECT callee_address FROM function_callees "
                         "WHERE function_address = ?")

    def reverse_dependency_closure(self, address):
        """Everything that (transitively) calls this function."""
        return self._bfs(address, MAX_DEPTH,
                         "SELECT caller_address FROM function_callers "
                         "WHERE function_address = ?")

    # ----------------------------------------------------------------
    # strongly connected components / cycles
    # ----------------------------------------------------------------

    def _successors(self, addresses):
        succ = {a: set() for a in addresses}
        for a in addresses:
            for row in self.conn.execute(
                    "SELECT callee_address FROM function_callees "
                    "WHERE function_address = ?", (a,)):
                if row[0] in succ:
                    succ[a].add(row[0])
        return succ

    def sccs_from(self, address):
        """Tarjan SCCs among nodes reachable from address (callees).

        Returns a list of sets; only SCCs that are actual cycles (more
        than one node, or a self-loop) are interesting but all are
        returned for completeness.
        """
        start = _normalize(address)
        closure = self.dependency_closure(start)
        nodes = set(closure) | {start}
        succ = self._successors(nodes)

        index_counter = [0]
        stack, on_stack = [], set()
        index, lowlink = {}, {}
        result = []

        def strongconnect(v):
            # iterative Tarjan to avoid Python recursion limits
            work = [(v, iter(succ[v]))]
            index[v] = lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack.add(v)

            while work:
                node, it = work[-1]
                advanced = False
                for w in it:
                    if w not in index:
                        index[w] = lowlink[w] = index_counter[0]
                        index_counter[0] += 1
                        stack.append(w)
                        on_stack.add(w)
                        work.append((w, iter(succ[w])))
                        advanced = True
                        break
                    elif w in on_stack:
                        lowlink[node] = min(lowlink[node], index[w])
                if advanced:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    lowlink[parent] = min(lowlink[parent], lowlink[node])
                if lowlink[node] == index[node]:
                    comp = set()
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        comp.add(w)
                        if w == node:
                            break
                    result.append(comp)

        for v in sorted(nodes):
            if v not in index:
                strongconnect(v)
        return [c for c in result
                if len(c) > 1 or (len(c) == 1
                                  and next(iter(c)) in succ[next(iter(c))])]

    # ----------------------------------------------------------------
    # one-function report
    # ----------------------------------------------------------------

    def summary(self, address, depth=1):
        address = _normalize(address)
        info = self.function(address)
        if info.get("name") is None and info.get("status") is None \
                and info.get("size") is None:
            print("Function %s not found in database" % address,
                  file=sys.stderr)
            return None

        callers = self.direct_callers(address)
        callees = self.direct_callees(address)

        caller_infos = [dict(self.function(c["address"]),
                             **{"edge_depth": 1}) for c in callers]
        callee_infos = [dict(self.function(c["address"]),
                             **{"edge_depth": 1}) for c in callees]

        callers_deep = self.callers_up_to(address, depth)
        callees_deep = self.callees_up_to(address, depth)

        globals_rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM function_globals WHERE function_address = ?",
            (address,))]
        strings_rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM function_strings WHERE function_address = ?",
            (address,))]
        indirect_rows = [dict(r) for r in self.conn.execute(
            "SELECT * FROM indirect_calls WHERE function_address = ?",
            (address,))]

        return {
            "address": address,
            "function": info,
            "direct_callers": caller_infos,
            "direct_callees": callee_infos,
            "callers_depth": {"limit": depth, "found": len(callers_deep),
                              "addresses": sorted(callers_deep)},
            "callees_depth": {"limit": depth, "found": len(callees_deep),
                              "addresses": sorted(callees_deep)},
            "dependency_depth": max(callees_deep.values(), default=0),
            "globals": globals_rows,
            "strings": strings_rows,
            "indirect_calls": indirect_rows,
            "cycles": [sorted(c) for c in self.sccs_from(address)],
        }


def print_summary(report):
    info = report["function"]
    print("Function %s" % DependencyGraph.label(info))
    print("  status: %s  category: %s  size: %s  analyzed: %s" % (
        info.get("status") or "unimported",
        info.get("category") or "-",
        info.get("size") or "-",
        "yes" if info.get("analyzed") else "no"))

    print("\nDirect callers (%d):" % len(report["direct_callers"]))
    for c in report["direct_callers"]:
        print("  %-6s %s" % (c.get("status") or "unimported",
                             DependencyGraph.label(c)))
    print("\nDirect callees (%d):" % len(report["direct_callees"]))
    for c in report["direct_callees"]:
        print("  %-6s %s" % (c.get("status") or "unimported",
                             DependencyGraph.label(c)))

    print("\nTraversal (depth limit %d): %d callers, %d callees, "
          "dependency depth %d" % (
              report["callers_depth"]["limit"],
              report["callers_depth"]["found"],
              report["callees_depth"]["found"],
              report["dependency_depth"]))

    print("\nGlobals (%d):" % len(report["globals"]))
    for g in report["globals"]:
        print("  %s %-11s %s" % (g["global_address"],
                                 g["access_type"] or "-",
                                 g["label"] or g["data_type"] or ""))
    print("\nStrings (%d):" % len(report["strings"]))
    for s in report["strings"]:
        print("  %s (%s) %r" % (s["string_address"], s["encoding"],
                                (s["contents"] or "")[:60]))
    print("\nIndirect calls (%d):" % len(report["indirect_calls"]))
    for i in report["indirect_calls"]:
        virtual = json.loads(i["virtual_call"]) if i["virtual_call"] else None
        print("  %s -> %s%s" % (i["instruction_address"],
                                i["target"] or "?",
                                ("  " + virtual["pattern"])
                                if virtual else ""))

    if report["cycles"]:
        print("\nCycles/SCCs: %s" % "; ".join(
            ",".join(c) for c in report["cycles"]))
    else:
        print("\nCycles/SCCs: none reachable")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("address", help="function address")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--depth", type=int, default=1,
                    help="traversal depth for callers/callees (default 1)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not os.path.exists(args.db):
        print("Database %s not found. Run:" % args.db)
        print("  python3 tools/ai_decomp/import_analysis.py")
        return 1

    conn = db.connect(args.db)
    graph = DependencyGraph(conn)
    report = graph.summary(args.address, depth=args.depth)
    conn.close()

    if report is None:
        return 1
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_summary(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
