#!/usr/bin/env python3
"""SQLite database layer for the AI decompilation pipeline.

The database is completely local (tools/ai_decomp/decomp.db, git-ignored)
and caches everything the pipeline knows about the binary:

  functions           one row per function (Ghidra + ELF symbol table)
  function_callers    direct call edges into a function
  function_callees    direct call edges out of a function
  globals             defined data catalog (all defined data)
  strings             defined string data
  function_globals    per-function global/data references (#11)
  function_strings    per-function string references (#12)
  instructions        disassembly per analyzed function
  indirect_calls      bctr/bcctr sites + virtual-call patterns (#9)
  category_stats      objdiff per-category match aggregates
  analysis_runs       import/analysis history log

All writes are upserts keyed on natural keys, so running the importer
twice never creates duplicates. There are no foreign-key constraints on
purpose: callers/callees may reference functions that are not imported
(or do not exist) yet.
"""

import json
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "decomp.db")

STATUSES = ("unknown", "candidate", "in_progress", "matching",
            "matched", "blocked", "review")

# Ghidra auto-generated names, replaceable by real symbols
GenericNamePrefixes = ("FUN_", "thunk_FUN_", "fcn_", "??", "DAT_", "s_")

SCHEMA = """
CREATE TABLE IF NOT EXISTS functions (
    address      TEXT PRIMARY KEY,
    name         TEXT,
    size         INTEGER,
    section      TEXT,
    is_thunk     INTEGER NOT NULL DEFAULT 0,
    is_external  INTEGER NOT NULL DEFAULT 0,
    signature    TEXT,
    return_type  TEXT,
    status       TEXT NOT NULL DEFAULT 'unknown',
    category     TEXT,
    analyzed     INTEGER NOT NULL DEFAULT 0,
    source       TEXT,
    updated_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_functions_status   ON functions(status);
CREATE INDEX IF NOT EXISTS idx_functions_section  ON functions(section);
CREATE INDEX IF NOT EXISTS idx_functions_category ON functions(category);
CREATE INDEX IF NOT EXISTS idx_functions_name     ON functions(name);

CREATE TABLE IF NOT EXISTS function_callers (
    function_address TEXT NOT NULL,
    caller_address   TEXT NOT NULL,
    PRIMARY KEY (function_address, caller_address)
);
CREATE INDEX IF NOT EXISTS idx_callers_caller
    ON function_callers(caller_address);

CREATE TABLE IF NOT EXISTS function_callees (
    function_address TEXT NOT NULL,
    callee_address   TEXT NOT NULL,
    PRIMARY KEY (function_address, callee_address)
);
CREATE INDEX IF NOT EXISTS idx_callees_callee
    ON function_callees(callee_address);

CREATE TABLE IF NOT EXISTS globals (
    address      TEXT PRIMARY KEY,
    section      TEXT,
    label        TEXT,
    data_type    TEXT,
    data_size    INTEGER,
    string_value TEXT,
    source       TEXT
);
CREATE INDEX IF NOT EXISTS idx_globals_section ON globals(section);
CREATE INDEX IF NOT EXISTS idx_globals_label   ON globals(label);

CREATE TABLE IF NOT EXISTS strings (
    address   TEXT PRIMARY KEY,
    contents  TEXT,
    encoding  TEXT,
    data_type TEXT,
    length    INTEGER,
    section   TEXT
);

CREATE TABLE IF NOT EXISTS function_globals (
    function_address       TEXT NOT NULL,
    global_address         TEXT NOT NULL,
    access_type            TEXT,
    indexed                INTEGER,
    width                  INTEGER,
    base_register          TEXT,
    index_expression       TEXT,
    resolved_base_address  TEXT,
    symbolic_expression    TEXT,
    defined                INTEGER,
    label                  TEXT,
    data_type              TEXT,
    instruction_addresses  TEXT,
    PRIMARY KEY (function_address, global_address)
);
CREATE INDEX IF NOT EXISTS idx_fg_global
    ON function_globals(global_address);

CREATE TABLE IF NOT EXISTS function_strings (
    function_address       TEXT NOT NULL,
    string_address         TEXT NOT NULL,
    contents               TEXT,
    encoding               TEXT,
    reference_instruction  TEXT,
    reference_kind         TEXT,
    PRIMARY KEY (function_address, string_address)
);
CREATE INDEX IF NOT EXISTS idx_fs_string
    ON function_strings(string_address);

CREATE TABLE IF NOT EXISTS instructions (
    function_address TEXT NOT NULL,
    address          TEXT NOT NULL,
    mnemonic         TEXT,
    operands         TEXT,
    ordinal          INTEGER,
    PRIMARY KEY (function_address, address)
);

CREATE TABLE IF NOT EXISTS indirect_calls (
    function_address    TEXT NOT NULL,
    instruction_address TEXT NOT NULL,
    target              TEXT,
    virtual_call        TEXT,
    PRIMARY KEY (function_address, instruction_address)
);

CREATE TABLE IF NOT EXISTS category_stats (
    category         TEXT PRIMARY KEY,
    total_functions  INTEGER,
    matched_functions INTEGER
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at     TEXT,
    kind       TEXT,
    source     TEXT,
    details    TEXT
);

CREATE TABLE IF NOT EXISTS idioms (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                TEXT NOT NULL,
    normalized_source   TEXT,
    normalized_asm      TEXT,
    compiler            TEXT NOT NULL DEFAULT 'MWCC',
    architecture        TEXT NOT NULL DEFAULT 'PowerPC',
    target              TEXT NOT NULL DEFAULT 'ppc-mwcc',
    observation_count   INTEGER NOT NULL DEFAULT 0,
    matched_count       INTEGER NOT NULL DEFAULT 0,
    best_objdiff_score  REAL,
    average_improvement REAL,
    improvement_samples INTEGER NOT NULL DEFAULT 0,
    last_seen           TEXT,
    UNIQUE (kind, normalized_source, normalized_asm,
            compiler, architecture)
);
CREATE INDEX IF NOT EXISTS idx_idioms_kind ON idioms(kind);
CREATE INDEX IF NOT EXISTS idx_idioms_compiler ON idioms(compiler,
                                                         architecture);

CREATE TABLE IF NOT EXISTS idiom_observations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    idiom_id          INTEGER NOT NULL REFERENCES idioms(id),
    function_address  TEXT,
    function_name     TEXT,
    attempt_number    INTEGER,
    compiler          TEXT,
    source_excerpt    TEXT,
    assembly_excerpt  TEXT,
    objdiff_percent   REAL,
    accepted_as_best  INTEGER,
    evidence_level    TEXT NOT NULL,
    note              TEXT,
    created_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_idiom_obs_idiom
    ON idiom_observations(idiom_id);
CREATE INDEX IF NOT EXISTS idx_idiom_obs_function
    ON idiom_observations(function_address);

CREATE TABLE IF NOT EXISTS type_evidence (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                TEXT NOT NULL,
    function_address    TEXT,
    function_name       TEXT,
    register            TEXT,
    offset              INTEGER,
    access              TEXT,
    width               INTEGER,
    slot_offset         INTEGER,
    slot_index          INTEGER,
    call_site           TEXT,
    instruction_address TEXT,
    evidence_level      TEXT NOT NULL DEFAULT 'observed',
    matched_count       INTEGER NOT NULL DEFAULT 0,
    observation_count   INTEGER NOT NULL DEFAULT 1,
    last_seen           TEXT,
    UNIQUE (kind, function_address, register, offset, access, width,
            slot_offset, call_site, instruction_address)
);
CREATE INDEX IF NOT EXISTS idx_type_evidence_function
    ON type_evidence(function_address);
CREATE INDEX IF NOT EXISTS idx_type_evidence_kind ON type_evidence(kind);
"""


def connect(path=DB_PATH):
    """Open (and create) the database with a sensible pragma setup."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    init_schema(conn)
    return conn


def init_schema(conn):
    conn.executescript(SCHEMA)
    conn.commit()


def normalize_address(addr):
    """Normalize an address to lowercase 8-digit hex."""
    if addr is None:
        return None
    a = str(addr).strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    return a.zfill(8)


# ----------------------------------------------------------------
# upsert helpers
# ----------------------------------------------------------------

def upsert_function(conn, address, name=None, size=None, section=None,
                    is_thunk=None, is_external=None, signature=None,
                    return_type=None, status=None, category=None,
                    analyzed=None, source=None, merge=True,
                    priority="low"):
    """Insert or update a function row.

    With merge=True (default), NULL/absent fields never clobber existing
    values, so the Ghidra importer, the symbol importer and the
    analyzed-JSON importer can all run in any order.

    `priority` applies to name/size/section only: sources derived from
    the original layout (symbols.txt, priority='high') always overwrite,
    while lower-priority sources (Ghidra heuristics) only fill gaps.
    """
    address = normalize_address(address)
    existing = conn.execute(
        "SELECT * FROM functions WHERE address = ?", (address,)).fetchone()

    high = priority == "high"

    def pick(field, value):
        cur = existing[field] if existing is not None else None
        if field in ("name", "size", "section"):
            # layout-derived sources (priority='high') always win;
            # heuristic sources only fill gaps and generic names
            if high:
                return value if value is not None else cur
            if value is not None:
                generic = (field == "name" and cur
                           and cur.startswith(GenericNamePrefixes))
                return value if (not cur or generic) else cur
            return cur
        return value if value is not None else cur

    row = (
        pick("name", name),
        pick("size", size),
        pick("section", section),
        int(bool(pick("is_thunk", is_thunk) or 0)),
        int(bool(pick("is_external", is_external) or 0)),
        pick("signature", signature),
        pick("return_type", return_type),
        status or (existing["status"] if existing is not None and merge
                   else None) or "unknown",
        pick("category", category),
        int(bool(pick("analyzed", analyzed) or 0)),
        source or (existing["source"] if existing is not None and merge
                   else None),
        address,
    )

    conn.execute(
        """INSERT INTO functions (name, size, section, is_thunk,
               is_external, signature, return_type, status, category,
               analyzed, source, updated_at, address)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                   datetime('now'), ?)
           ON CONFLICT(address) DO UPDATE SET
               name=excluded.name, size=excluded.size,
               section=excluded.section, is_thunk=excluded.is_thunk,
               is_external=excluded.is_external,
               signature=excluded.signature,
               return_type=excluded.return_type,
               status=excluded.status, category=excluded.category,
               analyzed=excluded.analyzed, source=excluded.source,
               updated_at=datetime('now')""",
        row)
    return address


def set_function_links(conn, table, column, function_address, addresses):
    """Replace the caller/callee link rows for one function."""
    function_address = normalize_address(function_address)
    conn.execute("DELETE FROM %s WHERE function_address = ?" % table,
                 (function_address,))
    conn.executemany(
        "INSERT OR IGNORE INTO %s (function_address, %s) VALUES (?, ?)"
        % (table, column),
        [(function_address, normalize_address(a)) for a in addresses])


def replace_instructions(conn, function_address, instruction_lines):
    """Replace the instruction rows for one function.

    `instruction_lines` are the exporter's "address: mnemonic operands"
    strings; they are parsed here so the DB stores structured columns.
    """
    import re
    function_address = normalize_address(function_address)
    conn.execute("DELETE FROM instructions WHERE function_address = ?",
                 (function_address,))
    rows = []
    for ordinal, line in enumerate(instruction_lines):
        m = re.match(r"^\s*([0-9a-fA-F]+):\s*(\S+)\s*(.*)$", line)
        if not m:
            continue
        rows.append((function_address, normalize_address(m.group(1)),
                     m.group(2).lower(), m.group(3).strip(), ordinal))
    conn.executemany(
        """INSERT OR REPLACE INTO instructions
               (function_address, address, mnemonic, operands, ordinal)
           VALUES (?, ?, ?, ?, ?)""", rows)
    return len(rows)


def record_indirect_calls(conn, function_address, indirect_calls):
    """Replace the indirect-call rows for one function."""
    import json as _json
    function_address = normalize_address(function_address)
    conn.execute("DELETE FROM indirect_calls WHERE function_address = ?",
                 (function_address,))
    rows = []
    for c in indirect_calls:
        virtual = c.get("virtual_call")
        rows.append((function_address,
                     normalize_address(c.get("address")),
                     c.get("target"),
                     _json.dumps(virtual) if virtual else None))
    conn.executemany(
        """INSERT OR REPLACE INTO indirect_calls
               (function_address, instruction_address, target,
                virtual_call)
           VALUES (?, ?, ?, ?)""", rows)
    return len(rows)


def upsert_globals(conn, records, source="catalog", priority="low"):
    """Bulk upsert defined data (address/label/type/size/section/string).

    Label priority: symbols.txt ('high') overwrites, the Ghidra catalog
    ('low') only fills gaps, so re-importing the catalog never clobbers
    real symbol names.
    """
    if priority == "high":
        label_rule = "COALESCE(excluded.label, globals.label)"
    else:
        label_rule = "COALESCE(globals.label, excluded.label)"
    conn.executemany(
        """INSERT INTO globals
               (address, section, label, data_type, data_size,
                string_value, source)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(address) DO UPDATE SET
               section=COALESCE(excluded.section, globals.section),
               label=""" + label_rule + """,
               data_type=COALESCE(excluded.data_type, globals.data_type),
               data_size=COALESCE(excluded.data_size, globals.data_size),
               string_value=COALESCE(excluded.string_value,
                                     globals.string_value),
               source=excluded.source""",
        [(normalize_address(r["address"]), r.get("section"), r.get("label"),
          r.get("data_type"), r.get("data_size"), r.get("string"), source)
         for r in records])
    return len(records)


def upsert_strings(conn, records):
    """Bulk upsert defined strings."""
    conn.executemany(
        """INSERT INTO strings
               (address, contents, encoding, data_type, length, section)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(address) DO UPDATE SET
               contents=excluded.contents, encoding=excluded.encoding,
               data_type=excluded.data_type, length=excluded.length,
               section=COALESCE(excluded.section, strings.section)""",
        [(normalize_address(r["address"]), r.get("contents"),
          r.get("encoding"), r.get("data_type"), r.get("length"),
          r.get("section")) for r in records])
    return len(records)


def link_function_globals(conn, function_address, global_references):
    """Replace the function's global-reference rows (#11 records)."""
    import json as _json
    function_address = normalize_address(function_address)
    conn.execute("DELETE FROM function_globals WHERE function_address = ?",
                 (function_address,))
    rows = []
    for g in global_references:
        rows.append((
            function_address, normalize_address(g["address"]),
            g.get("access_type"),
            int(bool(g.get("indexed"))) if g.get("indexed") is not None
                else None,
            g.get("width"), g.get("base_register"),
            g.get("index_expression"), g.get("resolved_base_address"),
            g.get("symbolic_expression"),
            int(bool(g.get("defined"))) if g.get("defined") is not None
                else None,
            g.get("label"), g.get("data_type"),
            _json.dumps(g.get("instruction_addresses"))
                if g.get("instruction_addresses") else None,
        ))
    conn.executemany(
        """INSERT OR REPLACE INTO function_globals
               (function_address, global_address, access_type, indexed,
                width, base_register, index_expression,
                resolved_base_address, symbolic_expression, defined,
                label, data_type, instruction_addresses)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", rows)
    return len(rows)


def link_function_strings(conn, function_address, string_references):
    """Replace the function's string-reference rows (#12 records)."""
    function_address = normalize_address(function_address)
    conn.execute("DELETE FROM function_strings WHERE function_address = ?",
                 (function_address,))
    rows = [(function_address, normalize_address(s["address"]),
             s.get("contents"), s.get("encoding"),
             s.get("reference_instruction"), s.get("reference_kind"))
            for s in string_references]
    conn.executemany(
        """INSERT OR REPLACE INTO function_strings
               (function_address, string_address, contents, encoding,
                reference_instruction, reference_kind)
           VALUES (?, ?, ?, ?, ?, ?)""", rows)
    return len(rows)


def upsert_category_stats(conn, stats):
    """stats: list of {category, total_functions, matched_functions}."""
    conn.executemany(
        """INSERT INTO category_stats
               (category, total_functions, matched_functions)
           VALUES (?, ?, ?)
           ON CONFLICT(category) DO UPDATE SET
               total_functions=excluded.total_functions,
               matched_functions=excluded.matched_functions""",
        [(s["category"], s.get("total_functions"),
          s.get("matched_functions")) for s in stats])


def record_analysis_run(conn, kind, source, details):
    conn.execute(
        """INSERT INTO analysis_runs (run_at, kind, source, details)
           VALUES (datetime('now'), ?, ?, ?)""",
        (kind, source, json.dumps(details) if details else None))


def set_status(conn, address, status):
    """Update a function's pipeline status (#13 status vocabulary)."""
    if status not in STATUSES:
        raise ValueError("invalid status %r (want one of %s)"
                         % (status, STATUSES))
    conn.execute(
        """UPDATE functions SET status = ?, updated_at = datetime('now')
           WHERE address = ?""", (status, normalize_address(address)))


# ----------------------------------------------------------------
# query helpers (used by status.py and the future pipeline)
# ----------------------------------------------------------------

def status_counts(conn):
    return {row["status"]: row["n"] for row in conn.execute(
        "SELECT status, COUNT(*) AS n FROM functions GROUP BY status")}


def category_counts(conn):
    return {row["category"]: row["n"] for row in conn.execute(
        """SELECT COALESCE(category, 'uncategorized') AS category,
                  COUNT(*) AS n
           FROM functions GROUP BY category""")}


def functions_with_globals(conn):
    return conn.execute(
        "SELECT COUNT(DISTINCT function_address) AS n "
        "FROM function_globals").fetchone()["n"]


def functions_with_strings(conn):
    return conn.execute(
        "SELECT COUNT(DISTINCT function_address) AS n "
        "FROM function_strings").fetchone()["n"]


def functions_with_indirect_calls(conn):
    return conn.execute(
        "SELECT COUNT(DISTINCT function_address) AS n "
        "FROM indirect_calls").fetchone()["n"]


def record_type_evidence(conn, records, function_address=None,
                         function_name=None, matched=False):
    """Persist conservative type/vtable/field evidence records.

    Idempotent: an identical evidence record (same kind, function,
    register, offsets, access, width, sites) is not duplicated — only
    its last_seen is refreshed and its matched_count incremented when
    the owning function is objdiff-verified at 100.0.
    """
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    written = 0
    for rec in records:
        row = conn.execute(
            """SELECT id, observation_count, matched_count
               FROM type_evidence
               WHERE kind = ? AND function_address IS ?
                 AND register IS ? AND offset IS ? AND access IS ?
                 AND width IS ? AND slot_offset IS ? AND slot_index IS ?
                 AND call_site IS ? AND instruction_address IS ?""",
            (rec.get("kind"), function_address, rec.get("register"),
             rec.get("offset"), rec.get("access"), rec.get("width"),
             rec.get("slot_offset"), rec.get("slot_index"),
             rec.get("call_site"), rec.get("instruction_address"))
        ).fetchone()
        if row is None:
            conn.execute(
                """INSERT INTO type_evidence
                       (kind, function_address, function_name, register,
                        offset, access, width, slot_offset, slot_index,
                        call_site, instruction_address, evidence_level,
                        matched_count, observation_count, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)""",
                (rec.get("kind"), function_address, function_name,
                 rec.get("register"), rec.get("offset"),
                 rec.get("access"), rec.get("width"),
                 rec.get("slot_offset"), rec.get("slot_index"),
                 rec.get("call_site"), rec.get("instruction_address"),
                 "matched" if matched else "observed",
                 1 if matched else 0, now))
        else:
            matched_count = row["matched_count"] + (1 if matched else 0)
            conn.execute(
                """UPDATE type_evidence
                   SET last_seen = ?, observation_count = ?,
                       matched_count = ?,
                       evidence_level = ?
                   WHERE id = ?""",
                (now, row["observation_count"] + 1, matched_count,
                 "matched" if matched_count else rec.get(
                     "evidence_level", "observed"),
                 row["id"]))
        written += 1
    conn.commit()
    return written


def effective_idiom_level(observation_count, matched_count):
    """Evidence level of an idiom derived from its observations.

    matched  - at least one observation from an objdiff-verified 100%
    repeated - observed in multiple independent compilations
    observed - seen in exactly one real compilation
    (a 'hypothesis' level exists but is only written explicitly; the
    automatic learner never produces it, and 'rejected' marks are kept
    per-observation without changing the idiom's level)
    """
    if matched_count:
        return "matched"
    if observation_count > 1:
        return "repeated"
    return "observed"


def upsert_idiom(conn, kind, normalized_source=None, normalized_asm=None,
                 compiler="MWCC", architecture="PowerPC",
                 target="ppc-mwcc"):
    """Return the idiom row id, creating it when new."""
    conn.execute(
        """INSERT OR IGNORE INTO idioms
               (kind, normalized_source, normalized_asm, compiler,
                architecture, target)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (kind, normalized_source, normalized_asm, compiler,
         architecture, target))
    row = conn.execute(
        """SELECT id FROM idioms WHERE kind = ? AND
               normalized_source IS ? AND normalized_asm IS ? AND
               compiler = ? AND architecture = ?""",
        (kind, normalized_source, normalized_asm, compiler,
         architecture)).fetchone()
    return row["id"]


def add_idiom_observation(conn, idiom_id, function_address=None,
                          function_name=None, attempt_number=None,
                          source_excerpt=None, assembly_excerpt=None,
                          objdiff_percent=None, accepted_as_best=None,
                          evidence_level="observed", note=None,
                          improvement=None):
    """Record one real compile+objdiff observation of an idiom.

    Duplicate observations (same idiom, function, attempt and level)
    are ignored, so re-running an import never inflates counts.
    """
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    cur = conn.execute(
        """SELECT id FROM idiom_observations
           WHERE idiom_id = ? AND function_address IS ?
             AND attempt_number IS ? AND evidence_level = ?""",
        (idiom_id, function_address, attempt_number, evidence_level))
    if cur.fetchone() is not None:
        return None

    conn.execute(
        """INSERT INTO idiom_observations
               (idiom_id, function_address, function_name,
                attempt_number, compiler, source_excerpt,
                assembly_excerpt, objdiff_percent, accepted_as_best,
                evidence_level, note, created_at)
           SELECT id, ?, ?, ?, compiler, ?, ?, ?, ?, ?, ?, ?
           FROM idioms WHERE id = ?""",
        (function_address, function_name, attempt_number,
         source_excerpt, assembly_excerpt, objdiff_percent,
         int(bool(accepted_as_best)) if accepted_as_best is not None
            else None,
         evidence_level, note, now, idiom_id))

    matched = evidence_level == "matched"
    conn.execute(
        """UPDATE idioms SET
               observation_count = observation_count + 1,
               matched_count = matched_count + ?,
               best_objdiff_score = MAX(COALESCE(best_objdiff_score, ?),
                                        ?),
               average_improvement = CASE
                   WHEN ? IS NULL THEN average_improvement
                   ELSE ROUND((COALESCE(average_improvement, 0) *
                               improvement_samples + ?) /
                              (improvement_samples + 1), 4)
               END,
               improvement_samples = improvement_samples + CASE
                   WHEN ? IS NULL THEN 0 ELSE 1 END,
               last_seen = ?
           WHERE id = ?""",
        (1 if matched else 0, objdiff_percent, objdiff_percent,
         improvement, improvement, improvement, now, idiom_id))
    return conn.execute(
        "SELECT last_insert_rowid() AS id").fetchone()["id"]


def get_idiom(conn, idiom_id):
    return dict(conn.execute(
        "SELECT * FROM idioms WHERE id = ?", (idiom_id,)).fetchone())


def total_counts(conn):
    row = conn.execute(
        """SELECT
               (SELECT COUNT(*) FROM functions) AS functions,
               (SELECT COUNT(*) FROM globals) AS globals,
               (SELECT COUNT(*) FROM strings) AS strings,
               (SELECT COUNT(*) FROM instructions) AS instructions,
               (SELECT COUNT(*) FROM function_callers) AS caller_edges,
               (SELECT COUNT(*) FROM analysis_runs) AS runs
       """).fetchone()
    return dict(row)
