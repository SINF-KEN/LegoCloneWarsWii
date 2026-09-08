#!/usr/bin/env python3
"""MWCC compiler-idiom knowledge base (roadmap Phase 5.3).

Correlates C/C++ source constructs with observed MWCC/PowerPC compiler
output and objdiff outcomes, so future attempts can reuse proven
compiler-behavior evidence.

The critical distinction this module maintains:

    an idiom is an OBSERVATION ("source construct X was compiled in
    function F under build configuration Y and objdiff scored it P%"),
    never a rule ("MWCC always generates this").

Only real compile + objdiff outcomes create observations. LLM claims,
compiler failures and globally regressed candidates never become
successful matching idioms (failed/regressed candidates may be stored
explicitly marked 'rejected' for diagnostics).

Normalization is deliberately conservative:
  - source: whitespace collapse, hex-case folding, and a small set of
    targeted canonicalizations (e.g. (x & 0xff) << 2 and
    (x & 255) * 4 group together); the original excerpt is preserved
    separately as evidence
  - assembly: register names, address-like immediates and local labels
    are genericized; mnemonics, small immediates (shifts, masks,
    vtable offsets) and operand structure are preserved
"""

import os
import re

import database as db

COMPILER = "MWCC"
ARCHITECTURE = "PowerPC"
TARGET = "ppc-mwcc"

MAX_EXCERPT = 500
DEFAULT_RETRIEVE_LIMIT = 5


# ----------------------------------------------------------------
# normalization
# ----------------------------------------------------------------

def normalize_source(text):
    """Conservative source normalization (never destructive to
    evidence: callers keep the original excerpt separately)."""
    if text is None:
        return None
    s = re.sub(r"\s+", " ", str(text)).strip()
    s = re.sub(r"0[xX]([0-9A-Fa-f]+)", lambda m: "0x" + m.group(1).lower(), s)
    # common decimal/hex mask equivalence
    s = re.sub(r"\b255\b", "0xff", s)
    s = re.sub(r"\b65535\b", "0xffff", s)
    return s


def canonical_mask_shift(text):
    """Canonical form for mask+shift/multiply indexing, or None.

    (x & 0xff) << 2 and (x & 255) * 4 both become
    'mask_shift(bits=8, shift=2)'.
    """
    if text is None:
        return None
    s = normalize_source(text)
    m = re.search(r"\(\s*(\w+)\s*&\s*(0x[0-9a-f]+|\d+)\s*\)\s*"
                  r"(<<|\*)\s*(\d+)", s)
    if not m:
        return None
    mask = int(m.group(2), 0)
    op, amount = m.group(3), int(m.group(4))
    if op == "*":
        if amount == 0 or (amount & (amount - 1)) != 0:
            return None  # not a power of two: not a shift
        amount = amount.bit_length() - 1
    return "mask_shift(mask_bits=%d, shift=%d)" % (mask.bit_length(),
                                                   amount)


def normalize_asm_line(line):
    """Structural normalization of one assembly line.

    Genericizes register numbers, address-like immediates and local
    labels; keeps mnemonics, small immediates and operand structure.
    """
    line = line.strip()
    line = re.sub(r"^[0-9a-fA-F]+:\s*", "", line)  # address prefix
    line = re.sub(r"\br\d+\b", "r#", line)
    line = re.sub(r"\bf\d+\b", "f#", line)
    line = re.sub(r"-?0x[0-9a-fA-F]{4,}\b", "0xADDR", line)  # addresses
    line = re.sub(r"\bfn_[0-9a-fA-F]+\b", "SYM", line)
    line = re.sub(r"\.L[0-9a-fA-F_]+", ".LOC", line)
    return re.sub(r"\s+", " ", line).strip()


def normalize_asm_sequence(lines):
    return " ; ".join(normalize_asm_line(l) for l in lines
                      if normalize_asm_line(l))


# ----------------------------------------------------------------
# conservative idiom extraction
# ----------------------------------------------------------------

MASK_SHIFT_RE = re.compile(r"\(\s*(\w+)\s*&\s*(0x[0-9a-f]+|\d+)\s*\)\s*"
                           r"(<<|\*)\s*(\d+)")
NULL_CHECK_RE = re.compile(r"(\w+)\s*(?:==|!=)\s*(?:0\b|NULL\b|nullptr\b)"
                           r"|!\s*\(\s*\w+\s*\)|!\s*\w+")
PTR_CAST_CALL_RE = re.compile(r"\(\s*[A-Za-z_]\w*\s*\*+\s*\*?\s*\)[^\n;]*"
                              r"\)\s*\(")
RLWINM_RE = re.compile(r"\brlwinm\b")
MASKED_INDEX_RE = re.compile(r"\[\s*(\w+)\s*&\s*(0x[0-9a-f]+|\d+)\s*\]")
CMPWI0_RE = re.compile(r"\bcmpwi\s+r#,0(?:x0?)?\b")


def extract_idioms(source_text, assembly_lines):
    """Extract conservative idiom candidates from one compiled pair.

    Returns a list of {kind, normalized_source, normalized_asm,
    source_excerpt, assembly_excerpt}. Only patterns corroborated on
    BOTH sides (source construct present AND matching assembly
    structure present) are emitted; pure assembly-side patterns (high/
    low address constants, small-data access, virtual-call shape) are
    also recorded with a null source pattern.
    """
    src_lines = []
    for raw in (source_text or "").splitlines():
        line = raw.strip()
        if line.startswith("+"):
            line = line[1:]
        if line:
            src_lines.append(line)
    asm_lines = list(assembly_lines or [])

    patterns = []

    def add(kind, norm_src, norm_asm, src_exc, asm_exc):
        patterns.append({
            "kind": kind,
            "normalized_source": norm_src,
            "normalized_asm": norm_asm,
            "source_excerpt": (src_exc or "")[:MAX_EXCERPT],
            "assembly_excerpt": (asm_exc or "")[:MAX_EXCERPT],
        })

    norm_asm_all = [normalize_asm_line(l) for l in asm_lines]
    joined_asm = " ; ".join(norm_asm_all)

    # mask+shift indexing correlated with rlwinm
    for line in src_lines:
        canonical = canonical_mask_shift(line)
        if canonical and any(RLWINM_RE.search(a) for a in norm_asm_all):
            rlwinm = next(a for a in norm_asm_all
                          if RLWINM_RE.search(a))
            add("mask_shift_index", canonical, rlwinm, line, rlwinm)

    # null check correlated with cmpwi ...,0 / 0x0
    for line in src_lines:
        if NULL_CHECK_RE.search(line) and \
                any(CMPWI0_RE.search(a) for a in norm_asm_all):
            cmp_line = next(a for a in norm_asm_all
                            if CMPWI0_RE.search(a))
            add("null_check", normalize_source(line), cmp_line,
                line, cmp_line)

    # masked table indexing correlated with rlwinm
    for line in src_lines:
        m = MASKED_INDEX_RE.search(line)
        if m and any(RLWINM_RE.search(a) for a in norm_asm_all):
            rlwinm = next(a for a in norm_asm_all
                          if RLWINM_RE.search(a))
            mask = int(m.group(2), 0)
            add("masked_table_index",
                "masked_index(mask_bits=%d)" % mask.bit_length(),
                rlwinm, line, rlwinm)

    # pointer-cast call correlated with an indirect branch
    for line in src_lines:
        if PTR_CAST_CALL_RE.search(line) and \
                any(a.startswith(("bctr", "bctrl")) for a in norm_asm_all):
            add("function_pointer_call", normalize_source(line),
                "bctr", line, "bctr")

    # high/low address construction (assembly-side observation)
    for i in range(len(norm_asm_all) - 1):
        a, b = norm_asm_all[i], norm_asm_all[i + 1]
        if a.startswith("lis r#") and b.startswith("addi r#,r#,"):
            add("high_low_address_const", None,
                a + " ; " + b, None,
                (asm_lines[i] if i < len(asm_lines) else a))

    # small-data-area access via r13
    for i, a in enumerate(norm_asm_all):
        if "(r13)" in a:
            add("small_data_access", None, a, None,
                asm_lines[i] if i < len(asm_lines) else a)

    # virtual call shape: lwz; lwz; mtctr; bctr window
    for i in range(len(norm_asm_all) - 3):
        w = norm_asm_all[i:i + 4]
        if (w[0].startswith("lwz") and w[1].startswith("lwz")
                and w[2].startswith("mtctr") and w[3].startswith("bctr")):
            add("virtual_call", None, " ; ".join(w), None,
                " ; ".join(asm_lines[i:i + 4]))
            break

    # dedupe within the same extraction
    seen = set()
    unique = []
    for p in patterns:
        key = (p["kind"], p["normalized_source"], p["normalized_asm"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


# ----------------------------------------------------------------
# learning from real compile + objdiff outcomes
# ----------------------------------------------------------------

def learn_from_attempt(conn, address, function_name=None,
                       attempt_number=None, source_text=None,
                       assembly_lines=None, objdiff_percent=None,
                       accepted_as_best=None, regressed=False,
                       compiled=False, improvement=None):
    """Record idiom observations from one candidate evaluation.

    Returns the list of observation summaries. Rules:
      - candidates that never compiled produce nothing
      - objdiff 100.0 -> evidence level 'matched' (strongest)
      - global regression or unmeasured candidate -> 'rejected'
      - everything else that compiled -> 'observed'
    """
    if not compiled:
        return []
    if objdiff_percent == 100.0:
        level = "matched"
    elif regressed or objdiff_percent is None:
        level = "rejected"
    else:
        level = "observed"

    learned = []
    for p in extract_idioms(source_text, assembly_lines):
        idiom_id = db.upsert_idiom(conn, p["kind"],
                                   p["normalized_source"],
                                   p["normalized_asm"],
                                   compiler=COMPILER,
                                   architecture=ARCHITECTURE,
                                   target=TARGET)
        obs_id = db.add_idiom_observation(
            conn, idiom_id, function_address=address,
            function_name=function_name, attempt_number=attempt_number,
            source_excerpt=p["source_excerpt"],
            assembly_excerpt=p["assembly_excerpt"],
            objdiff_percent=objdiff_percent,
            accepted_as_best=accepted_as_best,
            evidence_level=level,
            note="regressed" if regressed else None,
            improvement=improvement)
        if obs_id is not None:
            learned.append({
                "idiom_id": idiom_id, "kind": p["kind"],
                "level": level, "observation_id": obs_id,
            })
    conn.commit()
    return learned


# ----------------------------------------------------------------
# retrieval for LLM context
# ----------------------------------------------------------------

def _idiom_level(conn, idiom_id):
    row = conn.execute(
        "SELECT observation_count, matched_count FROM idioms "
        "WHERE id = ?", (idiom_id,)).fetchone()
    if row is None:
        return "observed", 0, 0
    return db.effective_idiom_level(row["observation_count"],
                                    row["matched_count"]), \
        row["observation_count"], row["matched_count"]


def retrieve_relevant_idioms(conn, assembly_lines=None, source_text=None,
                             limit=DEFAULT_RETRIEVE_LIMIT,
                             compiler=COMPILER,
                             architecture=ARCHITECTURE):
    """Idioms relevant to the target assembly / candidate source.

    Relevance: the idiom's normalized assembly pattern appears in the
    target assembly (score 2), or its normalized source pattern appears
    in the candidate source (score 1). Ranked by relevance, then
    matched_count, observation_count, best score. Compiler and
    architecture filters are applied first.
    """
    norm_target = " ; ".join(normalize_asm_line(l)
                             for l in (assembly_lines or []))
    norm_source = normalize_source(source_text or "")

    scored = []
    for row in conn.execute(
            """SELECT * FROM idioms
               WHERE compiler = ? AND architecture = ?""",
            (compiler, architecture)):
        score = 0
        if row["normalized_asm"] and row["normalized_asm"] in norm_target:
            score += 2
        if row["normalized_source"] and norm_source and \
                row["normalized_source"] in norm_source:
            score += 1
        if score == 0:
            continue
        scored.append((score, row["matched_count"],
                       row["observation_count"],
                       row["best_objdiff_score"] or 0, row))

    scored.sort(key=lambda t: (-t[0], -t[1], -t[2], -t[3]))
    out = []
    for _score, _mc, _oc, _best, row in scored[:limit]:
        level, oc, mc = _idiom_level(conn, row["id"])
        out.append({
            "id": row["id"],
            "kind": row["kind"],
            "normalized_source": row["normalized_source"],
            "normalized_asm": row["normalized_asm"],
            "level": level,
            "observation_count": oc,
            "matched_count": mc,
            "best_objdiff_score": row["best_objdiff_score"],
            "last_seen": row["last_seen"],
        })
    return out


def render_idioms_markdown(idioms):
    """Bounded prompt block with the mandatory non-authority caveat."""
    if not idioms:
        return ""
    lines = ["### Known MWCC compiler idioms relevant to this target",
             "",
             "These are observed compiler patterns, not guarantees. "
             "Use them as evidence, but verify against the target "
             "assembly and objdiff.", ""]
    for i, idi in enumerate(idioms, 1):
        lines.append("%d. %s" % (i, idi["kind"]))
        lines.append("   level: %s | observed in %d compilation(s), "
                     "%d objdiff-verified 100%%"
                     % (idi["level"], idi["observation_count"],
                        idi["matched_count"]))
        if idi["normalized_source"]:
            lines.append("   source pattern: `%s`"
                         % idi["normalized_source"])
        if idi["normalized_asm"]:
            lines.append("   assembly pattern: `%s`"
                         % idi["normalized_asm"])
        if idi["best_objdiff_score"] is not None:
            lines.append("   best objdiff score seen: %s%%"
                         % idi["best_objdiff_score"])
        lines.append("   last seen: %s" % (idi["last_seen"] or "?"))
    return "\n".join(lines)


# ----------------------------------------------------------------
# convenience: learn directly from an attempt record on disk
# ----------------------------------------------------------------

def learn_from_attempt_record(conn, attempts_root, address,
                              attempt_number, ghidra_output_dir=None):
    """Learn from a recorded attempt (attempts/<addr>/attempt-NNN).

    Uses only objective artifacts: patch.diff (the candidate source),
    the analyzed Ghidra export (target assembly) and the attempt's
    objdiff/result records. Returns the learned observations.
    """
    import json
    attempt_dir = os.path.join(attempts_root, address,
                               "attempt-%03d" % attempt_number)
    result_path = os.path.join(attempt_dir, "result.json")
    if not os.path.exists(result_path):
        return []
    with open(result_path) as f:
        result = json.load(f)

    function_name = None
    context_path = os.path.join(attempt_dir, "context.json")
    if os.path.exists(context_path):
        with open(context_path) as f:
            function_name = (json.load(f).get("function") or {}).get(
                "name")

    patch_path = os.path.join(attempt_dir, "patch.diff")
    patch = open(patch_path).read() if os.path.exists(patch_path) else ""

    asm = []
    if ghidra_output_dir:
        export = os.path.join(
            ghidra_output_dir,
            "function_%s.json" % db.normalize_address(address))
        if os.path.exists(export):
            with open(export) as f:
                asm = json.load(f).get("instructions", [])

    od = result.get("objdiff") or {}
    classification = result.get("classification")
    compiled = (od.get("match_percent") is not None
                or classification in ("matching", "ok",
                                      "objdiff_no_improvement"))
    accepted = result.get("accepted_as_best")
    return learn_from_attempt(
        conn, address=address, function_name=function_name,
        attempt_number=attempt_number, source_text=patch,
        assembly_lines=asm, objdiff_percent=od.get("match_percent"),
        accepted_as_best=accepted if accepted is not None else None,
        regressed=bool(od.get("regressions")), compiled=compiled)


if __name__ == "__main__":
    print("module — see test_idioms.py and orchestrator integration")
