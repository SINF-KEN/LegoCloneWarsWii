#!/usr/bin/env python3
"""Objective mismatch evidence extraction (roadmap Phase 5.2).

The project's objdiff-cli (v3.0.0-beta.8) exposes, through its CLI:

  - per-function fuzzy_match_percent / sizes  (report generate)
  - global before/after aggregates            (report changes)
  - an one-shot `diff` command that returns an empty object in this
    beta build (verified: no instruction-level data is available)

dtk dol diff is a strict sequential verifier that aborts at the first
shifted symbol, so it cannot describe a function deep inside a
partially-matched binary.

This module therefore extracts mismatch evidence the same way objdiff
itself does — by comparing the two object files the project already
produces:

  - target .o  (dtk-extracted original object, build/SC4P64/obj/...)
  - base .o    (candidate built from source, build/SC4P64/src/...)

For the target symbol it reads each object's symbol table, extracts the
function bytes, and reports:

  - function size mismatch
  - every differing 32-bit instruction word (bounded), with
    expected/actual hex
  - the expected mnemonic from the Ghidra export when the export's
    instruction count matches the target function exactly

Nothing is invented: absent data is reported as available=false with a
reason, and the actual side is never disassembled (no PowerPC
disassembler is bundled).
"""

import json
import os
import re
import struct

MAX_DIFFERENCES = 16

MH = re.compile(r"^\s*([0-9a-fA-F]+):\s*(.+)$")


def _parse_object(path):
    """Minimal ELF32 big-endian reader: symbol table + section data.

    Works for both dtk-extracted and MWCC-produced relocatable objects.
    Returns {name: (value, size, sh_offset, sh_addr)}.
    """
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        raise ValueError("%s is not an ELF file" % path)
    e_shoff = struct.unpack_from(">I", data, 0x20)[0]
    e_shentsize = struct.unpack_from(">H", data, 0x2E)[0]
    e_shnum = struct.unpack_from(">H", data, 0x30)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, _flags, addr, offset, size, link = \
            struct.unpack_from(">7I", data, off)
        sections.append(dict(typ=typ, addr=addr, offset=offset,
                             size=size, link=link))
    symtab = next((s for s in sections if s["typ"] == 2), None)
    if symtab is None:
        return {}
    strtab = sections[symtab["link"]]
    symbols = {}
    for i in range(symtab["size"] // 16):
        off = symtab["offset"] + i * 16
        name_off, value, size, info = struct.unpack_from(">IIIB",
                                                         data, off)
        shndx = struct.unpack_from(">H", data, off + 14)[0]
        if not name_off or shndx >= len(sections):
            continue
        start = strtab["offset"] + name_off
        end = data.index(b"\0", start)
        name = data[start:end].decode("utf-8", "replace")
        if name and size:
            sec = sections[shndx]
            symbols[name] = (value, size, sec["offset"], sec["addr"],
                             data)
    return symbols


def _symbol_bytes(symbols, name):
    entry = symbols.get(name)
    if entry is None:
        return None
    value, size, sec_off, _sec_addr, data = entry
    raw = data[sec_off + value: sec_off + value + size]
    if len(raw) != size:
        return None
    return raw


def _mnemonic_map(instruction_lines):
    """Ghidra export lines -> {word_index: mnemonic text}."""
    out = []
    for line in instruction_lines or []:
        m = MH.match(line)
        if m:
            out.append(m.group(2).strip())
    return out


def collect_mismatch(worktree, symbol, address=None, unit_name=None,
                     target_path=None, base_path=None,
                     instruction_lines=None, max_differences=16):
    """Build the structured mismatch evidence for one symbol.

    `target_path`/`base_path` are the two object files objdiff compares
    (extracted original and candidate build). `instruction_lines` are
    the Ghidra export's address: instruction lines for this function.
    """
    result = {
        "target": address,
        "symbol": symbol,
        "available": False,
        "reason": None,
        "match_percent": None,
        "source": "object byte comparison (extracted original .o vs "
                  "built candidate .o)",
        "expected_size": None,
        "actual_size": None,
        "size_matches": None,
        "total_words": None,
        "differing_words": None,
        "differences": [],
        "truncated": False,
        "max_differences": max_differences,
    }

    if not target_path or not base_path:
        result["reason"] = ("no unit object paths resolved for symbol "
                            "%r" % symbol)
        return result
    for p in (target_path, base_path):
        if not os.path.exists(p):
            result["reason"] = "object file missing: %s" % p
            return result

    try:
        target_syms = _parse_object(target_path)
        base_syms = _parse_object(base_path)
    except (OSError, ValueError) as exc:
        result["reason"] = "object parse failed: %s" % exc
        return result

    target_raw = _symbol_bytes(target_syms, symbol)
    base_raw = _symbol_bytes(base_syms, symbol)

    if target_raw is None and base_raw is None:
        result["reason"] = ("symbol %r not found in either object"
                            % symbol)
        return result
    if target_raw is None:
        result["reason"] = ("symbol %r not present in the extracted "
                            "original object" % symbol)
        return result
    if base_raw is None:
        result["reason"] = ("symbol %r not present in the built "
                            "candidate object (not implemented in the "
                            "unit source yet)" % symbol)
        return result

    result["available"] = True
    result["reason"] = None
    result["expected_size"] = len(target_raw)
    result["actual_size"] = len(base_raw)
    result["size_matches"] = len(target_raw) == len(base_raw)
    result["total_words"] = max(len(target_raw), len(base_raw)) // 4

    mnemonics = _mnemonic_map(instruction_lines)
    aligned = (len(mnemonics) == len(target_raw) // 4)

    word_count = min(len(target_raw), len(base_raw)) // 4
    differences = []
    for w in range(word_count):
        expected_word = target_raw[w * 4:w * 4 + 4]
        actual_word = base_raw[w * 4:w * 4 + 4]
        if expected_word == actual_word:
            continue
        entry = {
            "offset": w * 4,
            "kind": "instruction",
            "expected": expected_word.hex(),
            "actual": actual_word.hex(),
        }
        if aligned:
            entry["expected_mnemonic"] = mnemonics[w]
        differences.append(entry)

    if not result["size_matches"]:
        differences.append({
            "offset": word_count * 4,
            "kind": "function_size",
            "expected": "%d bytes" % len(target_raw),
            "actual": "%d bytes" % len(base_raw),
        })

    result["differing_words"] = sum(
        1 for d in differences if d["kind"] == "instruction")
    if len(differences) > max_differences:
        result["truncated"] = True
    result["differences"] = differences[:max_differences]
    return result


def unit_object_paths(worktree, unit_name, config_path=None):
    """Resolve (target_path, base_path) for a unit from objdiff.json."""
    config_path = config_path or os.path.join(worktree, "objdiff.json")
    if not unit_name or not os.path.exists(config_path):
        return None, None
    with open(config_path) as f:
        config = json.load(f)
    for unit in config.get("units", []):
        if unit.get("name") == unit_name:
            base = unit.get("base_path")
            target = unit.get("target_path")
            mk = lambda p: os.path.join(worktree, p) if p else None
            return mk(target), mk(base)
    return None, None


def render_mismatch_markdown(mismatch):
    """Bounded Markdown block for LLM prompts."""
    if not mismatch:
        return ""
    lines = ["```json"]
    text = json.dumps(mismatch, indent=2)
    if len(text) > 6000:
        text = text[:6000] + "\n/* ...truncated... */"
    lines.append(text)
    lines.append("```")
    return "\n".join(lines)


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worktree", required=True)
    ap.add_argument("--symbol", required=True)
    ap.add_argument("--address")
    ap.add_argument("--unit")
    ap.add_argument("--instructions",
                    help="Ghidra export JSON with instruction lines")
    args = ap.parse_args()

    instructions = None
    if args.instructions and os.path.exists(args.instructions):
        with open(args.instructions) as f:
            instructions = json.load(f).get("instructions")

    target, base = unit_object_paths(args.worktree, args.unit)
    report = os.path.join(args.worktree, "build", "SC4P64", "report.json")
    match_percent = None
    if os.path.exists(report):
        with open(report) as f:
            rep = json.load(f)
        _unit, entry = None, None
        for unit in rep.get("units", []):
            for fn in unit.get("functions", []):
                if fn.get("name") == args.symbol:
                    entry = fn
        match_percent = (entry or {}).get("fuzzy_match_percent")

    result = collect_mismatch(args.worktree, args.symbol,
                              address=args.address, unit_name=args.unit,
                              target_path=target, base_path=base,
                              instruction_lines=instructions)
    result["match_percent"] = match_percent
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    main()
