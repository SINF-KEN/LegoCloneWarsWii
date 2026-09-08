#!/usr/bin/env python3
"""m2c integration: produce candidate C from analyzed PowerPC assembly
(roadmap item #17).

Assembly is taken from the existing Ghidra exports
(tools/ghidra/output/function_<addr>_analyzed.json, falling back to
function_<addr>.json), translated from Ghidra syntax into the form m2c
expects, and passed to a locally installed m2c
(https://github.com/matt-kempster/m2c) with the ppc-mwcc target.

m2c output is a CANDIDATE, never authoritative. Only objdiff comparing
compiled output against the original binary decides correctness.

Known m2c limitation handled here: the original m2c cannot represent
PPC virtual calls (mtctr/bctr) or switch jump tables it has not seen.
The wrapper names such dispatch sites as synthetic jtbl_<addr> symbols
with a one-entry table pointing at the fallthrough address, and reports
this as a warning on the result.

Output (all under tools/ai_decomp/attempts/<addr>/m2c/, git-ignored):
    fn.s         translated assembly fed to m2c
    jtbl.s       synthetic jump-table data (only when needed)
    candidate.c  m2c's C output (empty on failure)
    meta.json    function, m2c path/version, warnings, errors, exit code

CLI:
    python3 tools/ai_decomp/m2c.py 801b16b0
    python3 tools/ai_decomp/m2c.py 801b16b0 --json
    python3 tools/ai_decomp/m2c.py 801b16b0 --refresh   # re-run Ghidra export

Exit codes: 0 ok, 1 usage/input error, 2 m2c not found,
3 m2c decompilation failure, 4 missing analysis input.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTPUT_DIR = os.path.join(REPO, "tools", "ghidra", "output")
ATTEMPTS_DIR = os.path.join(HERE, "attempts")
DEFAULT_M2C = os.path.expanduser("~/Decomp/tools/m2c/m2c.py")
M2C_TARGET = "ppc-mwcc"

EXIT_OK = 0
EXIT_INPUT = 1
EXIT_NO_M2C = 2
EXIT_DECOMP_FAILURE = 3
EXIT_MISSING_INPUT = 4

RETURN_LIKE = {"blr", "blrl", "bctr", "bctrl", "bclr", "bclrl"}
BRANCH_MNEMONICS = {"b", "ba", "bl", "bla", "beq", "bne", "blt", "bgt",
                    "ble", "bge", "bdnz", "bdz", "beql", "bnel", "bltl",
                    "bgtl", "blel", "bgel", "bso", "bns"}


def find_m2c(explicit=None):
    """Locate the m2c entry script. Returns (path, error)."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    for env in ("M2C_PATH", "M2C"):
        value = os.environ.get(env)
        if value:
            candidates.append(value)
    candidates.append(DEFAULT_M2C)
    candidates.append(os.path.expanduser("~/Decomp/tools/m2c-rewrite/m2c.py"))

    for candidate in candidates:
        path = os.path.abspath(os.path.expanduser(candidate))
        if os.path.isdir(path):
            path = os.path.join(path, "m2c.py")
        if os.path.exists(path):
            return path, None
    return None, ("m2c not found. Install it (git clone "
                  "https://github.com/matt-kempster/m2c ~/Decomp/tools/m2c) "
                  "or point M2C_PATH at its m2c.py.")


def m2c_version(m2c_path):
    """Best-effort version string for the local m2c installation."""
    repo = os.path.dirname(m2c_path)
    try:
        head = subprocess.run(
            ["git", "-C", repo, "log", "-1", "--format=%h %cs"],
            capture_output=True, text=True, timeout=10)
        if head.returncode == 0 and head.stdout.strip():
            return "matt-kempster m2c (git %s)" % head.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "unknown"


def load_asm(address, refresh=False, output_dir=OUTPUT_DIR):
    """Assembly lines for a function from the Ghidra export."""
    address = db_normalize(address)
    for name in ("function_%s_analyzed.json" % address,
                 "function_%s.json" % address):
        path = os.path.join(output_dir, name)
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            return data, path
    return None, None


def db_normalize(address):
    a = str(address).strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    return a.zfill(8)


def translate_assembly(instruction_lines, function_address):
    """Translate Ghidra-flavored instruction text into m2c asm.

    Returns (asm_text, jtbl_text, warnings).
    """
    warnings = []
    parsed = []
    labels = set()

    for line in instruction_lines:
        m = re.match(r"^\s*([0-9a-fA-F]+):\s*(\S+)\s*(.*)$", line)
        if not m:
            continue
        addr = m.group(1).lower()
        mnemonic = m.group(2).lower()
        ops = m.group(3).strip()

        # canonical SPR mnemonics for m2c (ops exclude the mnemonic)
        spr = re.match(r"^(ctr|lr)\s*,\s*(.+)$", ops, re.IGNORECASE)
        if spr:
            mnemonic = "mt" + spr.group(1).lower()
            ops = spr.group(2)
        else:
            spr = re.match(r"^(.+?)\s*,\s*(ctr|lr)$", ops, re.IGNORECASE)
            if spr:
                mnemonic = "mf" + spr.group(2).lower()
                ops = spr.group(1)

        # calls -> external symbols first, then branch targets -> labels
        if mnemonic == "bl":
            ops = re.sub(r"0x([0-9a-fA-F]+)",
                         lambda mo: "fn_" + mo.group(1).lower(), ops)
        elif mnemonic in BRANCH_MNEMONICS:
            def to_label(match):
                target = match.group(0)[2:].lower()
                labels.add(target)
                return ".L" + target
            ops = re.sub(r"0x[0-9a-fA-F]+", to_label, ops)

        parsed.append((addr, mnemonic, ops))

    # virtual-call dispatch: name the CTR source so m2c can chew on it.
    # pattern: <reg> = lwz ... ; ... ; mtctr <reg> ; bctr
    jtbls = []  # (symbol, fallthrough_addr)
    for i, (addr, mnemonic, ops) in enumerate(parsed):
        if mnemonic != "mtctr" or i + 1 >= len(parsed):
            continue
        nxt = parsed[i + 1]
        if nxt[1] not in ("bctr", "bctrl"):
            continue
        target_reg = ops.strip()
        # find the last write of target_reg before mtctr
        for j in range(i - 1, -1, -1):
            jaddr, jmn, jops = parsed[j]
            if jmn.startswith("lwz") and jops.split(",")[0] == target_reg:
                symbol = "jtbl_" + addr
                if i + 2 < len(parsed):
                    fallthrough = parsed[i + 2][0]
                else:
                    # bctr ends the function: park the table at a
                    # synthetic label after the last instruction
                    fallthrough = "%08x_end" % (int(parsed[-1][0], 16) + 4)
                    parsed.append((fallthrough, "", ""))
                labels.add(fallthrough)
                mem = re.search(r"\((\w+)\)$", jops)
                parsed[j] = (jaddr, jmn, "%s,%s@l(%s)" % (
                    target_reg, symbol, mem.group(1) if mem else "r0"))
                jtbls.append((symbol, fallthrough))
                warnings.append(
                    "synthetic jump table %s introduced for virtual "
                    "call dispatch at %s (m2c cannot represent "
                    "mtctr/bctr directly)" % (symbol, addr))
                break

    out = [".text", ".globl fn_" + function_address,
           "fn_" + function_address + ":"]
    for addr, mnemonic, ops in parsed:
        if addr in labels:
            out.append(".L" + addr + ":")
        if mnemonic:
            out.append((mnemonic + " " + ops).strip())
    asm_text = "\n".join(out) + "\n"

    jtbl_text = None
    if jtbls:
        lines = [".data"]
        for symbol, fallthrough in jtbls:
            lines.append(".globl " + symbol)
            lines.append(symbol + ":")
            lines.append(".4byte .L" + fallthrough)
        jtbl_text = "\n".join(lines) + "\n"

    return asm_text, jtbl_text, warnings


def run_m2c(m2c_path, asm_paths, cwd):
    started = time.time()
    proc = subprocess.run(
        [sys.executable, m2c_path, "-t", M2C_TARGET] + asm_paths,
        capture_output=True, text=True, timeout=120, cwd=cwd)
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "latency_seconds": round(time.time() - started, 3),
    }


def is_decomp_failure(result):
    return result["exit_code"] != 0 or "Decompilation failure" in \
        result["stdout"]


def decompile(address, m2c_path=None, output_root=ATTEMPTS_DIR,
              write=True, output_dir=OUTPUT_DIR):
    """Full m2c attempt for one function. Returns a result dict."""
    address = db_normalize(address)
    result = {
        "function": address,
        "tool": "m2c",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "errors": [],
        "warnings": [],
    }

    data, source_path = load_asm(address, output_dir=output_dir)
    if data is None:
        result["errors"].append(
            "no analysis export for %s under %s; run "
            "./tools/ghidra/export_function.sh %s" % (
                address, OUTPUT_DIR, address))
        result["exit_code"] = EXIT_MISSING_INPUT
        return result
    result["assembly_source"] = source_path

    path, err = find_m2c(m2c_path)
    if path is None:
        result["errors"].append(err)
        result["exit_code"] = EXIT_NO_M2C
        return result
    result["m2c_path"] = path
    result["m2c_version"] = m2c_version(path)

    asm_text, jtbl_text, warnings = translate_assembly(
        data.get("instructions", []), address)
    result["warnings"].extend(warnings)

    out_dir = os.path.join(output_root, address, "m2c")
    if write:
        os.makedirs(out_dir, exist_ok=True)

    fn_s = os.path.join(out_dir, "fn.s")
    jtbl_s = os.path.join(out_dir, "jtbl.s")
    cand_c = os.path.join(out_dir, "candidate.c")
    meta_f = os.path.join(out_dir, "meta.json")
    if write:
        with open(fn_s, "w") as f:
            f.write(asm_text)

    asm_paths = [fn_s]
    if jtbl_text:
        if write:
            with open(jtbl_s, "w") as f:
                f.write(jtbl_text)
        asm_paths.append(jtbl_s)

    run = run_m2c(path, asm_paths, cwd=out_dir if write else ".")
    result.update(run)

    if is_decomp_failure(run):
        result["status"] = "decompilation_failed"
        result["exit_code"] = EXIT_DECOMP_FAILURE
        # m2c reports failures in a /* */ block on stdout
        result["errors"].append(
            (run["stdout"] or run["stderr"]).strip())
        candidate = ""
    else:
        result["status"] = "ok"
        result["exit_code"] = EXIT_OK
        candidate = run["stdout"]

    result["candidate_c"] = candidate
    if write:
        with open(cand_c, "w") as f:
            f.write(candidate)
        with open(meta_f, "w") as f:
            json.dump(result, f, indent=2)
    return result


def print_result(result):
    print("function:  %s" % result["function"])
    print("assembly:  %s" % result.get("assembly_source", "-"))
    print("m2c path:  %s" % result.get("m2c_path", "-"))
    print("m2c ver:   %s" % result.get("m2c_version", "-"))
    print("status:    %s" % result.get("status", "-"))
    for warning in result.get("warnings", []):
        print("warning:   %s" % warning)
    for error in result.get("errors", []):
        print("error:     %s" % error)
    print("--- generated C ---")
    print(result.get("candidate_c", "") or "(none)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("address", help="function address")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--m2c", help="path to m2c.py (or set M2C_PATH)")
    ap.add_argument("--no-write", action="store_true",
                    help="do not store output under attempts/")
    args = ap.parse_args(argv)

    result = decompile(args.address, m2c_path=args.m2c,
                       write=not args.no_write)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_result(result)
    return result.get("exit_code", EXIT_INPUT)


if __name__ == "__main__":
    sys.exit(main())
