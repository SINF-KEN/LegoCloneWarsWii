#!/usr/bin/env python3
"""Build orchestration inside an isolated worktree (roadmap item #23).

Uses the project's existing build system exactly as-is:

    python3 configure.py <configure_args>   # only when build.ninja is
                                            # missing (fresh worktree)
    ninja                                   # the actual build

The heavy tool downloads (dtk, MWCC compilers, objdiff-cli) are shared
with the primary checkout by symlinking build/tools, build/compilers
and build/binutils into the worktree before the first build, so no
network access and no multi-GB re-download is needed.

Captured per build: exit code, stdout, stderr, duration, compiler
errors, compiler warnings, and the object files mentioned in the
output. Warnings are reported but are NOT failures; only ninja's exit
code decides success. A configurable timeout kills runaway builds and
is reported as a failure with classification "timeout".

Logs are preserved by the caller (orchestrator) under
attempts/<address>/<attempt>/build.log; run_build() returns the full
record.

CLI:
    python3 tools/ai_decomp/build.py --worktree .worktrees/X/attempt-001
    python3 tools/ai_decomp/build.py --worktree W --configure-only
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

DEFAULT_TIMEOUT = 3600  # seconds; first worktree build compiles everything
SHARED_TOOL_DIRS = ("tools", "compilers", "binutils")
# read-only resources a fresh worktree needs but cannot regenerate: the
# game dump lives in orig/ (git-ignored). Attempts never write there
# (editor.py rejects orig/ paths outright), so a symlink is safe.
SHARED_LINKS = SHARED_TOOL_DIRS + ("orig",)

ERROR_RE = re.compile(r"\berror\b|Error ", re.IGNORECASE)
WARNING_RE = re.compile(r"\bwarning\b", re.IGNORECASE)
NINJA_ERR_RE = re.compile(r"^FAILED:", re.MULTILINE)
OBJECT_RE = re.compile(r"build/SC4P64/(?:src|obj)/[^\s:]+\.o")


class BuildError(Exception):
    pass


def _configure_args(repo=REPO):
    """Read configure_args from the primary build.ninja."""
    ninja = os.path.join(repo, "build.ninja")
    if not os.path.exists(ninja):
        return "--version SC4P64"  # the project's default target
    with open(ninja) as f:
        for line in f:
            if line.startswith("configure_args ="):
                return line.split("=", 1)[1].strip()
    return "--version SC4P64"


def share_tool_links(worktree, repo=REPO):
    """Symlink shared tool dirs and the read-only orig/ dump into a
    fresh worktree so the build never needs network access."""
    linked = []
    for entry in SHARED_TOOL_DIRS:
        src = os.path.join(repo, "build", entry)
        dst = os.path.join(worktree, "build", entry)
        if not os.path.isdir(src) or os.path.exists(dst):
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.symlink(src, dst)
        linked.append(dst)
    # orig/: read-only game dump reference (never written by attempts).
    # The branch tracks placeholder .gitkeep entries under orig/, so a
    # fresh worktree has an empty orig/ tree: replace it with the
    # symlink when it contains nothing but placeholders.
    orig_src = os.path.join(repo, "orig")
    orig_dst = os.path.join(worktree, "orig")
    if os.path.isdir(orig_src) and not os.path.islink(orig_dst) \
            and os.path.isdir(orig_dst):
        placeholders_only = True
        for root, _dirs, files in os.walk(orig_dst):
            for name in files:
                if name != ".gitkeep":
                    placeholders_only = False
                    break
        if placeholders_only:
            import shutil
            shutil.rmtree(orig_dst)
    if os.path.isdir(orig_src) and not os.path.exists(orig_dst):
        os.symlink(orig_src, orig_dst)
        linked.append(orig_dst)
    return linked


def configure(worktree, repo=REPO, timeout=300):
    """Run configure.py when the worktree has no build.ninja yet."""
    if os.path.exists(os.path.join(worktree, "build.ninja")):
        return {"configured": False, "note": "build.ninja already present"}

    shared = share_tool_links(worktree, repo=repo)
    python = sys.executable
    started = time.time()
    proc = subprocess.run(
        [python, "configure.py"] + _configure_args(repo).split(),
        cwd=worktree, capture_output=True, text=True, timeout=timeout)
    return {
        "configured": True,
        "exit_code": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "duration_seconds": round(time.time() - started, 3),
        "shared_tool_links": shared,
    }


def classify_output(text):
    """Extract errors/warnings/object mentions from build output."""
    errors = sorted({line.strip() for line in text.splitlines()
                     if NINJA_ERR_RE.search(line)
                     or (ERROR_RE.search(line)
                         and not line.strip().startswith("ninja: no work"))})
    warnings = sorted({line.strip() for line in text.splitlines()
                       if WARNING_RE.search(line)
                       and line not in errors})
    objects = sorted(set(OBJECT_RE.findall(text)))
    return errors, warnings, objects


def run_build(worktree, timeout=DEFAULT_TIMEOUT, repo=REPO,
              build_cmd=("ninja",)):
    """Run the build inside worktree. Never raises on build failure."""
    if not os.path.isdir(worktree):
        raise BuildError("worktree does not exist: %s" % worktree)

    record = {
        "worktree": worktree,
        "command": list(build_cmd),
        "timeout_seconds": timeout,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "configure": None,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "duration_seconds": None,
        "errors": [],
        "warnings": [],
        "objects": [],
        "success": False,
        "classification": "unknown",
    }

    try:
        record["configure"] = configure(worktree, repo=repo)
        if record["configure"].get("configured") \
                and record["configure"].get("exit_code") != 0:
            record["classification"] = "configure_error"
            record["errors"] = ["configure.py failed"] + [
                record["configure"]["stderr"][-2000:]]
            return record

        started = time.time()
        proc = subprocess.run(
            list(build_cmd), cwd=worktree, capture_output=True,
            text=True, timeout=timeout)
        record["exit_code"] = proc.returncode
        record["duration_seconds"] = round(time.time() - started, 3)
        record["stdout"] = proc.stdout[-100000:]
        record["stderr"] = proc.stderr[-50000:]

        errors, warnings, objects = classify_output(
            proc.stdout + "\n" + proc.stderr)
        record["errors"] = errors
        record["warnings"] = warnings
        record["objects"] = objects
        record["success"] = proc.returncode == 0
        record["classification"] = "ok" if proc.returncode == 0 \
            else "compile_error"
    except subprocess.TimeoutExpired as exc:
        record["exit_code"] = None
        record["duration_seconds"] = timeout
        record["stdout"] = (exc.stdout or "")[-20000:] \
            if isinstance(exc.stdout, str) else ""
        record["stderr"] = "build timed out after %s seconds" % timeout
        record["classification"] = "timeout"
        record["success"] = False
    return record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worktree", required=True)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--out", help="write the JSON record to a file")
    ap.add_argument("--configure-only", action="store_true")
    args = ap.parse_args(argv)

    try:
        if args.configure_only:
            record = configure(args.worktree)
        else:
            record = run_build(args.worktree, timeout=args.timeout)
    except BuildError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, "w") as f:
            json.dump(record, f, indent=2)
    summary = {k: v for k, v in record.items()
               if k in ("success", "classification", "exit_code",
                        "duration_seconds")}
    summary["errors"] = len(record.get("errors", []))
    summary["warnings"] = len(record.get("warnings", []))
    summary["objects"] = len(record.get("objects", []))
    print(json.dumps(summary, indent=2))
    return 0 if record.get("success", False) else 1


if __name__ == "__main__":
    sys.exit(main())
