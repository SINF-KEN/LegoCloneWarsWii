#!/usr/bin/env python3
"""Safe source editor for LLM-proposed changes (roadmap item #21).

Accepts structured edits from the model:

    {"source_changes": [
        {"path": "src/foo.cpp",
         "operation": "replace",       # replace | create | append
         "old_text": "...exact current text...",
         "new_text": "...replacement..."}
    ]}

Safety rules, enforced unconditionally:

  - only src/ and include/ are writable
  - absolute paths, '..' traversal and symlink escapes are rejected
  - protected trees (orig/, build/, .git/, tools/ghidra/output/) are
    never writable even via a misplaced allow-list change
  - replace requires old_text to match EXACTLY ONCE (otherwise the
    patch is ambiguous and refused)
  - create requires the file not to exist; append requires it to exist
  - a unified diff of every change is produced BEFORE anything is
    written; original contents are recorded for rollback
  - dry-run performs all validation and diff generation and writes
    nothing

A unified diff can also be applied (--patch file), validated with the
same path rules and `git apply --check` before being applied.

CLI:
    python3 tools/ai_decomp/editor.py --changes changes.json [--repo R]
    python3 tools/ai_decomp/editor.py --changes changes.json --dry-run
    python3 tools/ai_decomp/editor.py --patch patch.diff --repo R
"""

import argparse
import difflib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))

ALLOWED_ROOTS = ("src", "include")

PROTECTED = ("orig", "build", ".git", ".worktrees",
             os.path.join("tools", "ghidra", "output"))

OPERATIONS = ("replace", "create", "append")


class EditError(Exception):
    """Refusal with reason; the repository is untouched."""


def validate_relpath(raw):
    """Validate and normalize a proposed path. Returns repo-relative
    posix path. Raises EditError on any violation."""
    if not raw or not isinstance(raw, str):
        raise EditError("empty path")
    if raw.startswith("/") or (len(raw) > 1 and raw[1] == ":"):
        raise EditError("absolute paths are not allowed: %r" % raw)
    if "\\" in raw:
        raise EditError("backslashes are not allowed in paths: %r" % raw)
    parts = raw.split("/")
    if any(p in ("..", ".") for p in parts):
        raise EditError("path traversal is not allowed: %r" % raw)
    clean = "/".join(p for p in parts if p)
    if clean != raw:
        raise EditError("path is not in normalized form: %r" % raw)
    top = parts[0]
    if top not in ALLOWED_ROOTS:
        raise EditError(
            "only %s are writable, got %r" % ("/".join(ALLOWED_ROOTS),
                                              raw))
    for protected in PROTECTED:
        if clean == protected or clean.startswith(protected + "/"):
            raise EditError("protected path: %r" % raw)
    return clean


def _is_within(repo_root, rel):
    """True if repo_root/rel is a real file/dir without symlink escape."""
    path = os.path.join(repo_root, rel)
    if not os.path.exists(path):
        return True  # creating a new file is fine if parents are real
    real_repo = os.path.realpath(repo_root)
    real = os.path.realpath(path)
    return real == repo_root or real.startswith(real_repo + os.sep)


def validate_changes(changes, repo_root=REPO):
    """Validate a list of structured edits against the working tree."""
    if not isinstance(changes, list) or not changes:
        raise EditError("source_changes must be a non-empty list")
    seen = set()
    for change in changes:
        if not isinstance(change, dict):
            raise EditError("each change must be an object")
        rel = validate_relpath(change.get("path"))
        op = change.get("operation")
        if op not in OPERATIONS:
            raise EditError("invalid operation %r (want %s)"
                            % (op, "|".join(OPERATIONS)))
        key = (rel, op)
        if key in seen:
            raise EditError("duplicate change for %s (%s)" % key)
        seen.add(key)

        path = os.path.join(repo_root, rel)
        exists = os.path.exists(path)
        if not _is_within(repo_root, rel):
            raise EditError("path escapes the repository: %r" % rel)
        if op == "create" and exists:
            raise EditError("create but %s already exists" % rel)
        if op in ("replace", "append") and not exists:
            raise EditError("%s but %s does not exist" % (op, rel))

        old_text = change.get("old_text")
        new_text = change.get("new_text")
        if new_text is None:
            raise EditError("missing new_text for %s" % rel)
        if op == "replace":
            if not isinstance(old_text, str) or not old_text:
                raise EditError("replace needs non-empty old_text for %s"
                                % rel)
            with open(path, errors="replace") as f:
                current = f.read()
            count = current.count(old_text)
            if count == 0:
                raise EditError("old_text not found in %s (refusing "
                                "ambiguous patch)" % rel)
            if count > 1:
                raise EditError("old_text matches %d times in %s "
                                "(refusing ambiguous patch)"
                                % (count, rel))


def plan_changes(changes, repo_root=REPO):
    """Compute (path, new_content) pairs without writing anything."""
    planned = []
    for change in changes:
        rel = validate_relpath(change.get("path"))
        op = change.get("operation")
        path = os.path.join(repo_root, rel)
        new_text = change["new_text"]
        if op == "replace":
            with open(path, errors="replace") as f:
                current = f.read()
            planned.append((rel, current.replace(change["old_text"],
                                                 new_text, 1)))
        elif op == "create":
            planned.append((rel, new_text))
        elif op == "append":
            with open(path, errors="replace") as f:
                current = f.read()
            planned.append((rel, current + new_text))
    return planned


def make_patch(planned, repo_root=REPO):
    """Unified diff for planned (rel, new_content) pairs."""
    diffs = []
    for rel, new_content in planned:
        path = os.path.join(repo_root, rel)
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                old_content = f.read()
        else:
            old_content = ""
        diff = difflib.unified_diff(
            old_content.splitlines(keepends=True),
            new_content.splitlines(keepends=True),
            fromfile="a/" + rel, tofile="b/" + rel)
        diffs.extend(diff)
    return "".join(diffs)


def record_originals(changes, repo_root=REPO):
    """Snapshot original contents of every touched existing file."""
    originals = {}
    for change in changes:
        rel = validate_relpath(change.get("path"))
        path = os.path.join(repo_root, rel)
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                originals[rel] = f.read()
        else:
            originals[rel] = None
    return originals


def rollback(originals, repo_root=REPO):
    """Restore files to their recorded original state."""
    restored = []
    for rel, content in originals.items():
        validate_relpath(rel)  # never restore outside allowed roots
        path = os.path.join(repo_root, rel)
        if content is None:
            if os.path.exists(path):
                os.remove(path)
                restored.append((rel, "deleted"))
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(content)
            restored.append((rel, "restored"))
    return restored


def apply_changes(changes, repo_root=REPO, dry_run=False):
    """Validate, diff, and (unless dry-run) apply structured edits.

    Returns a result dict with the patch, originals (for rollback) and
    per-file actions. Raises EditError without touching anything when a
    change is invalid or ambiguous. Use restrict_to() beforehand to keep
    attempts focused on specific files.
    """
    validate_changes(changes, repo_root=repo_root)

    planned = plan_changes(changes, repo_root=repo_root)
    patch = make_patch(planned, repo_root=repo_root)
    originals = record_originals(changes, repo_root=repo_root)

    result = {
        "dry_run": dry_run,
        "applied": [],
        "patch": patch,
        "originals": originals,
    }
    if dry_run:
        result["applied"] = [(rel, "dry-run") for rel, _ in planned]
        return result

    for rel, new_content in planned:
        path = os.path.join(repo_root, rel)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(new_content)
        result["applied"].append((rel, "written"))
    return result


def rel_form(p):
    """Reduce a path to its src/- or include/- relative form."""
    p = str(p).strip("/")
    for root in ALLOWED_ROOTS:
        idx = p.find(root + "/")
        if idx != -1:
            return p[idx:]
    return p


def restrict_to(changes, allowed_paths):
    """Refuse changes touching files outside allowed_paths.

    The orchestrator uses this to keep attempts focused on the target
    function's unit. Allowed paths may be absolute or relative; they are
    compared on their src/- or include/- relative form.
    """
    normalized = {rel_form(p) for p in allowed_paths}
    for change in changes:
        rel = validate_relpath(change.get("path"))
        if rel not in normalized:
            raise EditError(
                "change to unrelated file %r refused (allowed: %s)"
                % (rel, sorted(normalized)))


def validate_unified_diff(diff_text, repo_root=REPO):
    """Strictly validate a unified diff's target paths."""
    if not diff_text or not diff_text.strip():
        raise EditError("empty diff")
    for line in diff_text.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            path = line[4:].split("\t")[0].strip()
            if path in ("/dev/null",):
                continue
            if path.startswith("a/") or path.startswith("b/"):
                path = path[2:]
            validate_relpath(path)


def apply_unified_diff(diff_text, repo_root=REPO, dry_run=False):
    """Apply a unified diff via git apply after strict validation."""
    validate_unified_diff(diff_text, repo_root=repo_root)

    def git(args, check):
        proc = subprocess.run(
            ["git", "-C", repo_root] + args, input=diff_text,
            capture_output=True, text=True)
        if check and proc.returncode != 0:
            raise EditError("git %s failed: %s"
                            % (args[0], proc.stderr.strip()))
        return proc

    if dry_run:
        git(["apply", "--check", "--whitespace=nowarn"], check=True)
        return {"dry_run": True, "applied": [], "patch": diff_text,
                "originals": {}}
    git(["apply", "--whitespace=nowarn"], check=True)
    return {"dry_run": False, "applied": [("diff", "applied")],
            "patch": diff_text, "originals": {}}


# ----------------------------------------------------------------
# CLI
# ----------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--changes", help="JSON file with source_changes")
    ap.add_argument("--patch", help="unified diff file")
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.changes and not args.patch:
        ap.error("one of --changes / --patch is required")

    try:
        if args.changes:
            with open(args.changes) as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                payload = payload.get("source_changes")
            result = apply_changes(payload, repo_root=args.repo,
                                   dry_run=args.dry_run)
        else:
            with open(args.patch) as f:
                diff_text = f.read()
            result = apply_unified_diff(diff_text, repo_root=args.repo,
                                        dry_run=args.dry_run)
    except (EditError, OSError, json.JSONDecodeError) as exc:
        print("refused: %s" % exc, file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({k: v for k, v in result.items()
                          if k != "originals"}, indent=2))
    else:
        print("%s %d file(s)%s" % (
            "DRY-RUN" if result["dry_run"] else "applied",
            len(result["applied"]),
            ":" if result["patch"] else ""))
        if result["patch"]:
            print(result["patch"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
