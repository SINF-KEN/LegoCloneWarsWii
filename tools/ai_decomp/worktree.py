#!/usr/bin/env python3
"""Isolated git worktrees for AI decompilation attempts (roadmap #22).

Layout:

    .worktrees/<address>/attempt-001/     a full checkout + branch

Safety rules:

  - worktrees are always created from the ai-decomp branch (or an
    explicitly given start point)
  - the primary working tree is never modified by an attempt
  - if the primary working tree is dirty, creation is refused unless
    explicitly overridden
  - removal uses `git worktree remove`; the branch of an attempt is
    deleted only when it matches the attempt-branch naming scheme, and
    never any user branch
  - no destructive git commands (reset --hard, clean, push, rebase) are
    ever run against the primary working tree

API:

    from worktree import WorktreeManager
    mgr = WorktreeManager()
    info = mgr.create_worktree("801b16b0", attempt=1)
    mgr.remove_worktree("801b16b0", attempt=1)

CLI:
    python3 tools/ai_decomp/worktree.py create 801b16b0 --attempt 1
    python3 tools/ai_decomp/worktree.py remove 801b16b0 --attempt 1
    python3 tools/ai_decomp/worktree.py list
"""

import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
WORKTREES_DIR = os.path.join(REPO, ".worktrees")

BASE_BRANCH = "ai-decomp"
ATTEMPT_BRANCH_PREFIX = "ai-attempt/"


class WorktreeError(Exception):
    pass


def _git(repo, *args, input_text=None, check=True):
    proc = subprocess.run(["git", "-C", repo, *args],
                          input=input_text, capture_output=True,
                          text=True)
    if check and proc.returncode != 0:
        raise WorktreeError("git %s failed: %s"
                            % (args[0], proc.stderr.strip()))
    return proc


class WorktreeManager:
    def __init__(self, repo=REPO, worktrees_dir=WORKTREES_DIR,
                 base_branch=BASE_BRANCH):
        self.repo = repo
        self.worktrees_dir = worktrees_dir
        self.base_branch = base_branch

    # ---- safety checks ----

    def primary_is_dirty(self):
        proc = _git(self.repo, "status", "--porcelain")
        return bool(proc.stdout.strip())

    def dirty_paths(self):
        return [line for line in _git(
            self.repo, "status", "--porcelain").stdout.splitlines() if line]

    # ---- creation ----

    def attempt_path(self, address, attempt):
        return os.path.join(self.worktrees_dir, address,
                            "attempt-%03d" % attempt)

    def attempt_branch(self, address, attempt):
        return "%s%s-attempt-%03d" % (ATTEMPT_BRANCH_PREFIX, address,
                                      attempt)

    def create_worktree(self, address, attempt, allow_dirty=False,
                        start_point=None):
        """Create .worktrees/<address>/attempt-NNN on a new branch."""
        address = str(address).strip().lower()
        path = self.attempt_path(address, attempt)
        branch = self.attempt_branch(address, attempt)
        start = start_point or self.base_branch

        if self.primary_is_dirty() and not allow_dirty:
            raise WorktreeError(
                "primary working tree is dirty; refusing to start an "
                "attempt. Commit/stash or pass allow_dirty=True. "
                "Dirty: %s" % "; ".join(self.dirty_paths()[:5]))
        if os.path.exists(path):
            raise WorktreeError("worktree already exists: %s" % path)
        if not re.fullmatch(r"[0-9a-f]{8}", address):
            raise WorktreeError("invalid address %r" % address)

        # refuse to reuse a branch that already exists (never clobber)
        branches = _git(self.repo, "branch", "--list", branch).stdout
        if branches.strip():
            raise WorktreeError("branch %s already exists" % branch)

        _git(self.repo, "worktree", "add", path, "-b", branch, start)
        info = {
            "address": address,
            "attempt": attempt,
            "path": path,
            "branch": branch,
            "start_point": start,
            "primary_was_dirty": self.primary_is_dirty(),
        }
        meta = os.path.join(path, ".ai-attempt.json")
        with open(meta, "w") as f:
            json.dump(info, f, indent=2)
        return info

    # ---- removal ----

    def remove_worktree(self, address, attempt, force=False,
                        keep_branch=False):
        """Remove an attempt worktree; delete its attempt branch.

        Only branches under ai-attempt/<address>-attempt-NNN are ever
        deleted, and only when they belong to this attempt.
        """
        address = str(address).strip().lower()
        path = self.attempt_path(address, attempt)
        branch = self.attempt_branch(address, attempt)
        if not os.path.exists(path):
            raise WorktreeError("no worktree at %s" % path)

        _git(self.repo, "worktree", "remove",
             "--force" if force else "--no-force", path)

        deleted_branch = False
        expected = self.attempt_branch(address, attempt)
        if branch == expected and not keep_branch:
            # double-check the branch name against the attempt scheme
            # and that no worktree is checked out on it
            listing = _git(self.repo, "worktree", "list",
                           "--porcelain").stdout
            if not re.search(r"branch %s$" % re.escape(branch),
                             listing, re.MULTILINE):
                exists = _git(self.repo, "branch", "--list",
                              branch).stdout.strip()
                if exists:
                    _git(self.repo, "branch", "-D", branch)
                    deleted_branch = True

        return {"removed": path, "branch_deleted": deleted_branch,
                "branch": branch}

    def list(self):
        out = []
        if not os.path.isdir(self.worktrees_dir):
            return out
        for address in sorted(os.listdir(self.worktrees_dir)):
            addr_dir = os.path.join(self.worktrees_dir, address)
            if not os.path.isdir(addr_dir):
                continue
            for attempt_dir in sorted(os.listdir(addr_dir)):
                path = os.path.join(addr_dir, attempt_dir)
                if not os.path.isdir(path):
                    continue
                meta_file = os.path.join(path, ".ai-attempt.json")
                meta = {}
                if os.path.exists(meta_file):
                    with open(meta_file) as f:
                        meta = json.load(f)
                out.append({"address": address, "attempt_dir":
                            attempt_dir, "path": path, **meta})
        return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("create", "remove", "list"))
    ap.add_argument("address", nargs="?")
    ap.add_argument("--attempt", type=int, default=1)
    ap.add_argument("--allow-dirty", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="remove even if the worktree has changes")
    ap.add_argument("--keep-branch", action="store_true",
                    help="do not delete the attempt branch")
    args = ap.parse_args(argv)

    mgr = WorktreeManager()
    try:
        if args.command == "list":
            print(json.dumps(mgr.list(), indent=2))
            return 0
        if not args.address:
            ap.error("address is required for %s" % args.command)
        if args.command == "create":
            info = mgr.create_worktree(args.address, args.attempt,
                                       allow_dirty=args.allow_dirty)
            print(json.dumps(info, indent=2))
            return 0
        if args.command == "remove":
            result = mgr.remove_worktree(args.address, args.attempt,
                                         force=args.force,
                                         keep_branch=args.keep_branch)
            print(json.dumps(result, indent=2))
            return 0
    except WorktreeError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
