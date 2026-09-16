"""
Shared build/SCM helpers used by the orchestrator, independent of which
remediation strategy produced the change. Strategy-specific logic (scan, the
file mutation, runtime probe) lives in app/remediation/strategies/.
"""
from __future__ import annotations

import re

from app.remediation import workspace as ws_mod
from app.remediation._util import ProcResult, run


def branch_name(slug: str, suffix: str = "") -> str:
    slug = re.sub(r"[^0-9a-zA-Z]+", "-", slug).strip("-").lower() or "remediation"
    base = f"ctem/fix-{slug}"
    # A per-run suffix keeps each remediation on its own branch, so repeated demo
    # runs each open a fresh PR instead of colliding on one head branch (GitHub
    # rejects a second PR for the same head with a 422).
    return f"{base}-{suffix}" if suffix else base


def npm_install(ws_path: str) -> ProcResult:
    return run(["npm", "install", "--no-audit", "--no-fund"], cwd=ws_path, timeout=180)


def run_tests(ws_path: str, test_command: str = "npm test") -> ProcResult:
    return run(test_command.split() or ["npm", "test"], cwd=ws_path, timeout=180)


def commit_all(workspace: ws_mod.Workspace, message: str) -> ProcResult:
    ws_mod.git(workspace, "add", "-A")
    return ws_mod.git(workspace, "commit", "-m", message)


def diff_tree(workspace: ws_mod.Workspace, branch: str) -> str:
    return ws_mod.git(workspace, "diff", f"{workspace.base_branch}...{branch}").out.strip()
