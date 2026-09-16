"""
Per-run git working directory for a live remediation.

  - PR mode (default):  clone the configured GitHub repo (its base branch already
                        carries the vulnerable app, pushed there once during
                        setup). Repo identity comes from RemediationTarget.remoteRepo
                        or the CTEM_REMEDIATION_REPO env override.
  - Local mode (fallback): copy the committed target snapshot, `git init`, base
                        commit — used only for offline/test runs when no remote
                        repo is configured.

Either way the result is a real git repo on a clean base, ready to branch. Each
run gets its own directory so concurrent runs don't collide; `reset_workspaces()`
wipes them all (called from /api/reset).
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from app.models import RemediationTarget
from app.remediation import github_pr
from app.remediation._util import run

# backend/app  (this file is backend/app/remediation/workspace.py)
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WORKSPACE_ROOT = os.path.join(_APP_DIR, "data", "remediation_workspace")

_GIT_IDENTITY = [
    "-c", "user.name=CTEM Implementation Agent",
    "-c", "user.email=ctem-agent@mphasis.demo",
    "-c", "commit.gpgsign=false",
]

_IGNORE = shutil.ignore_patterns("node_modules", ".git")


@dataclass
class Workspace:
    path: str
    mode: str          # "pr" | "local"
    base_branch: str
    remote_repo: str = ""


def _snapshot_source(target: RemediationTarget) -> str:
    src = os.path.join(_APP_DIR, target.repoSnapshot)
    if not os.path.isdir(src):
        raise FileNotFoundError(f"remediation target snapshot not found: {src}")
    return src


def reset_workspaces() -> None:
    """Remove all scratch workspaces so the demo starts clean."""
    if os.path.isdir(_WORKSPACE_ROOT):
        shutil.rmtree(_WORKSPACE_ROOT, ignore_errors=True)


def prepare(run_id: str, target: RemediationTarget) -> Workspace:
    """Create a clean git workspace and install dependencies so it can be scanned."""
    os.makedirs(_WORKSPACE_ROOT, exist_ok=True)
    ws_path = os.path.join(_WORKSPACE_ROOT, run_id)
    shutil.rmtree(ws_path, ignore_errors=True)

    repo = github_pr.resolve_repo(target.remoteRepo, target.ecosystem, target.repoEnvVar)
    base = target.baseBranch or "main"
    remote_repo = ""

    if repo:
        # Clone the GitHub repo and work on it locally.
        clone = run(["git", "clone", "--depth", "1", "--branch", base,
                     github_pr.clone_url(repo), ws_path], cwd=_WORKSPACE_ROOT, timeout=180)
        if not clone.ok:
            raise RuntimeError(f"git clone of '{repo}' (branch {base}) failed: {clone.tail()}")
        mode = "pr"
        remote_repo = repo
    elif target.repoSnapshot:
        # Offline/test fallback: work from the committed snapshot.
        shutil.copytree(_snapshot_source(target), ws_path, ignore=_IGNORE)
        run(["git", "init", "-b", base], cwd=ws_path)
        run(["git", *_GIT_IDENTITY, "add", "-A"], cwd=ws_path)
        run(["git", *_GIT_IDENTITY, "commit", "-m", "base: vulnerable snapshot"], cwd=ws_path)
        mode = "local"
    else:
        raise RuntimeError(
            "remediation target has no remoteRepo (or CTEM_REMEDIATION_REPO) and no repoSnapshot"
        )

    # Install the (vulnerable) baseline so the before-scan sees real installed
    # versions. Maven targets skip this -- their scan reads pom.xml directly
    # (no JVM needed for that), and the real build/test happens on GitHub
    # Actions, not locally -- see live_adapter.run_live_remediation_ci.
    if target.ecosystem == "npm":
        run(["npm", "install", "--no-audit", "--no-fund"], cwd=ws_path, timeout=180)
    return Workspace(path=ws_path, mode=mode, base_branch=base, remote_repo=remote_repo)


def git(workspace: Workspace, *args: str, timeout: int = 60):
    return run(["git", *_GIT_IDENTITY, *args], cwd=workspace.path, timeout=timeout)
