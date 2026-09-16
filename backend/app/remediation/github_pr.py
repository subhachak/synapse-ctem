"""
GitHub clone/push/PR helpers for the live remediation.

The demo's source of truth is a GitHub repo: the pipeline clones it, works on a
branch locally, pushes the branch, and opens a PR. Repo identity comes from the
finding's RemediationTarget.remoteRepo (overridable by the CTEM_REMEDIATION_REPO
env var); the only secret is GITHUB_TOKEN. PR creation uses the GitHub REST API
over urllib (no extra dependency, like retrieval._voyage_embed). All calls are
non-fatal: failures degrade to local-branch evidence rather than breaking the
pipeline.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from app.remediation._util import run


def token() -> str:
    return os.environ.get("GITHUB_TOKEN", "").strip()


_ENV_OVERRIDE_BY_ECOSYSTEM = {
    "npm": "CTEM_REMEDIATION_REPO",
    "maven": "CTEM_LOG4J_REMEDIATION_REPO",
}


def resolve_repo(target_repo: str, ecosystem: str = "npm", env_var: str = "") -> str:
    """Env override wins, then the finding's configured repo. Empty => local
    fallback. The env var is per-ecosystem on purpose -- the npm
    (node-payments-api) and maven (log4j) demo targets are two different
    GitHub repos, and a single shared override would make whichever one you
    configured last silently clobber the other's remoteRepo. A target may name
    its own `env_var` to override the ecosystem default, so a third target that
    shares an ecosystem (the Spring maven target) gets its own key rather than
    colliding with log4j's CTEM_LOG4J_REMEDIATION_REPO."""
    env_key = env_var.strip() or _ENV_OVERRIDE_BY_ECOSYSTEM.get(ecosystem, "CTEM_REMEDIATION_REPO")
    return (os.environ.get(env_key, "").strip() or (target_repo or "").strip())


def _is_direct_url(repo: str) -> bool:
    # A full URL or local path (used by tests with a bare file:// remote).
    return "://" in repo or repo.startswith("/") or repo.startswith("file:")


def web_repo_url(repo: str) -> str:
    """Browser-facing URL for a resolved repo, for UI navigation during the demo.
    Only an "owner/repo" GitHub slug yields a link; local/file remotes (offline
    snapshot mode) have no web page, so they return empty (no broken link)."""
    if not repo or _is_direct_url(repo):
        return ""
    return f"https://github.com/{repo}"


def clone_url(repo: str) -> str:
    if _is_direct_url(repo):
        return repo
    tok = token()
    if tok:
        return f"https://x-access-token:{tok}@github.com/{repo}.git"
    return f"https://github.com/{repo}.git"


def push_branch(workspace_path: str, branch: str):
    """Push the fix branch to origin (set by clone). Returns a ProcResult."""
    return run(["git", "push", "--force-with-lease", "origin", branch], cwd=workspace_path, timeout=120)


def open_pull_request(repo: str, base: str, branch: str, title: str, body: str) -> dict:
    """
    Open a PR via the GitHub REST API. Returns {ok, url, detail}. Never raises.
    Only meaningful for a github.com "owner/repo" with a token; other remotes
    (e.g. a local bare repo in tests) return ok=False and the caller falls back
    to branch-level deployment evidence.
    """
    tok = token()
    if not tok or _is_direct_url(repo) or "/" not in repo:
        return {"ok": False, "url": "", "detail": "PR API skipped (no token or non-GitHub remote)"}
    payload = json.dumps({"title": title, "head": branch, "base": base, "body": body}).encode()
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/pulls",
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {tok}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "mphasis-synapse-ctem",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return {"ok": True, "url": data.get("html_url", ""), "detail": f"PR #{data.get('number')} opened against {base}"}
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")[:400]
        # 422 usually means a PR already exists for this head branch — non-fatal.
        return {"ok": False, "url": "", "detail": f"GitHub API {exc.code}: {body_text}"}
    except Exception as exc:  # pragma: no cover - network/DNS/TLS
        return {"ok": False, "url": "", "detail": f"GitHub API call failed: {exc}"}
