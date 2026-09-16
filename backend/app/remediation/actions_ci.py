"""
GitHub Actions client for the log4j (Maven/CI-verified) remediation scenario.

The demo host has no local JDK/Maven, so build/test/the JNDI runtime probe
can't run as local subprocesses the way the npm scenario's do. Instead this
module triggers the target repo's `ctem-verify.yml` workflow via
workflow_dispatch, polls the run to completion, and parses the plain-text
job log for a handful of CTEM_*_RESULT marker lines the workflow itself
prints (see remediation_targets/log4j-vulnerable-app/.github/workflows/).

Real GitHub Actions run, real Maven build, real JNDI lookup attempt against
the actual built jar -- this module is a remote-execution transport, not a
simulation of one.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from app.remediation import github_pr

_API = "https://api.github.com"
# Not anchored to line-start: every real log line is timestamp-prefixed
# (e.g. "2026-07-27T16:17:31.65Z CTEM_BUILD_RESULT=PASS"), so a `^CTEM_`
# anchor never matches anything. Value excludes quotes/CR so the workflow's
# own `Run echo "CTEM_X=Y"` command-echo line (which also contains the
# substring) captures a harmless quoted value that "last match wins"
# overwrites with the real one from the actual echoed output line right
# after it.
_MARKER_RE = re.compile(r'CTEM_([A-Z0-9_]+)=([^"\r\n]*)')


@dataclass
class ActionsRunResult:
    ok: bool                       # a completed run was found and its log was readable
    run_id: int = 0
    run_url: str = ""
    conclusion: str = ""           # "success" | "failure" | "cancelled" | ...
    markers: dict = field(default_factory=dict)  # e.g. {"TEST_RESULT": "PASS", ...}
    log_excerpt: str = ""
    detail: str = ""


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {github_pr.token()}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mphasis-synapse-ctem",
    }


def _api(method: str, path: str, data: dict | None = None, timeout: int = 30):
    """Returns (status_code, parsed_json_or_None). Never raises for HTTP errors."""
    req = urllib.request.Request(
        f"{_API}{path}",
        data=(json.dumps(data).encode() if data is not None else None),
        method=method,
        headers=_headers(),
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return exc.code, None


def trigger_workflow(repo: str, workflow_file: str, ref: str) -> tuple[bool, str]:
    status, _ = _api("POST", f"/repos/{repo}/actions/workflows/{workflow_file}/dispatches",
                      {"ref": ref})
    if status == 204:
        return True, "dispatched"
    return False, f"workflow_dispatch returned HTTP {status}"


def find_run(repo: str, workflow_file: str, ref: str, after_epoch: float,
             attempts: int = 12, delay_seconds: int = 5):
    """Polls the workflow's run list for the run our dispatch just created --
    matched by branch + created-after-dispatch-time, since workflow_dispatch's
    API response carries no run id directly."""
    for _ in range(attempts):
        status, data = _api(
            "GET",
            f"/repos/{repo}/actions/workflows/{workflow_file}/runs"
            f"?branch={ref}&event=workflow_dispatch&per_page=5",
        )
        if status == 200 and data:
            for run in data.get("workflow_runs", []):
                created = time.mktime(time.strptime(run["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
                if created >= after_epoch - 5:
                    return run["id"], run.get("html_url", "")
        time.sleep(delay_seconds)
    return None, ""


def wait_for_completion(repo: str, run_id: int, timeout_seconds: int = 480, delay_seconds: int = 10) -> str:
    """Polls a run until status == completed. Returns the conclusion, or
    'timeout'/'error' if polling itself didn't resolve in time."""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        status, data = _api("GET", f"/repos/{repo}/actions/runs/{run_id}")
        if status == 200 and data:
            if data.get("status") == "completed":
                return data.get("conclusion") or "unknown"
        time.sleep(delay_seconds)
    return "timeout"


class _DropAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """The jobs/{id}/logs endpoint 302s to a signed Azure Blob Storage URL
    that authenticates via a SAS token in the URL itself, not a bearer
    token. urllib's default redirect handling forwards the original
    request's headers (including our GitHub Authorization) to the redirect
    target -- Azure then rejects the request outright
    (InvalidAuthenticationInfo) because it doesn't understand a GitHub
    bearer token. (`curl -L` doesn't have this problem: it drops
    Authorization on cross-host redirects by default, which is what made
    manual curl testing of this endpoint work while this code didn't.)
    Fix: build a fresh, header-less request for the redirect hop."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return urllib.request.Request(newurl, method="GET")


def fetch_job_log(repo: str, run_id: int) -> str:
    """Plain-text log for the run's (single) job."""
    status, data = _api("GET", f"/repos/{repo}/actions/runs/{run_id}/jobs")
    if status != 200 or not data or not data.get("jobs"):
        return ""
    job_id = data["jobs"][0]["id"]
    opener = urllib.request.build_opener(_DropAuthOnRedirect)
    req = urllib.request.Request(f"{_API}/repos/{repo}/actions/jobs/{job_id}/logs", headers=_headers())
    try:
        with opener.open(req, timeout=30) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.read().decode(errors="replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def parse_markers(log_text: str) -> dict:
    """Last match wins per key -- a marker can legitimately be printed more
    than once across retries within one job; the final value is authoritative."""
    markers: dict = {}
    for match in _MARKER_RE.finditer(log_text):
        markers[match.group(1)] = match.group(2).strip()
    return markers


def run_and_wait(repo: str, workflow_file: str, ref: str,
                  run_timeout_seconds: int = 480) -> ActionsRunResult:
    """High-level: trigger -> locate the run -> wait for it -> fetch + parse its log."""
    dispatch_time = time.time()
    ok, detail = trigger_workflow(repo, workflow_file, ref)
    if not ok:
        return ActionsRunResult(ok=False, detail=detail)

    run_id, run_url = find_run(repo, workflow_file, ref, dispatch_time)
    if run_id is None:
        return ActionsRunResult(ok=False, detail="dispatched but no matching run appeared in time")

    conclusion = wait_for_completion(repo, run_id, timeout_seconds=run_timeout_seconds)
    log_text = fetch_job_log(repo, run_id)
    markers = parse_markers(log_text)

    return ActionsRunResult(
        ok=bool(markers),
        run_id=run_id,
        run_url=run_url,
        conclusion=conclusion,
        markers=markers,
        log_excerpt=log_text[-4000:],
        detail=f"run {run_id} {conclusion}" if markers else f"run {run_id} {conclusion}, no CTEM_* markers found in its log",
    )
