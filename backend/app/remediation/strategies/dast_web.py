"""
Agentic DAST web-fix strategy (the dynamic / running-app class).

Detection is BLACK-BOX: the scanner boots the real application and sends an HTTP
request with an XSS payload (see dast_probe.py) — it never reads the source. That
is what separates DAST from SAST. Synthesis is done by a coding agent (adds output
encoding); offline, a recorded deterministic fix stands in so the demo is
reproducible. Either way the change is accepted ONLY if the universal validation
gate passes (contract tests + a post-fix black-box re-probe that confirms the
payload is now neutralised + human approval). The agent is creative; the
probe/tests/verifier are the judge.
"""
from __future__ import annotations

import os
import re

from app import llm
from app.models import RawFinding
from app.remediation import dast_probe
from app.remediation._util import ProcResult
from app.remediation.scanner import ScanResult
from app.remediation.strategies.base import MutationResult, RemediationStrategy

# The recorded fix applied when no live model is available: add an HTML-escaping
# helper and route the reflected value through it.
_ESCAPE_HELPER = (
    "function escapeHtml(value) {\n"
    "  return String(value).replace(/[&<>\"']/g, (ch) => (\n"
    "    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[ch]\n"
    "  ));\n"
    "}\n\n"
)


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines)
    return t.strip() + "\n"


class DastWebStrategy(RemediationStrategy):
    name = "agentic-dast-fix"
    runtime_command = "http GET /greeting?name=<xss payload> (black-box re-probe)"

    def applies(self, finding: RawFinding) -> bool:
        t = finding.remediationTarget
        return t is not None and t.strategy == "dast-web"

    # --- detection (black-box HTTP probe against the running app) ---
    def scan(self, finding: RawFinding, ws_path: str) -> ScanResult:
        t = finding.remediationTarget
        advisory = t.vulnClass or "CWE-79"
        probe = dast_probe.probe_reflected_xss(ws_path, t.filePath or "src/server.js")
        return ScanResult(
            scannerName="dast-http-probe",
            installedVersion="running-app",
            targetAdvisory=advisory,
            targetPresent=probe.reflected,
            advisories=([{"id": advisory, "severity": "high",
                          "title": "Reflected cross-site scripting (unescaped HTML output)", "url": ""}]
                        if probe.reflected else []),
            raw=probe.detail + ("\n\n" + probe.body[:800] if probe.body else ""),
        )

    # --- synthesis (the coding agent) ---
    def mutate(self, finding: RawFinding, ws_path: str, attempt: int = 1, feedback: str = "") -> MutationResult:
        t = finding.remediationTarget
        path = os.path.join(ws_path, t.filePath or "src/server.js")
        with open(path) as handle:
            original = handle.read()
        patched, method = self._synthesize(original, t, attempt, feedback)
        if patched and patched != original:
            with open(path, "w") as handle:
                handle.write(patched)
            return MutationResult(applied=True,
                                  detail=f"Rewrote {t.filePath} to add output encoding on the reflected value",
                                  method=method)
        return MutationResult(applied=False, detail=f"No change produced for {t.filePath}", method=method)

    def _synthesize(self, original: str, target, attempt: int, feedback: str) -> tuple[str, str]:
        system = (
            "You are a secure-coding remediation agent. Fix the reflected XSS with the minimal safe change "
            "(HTML-encode untrusted output; do not change routing or behaviour for legitimate input). Return "
            "ONLY the complete corrected file content — every line, no markdown fences, no commentary."
        )
        retry_note = (
            f"\n\nThis is attempt {attempt}. A previous attempt did NOT close the vulnerability: {feedback} "
            "Ensure the reflected value in renderGreeting is HTML-escaped."
            if attempt > 1 and feedback else ""
        )
        user = (
            f"Vulnerability: reflected XSS (CWE-79) in {target.filePath}. The `name` query parameter is "
            f"interpolated into the HTML response of /greeting without escaping. Return the full corrected "
            f"file verbatim.{retry_note}\n\n=== {target.filePath} ===\n{original}"
        )
        text, mode = llm.llm_generate(system, user)
        if mode == "anthropic" and text is not None:
            candidate = _strip_fences(text)
            if self._plausible(candidate):
                return candidate, "anthropic-agent"
            return self._recorded_fix(original), "recorded-agent-fallback (live output rejected)"
        return self._recorded_fix(original), "recorded-agent-fallback"

    @staticmethod
    def _plausible(candidate: str) -> bool:
        # Structural sanity only — the black-box re-probe decides correctness.
        return bool(candidate) and "createServer" in candidate and "module.exports" in candidate \
            and "renderGreeting" in candidate

    @staticmethod
    def _recorded_fix(original: str) -> str:
        fixed = original
        if "function escapeHtml" not in fixed:
            fixed = fixed.replace("function renderGreeting", _ESCAPE_HELPER + "function renderGreeting", 1)
        fixed = fixed.replace("Hello, ${name}!", "Hello, ${escapeHtml(name)}!")
        return fixed

    def runtime_probe(self, finding: RawFinding, ws_path: str) -> ProcResult:
        t = finding.remediationTarget
        probe = dast_probe.probe_reflected_xss(ws_path, t.filePath or "src/server.js")
        # ok == exploit path closed: the app booted AND the payload is no longer reflected.
        closed = probe.ok and not probe.reflected
        return ProcResult(ok=closed, code=0 if closed else 1, out=probe.detail + "\n\n" + probe.body[:800])

    def branch_slug(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return t.vulnClass or t.targetCve or "xss-fix"

    def commit_message(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix(security): encode reflected output to remediate {t.vulnClass or 'reflected XSS'} in {t.filePath}"

    def pr_title(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix(security): remediate {t.vulnClass or 'reflected XSS'} in {t.filePath}"

    def pr_body(self, finding: RawFinding, diff: str) -> str:
        t = finding.remediationTarget
        return (f"Automated CTEM remediation for **{finding.name}** ({t.vulnClass or 'CWE-79'}).\n\n"
                f"A dynamic (DAST) probe found the `name` parameter reflected unescaped by `/greeting`. "
                f"An AI coding agent added output encoding in `{t.filePath}`. Contract tests pass; a post-fix "
                f"black-box re-probe confirms the payload is now HTML-encoded and no longer executes.\n\n"
                f"```diff\n{diff[:3000]}\n```")

    def runtime_detail(self, passed: bool) -> str:
        return ("Post-fix black-box probe re-sent the XSS payload over HTTP; the response now returns it "
                "HTML-encoded and the script does not execute." if passed
                else "Post-fix black-box probe still observed the payload reflected unescaped.")
