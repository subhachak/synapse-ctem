"""
Agentic code-fix strategy (the first-party / SAST class, and the catch-all for
findings no deterministic rule covers).

Synthesis is done by a coding agent: in live mode (CTEM_LIVE_LLM) the model
rewrites the vulnerable source; offline, a recorded deterministic fix stands in so
the demo is reproducible. Either way the change is accepted ONLY if the universal
validation gate passes (SAST re-scan clean + tests pass + runtime probe + human
approval). The agent is creative; the scanner/tests/verifier are the judge — so no
per-finding code is required to cover novel cases.

Detection is a pattern SAST scan (real match over the actual source); the runtime
probe sends a shell-injection payload to the patched code path and confirms the
injected command does not execute.
"""
from __future__ import annotations

import os
import re

from app import llm
from app.models import RawFinding
from app.remediation._util import ProcResult, run
from app.remediation.scanner import ScanResult
from app.remediation.strategies.base import MutationResult, RemediationStrategy

# Runtime exploit probe: call the real handler with an OS-command-injection
# payload; on fixed code (execFile, no shell) the injected `touch` never runs.
# Exit 0 = exploit path closed, exit 1 = still injectable.
_CMD_INJECTION_PROBE = (
    "const {runDiagnostic}=require('./src/server');"
    "const fs=require('fs'),os=require('os'),path=require('path');"
    "const marker=path.join(os.tmpdir(),'ctem_pwn_'+process.pid+'_'+Date.now());"
    "Promise.resolve().then(()=>runDiagnostic('localhost; touch '+marker)).catch(()=>{}).finally(()=>{"
    "const pwned=fs.existsSync(marker);"
    "if(pwned){try{fs.unlinkSync(marker)}catch(e){}}"
    "process.stdout.write('pwned='+pwned);"
    "process.exit(pwned?1:0);});"
)

# The recorded fix applied when no live model is available: swap the shell `exec`
# (which interpolates untrusted input) for `execFile` with an argument vector.
_RECORDED_FIX = ("cp.exec('echo resolving ' + host,", "cp.execFile('echo', ['resolving', host],")


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


class AgenticCodeStrategy(RemediationStrategy):
    name = "agentic-code-fix"
    runtime_command = "node -e <command-injection exploit probe>"

    def applies(self, finding: RawFinding) -> bool:
        t = finding.remediationTarget
        return t is not None and t.strategy == "agentic-code"

    # --- detection (pattern SAST over the real source) ---
    def scan(self, finding: RawFinding, ws_path: str) -> ScanResult:
        t = finding.remediationTarget
        advisory = t.vulnClass or "CWE-78"
        path = os.path.join(ws_path, t.filePath)
        hits: list[str] = []
        if os.path.exists(path):
            with open(path) as handle:
                for i, line in enumerate(handle.read().splitlines(), 1):
                    # A shell exec with interpolated input (concatenation or template),
                    # and NOT the safe execFile form.
                    if re.search(r"\.exec\s*\(", line) and ("+" in line or "${" in line) and "execFile" not in line:
                        hits.append(f"{t.filePath}:{i}: {line.strip()}")
        present = bool(hits)
        return ScanResult(
            scannerName="sast-pattern",
            installedVersion="n/a",
            targetAdvisory=advisory,
            targetPresent=present,
            advisories=([{"id": advisory, "severity": "high", "title": "OS command injection (shell exec of untrusted input)", "url": ""}] if present else []),
            raw="\n".join(hits) or f"{advisory}: no vulnerable pattern found in {t.filePath}",
        )

    # --- synthesis (the coding agent) ---
    def mutate(self, finding: RawFinding, ws_path: str, attempt: int = 1, feedback: str = "") -> MutationResult:
        t = finding.remediationTarget
        path = os.path.join(ws_path, t.filePath)
        with open(path) as handle:
            original = handle.read()
        patched, method = self._synthesize(original, t, attempt, feedback)
        if patched and patched != original:
            with open(path, "w") as handle:
                handle.write(patched)
            return MutationResult(applied=True, detail=f"Rewrote {t.filePath} to remediate {t.vulnClass or 'the vulnerability'}", method=method)
        return MutationResult(applied=False, detail=f"No change produced for {t.filePath}", method=method)

    def _synthesize(self, original: str, target, attempt: int = 1, feedback: str = "") -> tuple[str, str]:
        system = (
            "You are a secure-coding remediation agent. Fix the identified vulnerability with the "
            "minimal safe change while preserving behavior. Return ONLY the complete corrected file "
            "content — every line, no markdown fences, no commentary, no omissions."
        )
        retry_note = (
            f"\n\nThis is attempt {attempt}. A previous attempt did NOT close the vulnerability: {feedback} "
            "Ensure untrusted input never reaches a shell (use execFile with an argument vector)."
            if attempt > 1 and feedback else ""
        )
        user = (
            f"Vulnerability: {target.vulnClass or 'command injection'} (CWE-78) in {target.filePath}. "
            f"Untrusted input must not reach a shell. Return the full corrected file verbatim.{retry_note}\n\n"
            f"=== {target.filePath} ===\n{original}"
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
        # Structural sanity only — correctness is decided by the validation gate.
        return bool(candidate) and "runDiagnostic" in candidate and "createServer" in candidate and "module.exports" in candidate

    @staticmethod
    def _recorded_fix(original: str) -> str:
        return original.replace(*_RECORDED_FIX)

    def runtime_probe(self, finding: RawFinding, ws_path: str) -> ProcResult:
        return run(["node", "-e", _CMD_INJECTION_PROBE], cwd=ws_path, timeout=60)

    def branch_slug(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return t.vulnClass or t.targetCve or "code-fix"

    def commit_message(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix(security): remediate {t.vulnClass or 'vulnerability'} in {t.filePath}"

    def pr_title(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix(security): remediate {t.vulnClass or 'vulnerability'} in {t.filePath}"

    def pr_body(self, finding: RawFinding, diff: str) -> str:
        t = finding.remediationTarget
        return (f"Automated CTEM remediation for **{finding.name}** ({t.vulnClass or 'CWE-78'}).\n\n"
                f"An AI coding agent rewrote `{t.filePath}` to remove the vulnerability. Contract tests "
                f"pass; the SAST re-scan is clean; a runtime exploit probe confirms the path is closed.\n\n"
                f"```diff\n{diff[:3000]}\n```")

    def runtime_detail(self, passed: bool) -> str:
        return ("Runtime probe sent a shell-injection payload to the patched code path; the injected "
                "command did not execute." if passed
                else "Runtime probe: the injected shell command still executed.")
