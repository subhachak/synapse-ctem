"""
Deterministic dependency-bump strategy (the SCA / known-vulnerable-package class).

Discovery is the fixed version (declared on the finding in the demo; a live
FixResolver over OSV + the registry in production). Synthesis edits the manifest.
Detection re-runs the real scanner for the tracked advisory; the runtime probe
exercises the fixed library against the exploit (prototype pollution).
"""
from __future__ import annotations

import json
import os

from app.models import RawFinding
from app.remediation import scanner
from app.remediation._util import ProcResult, run
from app.remediation.scanner import ScanResult
from app.remediation.strategies.base import MutationResult, RemediationStrategy

# Exercise the ACTUAL installed library with a prototype-pollution payload and
# confirm the global prototype is untouched. Exit 0 = closed, exit 1 = pollutable.
_PROTO_PROBE = (
    "const _=require('lodash');"
    "const bad=JSON.parse('{\"__proto__\":{\"ctemPolluted\":true}}');"
    "_.merge({}, bad);"
    "const polluted=({}).ctemPolluted===true;"
    "process.stdout.write('polluted='+polluted);"
    "process.exit(polluted?1:0);"
)


def _bump_manifest(ws_path: str, target) -> bool:
    manifest_path = os.path.join(ws_path, target.manifest)
    with open(manifest_path) as handle:
        manifest = json.load(handle)
    changed = False
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = manifest.get(section, {})
        if target.vulnerablePackage in deps and deps[target.vulnerablePackage] != target.fixedVersion:
            deps[target.vulnerablePackage] = target.fixedVersion
            changed = True
    if changed:
        with open(manifest_path, "w") as handle:
            json.dump(manifest, handle, indent=2)
            handle.write("\n")
    return changed


class DeterministicDependencyStrategy(RemediationStrategy):
    name = "dependency-version-bump"
    runtime_command = "node -e <prototype-pollution probe>"

    def applies(self, finding: RawFinding) -> bool:
        t = finding.remediationTarget
        return t is not None and t.strategy == "dependency"

    def scan(self, finding: RawFinding, ws_path: str) -> ScanResult:
        return scanner.scan(ws_path, finding.remediationTarget)

    def mutate(self, finding: RawFinding, ws_path: str, attempt: int = 1, feedback: str = "") -> MutationResult:
        t = finding.remediationTarget
        changed = _bump_manifest(ws_path, t)
        detail = (
            f"Bumped {t.vulnerablePackage} {t.currentVersion} -> {t.fixedVersion}"
            if changed else f"{t.vulnerablePackage} already at {t.fixedVersion}"
        )
        return MutationResult(applied=changed, detail=detail, method="deterministic")

    def runtime_probe(self, finding: RawFinding, ws_path: str) -> ProcResult:
        return run(["node", "-e", _PROTO_PROBE], cwd=ws_path, timeout=60)

    def branch_slug(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return t.targetCve or t.targetAdvisory or t.vulnerablePackage

    def commit_message(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return (f"fix({t.vulnerablePackage}): bump {t.currentVersion} -> {t.fixedVersion} "
                f"for {t.targetCve or t.targetAdvisory}")

    def pr_title(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix({t.vulnerablePackage}): {t.currentVersion} -> {t.fixedVersion} [{t.targetCve or t.targetAdvisory}]"

    def pr_body(self, finding: RawFinding, diff: str) -> str:
        t = finding.remediationTarget
        return (f"Automated CTEM remediation for **{finding.name}** ({t.targetCve or t.targetAdvisory}).\n\n"
                f"Bumps `{t.vulnerablePackage}` `{t.currentVersion}` -> `{t.fixedVersion}`. "
                f"Contract tests pass; post-change scan confirms the advisory is no longer present.\n\n"
                f"```diff\n{diff[:3000]}\n```")

    def runtime_detail(self, passed: bool) -> str:
        return ("Runtime probe merged a prototype-pollution payload through the fixed dependency; "
                "the global prototype was not polluted." if passed
                else "Runtime probe still observed prototype pollution.")
