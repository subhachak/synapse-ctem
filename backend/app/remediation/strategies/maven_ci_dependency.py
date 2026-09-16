"""
Maven/GitHub-Actions-verified dependency-bump strategy (the log4j scenario).

Detection and the fix itself (bump a pom.xml property) are local -- pom.xml is
just XML, no JVM needed. But build/test and the JNDI runtime-probe genuinely
need a JVM, and this demo host has no local JDK/Maven, so those two steps run
for real on GitHub Actions instead of as local subprocesses. See
`app.remediation.live_adapter.run_live_remediation_ci`, which is the actual
orchestrator for this strategy (not the local-subprocess flow the npm
strategies use) -- runtime_probe() below is intentionally unused by it; it
exists only to satisfy the RemediationStrategy interface.
"""
from __future__ import annotations

from app.models import RawFinding
from app.remediation import scanner
from app.remediation._util import ProcResult
from app.remediation.scanner import ScanResult
from app.remediation.strategies.base import MutationResult, RemediationStrategy


class MavenCiDependencyStrategy(RemediationStrategy):
    name = "maven-dependency-version-bump"
    runtime_command = "GitHub Actions: scripts/jndi_probe.py (real JNDI lookup-attempt check)"

    def applies(self, finding: RawFinding) -> bool:
        t = finding.remediationTarget
        return t is not None and t.strategy == "maven-dependency"

    def scan(self, finding: RawFinding, ws_path: str) -> ScanResult:
        return scanner.scan_maven(ws_path, finding.remediationTarget)

    def mutate(self, finding: RawFinding, ws_path: str, attempt: int = 1, feedback: str = "") -> MutationResult:
        t = finding.remediationTarget
        changed, detail = scanner.mutate_maven(ws_path, t)
        return MutationResult(applied=changed, detail=detail, method="deterministic")

    def runtime_probe(self, finding: RawFinding, ws_path: str) -> ProcResult:  # pragma: no cover
        raise NotImplementedError(
            "MavenCiDependencyStrategy's runtime probe runs on GitHub Actions, read from the "
            "same CI run as the test step -- see live_adapter.run_live_remediation_ci."
        )

    def branch_slug(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return t.targetCve or t.targetAdvisory or t.vulnerablePackage

    def commit_message(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return (f"fix({t.versionProperty or t.vulnerablePackage}): bump "
                f"{t.currentVersion} -> {t.fixedVersion} for {t.targetCve or t.targetAdvisory}")

    def pr_title(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix(log4j-core): {t.currentVersion} -> {t.fixedVersion} [{t.targetCve or t.targetAdvisory}]"

    def pr_body(self, finding: RawFinding, diff: str) -> str:
        t = finding.remediationTarget
        return (
            f"Automated CTEM remediation for **{finding.name}** ({t.targetCve or t.targetAdvisory}).\n\n"
            f"Bumps `{t.vulnerablePackage}` `{t.currentVersion}` -> `{t.fixedVersion}`. Verified on GitHub "
            f"Actions: a real `mvn test` run against the fixed build, plus a real JNDI runtime probe "
            f"confirming the actual Log4Shell exploit path (`${{jndi:ldap://...}}` in a logged message) "
            f"no longer triggers an outbound lookup.\n\n"
            f"```diff\n{diff[:3000]}\n```"
        )

    def runtime_detail(self, passed: bool) -> str:
        return (
            "GitHub Actions ran the app with a real ${jndi:ldap://...} payload in a logged message; "
            "no outbound JNDI/LDAP connection attempt was observed -- the exploit path is closed."
            if passed else
            "GitHub Actions ran the app with a real ${jndi:ldap://...} payload in a logged message; "
            "an outbound JNDI/LDAP connection attempt was observed -- the exploit path is still open."
        )
