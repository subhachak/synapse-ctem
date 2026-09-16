"""
Spring Cloud Function SpEL RCE (CVE-2022-22963), GitHub-Actions-verified.

Same shape as the log4j Maven scenario — a one-property pom.xml bump verified
on GitHub Actions, since the demo host has no local JDK/Maven — but a genuinely
Spring-native vulnerability, which is the point for a Spring/Tanzu audience.

CVE-2022-22963: in spring-cloud-function-web <= 3.2.2, the value of the
`spring.cloud.function.routing-expression` HTTP header is evaluated as a SpEL
expression, so a single unauthenticated POST to /functionRouter runs arbitrary
code. Fixed in 3.2.3. Detection and the fix are a local pom.xml property bump
(3.2.2 -> 3.2.3); the build, `mvn test`, and the real SpEL exploit probe run on
GitHub Actions (see the target repo's scripts/spel_probe.py). Only the
finding-specific narrative differs from the log4j strategy, so this subclasses
MavenCiDependencyStrategy and overrides just the text.
"""
from __future__ import annotations

from app.models import RawFinding
from app.remediation.strategies.maven_ci_dependency import MavenCiDependencyStrategy


class SpringCloudFunctionCiStrategy(MavenCiDependencyStrategy):
    name = "maven-spring-cf-bump"
    runtime_command = "GitHub Actions: scripts/spel_probe.py (real SpEL RCE exploit probe)"

    def applies(self, finding: RawFinding) -> bool:
        t = finding.remediationTarget
        return t is not None and t.strategy == "maven-spring-cf"

    def pr_title(self, finding: RawFinding) -> str:
        t = finding.remediationTarget
        return f"fix(spring-cloud-function): {t.currentVersion} -> {t.fixedVersion} [{t.targetCve or t.targetAdvisory}]"

    def pr_body(self, finding: RawFinding, diff: str) -> str:
        t = finding.remediationTarget
        return (
            f"Automated CTEM remediation for **{finding.name}** ({t.targetCve or t.targetAdvisory}).\n\n"
            f"Bumps `{t.vulnerablePackage}` `{t.currentVersion}` -> `{t.fixedVersion}`. Verified on GitHub "
            f"Actions: a real `mvn test` run against the fixed build, plus a real SpEL exploit probe that "
            f"POSTs a `spring.cloud.function.routing-expression` header to `/functionRouter` and confirms "
            f"the injected command no longer executes.\n\n"
            f"```diff\n{diff[:3000]}\n```"
        )

    def runtime_detail(self, passed: bool) -> str:
        return (
            "GitHub Actions started the app and POSTed a spring.cloud.function.routing-expression header "
            "carrying a SpEL command-execution payload to /functionRouter; the injected command did not "
            "run -- the exploit path is closed."
            if passed else
            "GitHub Actions started the app and POSTed a spring.cloud.function.routing-expression header "
            "carrying a SpEL command-execution payload to /functionRouter; the injected command executed -- "
            "the exploit path is still open."
        )
