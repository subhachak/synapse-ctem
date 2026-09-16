from typing import List
from app.models import RawFinding, ContextGraphRecord, ReasoningEngineRecord, PlanningAgentOutput
from app.llm import llm_reason
from app.retrieval import retrieve, format_for_prompt

"""
LAYER 3 · PLANNING AGENT
"Generates the remediation plan for each prioritized finding"
Reasoning steps: identify fix (upgrade path, config,
patch); predict breaking changes from changelog + code analysis; map
transitive dependencies needing coordinated change; propose compensating
controls if fix is slow; estimate effort and risk, route to owner from graph
Target impact: "Days of triage compressed into minutes; plans ready for
human approval"
"""

_TARGET_VERSION_MAP = {
    "sw-browser-engines": "Update embedded render components to latest vendor-patched build",
    "sw-linux-kernel": "Kernel 5.15.x -> 6.1 LTS (backport privilege-escalation fixes if uplift blocked)",
    "sw-oss-deps": "Bump affected OSS dependency set to patched minor versions per SCA report",
    "sw-gnupg": "GnuPG 2.4.1 -> 2.4.5 (fixes TPM2 PKDECRYPT overflow)",
    "sw-gnutls-certtool": "GnuTLS 3.8.2 -> 3.8.3 (certtool off-by-one fix)",
    "sw-gnutls-san": "GnuTLS 3.8.2 -> 3.8.4 (otherName SAN double-free fix)",
    "sw-openssl": "OpenSSL 3.2.1 -> 3.2.2 (PKCS#12 PBMAC1/PBKDF2 fix)",
}


def run_planning_agent(
    finding: RawFinding, ctx: ContextGraphRecord, reasoning: ReasoningEngineRecord, retrieved: dict | None = None
) -> PlanningAgentOutput:
    retrieved = retrieved or retrieve(
        f"{finding.name} {finding.cve} {finding.affectedComponent} {reasoning.remediationApproach} remediation runbook precedent",
        {"runbook", "precedent", "policy"},
    )

    # A live-remediation target dictates the exact fix, and the plan must describe
    # the ACTUAL change + how it's proven closed for that strategy — not the generic
    # exposure boilerplate (WAF virtual patch, feature-flag disablement) that only
    # applies to findings with no direct fix available.
    fix_approach, target_version, breaking_changes, compensating_controls, validation_plan = _plan_for_target(
        finding, reasoning
    )

    narrative = llm_reason(
        "You are the Planning Agent in a CTEM pipeline. Given a prioritized finding, the selected "
        "remediation approach, and how the fix will be validated, produce a concise remediation plan. "
        "Describe the fix accurately for the stated approach — do NOT describe a dependency bump for a "
        "source-code or web fix. Note likely breaking changes and any interim mitigation if the fix is slow.",
        f"finding={finding.model_dump()} reasoning={reasoning.model_dump()}\n"
        f"selectedApproach={fix_approach!r}; change={target_version!r}; "
        f"validationGate={validation_plan}\n"
        f"{format_for_prompt(retrieved)}\nCite retrieved document IDs and do not invent missing internal guidance.",
    )

    return PlanningAgentOutput(
        findingId=finding.id,
        fixApproach=fix_approach,
        targetVersionOrConfig=target_version,
        predictedBreakingChanges=breaking_changes,
        transitiveDependencies=[f"{s.name} (transitive on {finding.affectedComponent})" for s in ctx.services],
        compensatingControls=compensating_controls,
        validationPlan=validation_plan,
        effortEstimate="high" if reasoning.blastRadius > 3 else ("medium" if reasoning.blastRadius > 1 else "low"),
        routedOwnerId=ctx.owner.id,
        mitigationRecipe=narrative,
        retrievalMode=retrieved["mode"],
        retrievalCitations=retrieved["citations"],
    )


_GOVERNANCE_STEP = "Ship as a PR gated by human governance approval + independent evidence verification"


def _plan_for_target(finding: RawFinding, reasoning: ReasoningEngineRecord):
    """Return (fixApproach, change, breakingChanges, compensatingControls, validationPlan)
    for a finding, branching on its remediation strategy. Each live-remediation
    strategy gets an accurate, self-consistent plan — including the deterministic
    validation gate the orchestrator will enforce to prove closure."""
    rt = finding.remediationTarget

    if rt is None:
        # No direct fix wired up: generic exposure handling (may need interim controls).
        return (
            reasoning.remediationApproach,
            _TARGET_VERSION_MAP.get(finding.softwareId, "Apply latest vendor patch"),
            _predict_breaking_changes(finding),
            (["WAF virtual patch on ingress", "Feature flag disablement of affected code path"]
             if reasoning.exploitableIssue else []),
            [],
        )

    cwe = rt.vulnClass or rt.targetCve or "the vulnerability"

    if rt.strategy == "agentic-code":
        return (
            f"Agentic code fix — eliminate {cwe} at the source (no dependency change)",
            f"AI coding agent rewrites {rt.filePath} so untrusted input never reaches a shell "
            f"(closes {rt.targetCve or 'CWE-78'} command injection)",
            [],  # behavior-preserving
            [],
            [
                f"SAST re-scan of {rt.filePath}: the vulnerable shell-exec pattern must be absent",
                "Runtime exploit probe: an injected shell command must NOT execute",
                "Contract tests must pass; the orchestrator self-corrects (bounded retries) if the gate fails",
                _GOVERNANCE_STEP,
            ],
        )

    if rt.strategy == "dast-web":
        return (
            f"Agentic DAST fix — HTML output-encoding on the reflected input (no dependency change)",
            f"AI coding agent adds output encoding to the reflected request parameter in {rt.filePath} "
            f"(closes {rt.targetCve or 'CWE-79'} reflected XSS)",
            [],  # behavior-preserving for legitimate input
            [],
            [
                "Black-box HTTP re-probe: the injected <script> payload must return HTML-encoded, not executable",
                "Contract tests must pass (legitimate input still renders unchanged)",
                "The orchestrator self-corrects (bounded retries) if the re-probe still shows reflection",
                _GOVERNANCE_STEP,
            ],
        )

    # deterministic dependency bump (npm SCA + maven)
    return (
        f"Dependency version bump ({rt.vulnerablePackage})",
        f"Bump {rt.vulnerablePackage} {rt.currentVersion} -> {rt.fixedVersion} "
        f"in {rt.manifest} (closes {rt.targetCve or rt.targetAdvisory})",
        _semver_breaking_changes(rt.currentVersion, rt.fixedVersion, rt.vulnerablePackage),
        [],  # a patched version is directly available; no interim control needed
        [
            f"Post-change re-scan: {rt.targetAdvisory or rt.targetCve} must be absent on the installed version",
            "Runtime probe: exercise the fixed library against the exploit and confirm it is closed",
            "Contract tests must pass (no behaviour regression)",
            _GOVERNANCE_STEP,
        ],
    )


def suppressed_planning_stub(finding: RawFinding, ctx: ContextGraphRecord) -> PlanningAgentOutput:
    """Used when the Triage Agent suppresses a finding — no LLM call needed."""
    return PlanningAgentOutput(
        findingId=finding.id,
        fixApproach="no action — suppressed by Triage Agent",
        targetVersionOrConfig="n/a",
        predictedBreakingChanges=[],
        transitiveDependencies=[],
        compensatingControls=[],
        effortEstimate="low",
        routedOwnerId=ctx.owner.id,
        mitigationRecipe="none required",
    )


def _semver_breaking_changes(current: str, fixed: str, package: str) -> List[str]:
    """Breaking-change risk for a dependency bump, derived from the semver delta."""
    import re

    def parts(v: str) -> List[int]:
        nums = re.findall(r"\d+", v)
        return [int(x) for x in (nums + ["0", "0", "0"])[:3]]

    c, f = parts(current), parts(fixed)
    if f[0] != c[0]:
        return [f"Major version bump ({current} -> {fixed}) — review {package} changelog for breaking changes; contract tests gate rollout"]
    if f[1] != c[1]:
        return [f"Minor version bump ({current} -> {fixed}) — run contract tests before rollout"]
    return []  # patch-level bump: no API changes expected


def _predict_breaking_changes(f: RawFinding) -> List[str]:
    if f.chainedWith:
        return [
            "Coordinated multi-service deploy required due to chained vulnerability",
            "Regression risk in dependent services",
        ]
    if f.severityLabel in ("Critical", "High"):
        return ["Minor API surface change possible — run contract tests before rollout"]
    return []
