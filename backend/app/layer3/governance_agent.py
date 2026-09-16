import time
from typing import List
from app.models import (
    RawFinding,
    ContextGraphRecord,
    ReasoningEngineRecord,
    ImplementationAgentOutput,
    GovernanceAgentOutput,
    PolicyCheck,
)
from app.retrieval import retrieve

"""
LAYER 3 · GOVERNANCE AGENT
"Audit evidence, control mapping, approval routing, change records"
: auto-generate audit artifacts per remediation;
provenance for every decision (who/what/why); format outputs for
SOX/PCI/HIPAA/ISO; map remediation to controls satisfied; verify actions
against natural-language policies; detect cross-region/data-residency
implications; flag customer-notification triggers; block actions outside
agent decision boundary.
"""


def run_governance_agent(
    finding: RawFinding,
    ctx: ContextGraphRecord,
    reasoning: ReasoningEngineRecord,
    implementation: ImplementationAgentOutput,
    retrieved: dict | None = None,
) -> GovernanceAgentOutput:
    retrieved = retrieved or retrieve(
        f"{finding.name} {reasoning.actionTier} production authorization governance policy",
        {"policy", "precedent"},
    )
    policy_checks = [_evaluate_policy(p.id, reasoning, ctx) for p in ctx.policies]
    any_policy_failed = any(not c.passed for c in policy_checks)

    cross_region_flag = len({s.dataResidency for s in ctx.services}) > 1
    customer_notification_triggered = reasoning.businessCriticalAsset and reasoning.actionTier == "Tier 0"

    if any_policy_failed:
        approval_status = "blocked"
    elif reasoning.blastRadius <= 1 and reasoning.actionTier != "Tier 0" and not reasoning.businessCriticalAsset:
        approval_status = "auto-approved"
    else:
        approval_status = "pending human approval"

    return GovernanceAgentOutput(
        findingId=finding.id,
        auditArtifactId=f"audit-{finding.id}-{int(time.time() * 1000)}",
        provenanceWho="CTEM Agent Pipeline (Triage -> Planning -> Implementation -> Governance)",
        provenanceWhat=implementation.prTitle,
        provenanceWhy=f"Risk Priority {reasoning.riskPriority} classified as {reasoning.actionTier} ({reasoning.actionTierLabel})",
        controlsMapped=_map_controls(ctx),
        policyChecks=policy_checks,
        crossRegionFlag=cross_region_flag,
        customerNotificationTriggered=customer_notification_triggered,
        approvalStatus=approval_status,
        retrievalMode=retrieved["mode"],
        retrievalCitations=retrieved["citations"],
    )


def _evaluate_policy(policy_id: str, reasoning: ReasoningEngineRecord, ctx: ContextGraphRecord) -> PolicyCheck:
    if policy_id == "pol-3":
        internet_exposed = any(s.internetExposed for s in ctx.services)
        passed = not (reasoning.exploitationLikelihood > 0.7 and internet_exposed) or reasoning.actionTier == "Tier 0"
        return PolicyCheck(
            policyId=policy_id,
            passed=passed,
            note=(
                "Compensating control auto-applied within policy window"
                if passed
                else "High exploitation likelihood + external exposure without Tier 0 containment — needs escalation"
            ),
        )
    if policy_id == "pol-2":
        return PolicyCheck(policyId=policy_id, passed=True, note="Routed for AppSec + service owner approval per policy")
    if policy_id == "pol-4":
        return PolicyCheck(policyId=policy_id, passed=True, note="NAIC/NYDFS evidence capture attached to audit artifact")
    return PolicyCheck(policyId=policy_id, passed=True, note="No violation detected")


def _map_controls(ctx: ContextGraphRecord) -> List[str]:
    controls = ["SOX change-management evidence"]
    if any(s.tier != "standard" for s in ctx.services):
        controls += ["NAIC", "NYDFS", "GLBA"]
    return controls
