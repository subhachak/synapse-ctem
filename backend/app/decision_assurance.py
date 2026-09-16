"""Decision-quality controls surrounding the authoritative risk engine.

Neither control changes a score. Data quality reports whether the inputs are
fit for use; the plausibility judge challenges contradictory output and can
recommend human review. This separation is intentional: AI is advisory while
the versioned deterministic model remains authoritative.
"""

from app.llm import llm_reason
from app.models import (
    ContextGraphRecord,
    DataQualityAssessment,
    PlausibilityAssessment,
    RawFinding,
    ReasoningEngineRecord,
)


def assess_data_quality(finding: RawFinding, ctx: ContextGraphRecord) -> DataQualityAssessment:
    cvss_status = "inferred" if finding.cvssSource == "severity-inferred" else (
        "missing" if finding.cvssBase <= 0 else "present"
    )
    statuses = {
        "cvss": cvss_status,
        "epss": "present" if 0 <= finding.epss <= 1 else "missing",
        "kev": "present",
        "assetContext": "simulated" if ctx.services else "missing",
        "owner": "simulated" if ctx.owner else "missing",
        "runtimeReachability": "simulated",  # demo adapter, not a live eBPF integration
        "policyContext": "simulated" if ctx.policies else "missing",
    }
    scores = {"present": 1.0, "inferred": 0.7, "simulated": 0.6, "missing": 0.0}
    completeness = round(sum(scores[value] for value in statuses.values()) / len(statuses), 2)
    issues = []
    if cvss_status == "inferred":
        issues.append("CVSS was inferred from severity and should be confirmed before production action")
    if statuses["runtimeReachability"] == "simulated":
        issues.append("Runtime reachability is demo evidence, not a live eBPF observation")
    if statuses["assetContext"] == "simulated":
        issues.append("Asset, owner, and policy context comes from the seeded demo graph")
    missing = [name for name, status in statuses.items() if status == "missing"]
    if missing:
        issues.append(f"Missing required evidence: {', '.join(missing)}")
    return DataQualityAssessment(
        findingId=finding.id,
        fieldStatus=statuses,
        completenessScore=completeness,
        decision="review-required" if missing else "ready",
        issues=issues,
    )


def judge_plausibility(
    finding: RawFinding,
    ctx: ContextGraphRecord,
    reasoning: ReasoningEngineRecord,
    quality: DataQualityAssessment,
) -> PlausibilityAssessment:
    concerns = []
    if finding.cisaKev and reasoning.actionTier != "Tier 0":
        concerns.append("A CISA KEV finding did not receive the configured Tier 0 policy disposition")
    if finding.runtimeReachable and finding.severityLabel == "Critical" and reasoning.actionTier == "Tier 3":
        concerns.append("A critical runtime-reachable finding was classified as backlog")
    if reasoning.riskPriority == 0 and finding.cvssBase >= 7:
        concerns.append("A high-severity advisory produced a zero risk score")
    if quality.decision == "review-required":
        concerns.append("Required decision evidence is incomplete")
    if finding.cvssSource == "severity-inferred" and finding.severityLabel in ("Critical", "High"):
        concerns.append("A high-severity decision is using inferred CVSS evidence and requires analyst confirmation")

    assessment = "inconsistent" if len(concerns) > 1 else ("questionable" if concerns else "plausible")
    action = "human-score-review" if concerns else "proceed"
    narrative = llm_reason(
        "You are a bounded decision-assurance reviewer. Briefly explain whether a deterministic CTEM "
        "risk result is plausible. You may advise human review but must not change the score or tier.",
        f"finding={finding.model_dump()} reasoning={reasoning.model_dump()} concerns={concerns}",
    )
    return PlausibilityAssessment(
        findingId=finding.id,
        assessment=assessment,
        confidence=0.96 if not concerns else 0.9,
        concerns=concerns,
        recommendedAction=action,
        advisoryNarrative=narrative,
        advisoryMode="deterministic-fallback" if narrative.startswith("[") else "anthropic",
    )
