from typing import List
from app.models import KpiSummary, ControlEfficacy

"""
CTEM program KPIs:
Mean Time to Contextualize (MTTCx), Mean Time to Validate (MTTV),
Mean Time to Mitigate/Remediate (MTTR), exploit-path closure time,
% findings auto-correlated to asset owners, % high-risk findings with
verified runtime reachability, % remediations verified closed,
% changes auto-remediated vs human approved, false-positive rate by
source/agent, exception debt (accepted risk still open), control efficacy.
"""


def compute_kpis(results: List[dict], observations: dict[str, dict] | None = None) -> KpiSummary:
    n = len(results) or 1
    avg = lambda vals: sum(vals) / (len(vals) or 1)
    observations = observations or {}

    def samples(name: str) -> list[float]:
        return [o[name] for o in observations.values() if name in o]

    contextualize = samples("contextualizeMs")
    validate = samples("validateMs")
    mitigate = samples("mitigateMs")
    closure = samples("closureMs")
    mean_ttcx = avg(contextualize)
    mean_ttv = avg(validate)
    mean_ttr = avg(mitigate)
    mean_closure = avg(closure)

    pct_auto_correlated = (sum(1 for r in results if r["layer1"].owner) / n) * 100

    high_risk = [r for r in results if r["layer2"].actionTier in ("Tier 0", "Tier 1")]
    pct_high_risk_reachable = (
        100.0
        if not high_risk
        else (sum(1 for r in high_risk if r["layer1"].reachability.runtimeReachable) / len(high_risk)) * 100
    )

    pct_verified_closed = (sum(1 for r in results if r["verification"].verifiedClosed) / n) * 100

    auto_remediated = sum(1 for r in results if r["governance"].approvalStatus == "auto-approved")
    pct_auto_vs_human = (auto_remediated / n) * 100

    # Only triage suppression is observable in this demo. It is not labelled
    # a false positive: no adjudicated ground-truth dataset exists.
    false_positive_rate = {}

    exception_debt = sum(1 for r in results if r["finding"].raOnBooks)

    # SLA at risk: high-tier findings (Tier 0/1) that haven't been auto-closed yet.
    sla_at_risk_count = sum(
        1
        for r in results
        if r["layer2"].actionTier in ("Tier 0", "Tier 1") and r["governance"].approvalStatus != "auto-approved"
    )

    # Closure requires the complete verification contract, never merely a
    # generated test plan or governance approval. Demo artifacts disclose
    # their simulated-adapter provenance in VerificationRecord.
    verified_closed_count = sum(1 for r in results if r["verification"].verifiedClosed)

    control_efficacy: list[ControlEfficacy] = []

    return KpiSummary(
        meanTimeToContextualizeMs=mean_ttcx,
        meanTimeToValidateMs=mean_ttv,
        meanTimeToMitigateMs=mean_ttr,
        meanExploitPathClosureMs=mean_closure,
        pctAutoCorrelatedToOwner=pct_auto_correlated,
        pctHighRiskVerifiedReachable=pct_high_risk_reachable,
        pctRemediationsVerifiedClosed=pct_verified_closed,
        pctAutoRemediatedVsHumanApproved=pct_auto_vs_human,
        falsePositiveRateByAgent=false_positive_rate,
        exceptionDebtOpenCount=exception_debt,
        controlEfficacy=control_efficacy,
        slaAtRiskCount=sla_at_risk_count,
        verifiedClosedCount=verified_closed_count,
        metricProvenance={
            "MTTCx": "Measured from run.created_at to context_graph.finished_at",
            "MTTV": "Measured from run.created_at to triage_agent.finished_at; human wait time is included",
            "MTTR": "Measured from run.created_at to the terminal remediation workflow event",
            "ExploitPathClosure": "Measured only to a persisted verified_closed transition backed by all four demo evidence artifacts",
            "VerifiedClosure": "Counted only when the verification contract reports verifiedClosed=true",
        },
        metricSampleCounts={
            "MTTCx": len(contextualize), "MTTV": len(validate), "MTTR": len(mitigate),
            "ExploitPathClosure": len(closure), "VerifiedClosure": len(results),
        },
        illustrativeTargets={
            "False-positive rate": "Requires adjudicated client outcomes; not calculated in this demo",
            "Control efficacy": "Requires observed control deployment and expiry data; not calculated in this demo",
            "30-day trend": "Illustrative visualization, not historical telemetry",
        },
    )
