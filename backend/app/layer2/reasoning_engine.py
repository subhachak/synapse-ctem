import math

from app.models import RawFinding, ContextGraphRecord, ReasoningEngineRecord
from app import graphdb
from app.settings_store import load_active_risk_model_settings

"""Deterministic, explainable exposure-risk model.

The model deliberately answers two questions separately:
1. How likely is exploitation within the decision horizon?
2. How damaging would successful exploitation be here?

Residual Risk = P(exploitation) × Business Impact × (1 - validated controls)

The likelihood coefficients and impact weights are governed demo defaults,
not production-calibrated client values. KEV remains an explicit policy
floor applied after the calculated score and tier.
"""


def run_reasoning_engine(finding: RawFinding, ctx: ContextGraphRecord, model=None) -> ReasoningEngineRecord:
    model = model or load_active_risk_model_settings()
    chainability = _score_chainability(finding)
    exploit_maturity = _score_exploit_maturity(finding)
    internet_exposed = 1.0 if any(s.internetExposed for s in ctx.services) else 0.0
    runtime_reachable = 1.0 if finding.runtimeReachable else 0.0
    threat_activity = 1.0 if finding.cisaKev else 0.0
    validated_control_effectiveness = _validated_control_effectiveness(ctx, model)

    coefficients = model.likelihoodCoefficients
    epss_log_odds = _logit(finding.epss)
    likelihood_inputs = {
        "epss": round(finding.epss, 3),
        "epssLogOdds": round(epss_log_odds, 3),
        "internetExposure": internet_exposed,
        "runtimeReachability": runtime_reachable,
        "exploitMaturity": exploit_maturity,
        "chainability": chainability,
        "threatActivity": threat_activity,
    }
    likelihood_contributions = {
        "intercept": round(coefficients.intercept, 3),
        "epssLogOdds": round(epss_log_odds * coefficients.epssLogOdds, 3),
        "internetExposure": round(internet_exposed * coefficients.internetExposure, 3),
        "runtimeReachability": round(runtime_reachable * coefficients.runtimeReachability, 3),
        "exploitMaturity": round(exploit_maturity * coefficients.exploitMaturity, 3),
        "chainability": round(chainability * coefficients.chainability, 3),
        "threatActivity": round(threat_activity * coefficients.threatActivity, 3),
    }
    likelihood_log_odds = sum(likelihood_contributions.values())
    exploitation_likelihood = round(_sigmoid(likelihood_log_odds), 3)

    impact_inputs = _impact_inputs(finding, ctx, model)
    impact_weights = model.impactWeights.model_dump()
    impact_contributions = {
        name: round(value * impact_weights[name] / 100.0, 3)
        for name, value in impact_inputs.items()
    }
    business_impact = round(sum(impact_contributions.values()), 3)
    residual_risk = round(
        100.0 * exploitation_likelihood * business_impact * (1.0 - validated_control_effectiveness), 1
    )
    risk_priority = max(0.0, min(100.0, residual_risk))

    # blastRadius stays the direct RUNS_ON footprint (ctx.services, already graph-sourced via
    # graphdb.get_service_software_owner) rather than graphdb.compute_blast_radius's DEPENDS_ON
    # BFS: this demo's 5-service synthetic dependency graph has a diameter of ~3, so a 3-hop BFS
    # reaches all 5 services from almost any starting point, collapsing every finding to the same
    # blastRadius and making governance_agent.py's `blastRadius <= 1` auto-approval branch
    # unreachable for every seed finding. compute_blast_radius is still available in graphdb.py
    # for callers that want the dependency-graph view specifically.
    blast_radius = len(ctx.services)
    business_critical_asset = any(s.tier in ("crown-jewel", "business-critical") for s in ctx.services)
    exploitable_issue = finding.cisaKev or finding.epss > 0.5

    calculated_tier, _ = _tier_for(risk_priority, model)
    tier = calculated_tier
    overrides = []
    if model.kevOverridesToTier0 and finding.cisaKev and calculated_tier != "Tier 0":
        tier = "Tier 0"
        overrides.append("POL-ACTIVE-EXPLOIT-001: CISA KEV overrides calculated tier to Tier 0")
    tier_label = _tier_label(tier)

    return ReasoningEngineRecord(
        findingId=finding.id,
        exploitationLikelihood=exploitation_likelihood,
        businessImpact=business_impact,
        residualRisk=risk_priority,
        likelihoodInputs=likelihood_inputs,
        likelihoodContributions=likelihood_contributions,
        impactInputs=impact_inputs,
        impactContributions=impact_contributions,
        validatedControlEffectiveness=validated_control_effectiveness,
        calculatedRiskPriority=risk_priority,
        calculatedActionTier=calculated_tier,
        riskPriority=risk_priority,
        exploitableIssue=exploitable_issue,
        chainedVulns=finding.chainedWith,
        businessCriticalAsset=business_critical_asset,
        blastRadius=blast_radius,
        predictiveRisk=_predict_trend(finding),
        remediationApproach=_pick_remediation_approach(finding, ctx),
        actionTier=tier,
        actionTierLabel=tier_label,
        riskModelVersion=model.version,
        decisionMethod="deterministic-model+policy-override" if overrides else "deterministic-model",
        policyOverrides=overrides,
    )


def _score_chainability(f: RawFinding) -> float:
    # Graph-backed: counts CHAINS_WITH edges from graphdb.py rather than the raw
    # finding.chainedWith list directly — but load_graph.py writes those edges FROM
    # that same chainedWith field at bootstrap, so the two stay in sync for seed
    # findings. Custom/live-injected findings have no chainedWith data and no
    # CHAINS_WITH edges, so they always score the chain_len==0 baseline below.
    chain_len = len(graphdb.get_chains_with(f.id))
    if chain_len == 0:
        return 0.3
    return round(min(1.0, 0.5 + chain_len * 0.25), 2)


def _validated_control_effectiveness(ctx: ContextGraphRecord, model) -> float:
    # Policies define expected behavior; their presence is not evidence that a
    # deployed control is effective. The demo has no live validation feed, so
    # it awards no control credit. A production adapter supplies this value.
    observed_effectiveness = 0.0
    return min(model.maxControlEffectiveness, observed_effectiveness)


def _score_exploit_maturity(f: RawFinding) -> float:
    if f.cisaKev:
        return 1.0
    if f.runtimeReachable and f.severityLabel in ("Critical", "High"):
        return 0.9
    if f.discoveredBy == "Mythos":
        return 0.75
    return 0.4


def _configured_criticality(ctx: ContextGraphRecord, model) -> float:
    configured = [e for e in model.appCriticality if e.applicationId in {s.id for s in ctx.services}]
    if configured:
        best_tier = min((int(e.tier[-1]) for e in configured), default=3)
    elif any(s.tier == "crown-jewel" for s in ctx.services):
        best_tier = 0
    elif any(s.tier == "business-critical" for s in ctx.services):
        best_tier = 1
    elif ctx.services:
        best_tier = 2
    else:
        best_tier = 3
    return {0: 1.0, 1: 0.8, 2: 0.6, 3: 0.45}[best_tier]


def _impact_inputs(finding: RawFinding, ctx: ContextGraphRecord, model) -> dict[str, float]:
    configured = [e for e in model.appCriticality if e.applicationId in {s.id for s in ctx.services}]
    sensitivities = {"Public": 0.2, "Internal": 0.4, "Confidential": 0.75, "Restricted": 1.0}
    data_sensitivity = max((sensitivities.get(e.dataSensitivity, 0.4) for e in configured), default=0.4)
    regulatory_safety = 1.0 if any(e.complianceScope for e in configured) else 0.0
    return {
        # The demo has a base score rather than a full CVSS v4 impact subscore;
        # production should replace this proxy with the vector's impact metrics.
        "cvssSeverity": max(0.0, min(1.0, finding.cvssBase / 10.0)),
        "appCriticality": _configured_criticality(ctx, model),
        "dataSensitivity": data_sensitivity,
        "blastRadius": min(1.0, len(ctx.services) / 5.0),
        "regulatorySafety": regulatory_safety,
    }


def _logit(value: float) -> float:
    bounded = max(0.01, min(0.99, value))
    return math.log(bounded / (1.0 - bounded))


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def rescore_immutable_snapshot(finding: RawFinding, recorded: ReasoningEngineRecord, model) -> dict:
    """Apply a candidate model to the exact normalized inputs captured at decision time."""
    coefficients = model.likelihoodCoefficients.model_dump()
    inputs = recorded.likelihoodInputs
    log_odds = coefficients["intercept"] + sum(
        inputs[name] * coefficients[name]
        for name in ("epssLogOdds", "internetExposure", "runtimeReachability", "exploitMaturity", "chainability", "threatActivity")
    )
    likelihood = round(_sigmoid(log_odds), 3)
    weights = model.impactWeights.model_dump()
    impact = round(sum(recorded.impactInputs[name] * weights[name] / 100 for name in weights), 3)
    score = round(100 * likelihood * impact * (1 - recorded.validatedControlEffectiveness), 1)
    tier, _ = _tier_for(score, model)
    if model.kevOverridesToTier0 and finding.cisaKev:
        tier = "Tier 0"
    return {"score": score, "tier": tier, "likelihood": likelihood, "impact": impact}


def _predict_trend(f: RawFinding) -> str:
    if f.discoveredBy == "Mythos" and f.cisaKev:
        return "rising"
    if f.severityLabel == "Medium":
        return "declining"
    return "stable"


def _pick_remediation_approach(f: RawFinding, ctx: ContextGraphRecord) -> str:
    internet_exposed = any(s.internetExposed for s in ctx.services)
    if f.cisaKev and internet_exposed:
        return "emergency patch"
    if f.chainedWith:
        return "dependency replacement"
    if f.runtimeReachable:
        return "version uplift"
    if f.severityLabel == "Medium":
        return "package pin/block"
    return "config hardening"


def _tier_for(risk_priority: float, model):
    """
    Action tiers:
     Tier 0: immediate auto-contain + incident
     Tier 1: patch in <24h
     Tier 2: change window within 72h
     Tier 3: backlog / preventive hardening
    """
    t = model.thresholds
    if risk_priority >= t.tier0:
        tier = "Tier 0"
    elif risk_priority >= t.tier1:
        tier = "Tier 1"
    elif risk_priority >= t.tier2:
        tier = "Tier 2"
    else:
        tier = "Tier 3"
    return tier, _tier_label(tier)


def _tier_label(tier: str) -> str:
    return {
        "Tier 0": "Immediate auto-contain + incident",
        "Tier 1": "Patch in <24h",
        "Tier 2": "Change window within 72h",
        "Tier 3": "Backlog / preventive hardening",
    }[tier]
