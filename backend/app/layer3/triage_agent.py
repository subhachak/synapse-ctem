from app.models import RawFinding, ContextGraphRecord, ReasoningEngineRecord, TriageAgentOutput
from app.llm import llm_reason
from app.retrieval import retrieve, format_for_prompt

"""
LAYER 3 · TRIAGE AGENT
"Decides whether a finding matters in your environment"
Inputs: CVE/advisory text + CVSS, affected services
from context graph, runtime reachability (eBPF telemetry), EPSS / CISA KEV
/ threat intel, policy (tier, scope, compliance flags)
Target impact: "80-90% reduction in human-actioned findings, explainable
per-decision"
"""


def run_triage_agent(
    finding: RawFinding, ctx: ContextGraphRecord, reasoning: ReasoningEngineRecord, retrieved: dict | None = None
) -> TriageAgentOutput:
    suppress = (not reasoning.exploitableIssue) and (not ctx.reachability.runtimeReachable)
    retrieved = retrieved or retrieve(
        f"{finding.name} {finding.cve} {finding.affectedComponent} {reasoning.actionTier} triage suppression precedent",
        {"precedent", "policy"},
    )

    reasoning_chain = [
        f"CVE/advisory: {finding.cve} ({finding.severityLabel}) on {finding.affectedComponent}",
        f"Affected services from context graph: {', '.join(s.name for s in ctx.services) or 'none'}",
        f"Runtime reachability (eBPF telemetry signal): {'reachable' if ctx.reachability.runtimeReachable else 'not observed reachable'}",
        f"EPSS {finding.epss:.2f} · CISA KEV: {'yes' if finding.cisaKev else 'no'} · discovered by {finding.discoveredBy}",
        f"Policy scope: {', '.join(p.id for p in ctx.policies) or 'none'} applied",
        f"Risk Priority computed by Layer 2: {reasoning.riskPriority} -> {reasoning.actionTier} ({reasoning.actionTierLabel})",
    ]

    narrative = llm_reason(
        "You are the Triage Agent in a Continuous Threat Exposure Management (CTEM) pipeline. "
        "Given structured finding context, explain in 2-3 sentences why this finding does or does "
        "not matter in this environment right now, referencing reachability and business criticality.",
        f"finding={finding.model_dump()} ctx={ctx.model_dump()} reasoning={reasoning.model_dump()}\n"
        f"{format_for_prompt(retrieved)}\nCite retrieved document IDs for claims based on precedent.",
    )
    reasoning_chain.append(f"Agent narrative: {narrative}")

    return TriageAgentOutput(
        findingId=finding.id,
        riskScore=reasoning.riskPriority,
        tier=reasoning.actionTier,
        reasoningChain=reasoning_chain,
        suppressed=suppress,
        suppressionReason="Not reachable at runtime and no active exploit signal" if suppress else None,
        confidence=0.6 if suppress else min(0.98, 0.7 + reasoning.exploitationLikelihood * 0.3),
        humanOverrideAvailable=True,
        retrievalMode=retrieved["mode"],
        retrievalCitations=retrieved["citations"],
    )
