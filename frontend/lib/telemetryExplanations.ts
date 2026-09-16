// Human-readable descriptions for each LangGraph node in the CTEM incident
// pipeline (see backend/app/graph.py's build_incident_graph). Edit the base
// text below to change what shows in the Telemetry timeline — dynamic
// enrichment (score/decision values) is appended automatically from that
// node's own output when available, and falls back to the base text alone
// if the shape doesn't match (e.g. an older/legacy run).

interface NodeExplainer {
  label: string;
  base: string;
  enrich?: (output: any) => string | null;
}

const EXPLAINERS: Record<string, NodeExplainer> = {
  context_graph: {
    label: "Context Graph",
    base: "Worked out which services, software, and owner this finding actually touches, and mapped a plausible attack path.",
    enrich: (o) => {
      const count = o?.ctx?.services?.length;
      const owner = o?.ctx?.owner?.name;
      if (count == null) return null;
      return `Found ${count} affected service${count === 1 ? "" : "s"}${owner ? `, owned by ${owner}` : ""}.`;
    },
  },
  parallel_enrichment: {
    label: "Parallel Enrichment Orchestrator",
    base: "Fanned out independent evidence-quality, ontology-match, and approved-knowledge retrieval work in parallel.",
  },
  evidence_quality_enrichment: {
    label: "Evidence Quality · Parallel",
    base: "Assessed evidence completeness independently while the other enrichment branches ran.",
  },
  ontology_match_enrichment: {
    label: "Ontology Match · Parallel",
    base: "Matched the finding to the governed ontology independently while other enrichment branches ran.",
  },
  knowledge_retrieval_enrichment: {
    label: "Approved Knowledge · Parallel",
    base: "Prefetched bounded policy, runbook, and precedent context for downstream specialist agents.",
  },
  enrichment_join: {
    label: "Enrichment Join",
    base: "Waited for all required enrichment branches and validated their outputs before allowing deterministic scoring.",
  },
  data_quality: {
    label: "Evidence Quality Gate",
    base: "Checked whether the evidence required for a defensible decision is present, inferred, missing, or simulated.",
    enrich: (o) => {
      const score = o?.quality?.completenessScore;
      const decision = o?.quality?.decision;
      return score == null ? null : `${(score * 100).toFixed(0)}% complete → ${decision}.`;
    },
  },
  category_match: {
    label: "Category Match",
    base: "Compared this finding against known vulnerability categories to see how confidently it matches something we've seen before.",
    enrich: (o) => {
      const confidence = o?.category_match_result?.confidence;
      const category = o?.category_match_result?.category?.name;
      const method = o?.category_match_result?.matchMethod;
      if (confidence == null) return null;
      return category
        ? `Matched "${category}" at ${(confidence * 100).toFixed(0)}% confidence${method ? ` via ${method}` : ""}.`
        : `No confident match (best guess ${(confidence * 100).toFixed(0)}% confidence) — flagged for human review.`;
    },
  },
  ontology_review_gate: {
    label: "Ontology Review Gate",
    base: "Paused here — no category matched confidently enough, so the run is waiting for a human to approve or reject a new category before continuing.",
  },
  reasoning_engine: {
    label: "Reasoning Engine",
    base: "Applied the active, versioned risk model and explicit policy overrides. Deterministic — no AI involved.",
    enrich: (o) => {
      const priority = o?.reasoning?.riskPriority;
      const tier = o?.reasoning?.actionTier;
      if (priority == null) return null;
      return `Risk Priority ${priority} → ${tier}.`;
    },
  },
  plausibility_judge: {
    label: "AI Plausibility Review",
    base: "Advisory AI challenged the deterministic result for contradictions. It cannot alter the authoritative score or tier.",
    enrich: (o) => {
      const assessment = o?.plausibility?.assessment;
      const action = o?.plausibility?.recommendedAction;
      return assessment ? `${assessment} → ${action}.` : null;
    },
  },
  score_review_gate: {
    label: "Human Score Review",
    base: "A human confirmed or reclassified the governed score after an advisory concern; the original calculation remains in the audit trail.",
  },
  triage_agent: {
    label: "Triage Agent",
    base: "An AI agent judged whether this finding is worth acting on right now, or should be suppressed as noise.",
    enrich: (o) => {
      const suppressed = o?.triage?.suppressed;
      if (suppressed == null) return null;
      return suppressed
        ? "Decision: suppressed — not worth acting on right now."
        : "Decision: not suppressed — proceeding to remediation.";
    },
  },
  skip_remediation: {
    label: "Skip Remediation",
    base: "Suppressed by Triage, so Planning and Implementation were skipped entirely — no agent spend on a finding nobody needs to fix.",
  },
  planning_agent: {
    label: "Planning Agent",
    base: "Worked out how to fix this — target version, predicted breaking changes, and effort estimate.",
    enrich: (o) => {
      const fix = o?.planning?.fixApproach;
      return fix ? `Recommended fix: ${fix}.` : null;
    },
  },
  implementation_agent: {
    label: "Implementation Agent",
    base: "Drafted the proposed fix and tests. It does not execute them or issue verification evidence.",
    enrich: (o) => {
      const title = o?.implementation?.prTitle;
      return title ? `Draft: ${title}.` : null;
    },
  },
  governance_agent: {
    label: "Governance Agent",
    base: "Checked the proposed action against policy and mapped it to the controls it satisfies.",
    enrich: (o) => {
      const status = o?.governance?.approvalStatus;
      return status ? `Approval status: ${status}.` : null;
    },
  },
  governance_review_gate: {
    label: "Governance Review Gate",
    base: "Paused here, waiting for a human reviewer to approve or reject before this finding is closed or blocked.",
  },
  auto_close: {
    label: "Suppression Finalization",
    base: "Finalized a revocable suppression lease without executing remediation or claiming verified closure.",
    enrich: (o) => {
      const status = o?.verification?.status;
      const mode = o?.verification?.evidenceMode;
      return status ? `${status}${mode ? ` (${mode.toLowerCase()} evidence)` : ""}.` : null;
    },
  },
  execute_remediation: {
    label: "Authorized Execution",
    base: "Executed the change only after the required policy or human authorization was present.",
    enrich: (o) => {
      const ev = o?.execution_evidence || o?.executionEvidence;
      if (!Array.isArray(ev) || ev.length === 0) return null;
      const live = ev.some((e: any) => e?.source === "live-integration");
      const pr = ev.find((e: any) => e?.prUrl)?.prUrl;
      if (!live) return "Simulated adapter executed the drafted change.";
      return `Live remediation: real dependency bump, test run, and rescan${pr ? ` — PR opened at ${pr}` : " (local branch mode)"}.`;
    },
  },
  independent_verification: {
    label: "Independent Verification",
    base: "A separate deterministic verifier evaluated sandbox, deployment, rescan, and runtime-path evidence it did not create.",
    enrich: (o) => {
      const status = o?.verification?.status;
      return status ? `Verification result: ${status}.` : null;
    },
  },
  finalize_closure: {
    label: "Closure Gate",
    base: "Closed the finding only when the independent evidence contract passed; otherwise retained a failed state.",
  },
  blocked_review: {
    label: "Blocked (Policy Review)",
    base: "Blocked — a policy check failed, pending review.",
  },
  escalate_human: {
    label: "Escalate to Human",
    base: "Escalated to a person for sign-off.",
  },
};

function safeParse(json: string | null): any {
  if (!json) return null;
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export function friendlyNodeLabel(nodeName: string): string {
  return EXPLAINERS[nodeName]?.label ?? nodeName;
}

export function describeNode(nodeName: string, outputSnapshot: string | null): string {
  const explainer = EXPLAINERS[nodeName];
  if (!explainer) return "No description available for this step.";

  let extra: string | null = null;
  if (explainer.enrich) {
    try {
      extra = explainer.enrich(safeParse(outputSnapshot));
    } catch {
      extra = null;
    }
  }
  return extra ? `${explainer.base} ${extra}` : explainer.base;
}
