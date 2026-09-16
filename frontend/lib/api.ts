const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

// Every response is unwrapped through here so a non-2xx can never be mistaken
// for a success payload. FastAPI returns errors as JSON ({"detail": ...}), so
// calling r.json() without checking the status yields a well-formed object of
// entirely the wrong shape — the failure then surfaces far from its cause, or
// not at all. Throwing here keeps it at the call site.
async function unwrap<T>(r: Response, what: string): Promise<T> {
  if (!r.ok) {
    let detail = "";
    try {
      const body = await r.json();
      if (typeof body?.detail === "string") detail = `: ${body.detail}`;
    } catch {
      // error body wasn't JSON; the status code is all we have
    }
    throw new Error(`${what} failed (${r.status})${detail}`);
  }
  return r.json() as Promise<T>;
}

async function getJson<T>(path: string, what: string): Promise<T> {
  return unwrap<T>(await fetch(`${API_BASE}${path}`), what);
}

async function postJson<T>(path: string, what: string, body: unknown = {}): Promise<T> {
  return unwrap<T>(
    await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
    what,
  );
}

export interface FindingPipelineResult {
  runId: string;
  finding: {
    id: string;
    cve: string;
    name: string;
    affectedComponent: string;
    severityLabel: "Critical" | "High" | "Medium" | "Low";
    cvssBase: number;
    demoScenario: "standard" | "sandbox-failure";
    discoveredBy: string;
    epss: number;
    cisaKev: boolean;
    runtimeReachable: boolean;
    chainedWith: string[];
    raOnBooks: boolean;
  };
  layer1: {
    services: { id: string; name: string; tier: string; internetExposed: boolean }[];
    software: { name: string; version: string };
    owner: { name: string; team: string };
    policies: { id: string; description: string }[];
    reachability: { runtimeReachable: boolean; attackPath: string[] };
  };
  dataQuality: {
    findingId: string;
    fieldStatus: Record<string, "present" | "inferred" | "missing" | "simulated">;
    completenessScore: number;
    decision: "ready" | "review-required";
    issues: string[];
  };
  layer2: {
    exploitationLikelihood: number;
    businessImpact: number;
    residualRisk: number;
    likelihoodInputs: Record<string, number>;
    likelihoodContributions: Record<string, number>;
    impactInputs: Record<string, number>;
    impactContributions: Record<string, number>;
    validatedControlEffectiveness: number;
    scoringFormula: string;
    calculatedRiskPriority: number;
    calculatedActionTier: string;
    riskPriority: number;
    exploitableIssue: boolean;
    chainedVulns: string[];
    businessCriticalAsset: boolean;
    blastRadius: number;
    predictiveRisk: string;
    remediationApproach: string;
    actionTier: string;
    actionTierLabel: string;
    riskModelVersion: string;
    decisionMethod: "deterministic-model" | "deterministic-model+policy-override" | "deterministic-model+human-override";
    policyOverrides: string[];
  };
  plausibility: {
    findingId: string;
    assessment: "plausible" | "questionable" | "inconsistent";
    confidence: number;
    concerns: string[];
    recommendedAction: "proceed" | "human-score-review";
    advisoryNarrative: string;
    advisoryMode: "anthropic" | "deterministic-fallback";
    authoritative: boolean;
  };
  triage: {
    riskScore: number;
    tier: string;
    reasoningChain: string[];
    suppressed: boolean;
    suppressionReason?: string;
    confidence: number;
    humanOverrideAvailable: boolean;
    retrievalMode: string;
    retrievalCitations: RetrievalCitation[];
  };
  planning: {
    fixApproach: string;
    targetVersionOrConfig: string;
    predictedBreakingChanges: string[];
    transitiveDependencies: string[];
    compensatingControls: string[];
    validationPlan: string[];
    effortEstimate: string;
    routedOwnerId: string;
    mitigationRecipe: string;
    retrievalMode: string;
    retrievalCitations: RetrievalCitation[];
  };
  implementation: {
    generatedTestSuite: string[];
    coverageDelta: string;
    untestablePaths: string[];
    prTitle: string;
    diffSummary: string;
    rationale: string;
    selfAssessedConfidence: number;
    sandboxedExecution: boolean;
    noProdDataOrSecrets: boolean;
    humanInTheLoop: boolean;
    retrievalMode: string;
    retrievalCitations: RetrievalCitation[];
  };
  governance: {
    auditArtifactId: string;
    provenanceWho: string;
    provenanceWhat: string;
    provenanceWhy: string;
    controlsMapped: string[];
    policyChecks: { policyId: string; passed: boolean; note: string }[];
    crossRegionFlag: boolean;
    customerNotificationTriggered: boolean;
    approvalStatus: string;
    retrievalMode: string;
    retrievalCitations: RetrievalCitation[];
  };
  verification: {
    findingId: string;
    status: "not-run" | "failed" | "verified-closed";
    verifiedClosed: boolean;
    evidenceMode: "SIMULATED" | "LIVE";
    evidence: {
      evidenceType: "sandbox-test" | "deployment-proof" | "post-change-rescan" | "runtime-path-check";
      artifactId: string;
      result: "pass" | "fail" | "not-run";
      source: "simulated-adapter" | "live-integration";
      detail: string;
      issuedBy?: string;
      command?: string;
      logExcerpt?: string;
      prUrl?: string;
    }[];
  };
  timings: {
    contextualizedAtMs: number;
    validatedAtMs: number;
    mitigatedAtMs: number;
    exploitPathClosedAtMs: number;
  };
  routePath: string[];
  finalStatus: string;
}

export interface RetrievalCitation {
  id: string;
  title: string;
  content: string;
  source: string;
  document_type: string;
  effective_date: string;
  status: string;
  similarity: number;
}

export interface FindingSummary {
  id: string;
  name: string;
  cve: string;
  severity: "Critical" | "High" | "Medium" | "Low";
}

export interface KpiSummary {
  meanTimeToContextualizeMs: number;
  meanTimeToValidateMs: number;
  meanTimeToMitigateMs: number;
  meanExploitPathClosureMs: number;
  pctAutoCorrelatedToOwner: number;
  pctHighRiskVerifiedReachable: number;
  pctRemediationsVerifiedClosed: number;
  pctAutoRemediatedVsHumanApproved: number;
  falsePositiveRateByAgent: Record<string, number>;
  exceptionDebtOpenCount: number;
  controlEfficacy: { control: string; timeBoughtHours: number }[];
  slaAtRiskCount: number;
  verifiedClosedCount: number;
  metricProvenance: Record<string, string>;
  metricSampleCounts: Record<string, number>;
  illustrativeTargets: Record<string, string>;
}

export interface ServiceSummary {
  id: string;
  name: string;
  ownerId: string;
  tier: "crown-jewel" | "business-critical" | "standard";
  internetExposed: boolean;
  dataResidency: string;
}

export interface OwnerSummary {
  id: string;
  name: string;
  team: string;
}

export interface AppCriticalityEntry {
  applicationId: string;
  tier: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
  dataSensitivity: string;
  accountableOwnerId: string;
  crownJewel: boolean;
  internetExposed: boolean;
  complianceScope: string[];
}

export interface LikelihoodCoefficients {
  intercept: number;
  epssLogOdds: number;
  internetExposure: number;
  runtimeReachability: number;
  exploitMaturity: number;
  chainability: number;
  threatActivity: number;
}

export interface ImpactWeights {
  cvssSeverity: number;
  appCriticality: number;
  dataSensitivity: number;
  blastRadius: number;
  regulatorySafety: number;
}

export interface RiskTierThresholds {
  tier0: number;
  tier1: number;
  tier2: number;
}

export interface RiskModelSettings {
  appCriticality: AppCriticalityEntry[];
  likelihoodCoefficients: LikelihoodCoefficients;
  impactWeights: ImpactWeights;
  thresholds: RiskTierThresholds;
  kevOverridesToTier0: boolean;
  maxControlEffectiveness: number;
  status: "draft" | "active";
  version: string;
}

export interface LearningSummary {
  sampleCount: number;
  reclassificationCount: number;
  raisedCount: number;
  loweredCount: number;
  activeSuppressions: number;
  reopenedSuppressions: number;
  suppressionEscapeCount: number;
  reasonCodes: Record<string, number>;
}

export interface BacktestResult {
  activeVersion: string;
  candidateVersion: string;
  sampleCount: number;
  labelledSampleCount: number;
  evaluationWindow: string;
  changedCount: number;
  authoritative: false;
  message: string;
  changes: { runId: string; finding: string; activeScore: number; activeTier: string; candidateScore: number; candidateTier: string; exploitationOutcome?: string; decisionAt?: string }[];
}

export interface SuppressionLease {
  run_id: string;
  status: "active" | "reopened";
  reason: string;
  created_at: string;
  expires_at: string;
  reopened_at?: string;
  reopen_trigger?: string;
  successor_run_id?: string;
}

export async function fetchHealth(): Promise<{ status: string; llmMode: string; retrievalMode: string }> {
  return getJson<{ status: string; llmMode: string; retrievalMode: string }>("/api/health", "health check");
}

export async function fetchLearningSummary(): Promise<LearningSummary> {
  return getJson<LearningSummary>("/api/learning/summary", "learning summary");
}

export async function backtestRiskModel(settings: RiskModelSettings): Promise<BacktestResult> {
  const r = await fetch(`${API_BASE}/api/settings/risk-model/backtest`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(settings),
  });
  if (!r.ok) throw new Error(`backtest failed (${r.status})`);
  return r.json();
}

export async function fetchSuppressions(): Promise<SuppressionLease[]> {
  return getJson<SuppressionLease[]>("/api/suppressions", "suppression list");
}

export async function reopenSuppression(runId: string, trigger: string): Promise<{ successorRunId: string }> {
  const r = await fetch(`${API_BASE}/api/suppressions/${runId}/reopen`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ trigger }),
  });
  if (!r.ok) throw new Error(`reopen failed (${r.status})`);
  return r.json();
}

export async function fetchFindings(): Promise<FindingSummary[]> {
  return getJson<FindingSummary[]>("/api/findings", "seed finding catalog");
}

// Looks up the bootstrapped seed run for a finding id (e.g. "find-2") and
// returns its result — for pages that pick a finding by its familiar seed
// id (the Demo Mode walkthrough's picker) rather than a run UUID.
export async function fetchSeedFindingResult(findingId: string): Promise<FindingPipelineResult> {
  const r = await fetch(`${API_BASE}/api/findings/${findingId}/result`);
  if (!r.ok) throw new Error(`seed finding ${findingId} not ready (${r.status})`);
  return r.json();
}

export async function fetchKpis(): Promise<KpiSummary> {
  return getJson<KpiSummary>("/api/kpis", "KPI summary");
}

export async function fetchServices(): Promise<ServiceSummary[]> {
  return getJson<ServiceSummary[]>("/api/services", "service list");
}

export async function fetchOwners(): Promise<OwnerSummary[]> {
  return getJson<OwnerSummary[]>("/api/owners", "owner list");
}

export async function fetchRiskModelSettings(): Promise<RiskModelSettings> {
  return getJson<RiskModelSettings>("/api/settings/risk-model", "risk model settings");
}

export async function saveRiskModelSettings(settings: RiskModelSettings): Promise<RiskModelSettings> {
  return postJson<RiskModelSettings>("/api/settings/risk-model", "saving risk model settings", settings);
}

// ---------------------------------------------------------------------------
// CTEM Demo v2 — incident injection, live runs, human-review queues.
// ---------------------------------------------------------------------------
export type RunStatus = "running" | "paused_ontology_review" | "paused_score_review" | "paused_governance_review" | "completed";

export interface Run {
  run_id: string;
  incident_source: string;
  finding_json: string;
  status: RunStatus;
  current_node: string | null;
  created_at: string;
  completed_at: string | null;
  final_status: string | null;
  // Enriched by GET /api/incidents once the run has reached the Governance
  // Agent (see main.py's list_incidents) — null until then, regardless of
  // whether the run came from a seed finding or a live-injected one.
  actionTier: string | null;
  riskPriority: number | null;
  ownerName: string | null;
}

export interface RunEvent {
  event_id: number;
  run_id: string;
  node_name: string;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
  input_snapshot: string | null;
  output_snapshot: string | null;
}

export interface IncidentDetail {
  run: Run;
  events: RunEvent[];
}

export interface QueueItemBase {
  item_id: string;
  run_id: string;
  status: string;
  created_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_note: string | null;
}

export interface OntologyQueueItem extends QueueItemBase {
  candidate_category_json: string;
  precedent_json: string | null;
}

export interface GovernanceQueueItem extends QueueItemBase {
  reason: string;
  details_json: string;
}

export interface ScoreReviewQueueItem extends QueueItemBase {
  assessment_json: string;
  reasoning_json: string;
  selected_tier: string | null;
}

export interface RemediationCase {
  run_id: string;
  state: string;
  owner_id: string;
  ticket_id: string;
  authorization: string;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationTransition {
  transition_id: number;
  run_id: string;
  from_state: string | null;
  to_state: string;
  actor: string;
  note: string | null;
  created_at: string;
}

export interface RemediationDetail {
  case: RemediationCase;
  transitions: RemediationTransition[];
}

// The custom-incident request shape lives with the injector that uses it:
// backend IncidentCreateRequest (app/main.py) and democtl.sh's inject-custom.
// Incident creation is command-line only — see /api/_control/incidents.

// Realistic-sounding display name for a run's incident_source. Seed/preset
// runs are stored as "seed:find-N" internally (needed for bootstrap
// idempotency, see backend's bootstrap_seed_incidents) — mapped here to the
// discovery engine that actually found it, per the "AI-Discovered
// Exposure — Mythos & Codex Findings" framing. Live custom injections
// already carry a realistic feed/tool name chosen at injection time (see the
// CLI fixture Source field), so those pass through unchanged.
export function sourceLabel(incidentSource: string, discoveredBy?: string): string {
  if (incidentSource.startsWith("seed:")) {
    if (discoveredBy === "Mythos") return "Mythos AI — Runtime Threat Detection";
    if (discoveredBy === "Codex") return "Codex AI — Dependency & SCA Scan";
    return incidentSource;
  }
  return incidentSource;
}

export interface QueueDecisionBody {
  resolved_by?: string;
  resolution_note?: string;
  edited_name?: string;
  edited_definition_text?: string;
  selected_tier?: "Tier 0" | "Tier 1" | "Tier 2" | "Tier 3";
}

export async function fetchIncidents(): Promise<Run[]> {
  return getJson<Run[]>("/api/incidents", "incident list");
}

export async function fetchIncidentDetail(runId: string): Promise<IncidentDetail> {
  return getJson<IncidentDetail>(`/api/incidents/${runId}`, `incident ${runId}`);
}

export function incidentStreamUrl(runId: string): string {
  return `${API_BASE}/api/incidents/${runId}/stream`;
}

export async function fetchIncidentResult(runId: string): Promise<FindingPipelineResult> {
  const r = await fetch(`${API_BASE}/api/incidents/${runId}/result`);
  if (!r.ok) throw new Error(`incident ${runId} not ready for triage view (${r.status})`);
  return r.json();
}

// Bulk "ready" results (every run, seed-originated or live-injected, that has
// reached the Governance Agent) — the shared dataset behind Dashboard's
// KPIs/charts and the History page.
export async function fetchIncidentResults(): Promise<FindingPipelineResult[]> {
  return getJson<FindingPipelineResult[]>("/api/incidents/results", "bulk incident results");
}

export async function fetchOntologyQueue(): Promise<OntologyQueueItem[]> {
  return getJson<OntologyQueueItem[]>("/api/queues/ontology", "ontology queue");
}

export async function resolveOntologyItem(
  itemId: string,
  action: "approve" | "reject",
  body: QueueDecisionBody = {}
): Promise<unknown> {
  return postJson<unknown>(`/api/queues/ontology/${itemId}/${action}`, `ontology ${action}`, body);
}

export async function fetchGovernanceQueue(): Promise<GovernanceQueueItem[]> {
  return getJson<GovernanceQueueItem[]>("/api/queues/governance", "governance queue");
}

export async function fetchScoreReviewQueue(): Promise<ScoreReviewQueueItem[]> {
  return getJson<ScoreReviewQueueItem[]>("/api/queues/score-review", "score review queue");
}

export async function resolveScoreReviewItem(
  itemId: string,
  action: "confirm" | "reclassify",
  body: QueueDecisionBody = {}
): Promise<unknown> {
  return postJson<unknown>(`/api/queues/score-review/${itemId}/${action}`, `score review ${action}`, body);
}

export async function resolveGovernanceItem(
  itemId: string,
  action: "approve" | "reject",
  body: QueueDecisionBody = {}
): Promise<unknown> {
  return postJson<unknown>(`/api/queues/governance/${itemId}/${action}`, `governance ${action}`, body);
}

export async function fetchRemediation(runId: string): Promise<RemediationDetail> {
  const r = await fetch(`${API_BASE}/api/remediations/${runId}`);
  if (!r.ok) throw new Error(`remediation ${runId} not found`);
  return r.json();
}

export interface AgentStep {
  seq: number;
  role: "orchestrator" | "scanner" | "planner" | "implementer" | "tester" | "verifier";
  agent: string;
  attempt: number;
  mode: "deterministic" | "agentic";
  action: string;
  detail: string;
  status: "ok" | "fail" | "info" | "retry";
  llmUsed: boolean;
  durationMs: number;
}

export interface AgentTrace {
  runId: string;
  strategy: string;
  scenarioClass: "SCA" | "SAST" | "DAST" | "generic";
  maxAttempts: number;
  attemptsUsed: number;
  converged: boolean;
  orchestrator: string;
  steps: AgentStep[];
  summary: string;
}

// Returns null (not an error) when a run has no orchestration trace — i.e. it
// wasn't a live code-remediation finding (SCA/SAST/DAST).
export async function fetchAgentTrace(runId: string): Promise<AgentTrace | null> {
  const r = await fetch(`${API_BASE}/api/incidents/${runId}/agent-trace`);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`agent trace ${runId} failed (${r.status})`);
  return r.json();
}

export interface IncidentLinks {
  repo: string;     // env-resolved "owner/repo" (may be empty in offline mode)
  repoUrl: string;  // browser URL for the target repo, or "" when not applicable
  prUrl: string;    // the real remediation PR, or "" before one exists
}

// Demo-navigation links (target repo + remediation PR). Never throws — returns
// empties so the UI simply omits the links when unavailable.
export async function fetchIncidentLinks(runId: string): Promise<IncidentLinks> {
  try {
    const r = await fetch(`${API_BASE}/api/incidents/${runId}/links`);
    if (!r.ok) return { repo: "", repoUrl: "", prUrl: "" };
    return await r.json();
  } catch {
    return { repo: "", repoUrl: "", prUrl: "" };
  }
}

export async function assignRemediationOwner(runId: string, ownerId: string): Promise<RemediationCase> {
  return postJson<RemediationCase>(`/api/remediations/${runId}/assign`, "owner assignment", { owner_id: ownerId });
}

export async function retryRemediation(runId: string): Promise<RemediationCase> {
  return postJson<RemediationCase>(`/api/remediations/${runId}/retry`, "remediation retry");
}

// ---------------------------------------------------------------------------
// Ontology / context graph (Settings > Ontology visual)
// ---------------------------------------------------------------------------
export type OntologyLabel = "Service" | "Software" | "Owner" | "Category";
export type OntologyEdgeType = "AFFECTS" | "RUNS_ON" | "DEPENDS_ON" | "CHAINS_WITH" | "OWNED_BY";

export interface OntologyNode {
  id: string;
  label: OntologyLabel;
  name?: string;
  [prop: string]: unknown;
}

export interface OntologyEdge {
  srcId: string;
  edgeType: OntologyEdgeType;
  dstId: string;
}

export interface OntologyGraph {
  nodes: OntologyNode[];
  edges: OntologyEdge[];
}

export async function fetchOntologyGraph(): Promise<OntologyGraph> {
  return getJson<OntologyGraph>("/api/ontology/graph", "ontology graph");
}
