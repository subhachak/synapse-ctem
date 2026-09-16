import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Link from "next/link";
import AppShell from "../../components/AppShell";
import ScoringBreakdown, { evidenceQualityLabel } from "../../components/ScoringBreakdown";
import {
  fetchIncidentDetail,
  fetchIncidentResult,
  fetchIncidentLinks,
  fetchGovernanceQueue,
  fetchScoreReviewQueue,
  fetchOntologyQueue,
  fetchSuppressions,
  incidentStreamUrl,
  reopenSuppression,
  resolveGovernanceItem,
  resolveOntologyItem,
  resolveScoreReviewItem,
  sourceLabel,
  FindingPipelineResult,
  IncidentLinks,
  GovernanceQueueItem,
  OntologyQueueItem,
  ScoreReviewQueueItem,
  Run,
  RunEvent,
  SuppressionLease,
} from "../../lib/api";
import { describeNode, friendlyNodeLabel } from "../../lib/telemetryExplanations";

function tierClass(tier: string) {
  if (tier === "Tier 0") return "tier-0";
  if (tier === "Tier 1") return "tier-1";
  if (tier === "Tier 2") return "tier-2";
  return "tier-3";
}

function statusBadgeClass(status: string) {
  if (status === "running") return "running";
  if (status.startsWith("paused_")) return "paused";
  return "pass";
}

function statusLabel(status: string) {
  if (status === "running") return "Running";
  if (status === "paused_ontology_review") return "Paused — Ontology Review";
  if (status === "paused_score_review") return "Paused — Score Review";
  if (status === "paused_governance_review") return "Paused — Governance Review";
  if (status === "completed") return "Completed";
  return status;
}

function safeParse(raw: string | null): any {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function prettyJson(raw: string | null): string {
  const parsed = safeParse(raw);
  return parsed ? JSON.stringify(parsed, null, 2) : raw ?? "";
}

// Per-node-type formatted detail, rendered inside a timeline entry's expand —
// the single place each field appears (no separate summary panels elsewhere
// on the page repeating the same data). Matched by which key is present in
// the node's output, not by node_name, since skip_remediation's output
// carries both a "planning" and an "implementation" key at once (its stub
// path covers both agents in one node) and should show both sections.
function NodeDetail({ output }: { output: any }) {
  if (!output) return null;
  return (
    <>
      {output.ctx && (
        <div className="kv-block">
          <div className="kv">
            <span className="k">Services:</span> {output.ctx.services?.map((s: any) => s.name).join(", ") || "none"}
          </div>
          <div className="kv">
            <span className="k">Software:</span> {output.ctx.software?.name} ({output.ctx.software?.version})
          </div>
          <div className="kv">
            <span className="k">Owner:</span> {output.ctx.owner?.name} ({output.ctx.owner?.team})
          </div>
          <div className="kv">
            <span className="k">Runtime reachability:</span>{" "}
            {output.ctx.reachability?.runtimeReachable ? "reachable" : "not observed reachable"}
          </div>
          {output.ctx.reachability?.attackPath?.length > 0 && (
            <div className="kv">
              <span className="k">Attack path:</span> {output.ctx.reachability.attackPath.join(" > ")}
            </div>
          )}
          <div className="badge-row">
            {output.ctx.policies?.map((p: any) => (
              <span key={p.id} className="badge" title={p.description}>
                {p.id}
              </span>
            ))}
          </div>
        </div>
      )}

      {output.reasoning && (
        <div className="kv-block">
          <div className="formula-row">
            <div className="factor-chip">
              <span className="fname">Governed model</span>
              <span className="fval">{output.reasoning.riskModelVersion}</span>
            </div>
            <div className="factor-chip">
              <span className="fname">Exploitation likelihood</span>
              <span className="fval">{Math.round(output.reasoning.exploitationLikelihood * 100)}%</span>
            </div>
            <div className="factor-chip">
              <span className="fname">Business impact</span>
              <span className="fval">{Math.round(output.reasoning.businessImpact * 100)}%</span>
            </div>
            <div className="factor-chip">
              <span className="fname">Residual risk</span>
              <span className="fval">{output.reasoning.calculatedRiskPriority}</span>
            </div>
            <div className="factor-chip">
              <span className="fname">Calculated tier</span>
              <span className="fval">{output.reasoning.calculatedActionTier}</span>
            </div>
            <div className="factor-chip" style={{ borderColor: "var(--accent)" }}>
              <span className="fname">Final policy tier</span>
              <span className="fval" style={{ color: "var(--accent)" }}>
                {output.reasoning.actionTier}
              </span>
            </div>
          </div>
          <div className="kv">
            <span className="k">Formula:</span> likelihood × impact × (1 − validated controls)
          </div>
          <ScoringBreakdown
            likelihoodInputs={output.reasoning.likelihoodInputs || {}}
            likelihoodContributions={output.reasoning.likelihoodContributions || {}}
            impactInputs={output.reasoning.impactInputs || {}}
            impactContributions={output.reasoning.impactContributions || {}}
          />
          {output.reasoning.policyOverrides?.map((override: string) => (
            <div className="kv" key={override}>
              <span className="badge fail">POLICY OVERRIDE</span> {override}
            </div>
          ))}
          <div className="kv">
            <span className="k">Blast radius:</span> {output.reasoning.blastRadius} services &middot;{" "}
            <span className="k">Modeled predictive risk:</span> {output.reasoning.predictiveRisk}
          </div>
        </div>
      )}

      {output.quality && (
        <div className="kv-block">
          <div className="kv">
            <span className="badge">DETERMINISTIC</span>{" "}
            <span className="k">Evidence completeness:</span>{" "}
            {(output.quality.completenessScore * 100).toFixed(0)}% &middot; {output.quality.decision}
          </div>
          <div className="badge-row">
            {Object.entries(output.quality.fieldStatus || {}).map(([field, status]) => (
              <span key={field} className={`badge ${status === "missing" ? "fail" : status === "present" ? "pass" : ""}`}>
                {field}: {String(status)}
              </span>
            ))}
          </div>
          {output.quality.issues?.map((issue: string) => <div className="kv" key={issue}>{issue}</div>)}
        </div>
      )}

      {output.plausibility && (
        <div className="kv-block">
          <div className="kv">
            <span className="badge">
              {output.plausibility.advisoryMode === "anthropic" ? "ANTHROPIC ADVISORY" : "DETERMINISTIC ADVISORY"}
            </span>{" "}
            <span className="k">Plausibility:</span> {output.plausibility.assessment} &middot;{" "}
            {Math.round(output.plausibility.confidence * 100)}% confidence
          </div>
          <div className="sub">Advisory only — cannot change the authoritative score or tier.</div>
          <div className="kv">{output.plausibility.advisoryNarrative}</div>
          {output.plausibility.concerns?.map((concern: string) => <div className="kv" key={concern}>{concern}</div>)}
        </div>
      )}

      {output.verification && (
        <div className="kv-block">
          <div className="kv">
            <span className={`badge ${output.verification.evidenceMode === "LIVE" ? "pass" : ""}`}>{output.verification.evidenceMode}</span>{" "}
            <span className="k">Closure verification:</span> {output.verification.status}
          </div>
          <div className="sub">
            {output.verification.evidenceMode === "LIVE"
              ? "Live evidence: real scanner, real test run, real git/PR, and a runtime probe against the fixed dependency."
              : "Evidence comes from typed demo adapters, not live enterprise integrations."}
          </div>
          {output.verification.evidence?.map((item: any) => (
            <div className="kv" key={item.artifactId} style={{ display: "block" }}>
              <div>
                <span className={`badge ${item.result === "pass" ? "pass" : item.result === "fail" ? "fail" : ""}`}>{item.result}</span>{" "}
                <span className="k">{item.evidenceType}:</span> {item.detail}
                {item.issuedBy ? <span className="sub"> · issued by {item.issuedBy}</span> : null}
              </div>
              {item.prUrl ? (
                <div className="sub">PR: <a href={item.prUrl} target="_blank" rel="noreferrer">{item.prUrl}</a></div>
              ) : null}
              {item.command ? <div className="sub">$ {item.command}</div> : null}
              {item.logExcerpt ? (
                <pre style={{ whiteSpace: "pre-wrap", fontSize: 11, background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 4, marginTop: 4, overflowX: "auto" }}>{item.logExcerpt}</pre>
              ) : null}
            </div>
          ))}
        </div>
      )}

      {[output.triage, output.planning, output.implementation, output.governance].filter(Boolean).map((agent: any, index: number) => (
        agent.retrievalCitations?.length > 0 && (
          <div className="kv-block" key={`retrieval-${index}`}>
            <div className="kv"><span className="badge">BOUNDED RETRIEVAL</span> <span className="k">Mode:</span> {agent.retrievalMode}</div>
            {agent.retrievalCitations.map((citation: any) => (
              <div className="panel" style={{ marginTop: 8 }} key={citation.id}>
                <div><strong>[{citation.id}] {citation.title}</strong></div>
                <div className="sub">{citation.source} &middot; effective {citation.effective_date} &middot; similarity {citation.similarity}</div>
                <div className="kv">{citation.content}</div>
              </div>
            ))}
            <div className="sub">Advisory context only — cannot change scoring, policy, authorization, or closure.</div>
          </div>
        )
      ))}

      {output.triage && (
        <div className="kv-block">
          <div className="field-label">Engine confidence</div>
          <div className="confidence-bar">
            <div className="confidence-bar-fill" style={{ width: `${output.triage.confidence * 100}%` }} />
          </div>
          <div className="sub" style={{ marginBottom: 8 }}>
            {(output.triage.confidence * 100).toFixed(0)}%
          </div>
          {output.triage.suppressed && output.triage.suppressionReason && (
            <div className="kv">
              <span className="k">Suppression reason:</span> {output.triage.suppressionReason}
            </div>
          )}
          <ol style={{ margin: "6px 0 0", paddingLeft: 18 }}>
            {output.triage.reasoningChain?.map((step: string, i: number) => (
              <li key={i} className="kv" style={{ margin: "4px 0" }}>
                {step}
              </li>
            ))}
          </ol>
        </div>
      )}

      {output.planning && (
        <div className="kv-block">
          <div className="kv">
            <span className="k">Fix:</span> {output.planning.fixApproach} &rarr; {output.planning.targetVersionOrConfig}
          </div>
          <div className="kv">
            <span className="k">Effort estimate:</span> {output.planning.effortEstimate}
          </div>
          {output.planning.predictedBreakingChanges?.length > 0 && (
            <div className="kv">
              <span className="k">Predicted breaking changes:</span>
              <ul className="chain-list">
                {output.planning.predictedBreakingChanges.map((c: string, i: number) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          )}
          {output.planning.compensatingControls?.length > 0 && (
            <div className="kv">
              <span className="k">Compensating controls:</span> {output.planning.compensatingControls.join(", ")}
            </div>
          )}
          <div className="kv">
            <span className="k">Mitigation recipe:</span> {output.planning.mitigationRecipe}
          </div>
        </div>
      )}

      {output.implementation && (
        <div className="kv-block">
          <div className="kv">
            <span className="k">PR:</span> {output.implementation.prTitle}
          </div>
          <div className="kv">
            <span className="k">Diff:</span> {output.implementation.diffSummary}
          </div>
          <div className="kv">
            <span className="k">Rationale:</span> {output.implementation.rationale}
          </div>
          <div className="badge-row">
            <span className="badge">DRAFT ONLY — adapter execution follows authorization</span>
            <span className="badge">confidence: {(output.implementation.selfAssessedConfidence * 100).toFixed(0)}%</span>
            {output.implementation.generatedTestSuite?.map((t: string, i: number) => (
              <span className="badge" key={i}>
                test: {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {output.governance && (
        <div className="kv-block">
          <div className="kv">
            <span className="k">Provenance (who/what/why):</span> {output.governance.provenanceWho} &mdash;{" "}
            {output.governance.provenanceWhat} &mdash; {output.governance.provenanceWhy}
          </div>
          <div className="kv">
            <span className="k">Controls mapped:</span> {output.governance.controlsMapped?.join(", ")}
          </div>
          <div className="badge-row">
            {output.governance.policyChecks?.map((p: any) => (
              <span key={p.policyId} className={`badge ${p.passed ? "pass" : "fail"}`} title={p.note}>
                {p.policyId}: {p.passed ? "pass" : "fail"}
              </span>
            ))}
            {output.governance.crossRegionFlag && <span className="badge fail">cross-region flag</span>}
            {output.governance.customerNotificationTriggered && (
              <span className="badge fail">customer notification triggered</span>
            )}
          </div>
        </div>
      )}
    </>
  );
}

export default function Review() {
  const router = useRouter();
  const { id } = router.query;

  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [data, setData] = useState<FindingPipelineResult | null>(null);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const [rawShown, setRawShown] = useState<Record<number, boolean>>({});
  const [ontologyItem, setOntologyItem] = useState<OntologyQueueItem | null>(null);
  const [governanceItem, setGovernanceItem] = useState<GovernanceQueueItem | null>(null);
  const [scoreReviewItem, setScoreReviewItem] = useState<ScoreReviewQueueItem | null>(null);
  const [reviewTier, setReviewTier] = useState<"Tier 0" | "Tier 1" | "Tier 2" | "Tier 3">("Tier 1");
  const [resolving, setResolving] = useState(false);
  const [suppressionLease, setSuppressionLease] = useState<SuppressionLease | null>(null);
  const [links, setLinks] = useState<IncidentLinks | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    if (typeof id !== "string") return;
    fetchIncidentDetail(id).then((d) => {
      setRun(d.run);
      setEvents(d.events);
    });
  }, [id]);

  useEffect(() => {
    if (typeof id !== "string") return;
    const es = new EventSource(incidentStreamUrl(id));
    es.onmessage = (e) => {
      const ev: RunEvent = JSON.parse(e.data);
      setEvents((prev) => (prev.some((p) => p.event_id === ev.event_id) ? prev.map((p) => (p.event_id === ev.event_id ? ev : p)) : [...prev, ev]));
    };
    es.addEventListener("run-status", (e: MessageEvent) => {
      const r: Run = JSON.parse(e.data);
      setRun(r);
      if (r.status === "completed") es.close();
    });
    return () => es.close();
  }, [id]);

  // Governance Agent has run by "completed" or "paused_governance_review" (it
  // runs before that gate) — either way there's a full layer1..governance
  // shape available. Still-running or paused-at-ontology-review runs haven't
  // computed that far yet, so don't bother fetching (would 409).
  const readyForFullResult = run?.status === "completed" || run?.status === "paused_governance_review";

  useEffect(() => {
    if (typeof id !== "string") return;
    fetchIncidentLinks(id).then(setLinks).catch(() => setLinks(null));
  }, [id, readyForFullResult]);

  useEffect(() => {
    if (typeof id !== "string" || !readyForFullResult) return;
    fetchIncidentResult(id).then((result) => {
      setData(result);
      if (result.triage.suppressed) {
        fetchSuppressions().then((items) => setSuppressionLease(items.find((item) => item.run_id === id) ?? null));
      }
    }).catch(() => setData(null));
  }, [id, readyForFullResult]);

  useEffect(() => {
    if (!run) return;
    if (run.status === "paused_ontology_review") {
      fetchOntologyQueue().then((items) => setOntologyItem(items.find((i) => i.run_id === run.run_id) ?? null));
      setGovernanceItem(null);
      setScoreReviewItem(null);
    } else if (run.status === "paused_score_review") {
      fetchScoreReviewQueue().then((items) => {
        const item = items.find((i) => i.run_id === run.run_id) ?? null;
        setScoreReviewItem(item);
        if (item) {
          const reasoning = safeParse(item.reasoning_json);
          if (reasoning?.actionTier) setReviewTier(reasoning.actionTier);
        }
      });
      setOntologyItem(null);
      setGovernanceItem(null);
    } else if (run.status === "paused_governance_review") {
      fetchGovernanceQueue().then((items) => setGovernanceItem(items.find((i) => i.run_id === run.run_id) ?? null));
      setOntologyItem(null);
      setScoreReviewItem(null);
    } else {
      setOntologyItem(null);
      setGovernanceItem(null);
      setScoreReviewItem(null);
    }
  }, [run?.status, run?.run_id]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3000);
    return () => clearTimeout(t);
  }, [toast]);

  async function handleOntologyDecision(action: "approve" | "reject") {
    if (!ontologyItem) return;
    setResolving(true);
    await resolveOntologyItem(ontologyItem.item_id, action, { resolved_by: "demo-reviewer" });
    setToast(action === "approve" ? "Category approved — run resuming" : "Rejected — proceeding with best-available category");
    setOntologyItem(null);
    setResolving(false);
  }

  async function handleGovernanceDecision(action: "approve" | "reject") {
    if (!governanceItem) return;
    setResolving(true);
    await resolveGovernanceItem(governanceItem.item_id, action, { resolved_by: "demo-reviewer" });
    setToast(action === "approve" ? "Approved — auto-closing" : "Rejected — blocked pending policy review");
    setGovernanceItem(null);
    setResolving(false);
  }

  async function handleScoreReview(action: "confirm" | "reclassify") {
    if (!scoreReviewItem) return;
    setResolving(true);
    await resolveScoreReviewItem(scoreReviewItem.item_id, action, {
      resolved_by: "demo-reviewer",
      resolution_note: action === "confirm" ? "Structured evidence reviewed; calculated decision confirmed." : "Human reclassification after evidence review.",
      selected_tier: action === "reclassify" ? reviewTier : undefined,
    });
    setToast(action === "confirm" ? "Score confirmed — run resuming" : `Reclassified to ${reviewTier} — run resuming`);
    setScoreReviewItem(null);
    setResolving(false);
  }

  async function handleSuppressionReopen() {
    if (!suppressionLease) return;
    setResolving(true);
    try {
      const reopened = await reopenSuppression(suppressionLease.run_id, "demo-context-change");
      setToast("Suppression revoked — finding is being re-evaluated against current context");
      await router.push(`/review/${reopened.successorRunId}`);
    } finally {
      setResolving(false);
    }
  }

  if (!run) {
    return (
      <AppShell activeNav="review">
        <div className="sub">Loading finding...</div>
      </AppShell>
    );
  }

  const routeId = typeof id === "string" ? id : run.run_id;
  const finding = safeParse(run.finding_json);
  const elapsedMs = (run.completed_at ? new Date(run.completed_at).getTime() : Date.now()) - new Date(run.created_at).getTime();
  const newestEventId = events.length ? events[events.length - 1].event_id : -1;
  const remediationActionLabel = !data
    ? "View remediation"
    : data.verification.verifiedClosed
      ? "View closure evidence"
      : run.status === "paused_governance_review" || data.governance.approvalStatus === "pending human approval"
        ? "Review remediation plan"
        : "View remediation";

  return (
    <AppShell activeNav="review">
      <div className="topbar">
        <div>
          <Link href="/dashboard#findings" className="back-link">
            &larr; back to queue
          </Link>
          <h1 style={{ marginTop: 8 }}>{finding?.name ?? sourceLabel(run.incident_source, finding?.discoveredBy)}</h1>
          <div className="sub">
            {finding?.cve} &middot; {finding?.affectedComponent} &middot; {sourceLabel(run.incident_source, finding?.discoveredBy)}
            {links?.repoUrl && (
              <>
                {" "}&middot;{" "}
                <a href={links.repoUrl} target="_blank" rel="noreferrer" className="repo-link">
                  {links.repo} &#8599;
                </a>
              </>
            )}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div className="badge-row" style={{ justifyContent: "flex-end" }}>
            <span className={`badge ${statusBadgeClass(run.status)}`}>{statusLabel(run.status)}</span>
            {data && <span className={`tier-badge ${tierClass(data.layer2.actionTier)}`}>{data.layer2.actionTier}</span>}
          </div>
          <div className="sub" style={{ marginTop: 6 }}>
            {(elapsedMs / 1000).toFixed(1)}s elapsed{run.final_status ? ` · ${run.final_status}` : ""}
          </div>
        </div>
      </div>

      {ontologyItem && (
        <div className="queue-panel">
          <div className="field-label">Ontology review — low-confidence category match</div>
          {(() => {
            const candidate = JSON.parse(ontologyItem.candidate_category_json);
            return (
              <>
                <div style={{ fontWeight: 600, marginTop: 6 }}>{candidate.name}</div>
                <div className="sub" style={{ marginTop: 4 }}>{candidate.definition_text}</div>
                <div className="sub" style={{ marginTop: 8, fontStyle: "italic" }}>{candidate.rationale}</div>
              </>
            );
          })()}
          <div className="action-btn-row">
            <button className="action-btn primary" disabled={resolving} onClick={() => handleOntologyDecision("approve")}>
              Approve new category
            </button>
            <button className="action-btn" disabled={resolving} onClick={() => handleOntologyDecision("reject")}>
              Reject — use best available
            </button>
          </div>
        </div>
      )}

      {governanceItem && (
        <div className="queue-panel">
          <div className="field-label">Governance review — {governanceItem.reason === "blocked" ? "policy check failed" : "pending human approval"}</div>
          {(() => {
            const details = JSON.parse(governanceItem.details_json);
            return (
              <div className="sub" style={{ marginTop: 6 }}>
                {details.provenanceWhy}
              </div>
            );
          })()}
          <div className="action-btn-row">
            <button className="action-btn primary" disabled={resolving} onClick={() => handleGovernanceDecision("approve")}>
              Approve controlled execution
            </button>
            <button className="action-btn" disabled={resolving} onClick={() => handleGovernanceDecision("reject")}>
              Reject — block
            </button>
          </div>
        </div>
      )}

      {scoreReviewItem && (() => {
        const assessment = safeParse(scoreReviewItem.assessment_json);
        const reasoning = safeParse(scoreReviewItem.reasoning_json);
        return (
          <div className="queue-panel" style={{ borderColor: "var(--tier-1)" }}>
            <div className="field-label">Human score review — AI advisory found a decision-quality concern</div>
            <div className="decision-strip" style={{ marginTop: 12 }}>
              <div className="decision-card"><div className="decision-label">Calculated score</div><div className="decision-value">{reasoning?.riskPriority}</div></div>
              <div className="decision-card"><div className="decision-label">Current final tier</div><div className="decision-value small">{reasoning?.actionTier}</div></div>
              <div className="decision-card"><div className="decision-label">AI assessment</div><div className="decision-value small">{assessment?.assessment}</div></div>
              <div className="decision-card"><div className="decision-label">Authority</div><div className="decision-value small">Human decision</div></div>
            </div>
            {(assessment?.concerns || []).map((concern: string) => <div className="kv" key={concern}>• {concern}</div>)}
            <div className="field-group" style={{ maxWidth: 240, marginTop: 12 }}>
              <label className="field-label">Reclassified tier</label>
              <select className="field-select" value={reviewTier} onChange={(e) => setReviewTier(e.target.value as typeof reviewTier)}>
                <option>Tier 0</option><option>Tier 1</option><option>Tier 2</option><option>Tier 3</option>
              </select>
            </div>
            <div className="action-btn-row">
              <button className="action-btn primary" disabled={resolving} onClick={() => handleScoreReview("confirm")}>Confirm calculated decision</button>
              <button className="action-btn" disabled={resolving} onClick={() => handleScoreReview("reclassify")}>Reclassify and resume</button>
            </div>
          </div>
        );
      })()}

      {data && (
        <div className="section">
          <div className="decision-strip">
            <div className="decision-card">
              <div className="decision-label">Evidence quality</div>
              <div className="decision-value small">{evidenceQualityLabel(data.dataQuality.fieldStatus)}</div>
              <div className="sub">{Math.round(data.dataQuality.completenessScore * 100)}% complete &middot; {data.dataQuality.decision}</div>
            </div>
            <div className="decision-card">
              <div className="decision-label">Governed model</div>
              <div className="decision-value small">{data.layer2.riskModelVersion}</div>
              <div className="sub">Calculated {data.layer2.calculatedRiskPriority} &middot; {data.layer2.calculatedActionTier}</div>
            </div>
            <div className="decision-card">
              <div className="decision-label">Final policy decision</div>
              <div className={`decision-value ${tierClass(data.layer2.actionTier)}`}>{data.layer2.actionTier}</div>
              <div className="sub">{data.layer2.policyOverrides.length ? "Explicit override applied" : "Calculated tier retained"}</div>
            </div>
            <div className="decision-card">
              <div className="decision-label">Decision assurance</div>
              <div className="decision-value small">{data.plausibility.assessment}</div>
              <div className="sub">
                {data.plausibility.advisoryMode === "anthropic" ? "Anthropic advisory" : "Deterministic fallback"}
                {" "}&middot; cannot change the decision
              </div>
            </div>
          </div>
          <div className="panel" style={{ display: "flex", gap: 20, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ fontFamily: "var(--mono)", fontSize: 36, fontWeight: 700, color: "var(--accent)" }}>
              {data.layer2.riskPriority}
            </div>
            <div style={{ flex: 1, minWidth: 220 }}>
              <div className="badge-row">
                {data.finding.cisaKev && <span className="badge fail">KEV active-exploit</span>}
                <span className="badge">CVSS {data.finding.cvssBase.toFixed(1)}</span>
                {data.triage.suppressed && <span className="badge">suppressed</span>}
                {data.finding.demoScenario === "sandbox-failure" && <span className="badge fail">SAFE-FAILURE SCENARIO</span>}
              </div>
              {data.layer2.policyOverrides.map((override) => (
                <div className="sub" style={{ marginTop: 6 }} key={override}><strong>Policy override:</strong> {override}</div>
              ))}
              <div className="sub" style={{ marginTop: 6 }}>
                Modeled blast radius: {data.layer2.blastRadius} findings across {data.layer1.services.length} apps &middot;{" "}
                {data.layer1.services.some((s) => s.internetExposed) ? "internet-exposed" : "internal only"}
              </div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 12, color: "var(--muted)", marginTop: 8 }}>
                {data.routePath.join("  ->  ")}
              </div>
            </div>
            {data.triage.suppressed ? (
              <div style={{ textAlign: "right" }}>
                <div className="sub">
                  Revocable until {suppressionLease ? new Date(suppressionLease.expires_at).toLocaleDateString() : "lease loads"}
                </div>
                <button className="action-btn primary" disabled={!suppressionLease || resolving} onClick={handleSuppressionReopen}>
                  {resolving ? "Reopening…" : "Reopen on context change"}
                </button>
              </div>
            ) : (
              <Link href={`/remediation/${routeId}`} className="action-btn primary">
                {remediationActionLabel} &rarr;
              </Link>
            )}
          </div>
        </div>
      )}

      <div className="section">
        <h2>Pipeline timeline</h2>
        <div className="timeline">
          {events.map((ev) => {
            const output = safeParse(ev.output_snapshot);
            return (
              <div key={ev.event_id} className={`timeline-entry ${ev.finished_at ? "done" : ""} ${ev.event_id === newestEventId ? "newest" : ""}`}>
                <span className="timeline-node-name">{friendlyNodeLabel(ev.node_name)}</span>
                {ev.duration_ms != null && <span className="timeline-duration">{ev.duration_ms.toFixed(1)}ms</span>}
                <div className="timeline-explain">{describeNode(ev.node_name, ev.output_snapshot)}</div>
                <div>
                  <button
                    className="timeline-json-toggle"
                    onClick={() => setExpanded((e) => ({ ...e, [ev.event_id]: !e[ev.event_id] }))}
                  >
                    {expanded[ev.event_id] ? "hide" : "show"} details
                  </button>
                </div>
                {expanded[ev.event_id] && (
                  <div className="timeline-detail">
                    <NodeDetail output={output} />
                    <button
                      className="timeline-json-toggle"
                      style={{ marginTop: 8 }}
                      onClick={() => setRawShown((r) => ({ ...r, [ev.event_id]: !r[ev.event_id] }))}
                    >
                      {rawShown[ev.event_id] ? "hide" : "view"} raw JSON
                    </button>
                    {rawShown[ev.event_id] && (
                      <div className="timeline-json">
                        --- input ---{"\n"}
                        {prettyJson(ev.input_snapshot)}
                        {"\n\n"}--- output ---{"\n"}
                        {prettyJson(ev.output_snapshot) || "(pending)"}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {toast && <div className="toast">{toast}</div>}
    </AppShell>
  );
}
