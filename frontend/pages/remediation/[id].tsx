import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import Link from "next/link";
import AppShell from "../../components/AppShell";
import {
  AgentStep,
  AgentTrace,
  assignRemediationOwner,
  fetchAgentTrace,
  fetchIncidentResult,
  fetchOwners,
  fetchRemediation,
  FindingPipelineResult,
  OwnerSummary,
  RemediationDetail,
  retryRemediation,
} from "../../lib/api";

const STEPS = ["Plan", "Assign", "Approve", "Execute", "Verify"];

function deriveStep(state: string): number {
  if (state === "verified_closed") return 5;
  if (["sandbox_validating", "sandbox_failed"].includes(state)) return 3;
  if (state === "deployed") return 4;
  if (["awaiting_approval", "blocked"].includes(state)) return 2;
  if (state === "implementation_drafted") return 1;
  return 0;
}

export default function RemediationWorkflow() {
  const router = useRouter();
  const { id } = router.query;
  const [data, setData] = useState<FindingPipelineResult | null>(null);
  const [owners, setOwners] = useState<OwnerSummary[]>([]);
  const [remediation, setRemediation] = useState<RemediationDetail | null>(null);
  const [trace, setTrace] = useState<AgentTrace | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  useEffect(() => {
    if (typeof id === "string") {
      fetchIncidentResult(id).then(setData);
      fetchRemediation(id).then(setRemediation).catch(() => setRemediation(null));
      fetchAgentTrace(id).then(setTrace).catch(() => setTrace(null));
    }
    fetchOwners().then(setOwners).catch(() => setOwners([]));
  }, [id]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 2500);
    return () => clearTimeout(t);
  }, [toast]);

  if (!data || !remediation) {
    return (
      <AppShell activeNav="remediation">
        <div className="sub">Loading remediation plan...</div>
      </AppShell>
    );
  }

  const { finding, layer1, planning, implementation, verification } = data;
  // The real remediation PR, surfaced at the top of the evidence section for
  // one-click navigation during the demo (also shown on its own evidence card).
  const prUrl = verification.evidence.find((e) => e.evidenceType === "deployment-proof" && e.prUrl)?.prUrl || "";
  const currentStep = deriveStep(remediation.case.state);
  // Route id (a run UUID) uniquely identifies this run, unlike finding.id —
  // the same seed finding can be injected live more than once, and
  // finding.id alone would collide across those runs.
  const routeId = typeof id === "string" ? id : finding.id;
  const ticketId = remediation.case.ticket_id;
  const breakingChangeRisk = planning.predictedBreakingChanges.length > 0 ? "Elevated" : "Low";

  const fixPlanItems = [
    planning.targetVersionOrConfig, // the concrete change (e.g. the exact dependency bump)
    planning.fixApproach,
    ...planning.compensatingControls,
    ...planning.predictedBreakingChanges.map((c) => `Coordinated change: ${c}`),
  ].filter((item) => item && item.toLowerCase() !== "n/a");

  async function handleOwnerChange(ownerId: string) {
    if (typeof id !== "string") return;
    await assignRemediationOwner(id, ownerId);
    setRemediation(await fetchRemediation(id));
    setToast("Owner assignment persisted");
  }

  async function handleRetry() {
    if (typeof id !== "string") return;
    await retryRemediation(id);
    setRemediation(await fetchRemediation(id));
    setToast("Returned to planning for correction");
  }

  return (
    <AppShell activeNav="remediation">
      <div className="topbar">
        <div>
          <Link href={`/review/${routeId}`} className="back-link">
            &larr; back to review
          </Link>
          <h1 style={{ marginTop: 8 }}>Remediation workflow</h1>
          <div className="sub">{finding.name}</div>
        </div>
      </div>

      <div className="demo-disclosure">
        <span className="badge">CONTROLLED EXECUTION</span>
        Generated plans are not proof of execution. Closure requires sandbox, deployment, rescan, and runtime-path evidence.
      </div>

      {verification.status === "failed" && (
        <div className="queue-panel" style={{ borderColor: "var(--tier-0)" }}>
          <div className="field-label">Safe failure — production deployment blocked</div>
          <div className="sub" style={{ marginTop: 5 }}>
            A sandbox contract test failed. Downstream deployment, rescan, and runtime closure were not run, and the case remains open.
          </div>
        </div>
      )}

      <div className="stepper">
        {STEPS.map((label, i) => (
          <div key={label} className={`stepper-step ${i < currentStep ? "done" : i === currentStep ? "current" : ""}`}>
            <div className="stepper-circle">{i + 1}</div>
            <div className="stepper-label">{label}</div>
          </div>
        ))}
      </div>

      {trace && <AgentOrchestrationPanel trace={trace} />}

      <div className="two-col">
        <div className="section">
          <h2>Fix plan</h2>
          <div className="panel">
            <ul className="checklist">
              {fixPlanItems.map((item, i) => (
                <li key={i}>
                  <span className="check-icon">&#10003;</span> {item}
                </li>
              ))}
            </ul>

            {planning.validationPlan && planning.validationPlan.length > 0 && (
              <div className="field-group" style={{ marginTop: 16 }}>
                <label className="field-label">Validation gate — how closure is proven</label>
                <ul className="checklist gate">
                  {planning.validationPlan.map((item, i) => (
                    <li key={i}>
                      <span className="check-icon gate">&#9670;</span> {item}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="field-group" style={{ marginTop: 16 }}>
              <label className="field-label">Owner</label>
              <select className="field-select" value={remediation.case.owner_id} onChange={(e) => handleOwnerChange(e.target.value)}>
                <option value={planning.routedOwnerId}>
                  {layer1.owner.name} ({layer1.owner.team})
                </option>
                {owners.filter((o) => o.id !== planning.routedOwnerId).map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name} ({o.team})
                  </option>
                ))}
              </select>
            </div>

            <div className="badge-row">
              <span className="badge">Effort: {planning.effortEstimate}</span>
              <span className={`badge ${breakingChangeRisk === "Low" ? "pass" : "fail"}`}>
                Breaking-change risk: {breakingChangeRisk}
              </span>
            </div>
          </div>
        </div>

        <div className="section">
          <h2>Ticket &amp; guardrails</h2>
          <div className="panel">
            <div className="kv">
              <span className="k">ServiceNow:</span> {ticketId} <span className="badge">SIMULATED ADAPTER</span>
            </div>
            <div className="sub" style={{ marginBottom: 12 }}>
              {layer1.services.length} apps &middot; illustrative change window: 72h &middot; non-prod first
            </div>

            <div className="field-label">Guardrails</div>
            <ul className="checklist">
              <li>
                <span className="check-icon">{implementation.sandboxedExecution ? "✓" : "✗"}</span> Sandboxed
                execution
              </li>
              <li>
                <span className="check-icon">{implementation.noProdDataOrSecrets ? "✓" : "✗"}</span> Never
                touches prod secrets
              </li>
              <li>
                <span className="check-icon">{implementation.humanInTheLoop ? "✓" : "✗"}</span> Human-in-the-loop
                approval
              </li>
            </ul>

            <div className="kv" style={{ marginTop: 12 }}>
              <span className="k">Authorization:</span>{" "}
              {remediation.case.authorization}
            </div>
            <div className="kv"><span className="k">Persisted state:</span> {remediation.case.state.replaceAll("_", " ")}</div>
            {remediation.case.last_error && <div className="kv"><span className="badge fail">BLOCKED</span> {remediation.case.last_error}</div>}
            <div className="sub">Execution controls are recorded by the backend workflow; this screen does not issue untracked actions.</div>
            {remediation.case.state === "sandbox_failed" && (
              <div className="action-btn-row"><button className="action-btn primary" onClick={handleRetry}>Return to planning</button></div>
            )}
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Persisted remediation timeline</h2>
        <div className="timeline">
          {remediation.transitions.map((transition) => (
            <div className="timeline-entry done" key={transition.transition_id}>
              <span className="timeline-node-name">{transition.to_state.replaceAll("_", " ")}</span>
              <div className="timeline-explain">{transition.note || "State updated"}</div>
              <div className="sub">{transition.actor} &middot; {new Date(transition.created_at).toLocaleString()}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="section-heading-row">
          <div>
            <h2>Closure evidence</h2>
            <div className="sub">Every artifact declares whether it came from a simulated adapter or a live integration.</div>
          </div>
          <div className="badge-row" style={{ alignItems: "center" }}>
            {prUrl && (
              <a href={prUrl} target="_blank" rel="noreferrer" className="pr-link">
                View pull request &#8599;
              </a>
            )}
            <span className={`badge ${verification.verifiedClosed ? "pass" : verification.status === "failed" ? "fail" : ""}`}>
              {verification.evidenceMode} &middot; {verification.status}
            </span>
          </div>
        </div>
        <div className="evidence-grid">
          {verification.evidence.length === 0 && <div className="panel sub">No verification was run for this outcome.</div>}
          {verification.evidence.map((item) => (
            <div className="evidence-card" key={item.artifactId}>
              <div className="badge-row">
                <span className={`badge ${item.result === "pass" ? "pass" : item.result === "fail" ? "fail" : ""}`}>{item.result}</span>
                <span className={`badge ${item.source === "live-integration" ? "pass" : ""}`}>{item.source}</span>
              </div>
              <div className="evidence-title">{item.evidenceType.replaceAll("-", " ")}</div>
              <div className="sub">{item.detail}</div>
              {item.prUrl ? (
                <div className="sub">PR: <a href={item.prUrl} target="_blank" rel="noreferrer">{item.prUrl}</a></div>
              ) : null}
              {item.command ? <div className="sub" style={{ fontFamily: "monospace" }}>$ {item.command}</div> : null}
              {item.logExcerpt ? (
                <pre style={{ whiteSpace: "pre-wrap", fontSize: 11, background: "rgba(0,0,0,0.25)", padding: 8, borderRadius: 4, marginTop: 6, maxHeight: 220, overflow: "auto" }}>{item.logExcerpt}</pre>
              ) : null}
              <div className="evidence-id">{item.artifactId}</div>
            </div>
          ))}
        </div>
      </div>

      {toast && <div className="toast">{toast}</div>}
    </AppShell>
  );
}

const ROLE_META: Record<AgentStep["role"], { label: string; color: string }> = {
  orchestrator: { label: "ORCH", color: "#7c3aed" },
  scanner: { label: "SCAN", color: "#0891b2" },
  planner: { label: "PLAN", color: "#2563eb" },
  implementer: { label: "IMPL", color: "#d97706" },
  tester: { label: "TEST", color: "#059669" },
  verifier: { label: "VERIFY", color: "#059669" },
};

const STATUS_ICON: Record<AgentStep["status"], string> = {
  ok: "✓",
  info: "•",
  retry: "↻",
  fail: "✗",
};

function AgentOrchestrationPanel({ trace }: { trace: AgentTrace }) {
  const scenarioColor =
    trace.scenarioClass === "SCA" ? "#0891b2" : trace.scenarioClass === "SAST" ? "#d97706" : trace.scenarioClass === "DAST" ? "#7c3aed" : "#64748b";
  return (
    <div className="section">
      <div className="section-heading-row">
        <div>
          <h2>Agentic remediation orchestration</h2>
          <div className="sub">
            One orchestrator delegating to specialist sub-agents. Each step is tagged{" "}
            <b>deterministic</b> (a rule/lookup) or <b>agentic</b> (a model decision) — agentic execution inside
            deterministic guardrails.
          </div>
        </div>
        <span className="badge" style={{ background: scenarioColor, color: "#fff", borderColor: scenarioColor }}>
          {trace.scenarioClass}
        </span>
      </div>

      <div className="panel">
        <div className="badge-row" style={{ marginBottom: 12 }}>
          <span className="badge">strategy: {trace.strategy}</span>
          <span className={`badge ${trace.converged ? "pass" : "fail"}`}>
            {trace.converged ? "converged" : "did not converge"}
          </span>
          <span className="badge">
            attempts: {trace.attemptsUsed}/{trace.maxAttempts}
          </span>
          <span className="badge" title="The bounded self-correcting loop: on a failed validation gate an agentic strategy re-plans and retries.">
            {trace.attemptsUsed > 1 ? "self-corrected" : "single-shot"}
          </span>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {trace.steps.map((s) => {
            const meta = ROLE_META[s.role];
            const isAgentic = s.mode === "agentic";
            const statusColor =
              s.status === "fail" ? "var(--tier-0, #dc2626)" : s.status === "retry" ? "#d97706" : s.status === "info" ? "#64748b" : "#059669";
            return (
              <div
                key={s.seq}
                style={{
                  display: "grid",
                  gridTemplateColumns: "auto auto auto 1fr auto",
                  gap: 10,
                  alignItems: "center",
                  padding: "8px 10px",
                  borderRadius: 6,
                  background: "rgba(127,127,127,0.06)",
                  borderLeft: `3px solid ${meta.color}`,
                }}
              >
                <span
                  style={{
                    fontFamily: "monospace",
                    fontSize: 10,
                    fontWeight: 700,
                    color: "#fff",
                    background: meta.color,
                    padding: "2px 6px",
                    borderRadius: 4,
                    minWidth: 52,
                    textAlign: "center",
                  }}
                >
                  {meta.label}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: 0.4,
                    color: isAgentic ? "#d97706" : "#64748b",
                    border: `1px solid ${isAgentic ? "#d97706" : "#94a3b8"}`,
                    borderRadius: 4,
                    padding: "1px 5px",
                  }}
                  title={isAgentic ? "Model-driven decision/synthesis" : "Deterministic rule or lookup"}
                >
                  {isAgentic ? "AGENTIC" : "DETERMIN."}
                </span>
                <span style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace" }}>
                  #{s.attempt}
                </span>
                <span style={{ fontSize: 13 }}>
                  <b>{s.agent}</b> <span style={{ color: "#94a3b8" }}>· {s.action}</span>
                  <div className="sub" style={{ marginTop: 2 }}>{s.detail}</div>
                </span>
                <span style={{ display: "flex", gap: 8, alignItems: "center", justifySelf: "end" }}>
                  {s.llmUsed && (
                    <span className="badge" style={{ fontSize: 9 }} title="Made a real Anthropic model call">
                      LLM
                    </span>
                  )}
                  {s.durationMs > 0 && (
                    <span style={{ fontSize: 10, color: "#94a3b8", fontFamily: "monospace" }}>
                      {Math.round(s.durationMs)}ms
                    </span>
                  )}
                  <span style={{ color: statusColor, fontWeight: 700, fontSize: 15 }} title={s.status}>
                    {STATUS_ICON[s.status]}
                  </span>
                </span>
              </div>
            );
          })}
        </div>

        <div className="sub" style={{ marginTop: 12 }}>
          {trace.summary} Scoring and approval are decided elsewhere by the deterministic engine and governance
          policy — this orchestrator only executes an already-authorized fix and gathers evidence for independent
          verification.
        </div>
      </div>
    </div>
  );
}
