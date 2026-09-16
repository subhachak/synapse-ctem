import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import AppShell from "../components/AppShell";
import BarChart from "../components/charts/BarChart";
import DonutChart from "../components/charts/DonutChart";
import {
  createIncident,
  fetchFindings,
  fetchIncidents,
  fetchIncidentResults,
  fetchKpis,
  fetchServices,
  resetDemo,
  sourceLabel,
  CustomIncidentPayload,
  FindingPipelineResult,
  FindingSummary,
  KpiSummary,
  Run,
  ServiceSummary,
} from "../lib/api";

const CUSTOM_SOURCE_OPTIONS = [
  "Manual Entry — SOC Analyst",
  "Qualys VMDR",
  "Tenable.io",
  "Snyk",
  "GitHub Dependabot",
  "CrowdStrike Falcon Spotlight",
];

const TIER_COLORS: Record<string, string> = {
  "Tier 0": "var(--tier-0)",
  "Tier 1": "var(--tier-1)",
  "Tier 2": "var(--tier-2)",
  "Tier 3": "var(--tier-3)",
};

const EXPOSURE_FUNNEL = [
  { label: "Detected findings", value: "1,844", note: "Illustrative baseline" },
  { label: "Open after remediation", value: "773", note: "Reconciled population" },
  { label: "Runtime reachable", value: "37", note: "Modeled demo subset" },
  { label: "Urgent attack paths", value: "12", note: "Decision queue" },
  { label: "Governance action", value: "1", note: "Staged now" },
];

function safeParse(raw: string | null): any {
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function tierClass(tier: string | null) {
  if (tier === "Tier 0") return "tier-0";
  if (tier === "Tier 1") return "tier-1";
  if (tier === "Tier 2") return "tier-2";
  if (tier === "Tier 3") return "tier-3";
  return "";
}

// Synthetic 30-day risk-posture trend — no historical time-series data exists
// in this demo yet, only a point-in-time snapshot per finding. Shape is
// illustrative (gentle rise, spike on the most recent day) to match the
// wireframe; it is not derived from real data.
function buildSyntheticTrend(latestValue: number) {
  const shape = [0.5, 0.62, 0.55, 0.7, 0.66, 0.8, 0.74, 1];
  return shape.map((f, i) => ({ label: `d-${(shape.length - i) * 4}`, value: Math.max(1, latestValue * f) }));
}

function runStatusClass(status: string) {
  if (status === "running") return "running";
  if (status.startsWith("paused_")) return "paused";
  return "pass";
}

function runStatusLabel(status: string) {
  if (status === "running") return "Running";
  if (status === "paused_ontology_review") return "Paused — Ontology Review";
  if (status === "paused_score_review") return "Paused — Score Review";
  if (status === "paused_governance_review") return "Paused — Governance Review";
  if (status === "completed") return "Completed";
  return status;
}

function dashboardAction(run: Run, result?: FindingPipelineResult): { label: string; href: string } {
  const reviewHref = `/review/${run.run_id}`;
  if (run.status === "running") return { label: "View live pipeline", href: reviewHref };
  if (run.status === "paused_ontology_review") return { label: "Review category", href: reviewHref };
  if (run.status === "paused_score_review") return { label: "Review score", href: reviewHref };
  if (run.status === "paused_governance_review") return { label: "Review approval", href: reviewHref };
  if (result?.triage.suppressed) return { label: "View decision", href: reviewHref };
  if (result?.verification.verifiedClosed) {
    return { label: "View closure evidence", href: `/remediation/${run.run_id}` };
  }
  if (result?.verification.status === "failed") {
    return { label: "Review failure", href: `/remediation/${run.run_id}` };
  }
  return { label: "View result", href: reviewHref };
}

const DEFAULT_CUSTOM: CustomIncidentPayload = {
  component: "",
  severity: "Medium",
  epss: 0.3,
  cisaKev: false,
  runtimeReachable: false,
  affectedServiceIds: [],
  source: CUSTOM_SOURCE_OPTIONS[0],
  simulateSandboxFailure: false,
};

export default function Dashboard() {
  const router = useRouter();
  const [kpis, setKpis] = useState<KpiSummary | null>(null);
  const [results, setResults] = useState<FindingPipelineResult[]>([]);
  const [loading, setLoading] = useState(true);

  const [findingsList, setFindingsList] = useState<FindingSummary[]>([]);
  const [servicesList, setServicesList] = useState<ServiceSummary[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [injectOpen, setInjectOpen] = useState(false);
  const [mode, setMode] = useState<"preset" | "custom">("preset");
  const [selectedPreset, setSelectedPreset] = useState("");
  const [custom, setCustom] = useState<CustomIncidentPayload>(DEFAULT_CUSTOM);
  const [injecting, setInjecting] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [injectError, setInjectError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([fetchKpis(), fetchIncidentResults()]).then(([k, r]) => {
      setKpis(k);
      setResults(r.sort((a, b) => b.layer2.riskPriority - a.layer2.riskPriority));
      setLoading(false);
    });
  }, []);

  // Command-line/API injections enter the same run store as UI-created
  // incidents. Refresh the derived dashboard data whenever the polled run
  // set changes so externally injected cases update KPIs and charts too.
  const runCompletionSignature = runs.map((run) => `${run.run_id}:${run.status}`).join("|");
  useEffect(() => {
    if (!runCompletionSignature) return;
    Promise.all([fetchKpis(), fetchIncidentResults()]).then(([k, r]) => {
      setKpis(k);
      setResults(r.sort((a, b) => b.layer2.riskPriority - a.layer2.riskPriority));
    });
  }, [runCompletionSignature]);

  useEffect(() => {
    fetchFindings().then((list) => {
      setFindingsList(list);
      if (list.length) setSelectedPreset(list[0].id);
    });
    fetchServices().then(setServicesList);
  }, []);

  // Live incidents: poll every 2s while any run is non-terminal, back off when idle.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      const r = await fetchIncidents().catch(() => []);
      if (cancelled) return;
      setRuns(r);
      const active = r.some((run) => run.status !== "completed");
      timer = setTimeout(poll, active ? 2000 : 8000);
    }
    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, []);

  function toggleService(id: string) {
    setCustom((c) => ({
      ...c,
      affectedServiceIds: c.affectedServiceIds.includes(id)
        ? c.affectedServiceIds.filter((x) => x !== id)
        : [...c.affectedServiceIds, id],
    }));
  }

  async function handleInject() {
    setInjecting(true);
    setInjectError(null);
    try {
      const payload = mode === "preset" ? { preset: selectedPreset } : { custom };
      const { run_id } = await createIncident(payload);
      router.push(`/review/${run_id}`);
    } catch {
      setInjectError("Could not start the incident — is the backend running?");
      setInjecting(false);
    }
  }

  async function handleReset() {
    if (!window.confirm("Reset the demo to bootstrap? This wipes every injected incident, queue item, and curated category — cannot be undone.")) {
      return;
    }
    setResetting(true);
    try {
      await resetDemo();
      window.location.reload();
    } catch {
      setInjectError("Could not reset the demo — is the backend running?");
      setResetting(false);
    }
  }

  const openFindings = results.length;
  const criticalCount = results.filter((r) => r.layer2.actionTier === "Tier 0").length;

  const tierCounts = ["Tier 0", "Tier 1", "Tier 2", "Tier 3"].map((tier) => ({
    label: tier,
    value: results.filter((r) => r.layer2.actionTier === tier).length,
    color: TIER_COLORS[tier],
  }));

  const trend = buildSyntheticTrend(openFindings || 1);

  return (
    <AppShell activeNav="dashboard">
      <div className="topbar">
        <div>
          <h1>Dashboard</h1>
          <div className="sub">Risk posture &middot; findings queue &middot; trends</div>
        </div>
      </div>

      <div className="demo-disclosure">
        <span className="badge">PRESENTATION MODE</span>
        Illustrative population figures and typed simulated connectors are used to demonstrate the operating model.
        Live enterprise integrations are not connected.
      </div>

      <div className="section">
        <div className="section-heading-row">
          <div>
            <h2>From scanner volume to governed action</h2>
            <div className="sub">The CTEM value story is reduction and correlation—not seven agents processing seven isolated rows.</div>
          </div>
          <span className="badge">ILLUSTRATIVE DEMO DATA</span>
        </div>
        <div className="exposure-funnel">
          {EXPOSURE_FUNNEL.map((stage, index) => (
            <div className="funnel-stage" key={stage.label}>
              <div className="funnel-value">{stage.value}</div>
              <div className="funnel-label">{stage.label}</div>
              <div className="funnel-note">{stage.note}</div>
              {index < EXPOSURE_FUNNEL.length - 1 && <span className="funnel-arrow">&rarr;</span>}
            </div>
          ))}
        </div>
      </div>

      {injectOpen && (
        <div className="panel inject-panel">
          <div className="field-group">
            <label className="field-label">Source</label>
            <div className="tier-picker">
              <button
                type="button"
                className={`tier-pick-btn ${mode === "preset" ? "selected" : ""}`}
                onClick={() => setMode("preset")}
              >
                Seed preset
              </button>
              <button
                type="button"
                className={`tier-pick-btn ${mode === "custom" ? "selected" : ""}`}
                onClick={() => setMode("custom")}
              >
                Custom
              </button>
            </div>
          </div>

          {mode === "preset" ? (
            <div className="field-group">
              <label className="field-label">Finding</label>
              <select className="field-select" value={selectedPreset} onChange={(e) => setSelectedPreset(e.target.value)}>
                {findingsList.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.name} — {f.cve} ({f.severity})
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <>
              <div className="field-row">
                <div className="field-group">
                  <label className="field-label">Component</label>
                  <input
                    className="field-input"
                    value={custom.component}
                    onChange={(e) => setCustom({ ...custom, component: e.target.value })}
                    placeholder="e.g. libxml2 (XML parsing)"
                  />
                </div>
                <div className="field-group">
                  <label className="field-label">Source</label>
                  <select
                    className="field-select"
                    value={custom.source}
                    onChange={(e) => setCustom({ ...custom, source: e.target.value })}
                  >
                    {CUSTOM_SOURCE_OPTIONS.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="field-row">
                <div className="field-group">
                  <label className="field-label">CVE (optional)</label>
                  <input
                    className="field-input"
                    value={custom.cve ?? ""}
                    onChange={(e) => setCustom({ ...custom, cve: e.target.value })}
                    placeholder="N/A (custom)"
                  />
                </div>
              </div>
              <div className="field-row">
                <div className="field-group">
                  <label className="field-label">Severity</label>
                  <select
                    className="field-select"
                    value={custom.severity}
                    onChange={(e) => setCustom({ ...custom, severity: e.target.value as CustomIncidentPayload["severity"] })}
                  >
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>
                </div>
                <div className="field-group">
                  <label className="field-label">CVSS base (optional)</label>
                  <input
                    className="field-input"
                    type="number"
                    min={0}
                    max={10}
                    step={0.1}
                    value={custom.cvssBase ?? ""}
                    onChange={(e) => setCustom({ ...custom, cvssBase: e.target.value === "" ? undefined : Number(e.target.value) })}
                    placeholder="Inferred if blank"
                  />
                </div>
                <div className="field-group">
                  <label className="field-label">EPSS</label>
                  <input
                    className="field-input"
                    type="number"
                    min={0}
                    max={1}
                    step={0.01}
                    value={custom.epss}
                    onChange={(e) => setCustom({ ...custom, epss: Number(e.target.value) })}
                  />
                </div>
              </div>
              <div className="toggle-row">
                <label className="field-label">CISA KEV listed</label>
                <button
                  type="button"
                  className={`toggle ${custom.cisaKev ? "on" : ""}`}
                  onClick={() => setCustom({ ...custom, cisaKev: !custom.cisaKev })}
                >
                  <span className="toggle-knob" />
                </button>
              </div>
              <div className="toggle-row">
                <label className="field-label">Runtime reachable</label>
                <button
                  type="button"
                  className={`toggle ${custom.runtimeReachable ? "on" : ""}`}
                  onClick={() => setCustom({ ...custom, runtimeReachable: !custom.runtimeReachable })}
                >
                  <span className="toggle-knob" />
                </button>
              </div>
              <div className="toggle-row">
                <label className="field-label">Safe-failure scenario</label>
                <button
                  type="button"
                  className={`toggle ${custom.simulateSandboxFailure ? "on" : ""}`}
                  onClick={() => setCustom({ ...custom, simulateSandboxFailure: !custom.simulateSandboxFailure })}
                >
                  <span className="toggle-knob" />
                </button>
                <span className="sub">Fail the sandbox contract test and prove deployment is blocked.</span>
              </div>
              <div className="field-group">
                <label className="field-label">Affected services</label>
                <div className="chip-toggle-row">
                  {servicesList.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      className={`chip-toggle ${custom.affectedServiceIds.includes(s.id) ? "selected" : ""}`}
                      onClick={() => toggleService(s.id)}
                    >
                      {s.name}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}

          {injectError && <div className="demo-error">{injectError}</div>}
          <div className="action-btn-row">
            <button
              className="action-btn primary"
              onClick={handleInject}
              disabled={injecting || (mode === "preset" ? !selectedPreset : !custom.component || custom.affectedServiceIds.length === 0)}
            >
              {injecting ? "Injecting…" : "Inject & Start"}
            </button>
          </div>
        </div>
      )}

      <div className="section" id="findings">
        <h2>Findings</h2>
        <div className="sub" style={{ marginBottom: 10 }}>
          Every finding runs through the same pipeline, seeded or imported — one queue, no
          distinction once it's running.
        </div>
        {runs.length === 0 ? (
          <div className="sub">No findings yet — the 7 seed findings bootstrap shortly after the backend starts.</div>
        ) : (
          <table className="findings">
            <thead>
              <tr>
                <th>Title</th>
                <th>Source <span className="badge">SIMULATED</span></th>
                <th>Tier</th>
                <th>Risk Priority</th>
                <th>Owner</th>
                <th>Status</th>
                <th>Started</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => {
                const parsedFinding = safeParse(r.finding_json);
                const result = results.find((item) => item.runId === r.run_id);
                const action = dashboardAction(r, result);
                return (
                <tr key={r.run_id}>
                  <td>{parsedFinding?.name ?? r.incident_source}</td>
                  <td>{sourceLabel(r.incident_source, parsedFinding?.discoveredBy)}</td>
                  <td>{r.actionTier ? <span className={`tier-badge ${tierClass(r.actionTier)}`}>{r.actionTier}</span> : "—"}</td>
                  <td style={{ fontFamily: "var(--mono)" }}>{r.riskPriority ?? "—"}</td>
                  <td>{r.ownerName ?? "—"}</td>
                  <td>
                    <span className={`badge ${runStatusClass(r.status)}`}>{runStatusLabel(r.status)}</span>
                    {r.final_status && <span className="sub" style={{ marginLeft: 8 }}>{r.final_status}</span>}
                  </td>
                  <td style={{ fontSize: 12, color: "var(--muted)" }}>{new Date(r.created_at).toLocaleTimeString()}</td>
                  <td>
                    <Link href={action.href} className="action-btn primary">
                      {action.label} &rarr;
                    </Link>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="kpi-grid">
        <div className="kpi-card" title="Current pipeline results returned by /api/incidents/results">
          <div className="label">Open findings</div>
          <div className="value">{loading ? "…" : openFindings}</div>
          <div className="kpi-source">Measured &middot; workflow state</div>
        </div>
        <div className="kpi-card" title="Final policy tier after explicit overrides">
          <div className="label">Critical &middot; Tier 0</div>
          <div className="value" style={{ color: "var(--tier-0)" }}>
            {loading ? "…" : criticalCount}
          </div>
          <div className="kpi-source">Measured &middot; governed model</div>
        </div>
        <div className="kpi-card" title="Tier 0/1 cases that are not automatically approved">
          <div className="label">SLA at risk</div>
          <div className="value" style={{ color: "var(--tier-1)" }}>
            {loading || !kpis ? "…" : kpis.slaAtRiskCount}
          </div>
          <div className="kpi-source">Measured &middot; policy state</div>
        </div>
        <div className="kpi-card" title="Requires sandbox, deployment, rescan, and runtime-path evidence">
          <div className="label">Verified closed</div>
          <div className="value" style={{ color: "var(--accent)" }}>
            {loading || !kpis ? "…" : kpis.verifiedClosedCount}
          </div>
          <div className="kpi-source">Measured &middot; simulated evidence</div>
        </div>
      </div>

      <div className="chart-row">
        <div className="chart-panel">
          <h3 className="chart-title-with-badge">
            <span>Risk posture — 30-day trend</span>
            <span className="badge">ILLUSTRATIVE</span>
          </h3>
          <BarChart data={trend} />
          <div className="bar-chart-note">Synthetic trend — no historical time-series data yet, illustrative only</div>
        </div>
        <div className="chart-panel">
          <h3>Open by tier</h3>
          <DonutChart segments={tierCounts} />
        </div>
      </div>

    </AppShell>
  );
}
