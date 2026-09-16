import { useEffect, useState } from "react";
import Link from "next/link";
import AppShell from "../components/AppShell";
import BarChart from "../components/charts/BarChart";
import DonutChart from "../components/charts/DonutChart";
import {
  fetchIncidents,
  fetchIncidentResults,
  fetchKpis,
  sourceLabel,
  FindingPipelineResult,
  KpiSummary,
  Run,
} from "../lib/api";

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

export default function Dashboard() {
  const [kpis, setKpis] = useState<KpiSummary | null>(null);
  const [results, setResults] = useState<FindingPipelineResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [runs, setRuns] = useState<Run[]>([]);

  useEffect(() => {
    Promise.all([fetchKpis(), fetchIncidentResults()])
      .then(([k, r]) => {
        setKpis(k);
        setResults(r.sort((a, b) => b.layer2.riskPriority - a.layer2.riskPriority));
      })
      .catch((err) => setLoadError(err instanceof Error ? err.message : "Could not load dashboard data"))
      .finally(() => setLoading(false));
  }, []);

  // Incidents are injected from the command line (./run.sh, democtl.sh) via the
  // /api/_control/* endpoints; the dashboard is read-only. Refresh the derived
  // data whenever the polled run set changes so injected cases reach KPIs too.
  const runCompletionSignature = runs.map((run) => `${run.run_id}:${run.status}`).join("|");
  useEffect(() => {
    if (!runCompletionSignature) return;
    Promise.all([fetchKpis(), fetchIncidentResults()])
      .then(([k, r]) => {
        setKpis(k);
        setResults(r.sort((a, b) => b.layer2.riskPriority - a.layer2.riskPriority));
      })
      // A refresh failure leaves the last good snapshot on screen rather than
      // blanking the dashboard; the initial load is what surfaces the error.
      .catch(() => {});
  }, [runCompletionSignature]);

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

      {loadError && (
        <div className="panel">
          <div className="demo-error">{loadError}</div>
          <div className="sub">Is the backend running and reachable at NEXT_PUBLIC_API_BASE?</div>
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
