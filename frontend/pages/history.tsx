import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AppShell from "../components/AppShell";
import BarChart from "../components/charts/BarChart";
import { fetchKpis, fetchIncidentResults, FindingPipelineResult, KpiSummary } from "../lib/api";

function tierClass(tier: string) {
  if (tier === "Tier 0") return "tier-0";
  if (tier === "Tier 1") return "tier-1";
  if (tier === "Tier 2") return "tier-2";
  return "tier-3";
}

function resultFor(r: FindingPipelineResult): "Accepted" | "Closed" | "Mitigated" | "Pending" {
  if (r.finding.raOnBooks) return "Accepted";
  if (r.verification.verifiedClosed) return "Closed";
  if (r.verification.status === "failed") return "Pending";
  return "Pending";
}

function resultClass(result: string) {
  if (result === "Closed") return "pass";
  if (result === "Pending") return "fail";
  return "";
}

// Synthetic dates — this demo has no real remediation-history timestamps,
// only a point-in-time pipeline snapshot per finding. Spread findings across
// the last couple weeks, most-recent first, purely for display.
function syntheticDate(index: number): string {
  const d = new Date();
  d.setDate(d.getDate() - index * 3);
  return d.toISOString().slice(0, 10);
}

export default function History() {
  const [results, setResults] = useState<FindingPipelineResult[]>([]);
  const [kpis, setKpis] = useState<KpiSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [tierFilter, setTierFilter] = useState("all");
  const [ownerFilter, setOwnerFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [dateFilter, setDateFilter] = useState("all");

  useEffect(() => {
    Promise.all([fetchIncidentResults(), fetchKpis()]).then(([r, k]) => {
      setResults(r);
      setKpis(k);
      setLoading(false);
    });
  }, []);

  const withDates = useMemo(
    () => results.map((r, i) => ({ r, date: syntheticDate(i), result: resultFor(r) })),
    [results]
  );

  const owners = useMemo(() => Array.from(new Set(results.map((r) => r.layer1.owner.name))), [results]);

  const filtered = withDates.filter(({ r, date }) => {
    if (tierFilter !== "all" && r.layer2.actionTier !== tierFilter) return false;
    if (ownerFilter !== "all" && r.layer1.owner.name !== ownerFilter) return false;
    if (sourceFilter !== "all" && r.finding.discoveredBy !== sourceFilter) return false;
    if (dateFilter !== "all") {
      const days = Number(dateFilter);
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - days);
      if (new Date(date) < cutoff) return false;
    }
    return true;
  });

  const acceptedRiskCount = results.filter((r) => r.finding.raOnBooks).length;

  const mttrBars = kpis
    ? [
        { label: "Contextualize", value: kpis.meanTimeToContextualizeMs },
        { label: "Validate", value: kpis.meanTimeToValidateMs },
        { label: "Mitigate", value: kpis.meanTimeToMitigateMs },
        { label: "Exploit-close", value: kpis.meanExploitPathClosureMs },
      ]
    : [];

  return (
    <AppShell activeNav="history">
      <div className="topbar">
        <div>
          <h1>History &amp; Reports</h1>
          <div className="sub">Remediation history &middot; accepted-risk register &middot; closure evidence</div>
        </div>
      </div>

      <div className="demo-disclosure">
        <span className="badge">REPORTING PROVENANCE</span>
        Workflow outcomes and closure evidence are measured from demo events. Display dates and the trend visualization remain illustrative.
      </div>

      <div className="filters-row">
        <select className="field-select" style={{ width: "auto" }} value={dateFilter} onChange={(e) => setDateFilter(e.target.value)}>
          <option value="all">Illustrative date: all</option>
          <option value="7">Last 7d</option>
          <option value="30">Last 30d</option>
          <option value="90">Last 90d</option>
        </select>
        <select className="field-select" style={{ width: "auto" }} value={tierFilter} onChange={(e) => setTierFilter(e.target.value)}>
          <option value="all">Tier: all</option>
          <option value="Tier 0">Tier 0</option>
          <option value="Tier 1">Tier 1</option>
          <option value="Tier 2">Tier 2</option>
          <option value="Tier 3">Tier 3</option>
        </select>
        <select className="field-select" style={{ width: "auto" }} value={ownerFilter} onChange={(e) => setOwnerFilter(e.target.value)}>
          <option value="all">Owner: all</option>
          {owners.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <select className="field-select" style={{ width: "auto" }} value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)}>
          <option value="all">Source: all</option>
          <option value="Mythos">Mythos</option>
          <option value="Codex">Codex</option>
          <option value="Scanner">Scanner (imported)</option>
        </select>
      </div>

      <div className="two-col">
        <div className="section" style={{ gridColumn: "1 / -1" }}>
          <h2>Remediation history</h2>
          <table className="findings">
            <thead>
              <tr>
                <th>Date <span className="badge">ILLUSTRATIVE</span></th>
                <th>Finding</th>
                <th>Action</th>
                <th>Owner</th>
                <th>Result</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={6} style={{ color: "var(--muted)" }}>
                    Loading...
                  </td>
                </tr>
              )}
              {filtered.map(({ r, date, result }) => (
                <tr key={r.runId}>
                  <td style={{ fontFamily: "var(--mono)", fontSize: 12.5 }}>{date}</td>
                  <td>
                    {r.finding.name}
                    <span className={`tier-badge ${tierClass(r.layer2.actionTier)}`} style={{ marginLeft: 8 }}>
                      {r.layer2.actionTier}
                    </span>
                  </td>
                  <td>{r.planning.fixApproach}</td>
                  <td>{r.layer1.owner.name}</td>
                  <td>
                    <span className={`badge ${resultClass(result)}`}>{result}</span>
                  </td>
                  <td>
                    <Link href={`/review/${r.runId}`} className="action-btn">
                      View &rarr;
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="chart-panel">
          <h3>Accepted-risk register</h3>
          <div className="stat-tile" style={{ border: "none", padding: 0 }}>
            <div className="stat-value">{acceptedRiskCount}</div>
            <div className="stat-label">Open accepted risks</div>
          </div>
        </div>

        <div className="chart-panel">
          <h3>Measured workflow timings (ms)</h3>
          {mttrBars.length > 0 && <BarChart data={mttrBars} height={110} />}
          {kpis && (
            <div className="bar-chart-note">
              Event-derived samples — MTTCx n={kpis.metricSampleCounts.MTTCx ?? 0}, MTTV n={kpis.metricSampleCounts.MTTV ?? 0}, MTTR n={kpis.metricSampleCounts.MTTR ?? 0}, closure n={kpis.metricSampleCounts.ExploitPathClosure ?? 0}.
            </div>
          )}
        </div>

        <div className="chart-panel" style={{ gridColumn: "1 / -1" }}>
          <h3>Metric provenance</h3>
          <ul className="checklist">
            {kpis && Object.entries(kpis.metricProvenance).map(([metric, source]) => (
              <li key={metric}><strong>{metric}</strong> — {source}</li>
            ))}
            {kpis && Object.entries(kpis.illustrativeTargets).map(([metric, note]) => (
              <li key={metric}><span className="badge">ILLUSTRATIVE / NOT MEASURED</span> <strong>{metric}</strong> — {note}</li>
            ))}
          </ul>
        </div>

        <div className="chart-panel" style={{ gridColumn: "1 / -1" }}>
          <h3>Closure evidence</h3>
          <ul className="checklist">
            <li>Re-scan diff (before/after) — generated by a visibly labeled simulated scanner adapter</li>
            <li>Deployed-version proof — generated by a simulated CI/CD adapter</li>
            <li>Runtime path closure and reasoning-chain snapshot</li>
          </ul>
        </div>
      </div>
    </AppShell>
  );
}
