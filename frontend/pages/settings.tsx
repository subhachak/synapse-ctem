import { useEffect, useState } from "react";
import AppShell from "../components/AppShell";
import OntologyGraphView from "../components/OntologyGraphView";
import {
  AppCriticalityEntry,
  backtestRiskModel,
  BacktestResult,
  fetchOntologyGraph,
  fetchOwners,
  fetchRiskModelSettings,
  fetchLearningSummary,
  fetchServices,
  ImpactWeights,
  LikelihoodCoefficients,
  LearningSummary,
  OntologyGraph,
  OwnerSummary,
  RiskModelSettings,
  saveRiskModelSettings,
  ServiceSummary,
} from "../lib/api";

const TIERS: AppCriticalityEntry["tier"][] = ["Tier 0", "Tier 1", "Tier 2", "Tier 3"];
const COMPLIANCE_OPTIONS = ["PCI-DSS", "SOX", "GDPR", "HIPAA"];
const IMPACT_FIELDS: { key: keyof ImpactWeights; label: string }[] = [
  { key: "cvssSeverity", label: "CVSS technical severity proxy" },
  { key: "appCriticality", label: "Application criticality" },
  { key: "dataSensitivity", label: "Data sensitivity" },
  { key: "blastRadius", label: "Blast radius" },
  { key: "regulatorySafety", label: "Regulatory / safety consequence" },
];
const LIKELIHOOD_FIELDS: { key: keyof LikelihoodCoefficients; label: string; description: string }[] = [
  { key: "intercept", label: "Baseline intercept", description: "Starting log-odds before finding-specific evidence" },
  { key: "epssLogOdds", label: "EPSS log-odds", description: "Weight applied to the calibrated EPSS signal" },
  { key: "internetExposure", label: "Internet exposure", description: "Externally reachable service contribution" },
  { key: "runtimeReachability", label: "Runtime reachability", description: "Observed affected path contribution" },
  { key: "exploitMaturity", label: "Exploit maturity", description: "Reproduction and exploit-evidence contribution" },
  { key: "chainability", label: "Chainability", description: "Graph-backed adjacent exploit-path contribution" },
  { key: "threatActivity", label: "Threat activity", description: "Active-exploitation signal contribution" },
];

function defaultEntryFor(svc: ServiceSummary): AppCriticalityEntry {
  return {
    applicationId: svc.id,
    tier: svc.tier === "crown-jewel" ? "Tier 0" : svc.tier === "business-critical" ? "Tier 1" : "Tier 2",
    dataSensitivity: svc.tier === "crown-jewel" ? "Restricted" : svc.tier === "business-critical" ? "Confidential" : "Internal",
    accountableOwnerId: svc.ownerId,
    crownJewel: svc.tier === "crown-jewel",
    internetExposed: svc.internetExposed,
    complianceScope: [],
  };
}

export default function Settings() {
  const [services, setServices] = useState<ServiceSummary[]>([]);
  const [owners, setOwners] = useState<OwnerSummary[]>([]);
  const [selectedAppId, setSelectedAppId] = useState<string>("");
  const [entries, setEntries] = useState<Record<string, AppCriticalityEntry>>({});
  const [likelihoodCoefficients, setLikelihoodCoefficients] = useState<LikelihoodCoefficients>({
    intercept: -2,
    epssLogOdds: 1.1,
    internetExposure: 0.7,
    runtimeReachability: 0.9,
    exploitMaturity: 0.5,
    chainability: 0.6,
    threatActivity: 0.8,
  });
  const [impactWeights, setImpactWeights] = useState<ImpactWeights>({
    cvssSeverity: 35,
    appCriticality: 30,
    dataSensitivity: 15,
    blastRadius: 10,
    regulatorySafety: 10,
  });
  const [thresholds, setThresholds] = useState({ tier0: 90, tier1: 75, tier2: 50 });
  const [kevOverride, setKevOverride] = useState(true);
  const [maxControlEffectiveness, setMaxControlEffectiveness] = useState(0.7);
  const [status, setStatus] = useState<"draft" | "active">("active");
  const [version, setVersion] = useState("v3.0-explainable-risk");
  const [toast, setToast] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [ontologyGraph, setOntologyGraph] = useState<OntologyGraph | null>(null);
  const [learning, setLearning] = useState<LearningSummary | null>(null);
  const [backtest, setBacktest] = useState<BacktestResult | null>(null);
  const [backtesting, setBacktesting] = useState(false);

  useEffect(() => {
    fetchOntologyGraph().then(setOntologyGraph);
    fetchLearningSummary().then(setLearning);
  }, []);

  useEffect(() => {
    Promise.all([fetchServices(), fetchOwners(), fetchRiskModelSettings()]).then(([svcs, owns, settings]) => {
      setServices(svcs);
      setOwners(owns);
      setSelectedAppId(svcs[0]?.id ?? "");

      const entryMap: Record<string, AppCriticalityEntry> = {};
      svcs.forEach((s) => (entryMap[s.id] = defaultEntryFor(s)));
      settings.appCriticality.forEach((e) => (entryMap[e.applicationId] = e));
      setEntries(entryMap);

      setLikelihoodCoefficients(settings.likelihoodCoefficients);
      setImpactWeights(settings.impactWeights);
      setThresholds(settings.thresholds);
      setKevOverride(settings.kevOverridesToTier0);
      setMaxControlEffectiveness(settings.maxControlEffectiveness);
      setStatus(settings.status);
      setVersion(settings.version);
      setLoaded(true);
    });
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3000);
    return () => clearTimeout(t);
  }, [toast]);

  const currentEntry = entries[selectedAppId];
  const weightTotal = Object.values(impactWeights).reduce((s, v) => s + Number(v || 0), 0);
  const weightsBalanced = Math.round(weightTotal) === 100;

  function updateEntry(patch: Partial<AppCriticalityEntry>) {
    if (!currentEntry) return;
    setEntries({ ...entries, [selectedAppId]: { ...currentEntry, ...patch } });
  }

  function toggleCompliance(scope: string) {
    if (!currentEntry) return;
    const has = currentEntry.complianceScope.includes(scope);
    updateEntry({
      complianceScope: has
        ? currentEntry.complianceScope.filter((s) => s !== scope)
        : [...currentEntry.complianceScope, scope],
    });
  }

  async function handleSave(nextStatus: "draft" | "active") {
    if (nextStatus === "active" && !weightsBalanced) {
      setToast("Severity weights must total 100% before activation");
      return;
    }
    const payload: RiskModelSettings = {
      appCriticality: Object.values(entries),
      likelihoodCoefficients,
      impactWeights,
      thresholds,
      kevOverridesToTier0: kevOverride,
      maxControlEffectiveness,
      status: nextStatus,
      version,
    };
    const saved = await saveRiskModelSettings(payload);
    setStatus(saved.status);
    setToast(nextStatus === "draft" ? "Draft saved — active decisions unchanged" : "Model activated for new decisions");
  }

  async function handleBacktest() {
    if (!weightsBalanced) {
      setToast("Business-impact weights must total 100% before backtesting");
      return;
    }
    setBacktesting(true);
    const candidate: RiskModelSettings = {
      appCriticality: Object.values(entries), likelihoodCoefficients, impactWeights, thresholds,
      kevOverridesToTier0: kevOverride, maxControlEffectiveness, status: "draft", version,
    };
    try {
      setBacktest(await backtestRiskModel(candidate));
    } finally {
      setBacktesting(false);
    }
  }

  if (!loaded || !currentEntry) {
    return (
      <AppShell activeNav="settings">
        <div className="sub">Loading risk model settings...</div>
      </AppShell>
    );
  }

  return (
    <AppShell activeNav="settings">
      <div className="topbar">
        <div>
          <h1>Settings &rsaquo; Risk Model &amp; App Criticality</h1>
          <div className="sub">
            AppSec defines criticality per app and tunes the severity model here; changes are versioned and require
            approval before the reasoning engine applies them.
          </div>
        </div>
      </div>

      <div className="demo-disclosure">
        <span className="badge">SYNTHETIC DEMO CONTEXT</span>
        Service names, owners, dependencies, application criticality, and ontology relationships are seeded demonstration data. Activated model settings are persisted and govern subsequent demo decisions.
      </div>

      <div className="section">
        <h2>Ontology &mdash; context graph components</h2>
        <div className="panel">
          {ontologyGraph ? (
            <OntologyGraphView graph={ontologyGraph} />
          ) : (
            <div className="sub">Loading ontology graph...</div>
          )}
        </div>
      </div>

      <div className="two-col">
        <div className="section">
          <h2>Define application criticality</h2>
          <div className="panel">
            <div className="field-group">
              <label className="field-label">Application</label>
              <select className="field-select" value={selectedAppId} onChange={(e) => setSelectedAppId(e.target.value)}>
                {services.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.id})
                  </option>
                ))}
              </select>
            </div>

            <div className="field-group">
              <label className="field-label">Business criticality tier</label>
              <div className="tier-picker">
                {TIERS.map((t) => (
                  <button
                    key={t}
                    type="button"
                    className={`tier-pick-btn ${currentEntry.tier === t ? "selected" : ""}`}
                    onClick={() => updateEntry({ tier: t })}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            <div className="field-row">
              <div className="field-group">
                <label className="field-label">Data sensitivity</label>
                <select
                  className="field-select"
                  value={currentEntry.dataSensitivity}
                  onChange={(e) => updateEntry({ dataSensitivity: e.target.value })}
                >
                  <option>Public</option>
                  <option>Internal</option>
                  <option>Confidential</option>
                  <option>Restricted</option>
                </select>
              </div>
              <div className="field-group">
                <label className="field-label">Accountable owner</label>
                <select
                  className="field-select"
                  value={currentEntry.accountableOwnerId}
                  onChange={(e) => updateEntry({ accountableOwnerId: e.target.value })}
                >
                  {owners.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="toggle-row">
              <label className="field-label">Crown-jewel / regulated asset</label>
              <button
                type="button"
                className={`toggle ${currentEntry.crownJewel ? "on" : ""}`}
                onClick={() => updateEntry({ crownJewel: !currentEntry.crownJewel })}
              >
                <span className="toggle-knob" />
              </button>
            </div>
            <div className="toggle-row">
              <label className="field-label">Internet-exposed</label>
              <button
                type="button"
                className={`toggle ${currentEntry.internetExposed ? "on" : ""}`}
                onClick={() => updateEntry({ internetExposed: !currentEntry.internetExposed })}
              >
                <span className="toggle-knob" />
              </button>
            </div>

            <div className="field-group">
              <label className="field-label">Compliance scope</label>
              <div className="chip-toggle-row">
                {COMPLIANCE_OPTIONS.map((c) => (
                  <button
                    key={c}
                    type="button"
                    className={`chip-toggle ${currentEntry.complianceScope.includes(c) ? "selected" : ""}`}
                    onClick={() => toggleCompliance(c)}
                  >
                    {c}
                  </button>
                ))}
              </div>
            </div>

            <div className="sub" style={{ marginTop: 10 }}>
              Effective criticality: <strong>{currentEntry.tier}</strong> (auto-derived, editable)
            </div>
          </div>
        </div>

        <div className="section">
          <h2>Explainable risk model — likelihood, impact, controls &amp; policy</h2>
          <div className="panel">
            <div className="demo-disclosure" style={{ marginBottom: 16 }}>
              Exploitation likelihood uses governed logistic coefficients for EPSS, exposure, reachability, exploit maturity,
              chainability, and threat activity. Validated controls are applied once as an explicit residual-risk dampener.
              These are demonstration defaults pending client backtesting.
            </div>
            <div className="kv-block" style={{ marginBottom: 18 }}>
              <div className="kv"><strong>Likelihood</strong> = sigmoid(intercept + weighted evidence contributions)</div>
              <div className="kv"><strong>Business impact</strong> = weighted sum of five normalized impact factors</div>
              <div className="kv"><strong>Residual risk</strong> = 100 × likelihood × impact × (1 − validated controls)</div>
              <div className="sub">KEV is applied afterward as an explicit Tier-0 policy floor; it is not hidden inside the probability model.</div>
            </div>

            <div className="field-label">Exploitation-likelihood coefficients (log-odds scale)</div>
            <div className="coefficient-grid">
              {LIKELIHOOD_FIELDS.map(({ key, label, description }) => (
                <label className="coefficient-field" key={key}>
                  <span><strong>{label}</strong><small>{description}</small></span>
                  <input
                    className="field-input"
                    type="number"
                    step="0.1"
                    value={likelihoodCoefficients[key]}
                    onChange={(e) => setLikelihoodCoefficients({ ...likelihoodCoefficients, [key]: Number(e.target.value) })}
                  />
                </label>
              ))}
            </div>

            <div className="field-label" style={{ marginTop: 20 }}>Business-impact weights</div>
            {IMPACT_FIELDS.map(({ key, label }) => (
              <div className="slider-row" key={key}>
                <div className="slider-row-head">
                  <span className="name">{label}</span>
                  <span className="val">{impactWeights[key]}%</span>
                </div>
                <input
                  type="range"
                  min={0}
                  max={100}
                  value={impactWeights[key]}
                  onChange={(e) => setImpactWeights({ ...impactWeights, [key]: Number(e.target.value) })}
                />
              </div>
            ))}
            <div className={`weight-total-row ${weightsBalanced ? "balanced" : "unbalanced"}`}>
              <span>Business-impact weights total</span>
              <span className="weight-total-value">{weightTotal}%</span>
            </div>

            <div className="field-label" style={{ marginTop: 20 }}>Validated-control treatment</div>
            <div className="slider-row">
              <div className="slider-row-head">
                <span className="name">Maximum permitted control-effectiveness credit</span>
                <span className="val">{Math.round(maxControlEffectiveness * 100)}%</span>
              </div>
              <input
                type="range"
                min={0}
                max={0.9}
                step={0.05}
                value={maxControlEffectiveness}
                onChange={(e) => setMaxControlEffectiveness(Number(e.target.value))}
              />
            </div>
            <div className="demo-disclosure" style={{ marginTop: 10 }}>
              <strong>Current demo observed effectiveness: 0%.</strong> This setting is a safety cap, not awarded credit.
              Policies describe expected behavior but are not proof that a deployed control is effective. Production credit requires independently validated control evidence.
            </div>

            <div className="field-label" style={{ marginTop: 18 }}>
              Residual-risk tier thresholds (likelihood &times; impact &times; remaining exposure after controls)
            </div>
            <div className="threshold-row">
              <span className="threshold-tag">&ge; Tier 0</span>
              <input
                className="field-input"
                type="number"
                value={thresholds.tier0}
                onChange={(e) => setThresholds({ ...thresholds, tier0: Number(e.target.value) })}
              />
            </div>
            <div className="threshold-row">
              <span className="threshold-tag">&ge; Tier 1</span>
              <input
                className="field-input"
                type="number"
                value={thresholds.tier1}
                onChange={(e) => setThresholds({ ...thresholds, tier1: Number(e.target.value) })}
              />
            </div>
            <div className="threshold-row">
              <span className="threshold-tag">&ge; Tier 2</span>
              <input
                className="field-input"
                type="number"
                value={thresholds.tier2}
                onChange={(e) => setThresholds({ ...thresholds, tier2: Number(e.target.value) })}
              />
            </div>

            <div className="toggle-row">
              <label className="field-label">Active-exploit (KEV) overrides to Tier 0</label>
              <button type="button" className={`toggle ${kevOverride ? "on" : ""}`} onClick={() => setKevOverride(!kevOverride)}>
                <span className="toggle-knob" />
              </button>
            </div>

            <div className="sub" style={{ marginTop: 10 }}>
              Model {version} &middot; {status === "draft" ? "Draft — active decisions unchanged" : "Active"} &middot;{" "}
              Owner: AppSec &middot; co-signed by service owner
            </div>

            <div className="action-btn-row">
              <button className="action-btn" onClick={() => handleSave("draft")}>
                Save draft
              </button>
              <button className="action-btn primary" onClick={() => handleSave("active")}>
                Activate model
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Observe &rarr; Learn &rarr; Govern</h2>
        <div className="panel">
          <div className="demo-disclosure">
            Outcome telemetry may propose model improvements, but this surface cannot activate them. Backtests are shadow-only and preserve the active decision record.
          </div>
          <div className="decision-strip" style={{ marginTop: 14 }}>
            <div className="decision-card"><div className="decision-label">Outcome samples</div><div className="decision-value">{learning?.sampleCount ?? 0}</div></div>
            <div className="decision-card"><div className="decision-label">Human reclassifications</div><div className="decision-value">{learning?.reclassificationCount ?? 0}</div><div className="sub">{learning?.raisedCount ?? 0} raised &middot; {learning?.loweredCount ?? 0} lowered</div></div>
            <div className="decision-card"><div className="decision-label">Active suppressions</div><div className="decision-value">{learning?.activeSuppressions ?? 0}</div></div>
            <div className="decision-card"><div className="decision-label">Reopened suppressions</div><div className="decision-value">{learning?.reopenedSuppressions ?? 0}</div></div>
          </div>
          <div className="action-btn-row">
            <button className="action-btn primary" disabled={backtesting} onClick={handleBacktest}>
              {backtesting ? "Running shadow backtest…" : "Backtest current draft"}
            </button>
          </div>
          {backtest && (
            <div style={{ marginTop: 14 }}>
              <div className="kv"><strong>{backtest.activeVersion}</strong> vs. <strong>{backtest.candidateVersion}</strong> &middot; {backtest.changedCount} of {backtest.sampleCount} decisions changed</div>
              <div className="kv">Outcome-labelled samples: {backtest.labelledSampleCount} &middot; Evaluation window: {backtest.evaluationWindow}</div>
              <div className="sub">{backtest.message}</div>
              {backtest.changes.slice(0, 8).map((change) => (
                <div className="kv" key={change.runId}>{change.finding}: {change.activeScore} / {change.activeTier} &rarr; {change.candidateScore} / {change.candidateTier}</div>
              ))}
            </div>
          )}
        </div>
      </div>

      {toast && <div className="toast">{toast}</div>}
    </AppShell>
  );
}
