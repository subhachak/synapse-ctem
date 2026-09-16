const LIKELIHOOD_LABELS: Record<string, string> = {
  intercept: "Model baseline",
  epssLogOdds: "EPSS",
  internetExposure: "Internet exposure",
  runtimeReachability: "Runtime reachability",
  exploitMaturity: "Exploit maturity",
  chainability: "Attack-path chainability",
  threatActivity: "Threat activity",
};

const IMPACT_LABELS: Record<string, string> = {
  cvssSeverity: "Technical severity",
  appCriticality: "Application criticality",
  dataSensitivity: "Data sensitivity",
  blastRadius: "Blast radius",
  regulatorySafety: "Regulatory / safety",
};

function signed(value: number) {
  return `${value >= 0 ? "+" : ""}${value.toFixed(3)}`;
}

function inputValue(value: number | undefined) {
  return value === undefined ? "—" : value.toFixed(2);
}

function BreakdownColumn({
  title,
  labels,
  inputs,
  contributions,
  impact = false,
}: {
  title: string;
  labels: Record<string, string>;
  inputs: Record<string, number>;
  contributions: Record<string, number>;
  impact?: boolean;
}) {
  return (
    <div style={{ flex: 1, minWidth: 280 }}>
      <div className="field-label">{title}</div>
      {Object.entries(contributions).map(([key, contribution]) => (
        <div className="kv" key={key} style={{ display: "grid", gridTemplateColumns: "1fr 72px 96px", gap: 8 }}>
          <span>{labels[key] ?? key}</span>
          <span className="sub" style={{ textAlign: "right" }}>
            {key === "intercept" ? "baseline" : `input ${inputValue(inputs[key])}`}
          </span>
          <span style={{ fontFamily: "var(--mono)", textAlign: "right" }}>
            {impact ? `${(contribution * 100).toFixed(1)} pts` : signed(contribution)}
          </span>
        </div>
      ))}
      {!impact && <div className="sub" style={{ marginTop: 6 }}>Contributions are additive log-odds, not percentage points.</div>}
    </div>
  );
}

export function evidenceQualityLabel(fieldStatus: Record<string, string>) {
  const values = Object.values(fieldStatus);
  if (values.includes("missing")) return "Low";
  if (values.some((value) => value === "simulated" || value === "inferred")) return "Medium";
  return "High";
}

export default function ScoringBreakdown({
  likelihoodInputs,
  likelihoodContributions,
  impactInputs,
  impactContributions,
}: {
  likelihoodInputs: Record<string, number>;
  likelihoodContributions: Record<string, number>;
  impactInputs: Record<string, number>;
  impactContributions: Record<string, number>;
}) {
  return (
    <div className="panel" style={{ display: "flex", gap: 24, alignItems: "flex-start", flexWrap: "wrap", marginTop: 12 }}>
      <BreakdownColumn
        title="Why the likelihood moved (log-odds)"
        labels={LIKELIHOOD_LABELS}
        inputs={likelihoodInputs}
        contributions={likelihoodContributions}
      />
      <BreakdownColumn
        title="What makes up business impact"
        labels={IMPACT_LABELS}
        inputs={impactInputs}
        contributions={impactContributions}
        impact
      />
    </div>
  );
}
