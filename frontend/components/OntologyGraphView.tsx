import { OntologyEdge, OntologyGraph, OntologyNode } from "../lib/api";

const COLUMN_ORDER: OntologyNode["label"][] = ["Service", "Software", "Owner", "Category"];

const COLUMN_TITLES: Record<OntologyNode["label"], string> = {
  Service: "Services",
  Software: "Software",
  Owner: "Owners",
  Category: "Categories",
};

function serviceTierClass(tier: unknown) {
  if (tier === "crown-jewel") return "tier-0";
  if (tier === "business-critical") return "tier-1";
  return "tier-3";
}

function str(v: unknown): string {
  return typeof v === "string" ? v : "";
}

export default function OntologyGraphView({ graph }: { graph: OntologyGraph }) {
  const { nodes, edges } = graph;
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const edgesFrom = (id: string, type?: OntologyEdge["edgeType"]) =>
    edges.filter((e) => e.srcId === id && (!type || e.edgeType === type));
  const edgesTo = (id: string, type?: OntologyEdge["edgeType"]) =>
    edges.filter((e) => e.dstId === id && (!type || e.edgeType === type));
  const nameOf = (id: string) => str(nodeById.get(id)?.name) || id;

  const byLabel = COLUMN_ORDER.map((label) => ({
    label,
    items: nodes.filter((n) => n.label === label),
  }));

  return (
    <div className="ontology-view">
      <div className="ontology-stats">
        {byLabel.map(({ label, items }) => (
          <div key={label} className="ontology-stat">
            <span className="ontology-stat-value">{items.length}</span>
            <span className="ontology-stat-label">{COLUMN_TITLES[label]}</span>
          </div>
        ))}
        <div className="ontology-stat">
          <span className="ontology-stat-value">{edges.length}</span>
          <span className="ontology-stat-label">Relationships</span>
        </div>
      </div>

      <div className="ontology-columns">
        {byLabel.map(({ label, items }) => (
          <div key={label} className="ontology-column">
            <div className="ontology-column-title">{COLUMN_TITLES[label]}</div>

            {items.map((n) => (
              <div key={n.id} className="ontology-node-card">
                {label === "Service" && (
                  <>
                    <div className="ontology-node-name">{str(n.name)}</div>
                    <div className="badge-row" style={{ marginTop: 4 }}>
                      <span className={`tier-badge ${serviceTierClass(n.tier)}`}>{str(n.tier)}</span>
                      {Boolean(n.internetExposed) && <span className="badge fail">internet-exposed</span>}
                    </div>
                    <div className="ontology-edge-list">
                      {edgesFrom(n.id, "OWNED_BY").map((e, i) => (
                        <div key={i} className="ontology-edge">
                          owned by <strong>{nameOf(e.dstId)}</strong>
                        </div>
                      ))}
                      {edgesFrom(n.id, "DEPENDS_ON").map((e, i) => (
                        <div key={i} className="ontology-edge">
                          depends on <strong>{nameOf(e.dstId)}</strong>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                {label === "Software" && (
                  <>
                    <div className="ontology-node-name">{str(n.name)}</div>
                    <div className="sub" style={{ fontSize: 12 }}>
                      v{str(n.version)}
                      {n.eolDate ? ` · EOL ${str(n.eolDate)}` : ""}
                    </div>
                    <div className="ontology-edge-list">
                      {edgesFrom(n.id, "RUNS_ON").map((e, i) => (
                        <div key={i} className="ontology-edge">
                          runs on <strong>{nameOf(e.dstId)}</strong>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                {label === "Owner" && (
                  <>
                    <div className="ontology-node-name">{str(n.name)}</div>
                    <div className="sub" style={{ fontSize: 12 }}>
                      {str(n.team)}
                    </div>
                    <div className="ontology-edge-list">
                      {edgesTo(n.id, "OWNED_BY").map((e, i) => (
                        <div key={i} className="ontology-edge">
                          owns <strong>{nameOf(e.srcId)}</strong>
                        </div>
                      ))}
                    </div>
                  </>
                )}

                {label === "Category" && (
                  <>
                    <div className="ontology-node-name">{str(n.name)}</div>
                    <div className="badge-row" style={{ marginTop: 4 }}>
                      <span className={`badge ${n.source_taxonomy === "derived" ? "pass" : ""}`}>
                        {n.source_taxonomy === "derived" ? "AI-curated" : "seed taxonomy"}
                      </span>
                    </div>
                    <div className="sub" style={{ fontSize: 12, marginTop: 4 }}>
                      {str(n.definition_text)}
                    </div>
                  </>
                )}
              </div>
            ))}

            {items.length === 0 && <div className="sub" style={{ fontSize: 12 }}>None</div>}
          </div>
        ))}
      </div>
    </div>
  );
}
