import { useEffect, useState } from "react";
import Link from "next/link";
import AppShell from "../../components/AppShell";
import { fetchOntologyQueue, resolveOntologyItem, OntologyQueueItem } from "../../lib/api";

export default function OntologyQueue() {
  const [items, setItems] = useState<OntologyQueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  function load() {
    fetchOntologyQueue()
      .then(setItems)
      .catch((err) => setLoadError(err instanceof Error ? err.message : "Could not load the ontology queue"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, []);

  async function decide(itemId: string, action: "approve" | "reject") {
    setBusyId(itemId);
    setLoadError(null);
    try {
      await resolveOntologyItem(itemId, action, { resolved_by: "demo-reviewer" });
    } catch (err) {
      // Surface it: a silently-dropped decision looks identical to an applied
      // one once the list reloads, which is the worst possible failure here.
      setLoadError(err instanceof Error ? err.message : `Could not ${action} this item`);
    } finally {
      setBusyId(null);
      load();
    }
  }

  return (
    <AppShell>
      <div className="topbar">
        <div>
          <h1>Ontology Review Queue</h1>
          <div className="sub">Low-confidence category matches awaiting AppSec review</div>
        </div>
      </div>

      <div className="section">
        {loadError && <div className="demo-error">{loadError}</div>}
        {loading && <div className="sub">Loading...</div>}
        {!loading && items.length === 0 && <div className="sub">No pending ontology items.</div>}
        {items.length > 0 && (
          <table className="findings">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Proposed category</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const candidate = JSON.parse(item.candidate_category_json);
                return (
                  <tr key={item.item_id}>
                    <td>
                      <Link href={`/review/${item.run_id}`} className="queue-table-link">
                        {item.run_id.slice(0, 8)}
                      </Link>
                    </td>
                    <td>
                      {candidate.name}
                      <div className="sub" style={{ fontSize: 12 }}>{candidate.definition_text}</div>
                    </td>
                    <td style={{ fontSize: 12, color: "var(--muted)" }}>{new Date(item.created_at).toLocaleString()}</td>
                    <td>
                      <div className="action-btn-row" style={{ marginTop: 0 }}>
                        <button
                          className="action-btn primary"
                          disabled={busyId === item.item_id}
                          onClick={() => decide(item.item_id, "approve")}
                        >
                          Approve
                        </button>
                        <button
                          className="action-btn"
                          disabled={busyId === item.item_id}
                          onClick={() => decide(item.item_id, "reject")}
                        >
                          Reject
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </AppShell>
  );
}
