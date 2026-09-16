import { useEffect, useState } from "react";
import Link from "next/link";
import AppShell from "../../components/AppShell";
import { fetchGovernanceQueue, resolveGovernanceItem, GovernanceQueueItem } from "../../lib/api";

export default function GovernanceQueue() {
  const [items, setItems] = useState<GovernanceQueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);

  function load() {
    fetchGovernanceQueue().then((r) => {
      setItems(r);
      setLoading(false);
    });
  }

  useEffect(() => {
    load();
  }, []);

  async function decide(itemId: string, action: "approve" | "reject") {
    setBusyId(itemId);
    await resolveGovernanceItem(itemId, action, { resolved_by: "demo-reviewer" });
    setBusyId(null);
    load();
  }

  return (
    <AppShell>
      <div className="topbar">
        <div>
          <h1>Governance Review Queue</h1>
          <div className="sub">Findings blocked or pending human approval</div>
        </div>
      </div>

      <div className="section">
        {loading && <div className="sub">Loading...</div>}
        {!loading && items.length === 0 && <div className="sub">No pending governance items.</div>}
        {items.length > 0 && (
          <table className="findings">
            <thead>
              <tr>
                <th>Incident</th>
                <th>Reason</th>
                <th>Details</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const details = JSON.parse(item.details_json);
                return (
                  <tr key={item.item_id}>
                    <td>
                      <Link href={`/review/${item.run_id}`} className="queue-table-link">
                        {item.run_id.slice(0, 8)}
                      </Link>
                    </td>
                    <td>
                      <span className={`badge ${item.reason === "blocked" ? "fail" : "paused"}`}>{item.reason}</span>
                    </td>
                    <td style={{ fontSize: 12.5 }}>{details.provenanceWhy}</td>
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
