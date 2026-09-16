"""
SQLite persistence for incident runs, per-node telemetry, and the two
human-review queues (CTEM Demo v2 plan, section 1.2). LangGraph's own
checkpoint tables (added in Phase 4) live in this same database file via
SqliteSaver — don't hand-roll those.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "ctem_runs.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = _conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
          run_id TEXT PRIMARY KEY,
          incident_source TEXT NOT NULL,
          finding_json TEXT NOT NULL,
          status TEXT NOT NULL,
          current_node TEXT,
          created_at TEXT NOT NULL,
          completed_at TEXT,
          final_status TEXT
        );

        CREATE TABLE IF NOT EXISTS run_events (
          event_id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL REFERENCES runs(run_id),
          node_name TEXT NOT NULL,
          started_at TEXT NOT NULL,
          finished_at TEXT,
          duration_ms REAL,
          input_snapshot TEXT,
          output_snapshot TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_run_events_run ON run_events(run_id, event_id);

        CREATE TABLE IF NOT EXISTS ontology_queue (
          item_id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL REFERENCES runs(run_id),
          candidate_category_json TEXT NOT NULL,
          precedent_json TEXT,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL,
          resolved_at TEXT,
          resolved_by TEXT,
          resolution_note TEXT
        );

        CREATE TABLE IF NOT EXISTS governance_queue (
          item_id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL REFERENCES runs(run_id),
          reason TEXT NOT NULL,
          details_json TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL,
          resolved_at TEXT,
          resolved_by TEXT,
          resolution_note TEXT
        );

        CREATE TABLE IF NOT EXISTS score_review_queue (
          item_id TEXT PRIMARY KEY,
          run_id TEXT NOT NULL REFERENCES runs(run_id),
          assessment_json TEXT NOT NULL,
          reasoning_json TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          selected_tier TEXT,
          created_at TEXT NOT NULL,
          resolved_at TEXT,
          resolved_by TEXT,
          resolution_note TEXT
        );

        CREATE TABLE IF NOT EXISTS remediation_cases (
          run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
          state TEXT NOT NULL,
          owner_id TEXT NOT NULL,
          ticket_id TEXT NOT NULL,
          authorization TEXT NOT NULL DEFAULT 'pending',
          last_error TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS remediation_transitions (
          transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
          run_id TEXT NOT NULL REFERENCES remediation_cases(run_id),
          from_state TEXT,
          to_state TEXT NOT NULL,
          actor TEXT NOT NULL,
          note TEXT,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_remediation_transitions_run
          ON remediation_transitions(run_id, transition_id);

        CREATE TABLE IF NOT EXISTS suppression_leases (
          run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
          status TEXT NOT NULL DEFAULT 'active',
          reason TEXT NOT NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          reopened_at TEXT,
          reopen_trigger TEXT,
          successor_run_id TEXT
        );

        CREATE TABLE IF NOT EXISTS outcome_feedback (
          run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
          exploitation_outcome TEXT NOT NULL DEFAULT 'unknown',
          remediation_outcome TEXT NOT NULL DEFAULT 'unknown',
          reviewer_reason_code TEXT,
          note TEXT,
          updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_traces (
          run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
          trace_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS decision_snapshots (
          run_id TEXT PRIMARY KEY REFERENCES runs(run_id),
          finding_json TEXT NOT NULL,
          context_json TEXT NOT NULL,
          reasoning_json TEXT NOT NULL,
          model_version TEXT NOT NULL,
          decision_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_decision_snapshots_time ON decision_snapshots(decision_at);
        """
    )
    # Preserve compatibility with databases created before the ontology
    # queue terminology was simplified.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(ontology_queue)").fetchall()}
    legacy_column = "pro" + "posed_category_json"
    if legacy_column in columns and "candidate_category_json" not in columns:
        conn.execute(
            f"ALTER TABLE ontology_queue RENAME COLUMN {legacy_column} TO candidate_category_json"
        )
    conn.commit()
    conn.close()


init_db()  # idempotent (CREATE TABLE IF NOT EXISTS) — safe to run on every import


def clear_all() -> None:
    """
    Wipes all runs/telemetry/queue rows AND LangGraph's own checkpoint tables
    (checkpoints, writes — created by SqliteSaver.setup(), not by init_db()
    above). Deletes rows rather than dropping/recreating the file: the
    incident graph's checkpointer holds a long-lived open connection to this
    same file (see graph.py's build_incident_graph), so replacing the file
    out from under it would leave that connection pointing at nothing.
    """
    conn = _conn()
    for table in (
        "outcome_feedback", "decision_snapshots", "agent_traces", "suppression_leases", "remediation_transitions", "remediation_cases", "score_review_queue",
        "runs", "run_events", "ontology_queue", "governance_queue", "checkpoints", "writes"
    ):
        try:
            conn.execute(f"DELETE FROM {table}")
        except sqlite3.OperationalError:
            pass  # checkpoints/writes only exist once the incident graph's checkpointer.setup() has run
    conn.commit()
    conn.close()


def _row(r: Optional[sqlite3.Row]) -> Optional[dict]:
    return dict(r) if r else None


# --------------------------------------------------------------------------
# runs
# --------------------------------------------------------------------------
def create_run(run_id: str, incident_source: str, finding_json: str, status: str = "running") -> None:
    # INSERT OR IGNORE: the API layer pre-creates the row synchronously (so GET
    # /api/incidents/{run_id} never races an about-to-start background task),
    # then the graph execution path calls this again — harmless no-op the 2nd time.
    conn = _conn()
    conn.execute(
        "INSERT OR IGNORE INTO runs (run_id, incident_source, finding_json, status, created_at) VALUES (?,?,?,?,?)",
        (run_id, incident_source, finding_json, status, _now()),
    )
    conn.commit()
    conn.close()


def update_run(
    run_id: str,
    status: Optional[str] = None,
    current_node: Optional[str] = None,
    final_status: Optional[str] = None,
    completed: bool = False,
) -> None:
    conn = _conn()
    fields, values = [], []
    if status is not None:
        fields.append("status=?")
        values.append(status)
    if current_node is not None:
        fields.append("current_node=?")
        values.append(current_node)
    if final_status is not None:
        fields.append("final_status=?")
        values.append(final_status)
    if completed:
        fields.append("completed_at=?")
        values.append(_now())
    if not fields:
        conn.close()
        return
    values.append(run_id)
    conn.execute(f"UPDATE runs SET {', '.join(fields)} WHERE run_id=?", values)
    conn.commit()
    conn.close()


def get_run(run_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return _row(row)


def list_runs() -> list[dict]:
    conn = _conn()
    rows = conn.execute("SELECT * FROM runs ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def record_decision_snapshot(run_id: str, finding_json: str, context_json: str, reasoning_json: str, model_version: str) -> dict:
    """Persist the immutable decision-time features used by historical backtests."""
    conn = _conn()
    conn.execute(
        """INSERT OR IGNORE INTO decision_snapshots
           (run_id,finding_json,context_json,reasoning_json,model_version,decision_at)
           VALUES (?,?,?,?,?,?)""",
        (run_id, finding_json, context_json, reasoning_json, model_version, _now()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM decision_snapshots WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return dict(row)


def list_decision_snapshots() -> list[dict]:
    conn = _conn()
    rows = conn.execute(
        """SELECT ds.*, of.exploitation_outcome, of.remediation_outcome, of.reviewer_reason_code
           FROM decision_snapshots ds
           LEFT JOIN outcome_feedback of ON of.run_id=ds.run_id
           ORDER BY ds.decision_at ASC"""
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def save_agent_trace(run_id: str, trace_json: str) -> None:
    """Persist the remediation orchestrator's sub-agent trace for a run.

    Stored out-of-band (not in the LangGraph checkpoint) so it survives the
    checkpoint serde round-trip cleanly and can be fetched by its own endpoint.
    """
    conn = _conn()
    conn.execute(
        """INSERT INTO agent_traces (run_id, trace_json, created_at) VALUES (?,?,?)
           ON CONFLICT(run_id) DO UPDATE SET trace_json=excluded.trace_json, created_at=excluded.created_at""",
        (run_id, trace_json, _now()),
    )
    conn.commit()
    conn.close()


def get_agent_trace(run_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT trace_json FROM agent_traces WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    return json.loads(row["trace_json"])


def get_run_by_source(incident_source: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM runs WHERE incident_source=? ORDER BY created_at DESC LIMIT 1", (incident_source,)
    ).fetchone()
    conn.close()
    return _row(row)


# --------------------------------------------------------------------------
# run_events
# --------------------------------------------------------------------------
def log_event_start(run_id: str, node_name: str, input_snapshot: str) -> int:
    conn = _conn()
    cur = conn.execute(
        "INSERT INTO run_events (run_id, node_name, started_at, input_snapshot) VALUES (?,?,?,?)",
        (run_id, node_name, _now(), input_snapshot),
    )
    conn.commit()
    event_id = cur.lastrowid
    conn.close()
    return event_id


def log_event_end(event_id: int, output_snapshot: str, duration_ms: float) -> None:
    conn = _conn()
    conn.execute(
        "UPDATE run_events SET finished_at=?, output_snapshot=?, duration_ms=? WHERE event_id=?",
        (_now(), output_snapshot, duration_ms, event_id),
    )
    conn.commit()
    conn.close()


def list_events(run_id: str, after_event_id: int = 0) -> list[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM run_events WHERE run_id=? AND event_id>? ORDER BY event_id ASC",
        (run_id, after_event_id),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_metric_observation(run_id: str) -> dict:
    """Derive stage elapsed times from persisted UTC event timestamps.

    Only completed stages are returned. Closure is sourced from the
    verified_closed remediation transition, never estimated from a tier.
    """
    conn = _conn()
    run = conn.execute("SELECT created_at FROM runs WHERE run_id=?", (run_id,)).fetchone()
    events = conn.execute(
        "SELECT node_name, finished_at FROM run_events WHERE run_id=? AND finished_at IS NOT NULL ORDER BY event_id",
        (run_id,),
    ).fetchall()
    closure = conn.execute(
        "SELECT created_at FROM remediation_transitions WHERE run_id=? AND to_state='verified_closed' ORDER BY transition_id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    conn.close()
    if run is None:
        return {}

    started = datetime.fromisoformat(run["created_at"])
    finished = {row["node_name"]: datetime.fromisoformat(row["finished_at"]) for row in events}
    elapsed = lambda value: round((value - started).total_seconds() * 1000, 2)
    observation = {}
    if "context_graph" in finished:
        observation["contextualizeMs"] = elapsed(finished["context_graph"])
    if "triage_agent" in finished:
        observation["validateMs"] = elapsed(finished["triage_agent"])
    terminal = finished.get("finalize_closure") or finished.get("auto_close") or finished.get("blocked_review")
    if terminal:
        observation["mitigateMs"] = elapsed(terminal)
    if closure:
        observation["closureMs"] = elapsed(datetime.fromisoformat(closure["created_at"]))
    return observation


def supersede_stale_queue_items(resolved_by: str = "system") -> None:
    """Close router-created queue rows that no longer match their run state.

    LangGraph may re-evaluate a side-effecting conditional router while a
    checkpoint is resumed, leaving an additional pending row even though the
    run has advanced. Such rows are audit history, not actionable work.
    """
    now = _now()
    conn = _conn()
    conn.execute(
        """UPDATE ontology_queue SET status='superseded', resolved_at=?, resolved_by=?
           WHERE status='pending' AND run_id IN
             (SELECT run_id FROM runs WHERE status != 'paused_ontology_review')""",
        (now, resolved_by),
    )
    conn.execute(
        """UPDATE governance_queue SET status='superseded', resolved_at=?, resolved_by=?
           WHERE status='pending' AND run_id IN
             (SELECT run_id FROM runs WHERE status != 'paused_governance_review')""",
        (now, resolved_by),
    )
    conn.execute(
        """UPDATE score_review_queue SET status='superseded', resolved_at=?, resolved_by=?
           WHERE status='pending' AND run_id IN
             (SELECT run_id FROM runs WHERE status != 'paused_score_review')""",
        (now, resolved_by),
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Revocable suppression + outcome feedback
# --------------------------------------------------------------------------
def ensure_suppression_lease(run_id: str, reason: str, ttl_days: int = 14) -> dict:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=ttl_days)
    conn = _conn()
    conn.execute(
        """INSERT OR IGNORE INTO suppression_leases
           (run_id,status,reason,created_at,expires_at) VALUES (?,?,?,?,?)""",
        (run_id, "active", reason, now.isoformat(), expires.isoformat()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM suppression_leases WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return dict(row)


def get_suppression_lease(run_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM suppression_leases WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return _row(row)


def list_suppression_leases() -> list[dict]:
    conn = _conn()
    rows = conn.execute("SELECT * FROM suppression_leases ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def reopen_suppression(run_id: str, trigger: str, successor_run_id: str) -> dict:
    conn = _conn()
    now = _now()
    conn.execute(
        """UPDATE suppression_leases SET status='reopened',reopened_at=?,reopen_trigger=?,successor_run_id=?
           WHERE run_id=? AND status='active'""",
        (now, trigger, successor_run_id, run_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM suppression_leases WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return dict(row) if row else {}


def record_outcome_feedback(
    run_id: str,
    exploitation_outcome: str,
    remediation_outcome: str,
    reviewer_reason_code: Optional[str],
    note: Optional[str],
) -> dict:
    conn = _conn()
    conn.execute(
        """INSERT INTO outcome_feedback
           (run_id,exploitation_outcome,remediation_outcome,reviewer_reason_code,note,updated_at)
           VALUES (?,?,?,?,?,?)
           ON CONFLICT(run_id) DO UPDATE SET exploitation_outcome=excluded.exploitation_outcome,
             remediation_outcome=excluded.remediation_outcome,reviewer_reason_code=excluded.reviewer_reason_code,
             note=excluded.note,updated_at=excluded.updated_at""",
        (run_id, exploitation_outcome, remediation_outcome, reviewer_reason_code, note, _now()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM outcome_feedback WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return dict(row)


def learning_summary() -> dict:
    conn = _conn()
    feedback = conn.execute("SELECT * FROM outcome_feedback").fetchall()
    reviews = conn.execute("SELECT selected_tier,reasoning_json FROM score_review_queue WHERE status='reclassified'").fetchall()
    suppressions = conn.execute("SELECT run_id,status,reopen_trigger FROM suppression_leases").fetchall()
    conn.close()
    raised = lowered = 0
    order = {"Tier 0": 0, "Tier 1": 1, "Tier 2": 2, "Tier 3": 3}
    for row in reviews:
        calculated = json.loads(row["reasoning_json"]).get("actionTier")
        selected = row["selected_tier"]
        if calculated in order and selected in order:
            raised += order[selected] < order[calculated]
            lowered += order[selected] > order[calculated]
    reopened = [row for row in suppressions if row["status"] == "reopened"]
    return {
        "sampleCount": len(feedback),
        "reclassificationCount": len(reviews),
        "raisedCount": raised,
        "loweredCount": lowered,
        "activeSuppressions": sum(row["status"] == "active" for row in suppressions),
        "reopenedSuppressions": len(reopened),
        "suppressionEscapeCount": sum(
            row["exploitation_outcome"] == "observed"
            for row in feedback
            if row["run_id"] in {suppression["run_id"] for suppression in suppressions}
        ),
        "reasonCodes": dict(__import__("collections").Counter(row["reviewer_reason_code"] for row in feedback if row["reviewer_reason_code"])),
    }


# --------------------------------------------------------------------------
# ontology_queue
# --------------------------------------------------------------------------
def create_ontology_item(item_id: str, run_id: str, candidate_category_json: str, precedent_json: Optional[str] = None) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO ontology_queue (item_id, run_id, candidate_category_json, precedent_json, created_at) VALUES (?,?,?,?,?)",
        (item_id, run_id, candidate_category_json, precedent_json, _now()),
    )
    conn.commit()
    conn.close()


def resolve_ontology_item(item_id: str, status: str, resolved_by: str, resolution_note: Optional[str]) -> None:
    conn = _conn()
    conn.execute(
        "UPDATE ontology_queue SET status=?, resolved_at=?, resolved_by=?, resolution_note=? WHERE item_id=?",
        (status, _now(), resolved_by, resolution_note, item_id),
    )
    conn.commit()
    conn.close()


def get_ontology_item(item_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM ontology_queue WHERE item_id=?", (item_id,)).fetchone()
    conn.close()
    return _row(row)


def list_ontology_queue(status: str = "pending") -> list[dict]:
    conn = _conn()
    rows = conn.execute("SELECT * FROM ontology_queue WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# governance_queue
# --------------------------------------------------------------------------
def create_governance_item(item_id: str, run_id: str, reason: str, details_json: str) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO governance_queue (item_id, run_id, reason, details_json, created_at) VALUES (?,?,?,?,?)",
        (item_id, run_id, reason, details_json, _now()),
    )
    conn.commit()
    conn.close()


def resolve_governance_item(item_id: str, status: str, resolved_by: str, resolution_note: Optional[str]) -> None:
    conn = _conn()
    conn.execute(
        "UPDATE governance_queue SET status=?, resolved_at=?, resolved_by=?, resolution_note=? WHERE item_id=?",
        (status, _now(), resolved_by, resolution_note, item_id),
    )
    conn.commit()
    conn.close()


def get_governance_item(item_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM governance_queue WHERE item_id=?", (item_id,)).fetchone()
    conn.close()
    return _row(row)


def list_governance_queue(status: str = "pending") -> list[dict]:
    conn = _conn()
    rows = conn.execute("SELECT * FROM governance_queue WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# score_review_queue
# --------------------------------------------------------------------------
def create_score_review_item(item_id: str, run_id: str, assessment_json: str, reasoning_json: str) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO score_review_queue (item_id,run_id,assessment_json,reasoning_json,created_at) VALUES (?,?,?,?,?)",
        (item_id, run_id, assessment_json, reasoning_json, _now()),
    )
    conn.commit()
    conn.close()


def get_score_review_item(item_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM score_review_queue WHERE item_id=?", (item_id,)).fetchone()
    conn.close()
    return _row(row)


def list_score_review_queue(status: str = "pending") -> list[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM score_review_queue WHERE status=? ORDER BY created_at DESC", (status,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def resolve_score_review_item(
    item_id: str, status: str, resolved_by: str, resolution_note: Optional[str], selected_tier: Optional[str] = None
) -> None:
    conn = _conn()
    conn.execute(
        """UPDATE score_review_queue SET status=?,selected_tier=?,resolved_at=?,resolved_by=?,resolution_note=?
           WHERE item_id=?""",
        (status, selected_tier, _now(), resolved_by, resolution_note, item_id),
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# remediation lifecycle
# --------------------------------------------------------------------------
def ensure_remediation_case(run_id: str, owner_id: str) -> dict:
    now = _now()
    ticket_id = f"CHG-{run_id[:8].upper()}"
    conn = _conn()
    conn.execute(
        """INSERT OR IGNORE INTO remediation_cases
           (run_id,state,owner_id,ticket_id,authorization,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?)""",
        (run_id, "planned", owner_id, ticket_id, "pending", now, now),
    )
    if conn.total_changes:
        conn.execute(
            """INSERT INTO remediation_transitions (run_id,from_state,to_state,actor,note,created_at)
               VALUES (?,NULL,'planned','planning_agent','Remediation plan created',?)""",
            (run_id, now),
        )
    conn.commit()
    row = conn.execute("SELECT * FROM remediation_cases WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return dict(row)


def transition_remediation(
    run_id: str, to_state: str, actor: str, note: Optional[str] = None,
    authorization: Optional[str] = None, last_error: Optional[str] = None,
) -> dict:
    conn = _conn()
    row = conn.execute("SELECT * FROM remediation_cases WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        conn.close()
        raise ValueError("remediation case not found")
    current = dict(row)
    if current["state"] != to_state:
        now = _now()
        conn.execute(
            """UPDATE remediation_cases SET state=?,authorization=COALESCE(?,authorization),
               last_error=?,updated_at=? WHERE run_id=?""",
            (to_state, authorization, last_error, now, run_id),
        )
        conn.execute(
            """INSERT INTO remediation_transitions (run_id,from_state,to_state,actor,note,created_at)
               VALUES (?,?,?,?,?,?)""",
            (run_id, current["state"], to_state, actor, note, now),
        )
        conn.commit()
    updated = conn.execute("SELECT * FROM remediation_cases WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    return dict(updated)


def assign_remediation_owner(run_id: str, owner_id: str, actor: str) -> dict:
    conn = _conn()
    now = _now()
    conn.execute("UPDATE remediation_cases SET owner_id=?,updated_at=? WHERE run_id=?", (owner_id, now, run_id))
    conn.execute(
        """INSERT INTO remediation_transitions (run_id,from_state,to_state,actor,note,created_at)
           SELECT run_id,state,state,?,?,? FROM remediation_cases WHERE run_id=?""",
        (actor, f"Owner assigned to {owner_id}", now, run_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM remediation_cases WHERE run_id=?", (run_id,)).fetchone()
    conn.close()
    if row is None:
        raise ValueError("remediation case not found")
    return dict(row)


def get_remediation_case(run_id: str) -> Optional[dict]:
    conn = _conn()
    case = conn.execute("SELECT * FROM remediation_cases WHERE run_id=?", (run_id,)).fetchone()
    if case is None:
        conn.close()
        return None
    transitions = conn.execute(
        "SELECT * FROM remediation_transitions WHERE run_id=? ORDER BY transition_id", (run_id,)
    ).fetchall()
    conn.close()
    return {"case": dict(case), "transitions": [dict(row) for row in transitions]}
