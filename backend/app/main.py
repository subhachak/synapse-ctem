import os
import threading
from typing import List, Literal, Optional

from dotenv import load_dotenv

# Must run before any app.* import — llm.py reads ANTHROPIC_API_KEY from
# os.environ at MODULE IMPORT TIME (`_api_key = os.environ.get(...)` at its
# top level), so loading .env after that import would be too late.
load_dotenv()

import asyncio
import json
import uuid

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app import graphdb
from app.data import runs_db
from app.data.seed import FINDINGS, SERVICES, OWNERS
from app.graph import (
    INCIDENT_EXECUTION_LOCK,
    bootstrap_seed_incidents,
    get_incident_result,
    start_incident_run,
    resume_incident_run,
)
from app.kpis import compute_kpis
from app.llm import IS_LIVE_MODE, offline_reasoning
from app.models import AgentTrace, ContextGraphRecord, FindingPipelineResult, KpiSummary, RawFinding, ReasoningEngineRecord, RemediationTarget, RiskModelSettings, ServiceNode, OwnerNode
from app.remediation import reset_workspaces
from app.remediation import github_pr
from app.scripts.load_graph import main as reseed_graph
from app.settings_store import load_risk_model_settings, load_active_risk_model_settings, save_risk_model_settings
from app.layer1.context_graph import build_context_graph_record
from app.layer2.reasoning_engine import rescore_immutable_snapshot, run_reasoning_engine
from app.retrieval import RETRIEVAL_MODE, embed_texts

app = FastAPI(title="Mphasis Synapse CTEM API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Bootstraps the 7 seed findings through the same incident graph live-injected
# incidents use (see graph.bootstrap_seed_incidents) — backgrounded so server
# startup isn't blocked on ~21 potential LLM calls; idempotent, so this is
# safe on every restart. Runs synchronously inside /api/reset instead, since
# that endpoint already blocks the caller with a "Resetting..." UI state.
threading.Thread(target=bootstrap_seed_incidents, daemon=True).start()


def _all_ready_results() -> List[dict]:
    """Every run (seed-originated or live-injected) that has reached the
    Governance Agent — the shared dataset behind /api/incidents/results,
    /api/kpis, and History. Runs still short of governance are silently
    skipped, same as a single get_incident_result(run_id) miss."""
    results = []
    for run in runs_db.list_runs():
        result = get_incident_result(run["run_id"])
        if result is not None:
            results.append(result)
    return results


@app.get("/api/health")
def health():
    return {"status": "ok", "llmMode": "live (Anthropic)" if IS_LIVE_MODE else "offline (deterministic)", "retrievalMode": RETRIEVAL_MODE}


@app.get("/api/findings")
def list_findings():
    return [
        {"id": f.id, "name": f.name, "cve": f.cve, "severity": f.severityLabel}
        for f in FINDINGS
    ]


@app.get("/api/findings/{finding_id}/result", response_model=FindingPipelineResult)
def get_seed_finding_result(finding_id: str):
    """
    Looks up the bootstrapped seed run for this finding id and returns its
    result — lets pages that pick a finding by its familiar seed id (e.g. the
    Demo Mode walkthrough's picker) reach the same unified incident-graph
    data everything else uses, without needing to know that finding's run_id.
    """
    run = runs_db.get_run_by_source(f"seed:{finding_id}")
    if run is None:
        raise HTTPException(status_code=404, detail=f"no seed run found for '{finding_id}'")
    result = get_incident_result(run["run_id"])
    if result is None:
        raise HTTPException(status_code=409, detail="this seed finding hasn't reached the Governance Agent yet")
    return result


@app.get("/api/incidents/results", response_model=list[FindingPipelineResult])
def list_incident_results():
    return _all_ready_results()


@app.get("/api/kpis", response_model=KpiSummary)
def get_kpis():
    results = _all_ready_results()
    observations = {result["runId"]: runs_db.get_metric_observation(result["runId"]) for result in results}
    return compute_kpis(results, observations)


@app.get("/api/services", response_model=list[ServiceNode])
def list_services():
    return SERVICES


@app.get("/api/owners", response_model=list[OwnerNode])
def list_owners():
    return OWNERS


@app.get("/api/ontology/graph")
def get_ontology_graph():
    """
    Full context-graph snapshot (Services/Software/Owners/Categories and their
    edges) for the Settings > Ontology visual — read-only, no pagination
    (this demo's graph.db has a few dozen nodes at most). Vulnerability nodes
    are intentionally excluded: they're transient findings flowing through
    the pipeline, not stable ontology/taxonomy components. Category nodes
    carry an internal retrieval vector that the ontology view should not render —
    stripped here at the API boundary rather than in graphdb.list_nodes,
    which stays a general-purpose reader.
    """
    nodes = [n for n in graphdb.list_nodes() if n["label"] != "Vulnerability"]
    for n in nodes:
        n.pop("embedding", None)
    node_ids = {n["id"] for n in nodes}
    edges = [e for e in graphdb.list_edges() if e["srcId"] in node_ids and e["dstId"] in node_ids]
    return {"nodes": nodes, "edges": edges}


@app.get("/api/settings/risk-model", response_model=RiskModelSettings)
def get_risk_model_settings():
    return load_risk_model_settings()


@app.post("/api/settings/risk-model", response_model=RiskModelSettings)
def post_risk_model_settings(settings: RiskModelSettings):
    return save_risk_model_settings(settings)


# ---------------------------------------------------------------------------
# Incident injection, live runs, human-review queues. This is the ONLY
# execution path in the app — seed findings and CLI-injected cases both use
# it. Mutation endpoints are hidden control surfaces for democtl.sh, not
# browser application actions.
# ---------------------------------------------------------------------------
class CustomIncidentPayload(BaseModel):
    component: str
    name: Optional[str] = None
    cve: str = "N/A (custom)"
    severity: Literal["Critical", "High", "Medium", "Low"]
    cvssBase: Optional[float] = None
    epss: float
    cisaKev: bool
    runtimeReachable: bool
    affectedServiceIds: List[str]
    source: str = "Manual Entry — SOC Analyst"  # display-only: which feed/tool this looks like it came from
    simulateSandboxFailure: bool = False
    # When set, execute_remediation runs a real code fix against this repo
    # instead of the simulated adapter (see app/remediation/).
    remediationTarget: Optional[RemediationTarget] = None


class IncidentCreateRequest(BaseModel):
    preset: Optional[str] = None
    custom: Optional[CustomIncidentPayload] = None


class QueueDecisionRequest(BaseModel):
    resolved_by: str = "demo-reviewer"
    resolution_note: Optional[str] = None
    edited_name: Optional[str] = None  # ontology approve-with-edits only
    edited_definition_text: Optional[str] = None
    selected_tier: Optional[Literal["Tier 0", "Tier 1", "Tier 2", "Tier 3"]] = None


class RemediationOwnerRequest(BaseModel):
    owner_id: str
    actor: str = "demo-reviewer"


class RemediationRetryRequest(BaseModel):
    actor: str = "demo-reviewer"
    note: str = "Retry requested after remediation plan correction"


class SuppressionReopenRequest(BaseModel):
    trigger: Literal["ttl-expired", "kev-change", "epss-change", "reachability-change", "attack-path-change", "asset-change", "version-change", "control-evidence-expired"]


class OutcomeFeedbackRequest(BaseModel):
    exploitation_outcome: Literal["unknown", "observed", "not-observed"] = "unknown"
    remediation_outcome: Literal["unknown", "successful", "failed", "rolled-back", "not-applicable"] = "unknown"
    reviewer_reason_code: Optional[Literal[
        "THREAT_UNDERESTIMATED", "BUSINESS_IMPACT_UNDERESTIMATED", "REACHABILITY_INCORRECT",
        "CONTROL_EVIDENCE_INCORRECT", "POLICY_EXCEPTION", "DUPLICATE_OR_FALSE_POSITIVE", "OTHER"
    ]] = None
    note: Optional[str] = None


def _slugify(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")


def _finding_from_request(req: IncidentCreateRequest) -> tuple[RawFinding, str]:
    if req.preset:
        finding = next((f for f in FINDINGS if f.id == req.preset), None)
        if finding is None:
            raise HTTPException(status_code=404, detail=f"unknown preset '{req.preset}'")
        return finding, f"seed:{finding.id}"

    if not req.custom:
        raise HTTPException(status_code=400, detail="request must include either 'preset' or 'custom'")

    c = req.custom
    default_cvss = {"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 3.0}
    finding_id = f"custom-{uuid.uuid4().hex[:8]}"
    software_id = f"custom-sw-{_slugify(c.component)}"

    # Custom incidents have no software dropdown (per plan) — synthesize a Software
    # node from the free-text component and graph it in, so the same
    # graphdb.get_service_software_owner() path used by seed findings works unmodified.
    graphdb.upsert_node(software_id, "Software", {"name": c.component, "version": "unknown", "eolDate": None})
    for sid in c.affectedServiceIds:
        graphdb.add_edge(software_id, "RUNS_ON", sid)

    finding = RawFinding(
        id=finding_id,
        cve=c.cve,
        name=c.name or f"Custom finding — {c.component}",
        affectedComponent=c.component,
        severityLabel=c.severity,
        cvssBase=c.cvssBase if c.cvssBase is not None else default_cvss[c.severity],
        cvssSource="analyst-provided" if c.cvssBase is not None else "severity-inferred",
        demoScenario="sandbox-failure" if c.simulateSandboxFailure else "standard",
        discoveredBy="Scanner",
        affectedServiceIds=c.affectedServiceIds,
        softwareId=software_id,
        epss=c.epss,
        cisaKev=c.cisaKev,
        runtimeReachable=c.runtimeReachable,
        chainedWith=[],
        raOnBooks=False,
        remediationTarget=c.remediationTarget,
    )
    graphdb.upsert_node(
        finding_id, "Vulnerability",
        {"cve": finding.cve, "name": finding.name, "affectedComponent": finding.affectedComponent,
         "severityLabel": finding.severityLabel, "cvssBase": finding.cvssBase,
         "discoveredBy": finding.discoveredBy, "epss": finding.epss,
         "cisaKev": finding.cisaKev, "runtimeReachable": finding.runtimeReachable, "raOnBooks": finding.raOnBooks},
    )
    graphdb.add_edge(finding_id, "AFFECTS", software_id)
    return finding, c.source


@app.post("/api/_control/incidents", include_in_schema=False)
def create_incident(req: IncidentCreateRequest, background_tasks: BackgroundTasks):
    finding, incident_source = _finding_from_request(req)
    run_id = str(uuid.uuid4())
    # Pre-create the row synchronously (create_run is INSERT OR IGNORE) so GET
    # /api/incidents/{run_id} never races the background task actually starting.
    runs_db.create_run(run_id, incident_source=incident_source, finding_json=finding.model_dump_json(), status="running")
    background_tasks.add_task(start_incident_run, run_id, finding, incident_source)
    return {"run_id": run_id}


@app.get("/api/incidents")
def list_incidents():
    """
    The single unified findings queue — every run regardless of origin
    (seed:* or custom), enriched with tier/risk/owner where the run has
    reached governance so the Dashboard and History page can render one
    table with no structural difference between seeded and imported rows.
    """
    enriched = []
    for run in runs_db.list_runs():
        result = get_incident_result(run["run_id"])
        enriched.append({
            **run,
            "actionTier": result["layer2"].actionTier if result else None,
            "riskPriority": result["layer2"].riskPriority if result else None,
            "ownerName": result["layer1"].owner.name if result else None,
        })
    return enriched


@app.get("/api/incidents/{run_id}")
def get_incident(run_id: str):
    run = runs_db.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return {"run": run, "events": runs_db.list_events(run_id)}


@app.get("/api/incidents/{run_id}/result", response_model=FindingPipelineResult)
def get_incident_result_endpoint(run_id: str):
    result = get_incident_result(run_id)
    if result is None:
        raise HTTPException(status_code=409, detail="incident hasn't reached the Governance Agent yet")
    return result


@app.get("/api/incidents/{run_id}/links")
def get_incident_links(run_id: str):
    """Demo-navigation links for a run: the target GitHub repo (env-resolved, so
    it works even when the finding's remoteRepo is blank) and the real PR URL once
    remediation has opened one. Empty strings when not applicable (e.g. offline
    snapshot mode, or before a PR exists)."""
    run = runs_db.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    finding = RawFinding.model_validate_json(run["finding_json"])
    repo = ""
    if finding.remediationTarget is not None:
        repo = github_pr.resolve_repo(finding.remediationTarget.remoteRepo, finding.remediationTarget.ecosystem)
    pr_url = ""
    result = get_incident_result(run_id)
    if result:
        for e in result["verification"].evidence:
            if e.evidenceType == "deployment-proof" and e.prUrl:
                pr_url = e.prUrl
                break
    return {"repo": repo, "repoUrl": github_pr.web_repo_url(repo), "prUrl": pr_url}


@app.get("/api/incidents/{run_id}/agent-trace", response_model=AgentTrace)
def get_incident_agent_trace(run_id: str):
    """The remediation orchestrator's sub-agent trace (scanner/planner/implementer/
    tester + the bounded self-correcting loop). Only present for findings that ran
    a live code remediation (the SCA/SAST/DAST scenarios); 404 otherwise."""
    trace = runs_db.get_agent_trace(run_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="no agent trace for this run (not a live-remediation finding)")
    return trace


@app.get("/api/incidents/{run_id}/stream")
async def stream_incident(run_id: str):
    """
    SSE: polls run_events every 500ms until the run reaches a terminal status.
    Re-fetches every event each poll (the table is tiny — a run has ~10 rows)
    and only re-emits one whose finished_at has changed since last sent. A
    pure "new event_id" cursor would miss a node transitioning from started
    to finished if that update lands between two polls after the row was
    already sent once — the client would be stuck showing it as unfinished
    forever, which is exactly what happened before this fix.
    """

    async def event_source():
        last_sent_finished_at: dict[int, object] = {}
        while True:
            run = runs_db.get_run(run_id)
            if run is None:
                yield "event: error\ndata: run not found\n\n"
                return
            for ev in runs_db.list_events(run_id):
                if last_sent_finished_at.get(ev["event_id"], "__unsent__") != ev["finished_at"]:
                    last_sent_finished_at[ev["event_id"]] = ev["finished_at"]
                    yield f"data: {json.dumps(ev)}\n\n"
            yield f"event: run-status\ndata: {json.dumps(run)}\n\n"
            # Keep streaming through paused_* states too — the frontend stays subscribed
            # so it sees new events the moment a human resolves the queue item and the
            # run resumes. Only a genuinely finished run ends the stream.
            if run["status"] == "completed":
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(event_source(), media_type="text/event-stream")


@app.get("/api/queues/ontology")
def list_ontology_queue():
    return runs_db.list_ontology_queue("pending")


@app.post("/api/queues/ontology/{item_id}/approve")
def approve_ontology_item(item_id: str, req: QueueDecisionRequest):
    item = runs_db.get_ontology_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="ontology queue item not found")
    candidate = json.loads(item["candidate_category_json"])
    name = req.edited_name or candidate["name"]
    definition_text = req.edited_definition_text or candidate["definition_text"]

    # Reuse the triggering finding's governed match input so the approved
    # category clears the same gate when the checkpointed run resumes.
    run = runs_db.get_run(item["run_id"])
    triggering_finding = json.loads(run["finding_json"])
    match_embedding, embedding_mode = embed_texts([
        graphdb.finding_match_text(triggering_finding["name"], triggering_finding["affectedComponent"], triggering_finding["severityLabel"])
    ], "document")
    match_embedding = match_embedding[0]

    new_category_id = f"cat-derived-{item_id[:8]}"
    graphdb.add_category(new_category_id, name, definition_text, match_embedding, source_taxonomy=f"derived:{embedding_mode}")
    runs_db.resolve_ontology_item(item_id, "approved", req.resolved_by, req.resolution_note)
    resume_incident_run(item["run_id"], "approve")
    return {"status": "approved", "new_category_id": new_category_id}


@app.post("/api/queues/ontology/{item_id}/reject")
def reject_ontology_item(item_id: str, req: QueueDecisionRequest):
    item = runs_db.get_ontology_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="ontology queue item not found")
    runs_db.resolve_ontology_item(item_id, "rejected", req.resolved_by, req.resolution_note)
    resume_incident_run(item["run_id"], "reject")
    return {"status": "rejected"}


@app.get("/api/queues/governance")
def list_governance_queue():
    return runs_db.list_governance_queue("pending")


@app.get("/api/queues/score-review")
def list_score_review_queue():
    return runs_db.list_score_review_queue("pending")


@app.post("/api/queues/score-review/{item_id}/confirm")
def confirm_score_review(item_id: str, req: QueueDecisionRequest):
    item = runs_db.get_score_review_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="score review item not found")
    runs_db.resolve_score_review_item(item_id, "confirmed", req.resolved_by, req.resolution_note)
    resume_incident_run(item["run_id"], "confirm")
    runs_db.supersede_stale_queue_items(req.resolved_by)
    return {"status": "confirmed"}


@app.post("/api/queues/score-review/{item_id}/reclassify")
def reclassify_score_review(item_id: str, req: QueueDecisionRequest):
    item = runs_db.get_score_review_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="score review item not found")
    if req.selected_tier is None:
        raise HTTPException(status_code=400, detail="selected_tier is required")
    runs_db.resolve_score_review_item(
        item_id, "reclassified", req.resolved_by, req.resolution_note, req.selected_tier
    )
    resume_incident_run(item["run_id"], "reclassify", req.selected_tier)
    runs_db.supersede_stale_queue_items(req.resolved_by)
    return {"status": "reclassified", "selectedTier": req.selected_tier}


@app.post("/api/queues/governance/{item_id}/approve")
def approve_governance_item(item_id: str, req: QueueDecisionRequest):
    item = runs_db.get_governance_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="governance queue item not found")
    runs_db.resolve_governance_item(item_id, "approved", req.resolved_by, req.resolution_note)
    if runs_db.get_remediation_case(item["run_id"]):
        runs_db.transition_remediation(
            item["run_id"], "approved", req.resolved_by, req.resolution_note or "Human approval recorded.",
            authorization="human-approved",
        )
    resume_incident_run(item["run_id"], "approve")
    return {"status": "approved"}


@app.post("/api/queues/governance/{item_id}/reject")
def reject_governance_item(item_id: str, req: QueueDecisionRequest):
    item = runs_db.get_governance_item(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="governance queue item not found")
    runs_db.resolve_governance_item(item_id, "rejected", req.resolved_by, req.resolution_note)
    resume_incident_run(item["run_id"], "reject")
    return {"status": "rejected"}


@app.get("/api/remediations/{run_id}")
def get_remediation(run_id: str):
    result = runs_db.get_remediation_case(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="remediation case not found")
    return result


@app.post("/api/remediations/{run_id}/assign")
def assign_remediation(run_id: str, req: RemediationOwnerRequest):
    try:
        return runs_db.assign_remediation_owner(run_id, req.owner_id, req.actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/remediations/{run_id}/retry")
def retry_remediation(run_id: str, req: RemediationRetryRequest):
    current = runs_db.get_remediation_case(run_id)
    if current is None:
        raise HTTPException(status_code=404, detail="remediation case not found")
    if current["case"]["state"] != "sandbox_failed":
        raise HTTPException(status_code=409, detail="only sandbox_failed remediation can be returned for correction")
    return runs_db.transition_remediation(
        run_id, "planned", req.actor, req.note, authorization="pending", last_error=None
    )


@app.get("/api/suppressions")
def list_suppressions():
    return runs_db.list_suppression_leases()


@app.post("/api/suppressions/{run_id}/reopen")
def reopen_suppression(run_id: str, req: SuppressionReopenRequest, background_tasks: BackgroundTasks):
    lease = runs_db.get_suppression_lease(run_id)
    run = runs_db.get_run(run_id)
    if not lease or not run:
        raise HTTPException(status_code=404, detail="suppression lease not found")
    if lease["status"] != "active":
        raise HTTPException(status_code=409, detail="suppression is not active")
    successor_run_id = str(uuid.uuid4())
    finding = RawFinding.model_validate_json(run["finding_json"])
    runs_db.reopen_suppression(run_id, req.trigger, successor_run_id)
    runs_db.update_run(run_id, final_status=f"suppression reopened: {req.trigger}")
    background_tasks.add_task(start_incident_run, successor_run_id, finding, f"reopen:{run_id}:{req.trigger}")
    return {"status": "reopened", "successorRunId": successor_run_id, "trigger": req.trigger}


@app.post("/api/incidents/{run_id}/outcome")
def record_outcome(run_id: str, req: OutcomeFeedbackRequest):
    if runs_db.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="run not found")
    return runs_db.record_outcome_feedback(
        run_id, req.exploitation_outcome, req.remediation_outcome, req.reviewer_reason_code, req.note
    )


@app.get("/api/learning/summary")
def get_learning_summary():
    return runs_db.learning_summary()


@app.post("/api/settings/risk-model/backtest")
def backtest_risk_model(candidate: RiskModelSettings):
    active = load_active_risk_model_settings()
    snapshots = runs_db.list_decision_snapshots()
    labelled = [row for row in snapshots if row.get("exploitation_outcome") not in (None, "unknown")]
    if len(labelled) >= 4:
        split = max(1, int(len(labelled) * 0.7))
        evaluation = labelled[split:]
        evaluation_window = "Later 30% of outcome-labelled immutable snapshots"
    elif labelled:
        evaluation = labelled
        evaluation_window = "All outcome-labelled immutable snapshots; insufficient history for temporal holdout"
    else:
        evaluation = snapshots
        evaluation_window = "All immutable snapshots in shadow mode; no observed outcome labels yet"
    rows = []
    for snapshot in evaluation:
        finding = RawFinding.model_validate_json(snapshot["finding_json"])
        recorded = ReasoningEngineRecord.model_validate_json(snapshot["reasoning_json"])
        candidate_result = rescore_immutable_snapshot(finding, recorded, candidate)
        if recorded.actionTier != candidate_result["tier"] or recorded.riskPriority != candidate_result["score"]:
            rows.append({
                "runId": snapshot["run_id"], "finding": finding.name,
                "activeScore": recorded.riskPriority, "activeTier": recorded.actionTier,
                "candidateScore": candidate_result["score"], "candidateTier": candidate_result["tier"],
                "exploitationOutcome": snapshot.get("exploitation_outcome") or "unknown",
                "decisionAt": snapshot["decision_at"],
            })
    return {
        "activeVersion": active.version,
        "candidateVersion": candidate.version,
        "sampleCount": len(evaluation),
        "labelledSampleCount": len(labelled),
        "evaluationWindow": evaluation_window,
        "changedCount": len(rows),
        "changes": rows,
        "authoritative": False,
        "message": "Shadow backtest uses immutable decision-time inputs; no live decision or active model was changed.",
    }


@app.post("/api/_control/reset", include_in_schema=False)
def reset_demo(mode: Literal["presentation", "technical"] = "presentation"):
    """
    Wipes all runs, run telemetry, queue items, LangGraph checkpoints, and any
    curation-loop-derived Category nodes — re-seeds graph.db back to the
    original starter categories/topology, then re-bootstraps the 7 seed
    findings through the incident graph synchronously (this endpoint already
    blocks the caller behind a "Resetting..." UI state, so there's no need to
    background it the way startup does).
    """
    # Keep the whole reset deterministic. Bootstrap itself already forces
    # offline reasoning, but presentation reset also resumes paused runs; if
    # those resumes use the live LLM, reset can take minutes and an interrupted
    # request leaves the dashboard in a half-transitioned state.
    with INCIDENT_EXECUTION_LOCK, offline_reasoning():
        runs_db.clear_all()
        reset_workspaces()  # wipe live-remediation scratch clones so the demo starts clean
        reseed_graph()
        bootstrap_seed_incidents()

        if mode == "presentation":
            # Ontology curation is valuable as a deliberately injected novelty
            # scenario, but several paused seeds make the executive opening look
            # stalled. Resolve seed-only taxonomy misses with the best available
            # category, then leave exactly find-2 staged at Governance so the
            # presenter has one intentional, high-value approval moment.
            # Resolve until the graph converges rather than trusting a single
            # queue snapshot. A resumed run may legitimately reach another
            # downstream gate during the same reset.
            for _ in range(20):
                pending_ontology = runs_db.list_ontology_queue("pending")
                if not pending_ontology:
                    break
                # Routers can emit duplicate audit rows for one checkpoint.
                # Resolve every row, but resume each run exactly once; a second
                # resume would apply the ontology decision at the next gate.
                by_run = {}
                for item in pending_ontology:
                    by_run.setdefault(item["run_id"], []).append(item)
                for run_id, items in by_run.items():
                    for item in items:
                        runs_db.resolve_ontology_item(
                            item["item_id"], "rejected", "presentation-reset",
                            "Seed baseline: proceed with best available category; use a custom finding to demo curation.",
                        )
                    resume_incident_run(run_id, "reject")
            else:
                raise HTTPException(status_code=500, detail="presentation reset did not clear ontology review")

            staged_run_id = None
            for _ in range(20):
                actionable_by_run = {}
                staged_items = []
                for item in runs_db.list_governance_queue("pending"):
                    run = runs_db.get_run(item["run_id"])
                    if run and run["incident_source"] == "seed:find-2":
                        staged_run_id = item["run_id"]
                        staged_items.append(item)
                    else:
                        actionable_by_run.setdefault(item["run_id"], []).append(item)

                # Preserve one current staged decision and retire duplicate
                # router audit rows so the UI always shows one approval card.
                for duplicate in staged_items[1:]:
                    runs_db.resolve_governance_item(
                        duplicate["item_id"], "superseded", "presentation-reset",
                        "Duplicate router audit row; newest staged decision retained.",
                    )

                if not actionable_by_run:
                    break
                for run_id, items in actionable_by_run.items():
                    for item in items:
                        runs_db.resolve_governance_item(
                            item["item_id"], "approved", "presentation-reset",
                            "Pre-resolved baseline case for repeatable executive demo.",
                        )
                    resume_incident_run(run_id, "approve")
            else:
                raise HTTPException(status_code=500, detail="presentation reset did not converge at governance review")

            runs_db.supersede_stale_queue_items("presentation-reset")

            runs = runs_db.list_runs()
            pending_ontology = runs_db.list_ontology_queue("pending")
            pending_scores = runs_db.list_score_review_queue("pending")
            pending_governance = runs_db.list_governance_queue("pending")
            staged_items = [
                item for item in pending_governance
                if (run := runs_db.get_run(item["run_id"])) and run["incident_source"] == "seed:find-2"
            ]
            incomplete_other_runs = [
                run for run in runs
                if run["incident_source"] != "seed:find-2" and run["status"] != "completed"
            ]
            if (
                len(runs) != len(FINDINGS)
                or pending_ontology
                or pending_scores
                or len(pending_governance) != 1
                or len(staged_items) != 1
                or incomplete_other_runs
            ):
                raise HTTPException(status_code=500, detail={
                    "message": "presentation reset failed baseline invariants",
                    "runCount": len(runs),
                    "pendingOntology": len(pending_ontology),
                    "pendingScoreReviews": len(pending_scores),
                    "pendingGovernance": len(pending_governance),
                    "stagedFind2": len(staged_items),
                    "incompleteOtherRuns": [run["incident_source"] for run in incomplete_other_runs],
                    "runStates": {run["incident_source"]: run["status"] for run in runs},
                })
            return {"status": "reset", "mode": mode, "stagedRunId": staged_run_id}

        return {"status": "reset", "mode": mode, "stagedRunId": None}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
