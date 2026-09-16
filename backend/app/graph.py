"""
LangGraph orchestration for the CTEM pipeline.

There is exactly one graph, used for every finding regardless of where it
came from — the 7 seed findings (bootstrapped once via bootstrap_seed_incidents,
below) and anything injected live through the dashboard both run through the
same COMPILED_INCIDENT_GRAPH, with the same checkpointed pause/resume
semantics and the same human-review gates. That's deliberate: seeded and
imported findings must be indistinguishable once they've run, sitting in the
same runs_db-backed queue on the Dashboard and History page.

    context_graph -> parallel_enrichment -> enrichment_join
                         |       |       |             |
                    evidence  ontology  approved       |
                    quality    match    knowledge      |
                                                    confident match?
                                                       |       |
                                                      NO      YES
                                                       v       v
                                      ontology_review_gate   reasoning_engine
                          |
                     triage_agent
                          |
      suppressed? ---- YES ----> skip_remediation --+
                          |                           |
                          NO                          |
                          v                            v
                    planning_agent -> implementation_agent -> governance_agent
                                                                     |
                                            auto-approved? ---- YES -------> execute
                                            else -----------------------> governance_review_gate (pause)
                                                                                  |
                                                             approve? -- YES --> execute
                                                             else ------------> blocked_review

    execute -> independent_verification -> finalize_closure

Three genuine decision points, not a fixed linear chain:
  1. Category match (ontology_review_gate) — a finding that doesn't confidently
     match a known vulnerability category pauses for a human to approve or
     reject a new category before scoring continues.
  2. Triage (skip_remediation) — a finding with no active exploit signal and
     no runtime reachability skips Planning/Implementation entirely (and
     their LLM calls).
  3. Governance (governance_review_gate) — auto-approved findings close
     immediately; anything else pauses for a human, who can still approve
     (auto-close) or reject (blocked pending policy review).

Authoritative decisions remain sequential. Only independent, read-only
enrichment runs concurrently, and an explicit join blocks scoring until its
required outputs are present. Every orchestrator node appends to route_path;
parallel child spans are persisted as overlapping run events.

Two outer feedback loops surround this per-run graph. Suppression leases can
create a correlated successor run after TTL or a material context trigger.
Outcome telemetry feeds governed backtest/shadow evaluation; only an approved,
versioned model can affect the reasoning_engine on future runs. Neither loop
mutates the historical decision recorded by this graph.
"""
import functools
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import sys
import threading
import time
import uuid
from typing import TypedDict, Annotated, List, Optional
import operator

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import StateGraph, END

from app import graphdb
from app.data.seed import FINDINGS
from app.data import runs_db
from app.llm import llm_reason, offline_reasoning
from app.models import (
    RawFinding,
    ContextGraphRecord,
    ReasoningEngineRecord,
    TriageAgentOutput,
    PlanningAgentOutput,
    ImplementationAgentOutput,
    GovernanceAgentOutput,
    DataQualityAssessment,
    PlausibilityAssessment,
    VerificationRecord,
    VerificationEvidence,
)
from app.decision_assurance import assess_data_quality, judge_plausibility
from app.verification import collect_demo_adapter_evidence, verification_not_run, verify_adapter_evidence
from app.remediation.live_adapter import safe_run_live_remediation
from app.retrieval import embed_texts, retrieve
from app.layer1.context_graph import build_context_graph_record
from app.layer2.reasoning_engine import run_reasoning_engine
from app.layer3.triage_agent import run_triage_agent
from app.layer3.planning_agent import run_planning_agent, suppressed_planning_stub
from app.layer3.implementation_agent import run_implementation_agent, suppressed_implementation_stub
from app.layer3.governance_agent import run_governance_agent


class PipelineState(TypedDict, total=False):
    finding: RawFinding
    ctx: ContextGraphRecord
    quality: DataQualityAssessment
    reasoning: ReasoningEngineRecord
    plausibility: PlausibilityAssessment
    triage: TriageAgentOutput
    planning: PlanningAgentOutput
    implementation: ImplementationAgentOutput
    governance: GovernanceAgentOutput
    verification: VerificationRecord
    execution_evidence: List[VerificationEvidence]
    route_path: Annotated[List[str], operator.add]
    final_status: str
    t_start: float
    t_context: float
    t_validate: float
    t_mitigate: float
    run_id: Optional[str]
    category_match_result: Optional[dict]
    retrieval_context: Optional[dict]
    human_decision: Optional[str]
    score_review_tier: Optional[str]


def _json_safe(obj) -> str:
    def default(o):
        if hasattr(o, "model_dump"):
            return o.model_dump()
        return str(o)

    try:
        return json.dumps(obj, default=default)
    except TypeError:
        return json.dumps(str(obj))


def traced(node_name: str):
    """
    Writes a run_events row on entry/exit of the wrapped node — a no-op
    (beyond calling the node) when state has no run_id, so this is safe to
    apply universally to every node regardless of which caller invoked the
    graph (every caller sets run_id today, but a bare .invoke() without one
    still degrades gracefully rather than erroring).
    """

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(state: PipelineState) -> dict:
            run_id = state.get("run_id")
            t0 = time.time()
            event_id = runs_db.log_event_start(run_id, node_name, _json_safe(state)) if run_id else None
            result = fn(state)
            if run_id and event_id:
                runs_db.log_event_end(event_id, _json_safe(result), (time.time() - t0) * 1000)
            return result

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
@traced("context_graph")
def node_context_graph(state: PipelineState) -> dict:
    ctx = build_context_graph_record(state["finding"])
    return {"ctx": ctx, "route_path": ["context_graph"], "t_context": time.time()}


@traced("reasoning_engine")
def node_reasoning_engine(state: PipelineState) -> dict:
    reasoning = run_reasoning_engine(state["finding"], state["ctx"])
    if state.get("run_id"):
        runs_db.record_decision_snapshot(
            state["run_id"], _json_safe(state["finding"]), _json_safe(state["ctx"]),
            _json_safe(reasoning), reasoning.riskModelVersion,
        )
    return {"reasoning": reasoning, "route_path": ["reasoning_engine"]}


@traced("data_quality")
def node_data_quality(state: PipelineState) -> dict:
    quality = assess_data_quality(state["finding"], state["ctx"])
    return {"quality": quality, "route_path": ["data_quality"]}


def _trace_parallel_branch(run_id: Optional[str], node_name: str, input_snapshot: dict, work):
    """Run one read-only enrichment branch with its own overlapping audit span."""
    t0 = time.time()
    event_id = runs_db.log_event_start(run_id, node_name, _json_safe(input_snapshot)) if run_id else None
    result = work()
    if run_id and event_id:
        runs_db.log_event_end(event_id, _json_safe(result), (time.time() - t0) * 1000)
    return result


def _prefetch_approved_knowledge(finding: RawFinding, ctx: ContextGraphRecord) -> dict:
    base = (
        f"{finding.name} {finding.cve} {finding.affectedComponent} {finding.severityLabel} "
        f"services {' '.join(service.name for service in ctx.services)}"
    )
    return {
        "triage": retrieve(f"{base} triage suppression", {"precedent", "policy"}),
        "planning": retrieve(f"{base} remediation mitigation", {"runbook", "precedent", "policy"}),
        "implementation": retrieve(f"{base} implementation tests rollback", {"runbook", "precedent"}),
        "governance": retrieve(f"{base} production authorization governance", {"policy", "precedent"}),
    }


@traced("parallel_enrichment")
def node_parallel_enrichment(state: PipelineState) -> dict:
    """Fan out independent, read-only enrichment and join their typed results."""
    finding, ctx, run_id = state["finding"], state["ctx"], state.get("run_id")
    branch_input = {"finding": finding, "ctx": ctx}
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="ctem-enrichment") as pool:
        quality_future = pool.submit(
            _trace_parallel_branch, run_id, "evidence_quality_enrichment", branch_input,
            lambda: {"quality": assess_data_quality(finding, ctx)},
        )
        category_future = pool.submit(
            _trace_parallel_branch, run_id, "ontology_match_enrichment", branch_input,
            lambda: _category_match_payload(finding),
        )
        retrieval_future = pool.submit(
            _trace_parallel_branch, run_id, "knowledge_retrieval_enrichment", branch_input,
            lambda: {"retrieval_context": _prefetch_approved_knowledge(finding, ctx)},
        )
        quality = quality_future.result()["quality"]
        category = category_future.result()["category_match_result"]
        retrieval_context = retrieval_future.result()["retrieval_context"]
    return {
        "quality": quality,
        "category_match_result": category,
        "retrieval_context": retrieval_context,
        "route_path": ["parallel_enrichment"],
    }


@traced("enrichment_join")
def node_enrichment_join(state: PipelineState) -> dict:
    missing = [key for key in ("quality", "category_match_result", "retrieval_context") if not state.get(key)]
    if missing:
        raise RuntimeError(f"enrichment join missing required branches: {', '.join(missing)}")
    return {"route_path": ["enrichment_join"]}


@traced("plausibility_judge")
def node_plausibility_judge(state: PipelineState) -> dict:
    assessment = judge_plausibility(
        state["finding"], state["ctx"], state["reasoning"], state["quality"]
    )
    return {"plausibility": assessment, "route_path": ["plausibility_judge"]}


def route_after_plausibility(state: PipelineState) -> str:
    if state["plausibility"].recommendedAction == "proceed":
        return "triage_agent"
    item_id = str(uuid.uuid4())
    runs_db.create_score_review_item(
        item_id,
        state["run_id"],
        _json_safe(state["plausibility"]),
        _json_safe(state["reasoning"]),
    )
    runs_db.update_run(state["run_id"], status="paused_score_review", current_node="score_review_gate")
    return "score_review_gate"


@traced("score_review_gate")
def node_score_review_gate(state: PipelineState) -> dict:
    reasoning = state["reasoning"]
    if state.get("human_decision") == "reclassify" and state.get("score_review_tier"):
        tier = state["score_review_tier"]
        labels = {
            "Tier 0": "Immediate auto-contain + incident",
            "Tier 1": "Patch in <24h",
            "Tier 2": "Change window within 72h",
            "Tier 3": "Backlog / preventive hardening",
        }
        reasoning = reasoning.model_copy(update={
            "actionTier": tier,
            "actionTierLabel": labels[tier],
            "decisionMethod": "deterministic-model+human-override",
            "policyOverrides": [*reasoning.policyOverrides, f"HUMAN-SCORE-REVIEW: reclassified to {tier}"],
        })
    return {"reasoning": reasoning, "route_path": ["score_review_gate"]}


@traced("triage_agent")
def node_triage(state: PipelineState) -> dict:
    triage = run_triage_agent(
        state["finding"], state["ctx"], state["reasoning"],
        (state.get("retrieval_context") or {}).get("triage"),
    )
    return {"triage": triage, "route_path": ["triage_agent"], "t_validate": time.time()}


def route_after_triage(state: PipelineState) -> str:
    return "skip_remediation" if state["triage"].suppressed else "planning_agent"


@traced("skip_remediation")
def node_skip_remediation(state: PipelineState) -> dict:
    planning = suppressed_planning_stub(state["finding"], state["ctx"])
    implementation = suppressed_implementation_stub(state["finding"])
    if state.get("run_id"):
        runs_db.ensure_suppression_lease(
            state["run_id"],
            "No active exploit signal and no observed runtime reachability",
            ttl_days=14,
        )
    return {"planning": planning, "implementation": implementation, "route_path": ["skip_remediation"]}


@traced("planning_agent")
def node_planning(state: PipelineState) -> dict:
    planning = run_planning_agent(
        state["finding"], state["ctx"], state["reasoning"],
        (state.get("retrieval_context") or {}).get("planning"),
    )
    if state.get("run_id"):
        runs_db.ensure_remediation_case(state["run_id"], planning.routedOwnerId)
    return {"planning": planning, "route_path": ["planning_agent"]}


@traced("implementation_agent")
def node_implementation(state: PipelineState) -> dict:
    implementation = run_implementation_agent(
        state["finding"], state["planning"],
        (state.get("retrieval_context") or {}).get("implementation"),
    )
    if state.get("run_id"):
        runs_db.transition_remediation(
            state["run_id"], "implementation_drafted", "implementation_agent",
            "Patch, tests, and rationale drafted; no production action taken.",
        )
    return {"implementation": implementation, "route_path": ["implementation_agent"]}


@traced("governance_agent")
def node_governance(state: PipelineState) -> dict:
    governance = run_governance_agent(
        state["finding"], state["ctx"], state["reasoning"], state["implementation"],
        (state.get("retrieval_context") or {}).get("governance"),
    )
    if state.get("run_id") and not state["triage"].suppressed:
        if governance.approvalStatus == "auto-approved":
            runs_db.transition_remediation(
                state["run_id"], "approved", "governance_agent", "Within automated policy boundary.",
                authorization="auto-approved",
            )
        elif governance.approvalStatus == "blocked":
            runs_db.transition_remediation(
                state["run_id"], "blocked", "governance_agent", "Policy check failed.", authorization="blocked"
            )
        else:
            existing = runs_db.get_remediation_case(state["run_id"])
            if existing and existing["case"]["authorization"] == "human-approved":
                runs_db.transition_remediation(
                    state["run_id"], "approved", "checkpoint-resume", "Existing human authorization preserved.",
                    authorization="human-approved",
                )
            else:
                runs_db.transition_remediation(
                    state["run_id"], "awaiting_approval", "governance_agent", "Human sign-off required.",
                    authorization="pending",
                )
    return {"governance": governance, "route_path": ["governance_agent"], "t_mitigate": time.time()}


@traced("auto_close")
def node_auto_close(state: PipelineState) -> dict:
    return {
        "verification": verification_not_run(state["finding"]),
        "final_status": "suppressed — no remediation executed",
        "route_path": ["auto_close"],
    }


@traced("execute_remediation")
def node_execute_remediation(state: PipelineState) -> dict:
    """Execute only after policy/human authorization; never certify closure here."""
    finding = _as(RawFinding, state["finding"])
    if finding.remediationTarget is not None:
        # Real remediation against a real repo, run by the sub-agent orchestrator:
        # scan -> (plan -> implement -> test)* -> (PR) -> runtime probe. Evidence is
        # source="live-integration"; the orchestration trace is persisted separately.
        live = safe_run_live_remediation(finding, state.get("run_id") or "adhoc")
        evidence = live.evidence
        if state.get("run_id") and live.trace is not None:
            try:
                runs_db.save_agent_trace(state["run_id"], live.trace.model_dump_json())
            except Exception as exc:  # pragma: no cover - never fail the pipeline on telemetry
                print(f"[graph] failed to persist agent trace: {exc}", file=sys.stderr)
    else:
        evidence = collect_demo_adapter_evidence(finding, state["implementation"])
    sandbox_passed = next(item for item in evidence if item.evidenceType == "sandbox-test").result == "pass"
    if state.get("run_id"):
        runs_db.transition_remediation(
            state["run_id"], "sandbox_validating", "implementation_agent", "Executing generated tests in demo sandbox."
        )
        if sandbox_passed:
            runs_db.transition_remediation(
                state["run_id"], "deployed", "demo-cicd-adapter", "Authorized change deployed (simulated adapter)."
            )
        else:
            runs_db.transition_remediation(
                state["run_id"], "sandbox_failed", "verification_engine",
                "Contract test failed; deployment blocked.", last_error="Sandbox contract test failed"
            )
    return {"execution_evidence": evidence, "route_path": ["execute_remediation"]}


@traced("independent_verification")
def node_independent_verification(state: PipelineState) -> dict:
    """A deterministic verifier evaluates adapter evidence it did not create."""
    verification = verify_adapter_evidence(state["finding"], state["execution_evidence"])
    if state.get("run_id") and verification.verifiedClosed:
        runs_db.transition_remediation(
            state["run_id"], "verified_closed", "verification_engine",
            "Independent sandbox, deployment, rescan, and runtime-path evidence passed."
        )
    return {"verification": verification, "route_path": ["independent_verification"]}


@traced("finalize_closure")
def node_finalize_closure(state: PipelineState) -> dict:
    verification = state["verification"]
    if verification.verifiedClosed:
        provenance = "live evidence" if verification.evidenceMode == "LIVE" else "simulated evidence"
        final_status = f"verified closed ({provenance})"
    else:
        final_status = "verification failed — deployment blocked"
    return {"final_status": final_status, "route_path": ["finalize_closure"]}


@traced("blocked_review")
def node_blocked_review(state: PipelineState) -> dict:
    if state.get("run_id") and not state["triage"].suppressed:
        runs_db.transition_remediation(
            state["run_id"], "blocked", "human-review", "Governance approval rejected.", authorization="rejected"
        )
    return {
        "verification": verification_not_run(state["finding"]),
        "final_status": "blocked pending policy review",
        "route_path": ["blocked_review"],
    }


# ---------------------------------------------------------------------------
# Category match + ontology review gate
# ---------------------------------------------------------------------------
CATEGORY_MATCH_THRESHOLD = 0.4
MAX_ONTOLOGY_ROUNDS = 3


def _draft_category_candidate(finding: RawFinding) -> dict:
    """
    Name/definition are built deterministically from the finding's own
    fields so approval-time retrieval reliably clears the same governed
    category gate. The LLM (offline-fallback safe, per llm.py) only drafts the
    free-text rationale — narrative only, never a decision, matching this
    codebase's existing LLM boundary (see layer3/*_agent.py).
    """
    name = f"{finding.affectedComponent} — {finding.severityLabel} Severity Findings"
    definition_text = (
        f"Findings affecting {finding.affectedComponent}, matching the pattern of {finding.name} "
        f"({finding.severityLabel} severity, discovered by {finding.discoveredBy})."
    )
    rationale = llm_reason(
        "You are the Ontology Curation reviewer's assistant in a CTEM pipeline. Given a finding that "
        "didn't confidently match any existing vulnerability category, draft a short rationale for why "
        "a new category is warranted.",
        f"finding={finding.model_dump()}",
    )
    return {"name": name, "definition_text": definition_text, "source_taxonomy": "derived", "rationale": rationale}


@traced("category_match")
def node_category_match(state: PipelineState) -> dict:
    return {**_category_match_payload(state["finding"]), "route_path": ["category_match"]}


def _category_match_payload(finding: RawFinding) -> dict:
    governed_category, governed_confidence, match_method = graphdb.governed_category_match(finding)
    if governed_category:
        return {
            "category_match_result": {
                "category": governed_category,
                "confidence": governed_confidence,
                "retrievalMode": "governed-taxonomy",
                "matchMethod": match_method,
            }
        }
    text = graphdb.finding_match_text(finding.name, finding.affectedComponent, finding.severityLabel)
    embedding, embedding_mode = embed_texts([text], "query")
    embedding = embedding[0]
    category, confidence = graphdb.match_category(embedding)
    return {
        "category_match_result": {
            "category": category,
            "confidence": confidence,
            "retrievalMode": embedding_mode,
            "matchMethod": "semantic" if embedding_mode.startswith("semantic:") else "lexical-fallback",
        },
    }


def route_after_category_match(state: PipelineState) -> str:
    match = state.get("category_match_result") or {}
    if match.get("confidence", 0.0) >= CATEGORY_MATCH_THRESHOLD:
        return "reasoning_engine"

    # Safety valve: category_match/ontology_review_gate is designed to loop back and
    # re-match after an approval, which should always clear the threshold on the next
    # round (see graphdb.finding_match_text's docstring). If a reviewer edits the
    # candidate text drastically before approving, re-match could still miss — cap the
    # rounds so a run can never loop forever, and proceed with best-available instead.
    match_rounds = state["route_path"].count("category_match") + state["route_path"].count("parallel_enrichment")
    if match_rounds >= MAX_ONTOLOGY_ROUNDS:
        return "reasoning_engine"

    # Side-effecting router: this is the last node to run before the graph
    # interrupts (interrupt_before=["ontology_review_gate"]) — the gate node
    # itself won't execute until resume, so the queue write has to happen
    # here, where category_match's output is still in scope.
    run_id = state["run_id"]
    finding = state["finding"]
    candidate = _draft_category_candidate(finding)
    duplicate = graphdb.find_duplicate_category(candidate["name"])
    if duplicate:
        return "reasoning_engine"
    item_id = str(uuid.uuid4())
    runs_db.create_ontology_item(
        item_id, run_id, candidate_category_json=json.dumps(candidate), precedent_json=_json_safe(state.get("category_match_result"))
    )
    runs_db.update_run(run_id, status="paused_ontology_review", current_node="ontology_review_gate")
    return "ontology_review_gate"


@traced("ontology_review_gate")
def node_ontology_review_gate(state: PipelineState) -> dict:
    # Only ever executes on resume (interrupt_before stops the graph just
    # before this node); by the time it runs, human_decision is already set.
    return {"route_path": ["ontology_review_gate"]}


def route_after_ontology_gate(state: PipelineState) -> str:
    if state.get("human_decision") == "approve":
        return "category_match"  # re-match now that the new Category node exists
    return "reasoning_engine"  # rejected — proceed with the best-available (low-confidence) category


# ---------------------------------------------------------------------------
# Governance review gate
# ---------------------------------------------------------------------------
def route_after_governance_gated(state: PipelineState) -> str:
    if state["triage"].suppressed:
        return "auto_close"
    status = state["governance"].approvalStatus
    if status == "auto-approved":
        return "execute_remediation"

    run_id = state["run_id"]
    item_id = str(uuid.uuid4())
    runs_db.create_governance_item(
        item_id, run_id,
        reason="blocked" if status == "blocked" else "pending_approval",
        details_json=_json_safe(state["governance"]),
    )
    runs_db.update_run(run_id, status="paused_governance_review", current_node="governance_review_gate")
    return "governance_review_gate"


@traced("governance_review_gate")
def node_governance_review_gate(state: PipelineState) -> dict:
    return {"route_path": ["governance_review_gate"]}


def route_after_governance_gate(state: PipelineState) -> str:
    if state.get("human_decision") == "approve":
        return "execute_remediation"
    return "blocked_review"


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------
def build_incident_graph():
    graph = StateGraph(PipelineState)

    graph.add_node("context_graph", node_context_graph)
    graph.add_node("parallel_enrichment", node_parallel_enrichment)
    graph.add_node("enrichment_join", node_enrichment_join)
    graph.add_node("category_match", node_category_match)
    graph.add_node("ontology_review_gate", node_ontology_review_gate)
    graph.add_node("reasoning_engine", node_reasoning_engine)
    graph.add_node("plausibility_judge", node_plausibility_judge)
    graph.add_node("score_review_gate", node_score_review_gate)
    graph.add_node("triage_agent", node_triage)
    graph.add_node("skip_remediation", node_skip_remediation)
    graph.add_node("planning_agent", node_planning)
    graph.add_node("implementation_agent", node_implementation)
    graph.add_node("governance_agent", node_governance)
    graph.add_node("governance_review_gate", node_governance_review_gate)
    graph.add_node("auto_close", node_auto_close)
    graph.add_node("execute_remediation", node_execute_remediation)
    graph.add_node("independent_verification", node_independent_verification)
    graph.add_node("finalize_closure", node_finalize_closure)
    graph.add_node("blocked_review", node_blocked_review)

    graph.set_entry_point("context_graph")
    graph.add_edge("context_graph", "parallel_enrichment")
    graph.add_edge("parallel_enrichment", "enrichment_join")

    graph.add_conditional_edges(
        "enrichment_join",
        route_after_category_match,
        {"reasoning_engine": "reasoning_engine", "ontology_review_gate": "ontology_review_gate"},
    )
    graph.add_conditional_edges(
        "category_match",
        route_after_category_match,
        {"reasoning_engine": "reasoning_engine", "ontology_review_gate": "ontology_review_gate"},
    )
    graph.add_conditional_edges(
        "ontology_review_gate",
        route_after_ontology_gate,
        {"category_match": "category_match", "reasoning_engine": "reasoning_engine"},
    )

    graph.add_edge("reasoning_engine", "plausibility_judge")
    graph.add_conditional_edges(
        "plausibility_judge", route_after_plausibility,
        {"triage_agent": "triage_agent", "score_review_gate": "score_review_gate"},
    )
    graph.add_edge("score_review_gate", "triage_agent")
    graph.add_conditional_edges(
        "triage_agent",
        route_after_triage,
        {"skip_remediation": "skip_remediation", "planning_agent": "planning_agent"},
    )
    graph.add_edge("skip_remediation", "governance_agent")
    graph.add_edge("planning_agent", "implementation_agent")
    graph.add_edge("implementation_agent", "governance_agent")

    graph.add_conditional_edges(
        "governance_agent",
        route_after_governance_gated,
        {
            "auto_close": "auto_close",
            "execute_remediation": "execute_remediation",
            "governance_review_gate": "governance_review_gate",
        },
    )
    graph.add_conditional_edges(
        "governance_review_gate",
        route_after_governance_gate,
        {"execute_remediation": "execute_remediation", "blocked_review": "blocked_review"},
    )
    graph.add_edge("execute_remediation", "independent_verification")
    graph.add_edge("independent_verification", "finalize_closure")
    graph.add_edge("finalize_closure", END)
    graph.add_edge("auto_close", END)
    graph.add_edge("blocked_review", END)

    _checkpoint_conn = sqlite3.connect(runs_db.DB_PATH, timeout=30, check_same_thread=False)
    _checkpoint_conn.execute("PRAGMA journal_mode=WAL")
    _checkpoint_conn.execute("PRAGMA busy_timeout=30000")
    checkpointer = SqliteSaver(_checkpoint_conn)
    checkpointer.setup()

    return graph.compile(
        checkpointer=checkpointer,
        interrupt_before=["ontology_review_gate", "score_review_gate", "governance_review_gate"],
    )


COMPILED_INCIDENT_GRAPH = build_incident_graph()
INCIDENT_EXECUTION_LOCK = threading.RLock()  # reset/bootstrap coordination only
_RUN_GRAPH_REGISTRY_LOCK = threading.Lock()
_RUN_GRAPHS: dict[str, object] = {}
_RUN_LOCKS: dict[str, threading.RLock] = {}


def _graph_for_run(run_id: str):
    with _RUN_GRAPH_REGISTRY_LOCK:
        if run_id not in _RUN_GRAPHS:
            _RUN_GRAPHS[run_id] = build_incident_graph()
            _RUN_LOCKS[run_id] = threading.RLock()
        return _RUN_GRAPHS[run_id], _RUN_LOCKS[run_id]


def _is_paused(run_id: str, graph=None) -> bool:
    config = {"configurable": {"thread_id": run_id}}
    graph = graph or _graph_for_run(run_id)[0]
    snapshot = graph.get_state(config)
    return bool(snapshot.next)


def _settle_run(run_id: str, state: dict, graph=None) -> None:
    if _is_paused(run_id, graph):
        return  # the gated router already set runs.status/current_node before pausing
    runs_db.update_run(run_id, status="completed", current_node="", final_status=state.get("final_status"), completed=True)


def start_incident_run(run_id: str, finding: RawFinding, incident_source: str) -> dict:
    graph, run_lock = _graph_for_run(run_id)
    with run_lock:
        runs_db.create_run(run_id, incident_source=incident_source, finding_json=_json_safe(finding))
        t_start = time.time()
        initial_state: PipelineState = {"finding": finding, "route_path": [], "t_start": t_start, "run_id": run_id}
        config = {"configurable": {"thread_id": run_id}}
        final_state = graph.invoke(initial_state, config=config)
        _settle_run(run_id, final_state, graph)
        return final_state


def resume_incident_run(run_id: str, human_decision: str, score_review_tier: Optional[str] = None) -> dict:
    graph, run_lock = _graph_for_run(run_id)
    with run_lock:
        config = {"configurable": {"thread_id": run_id}}
        update = {"human_decision": human_decision}
        if score_review_tier:
            update["score_review_tier"] = score_review_tier
        graph.update_state(config, update)
        runs_db.update_run(run_id, status="running", current_node=None)
        final_state = graph.invoke(None, config=config)
        _settle_run(run_id, final_state, graph)
        return final_state


def bootstrap_seed_incidents() -> None:
    """
    Runs each of the 7 seed findings (backend/app/data/seed.py) through the
    same incident graph used for live-injected incidents, tagged
    incident_source="seed:{finding.id}" — so they show up in the same
    runs_db-backed queue (GET /api/incidents) as anything injected live, with
    no structural difference on the Dashboard or History page. Idempotent:
    skips any seed finding that already has a run, so this is safe to call
    on every startup. A seed finding can pause for ontology/governance review
    exactly like a live one — that's intentional, not a bug to route around.
    """
    # Seed bootstrap must be fast and repeatable even when a live API key is
    # configured. Custom incidents still use live narratives when enabled.
    with INCIDENT_EXECUTION_LOCK, offline_reasoning():
        for finding in FINDINGS:
            source = f"seed:{finding.id}"
            if runs_db.get_run_by_source(source) is not None:
                continue
            start_incident_run(str(uuid.uuid4()), finding, source)


def _as(model_cls, value):
    """
    Normalizes a checkpoint-restored state value back into its Pydantic model
    instance. A fresh (non-checkpointed) graph.invoke() always hands node
    functions real model instances, but a value restored from
    COMPILED_INCIDENT_GRAPH.get_state() after a SqliteSaver round-trip isn't
    guaranteed to still be one (langgraph's serde can hand back a plain dict)
    — and downstream code (compute_kpis, response_model coercion) relies on
    attribute access like r["layer2"].actionTier, not r["layer2"]["actionTier"].
    """
    return value if isinstance(value, model_cls) else model_cls(**value)


def get_incident_result(run_id: str) -> Optional[dict]:
    """
    Reconstructs a FindingPipelineResult-shaped dict from a run's LangGraph
    checkpoint — the single source of truth for /api/incidents/{id}/result,
    /api/incidents/results (bulk, used by History + KPIs), and the enriched
    tier/riskPriority columns on GET /api/incidents.

    Gated on the Governance Agent having run: a run paused at
    ontology_review_gate hasn't computed reasoning/triage/planning/
    implementation/governance yet, so there's nothing coherent to show. A run
    paused at governance_review_gate (or fully completed) always has the full
    shape, since node_governance runs before that gate. Callers should treat
    None as "not ready for a triage view yet".
    """
    config = {"configurable": {"thread_id": run_id}}
    snapshot = _graph_for_run(run_id)[0].get_state(config)
    state = snapshot.values
    if not state or "governance" not in state:
        return None

    t_start = state["t_start"]
    to_ms = lambda t: round((t - t_start) * 1000, 2)
    measured = runs_db.get_metric_observation(run_id)
    finding = _as(RawFinding, state["finding"])
    context = _as(ContextGraphRecord, state["ctx"])
    reasoning = _as(ReasoningEngineRecord, state["reasoning"])
    quality = (
        _as(DataQualityAssessment, state["quality"])
        if state.get("quality")
        else assess_data_quality(finding, context)
    )
    plausibility = (
        _as(PlausibilityAssessment, state["plausibility"])
        if state.get("plausibility")
        else PlausibilityAssessment(
            findingId=finding.id,
            assessment="questionable",
            confidence=0.5,
            concerns=["Legacy run predates decision-assurance controls; rerun before relying on this decision"],
            recommendedAction="human-score-review",
            advisoryNarrative="Legacy checkpoint — no plausibility assessment was captured.",
        )
    )
    verification = (
        _as(VerificationRecord, state["verification"])
        if state.get("verification")
        else verification_not_run(finding)
    )

    return {
        "runId": run_id,
        "finding": finding,
        "layer1": context,
        "dataQuality": quality,
        "layer2": reasoning,
        "plausibility": plausibility,
        "triage": _as(TriageAgentOutput, state["triage"]),
        "planning": _as(PlanningAgentOutput, state["planning"]),
        "implementation": _as(ImplementationAgentOutput, state["implementation"]),
        "governance": _as(GovernanceAgentOutput, state["governance"]),
        "verification": verification,
        "timings": {
            "contextualizedAtMs": measured.get("contextualizeMs", to_ms(state["t_context"])),
            "validatedAtMs": measured.get("validateMs", to_ms(state["t_validate"])),
            "mitigatedAtMs": measured.get("mitigateMs", to_ms(state["t_mitigate"])),
            # Zero means no verified closure event exists. Never estimate it.
            "exploitPathClosedAtMs": measured.get("closureMs", 0.0),
        },
        "routePath": state["route_path"],
        "finalStatus": state.get("final_status") or "pending human review",
    }
