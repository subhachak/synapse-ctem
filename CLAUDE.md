# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Mphasis Synapse CTEM** — a working demo of a **3-layer CTEM (Continuous Threat Exposure Management) stack**, built from scratch. Python + FastAPI + LangGraph backend, Next.js frontend. It is client-agnostic: every entity name is synthetic and domain-neutral, intended for GTM demos across verticals. The scoring dimensions, agents, and KPI definitions follow the 3-layer reference architecture (see `README.md`) — read that before changing scoring logic or KPI definitions.

The three layers:
- **Layer 1 — Context Graph & Threat Ontology** (`backend/app/layer1/context_graph.py`, `backend/app/graphdb.py`): fuses Services/Software/Owners/Categories/Reachability per finding, backed by a SQLite graph store standing in for Neo4j.
- **Layer 2 — Adversarial Reasoning Engine** (`backend/app/layer2/reasoning_engine.py`): deterministic `Risk Priority` formula + Tier 0–3 action tiering.
- **Layer 3 — Agentic AI** (`backend/app/layer3/*_agent.py`): Triage → Planning → Implementation → Governance agents, orchestrated by a single, genuinely branching, checkpointed LangGraph `StateGraph`.

- `backend/` — Python, FastAPI, orchestrated with LangGraph
- `frontend/` — Next.js (Pages Router, TypeScript)
- `run.sh` — starts/stops both servers together and opens the demo in Chrome (see below)

## Commands

### Fastest path: run.sh
```bash
./run.sh start     # starts backend (:8000) + frontend (:3000), opens Chrome
./run.sh stop       # stops both, killing the full process tree
./run.sh restart
./run.sh status
```

### Backend
```bash
cd backend
python3 -m venv venv          # note: "venv", not ".venv" — matches run.sh
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # add ANTHROPIC_API_KEY, or leave blank for offline mode
python -m uvicorn app.main:app --reload --port 8000
```
A test suite lives in `backend/tests/` (32 tests: reasoning-engine scoring, graph smoke, workflow
persistence, decision assurance, verification, live remediation). It is written against the stdlib
runner, so either works:

```bash
pip install -r requirements-dev.txt   # optional, for pytest
python -m unittest discover -s tests  # no extra deps
python -m pytest tests -q
```

The tests read the seeded graph store, so on a fresh clone bootstrap it first or 16 of them error
with `software: Input should be a valid ... SoftwareNode`:

```bash
python -m app.scripts.load_graph
```

If you change scoring logic, extend `tests/test_reasoning_engine.py` — it pins Risk Priority output.

On first startup (and on every `democtl.sh reset`), the backend bootstraps the 7 seed findings through the incident graph in the background — see "One graph, one lifecycle" below. This can involve up to ~21 real Anthropic calls in live mode; startup itself isn't blocked on it (backgrounded via a daemon thread), but the Dashboard's Findings table may take a few seconds to fully populate after a fresh boot.

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
npm run dev      # http://localhost:3000
```

Frontend reads `NEXT_PUBLIC_API_BASE` (defaults to `http://localhost:8000`) to reach the Python backend directly, no proxy. FastAPI's interactive docs are available at `http://localhost:8000/docs` once the backend is running.

## Architecture

The core design decision is that **quantitative scoring is deterministic Python, never an LLM call.**

### One graph, one lifecycle

There is exactly one LangGraph `StateGraph` (`backend/app/graph.py`'s `COMPILED_INCIDENT_GRAPH`), checkpointed via `SqliteSaver` into `backend/app/data/ctem_runs.db`. Every finding runs through it — the 7 seed findings and cases injected through `democtl.sh`. There is deliberately no separate, simpler code path for seed data: they share the same pause/resume semantics, the same human-review gates, and end up in the same `runs_db`-backed queue, distinguishable only by `incident_source`.

```
context_graph -> category_match
                      |
confident match? -- NO --> ontology_review_gate (pause) --+
                      |                                     |
                      YES                                   | (approve: re-match / reject: proceed)
                      v                                      v
                 reasoning_engine <---------------------------+
                      |
                 triage_agent
                      |
  suppressed? -- YES --> skip_remediation --+
                      |                       |
                      NO                      |
                      v                        v
                planning_agent -> implementation_agent -> governance_agent
                                                                 |
                                        auto-approved? -- YES --> execute_remediation
                                        else -----------------> governance_review_gate (pause)
                                                                        |
                                                   approve? -- YES --> execute_remediation
                                                   else ------------> blocked_review

           execute_remediation -> independent_verification -> finalize_closure (auto_close | blocked_review)
```

`execute_remediation` is where the two live-remediation scenarios (see "Live code-remediation
scenario" in `README.md`) actually run: `app/remediation/live_adapter.py` clones/branches/fixes/tests/
pushes/opens a real PR for npm+node targets, or (for the log4j/Maven target) dispatches and awaits a
real GitHub Actions run, and `independent_verification` (`app/verification.py`) re-checks all four
resulting evidence artifacts — each must report `result: "pass"` from an allowlisted issuer for its
source — before `finalize_closure` certifies `verifiedClosed`. Everything else still closes on
**simulated** evidence from `verification.collect_demo_adapter_evidence`.

Three genuine decision points, not a fixed linear chain:
- **Category match** (`ontology_review_gate`): a finding that doesn't confidently match a known vulnerability Category (cosine similarity ≥ 0.4 against `graphdb.mock_embedding`'s hash-based pseudo-embeddings) pauses for a human to approve or reject a new Category before scoring continues. Approving derives a new Category node and re-matches (should clear the threshold — see `graphdb.finding_match_text`'s docstring for why the embedding text has to match a specific terse shape).
- **Triage** (`skip_remediation`): unreachable/unexploitable findings skip Planning/Implementation entirely (and their LLM calls) — the "suppressions" behavior.
- **Governance** (`governance_review_gate`): auto-approved findings close immediately; anything blocked or pending approval pauses for a human, who can still approve (auto-close) or reject (blocked pending policy review) — a real pause via LangGraph's checkpointer, not just a terminal status label.

Every node appends to `route_path` — the audit trail the Governance Agent's "auditable reasoning chain" requirement needs, rendered as both a one-line route string and a per-node timeline (with human-readable explanations, see `frontend/lib/telemetryExplanations.ts`) on `/review/[id]`.

- `reasoning_engine.py` deterministically calculates exploitation likelihood, business impact, and residual risk (`likelihood × impact × (1 − validated controls)`), then applies explicit policy overrides. It has **no LLM client anywhere in that module.**
- `triage_agent.py`, `planning_agent.py`, and `implementation_agent.py` are the *only* places `llm_reason()` (in `llm.py`) is invoked, and only ever to append narrative text (reasoning-chain entries, mitigation recipes, PR rationale, ontology-curation rationale) — never a score, tier, suppression decision, match confidence, or approval outcome.
- `governance_agent.py` has **zero LLM involvement** — approval routing is fully deterministic policy/blast-radius logic.
- When adding or modifying a node, preserve this boundary: quantitative/decision logic belongs in `layer2/reasoning_engine.py` and the deterministic branches of the layer3 agents; narrative-only LLM logic goes through `llm.py`.

### Module responsibilities (`backend/app/`)
- `models.py` — Pydantic models for every layer, plus the top-level API response `FindingPipelineResult` (note the `runId` field — a run's UUID, the only stable per-row identity now that the same seed/preset finding can be injected more than once) and `KpiSummary`.
- `main.py` — FastAPI app. Key endpoints: `/api/health`, `/api/findings` (seed catalog), `/api/findings/{id}/result` (seed finding's current result, by its familiar id — used by Demo Mode's picker), `/api/incidents` (the unified queue — every run, enriched with tier/riskPriority/ownerName once it's reached governance), `/api/incidents/{run_id}/result`, `/api/incidents/results` (bulk, ready-only — feeds KPIs, charts, History), `/api/kpis`, `/api/ontology/graph` (Settings visual — Services/Software/Owners/Categories and their edges; Vulnerability nodes are deliberately excluded, see Known constraints), `/api/queues/ontology` + `/api/queues/governance` (human-review queues), `/api/reset`. CORS is wide open (`allow_origins=["*"]`) — see Known constraints. Bootstraps seed incidents in a background thread on import (see `bootstrap_seed_incidents`).
- `graph.py` — the single `StateGraph` described above. `get_incident_result(run_id)` reconstructs a `FindingPipelineResult`-shaped dict from a run's checkpoint (gated on the Governance Agent having run) — the shared read path behind almost every endpoint above. Its `_as()` helper normalizes checkpoint-restored values back into real Pydantic instances, since LangGraph's serde doesn't guarantee attribute-style access survives a round-trip the way a fresh `.invoke()` does — `kpis.py` relies on that attribute access.
- `graphdb.py` — SQLite-backed graph store (`backend/app/data/graph.db`) standing in for Neo4j: `Service | Software | Vulnerability | Category | Owner` nodes, `AFFECTS | RUNS_ON | DEPENDS_ON | CHAINS_WITH | OWNED_BY` edges. `CHAINS_WITH` is schema-only today (never written). Category matching is deterministic hash-seeded pseudo-embeddings + cosine similarity — see `mock_embedding`'s docstring, not a real embeddings API.
- `data/runs_db.py` — SQLite persistence (`backend/app/data/ctem_runs.db`) for runs, per-node telemetry (`run_events`), and the two human-review queues. LangGraph's own checkpoint tables (`checkpoints`, `writes`) live in this same file via `SqliteSaver`.
- `data/seed.py` — 4 owners, 5 services, 7 software nodes, 4 policies, 7 hardcoded findings (`find-1`..`find-7`) modelled on an AI-discovered exposure report. Bootstrapped into both `graphdb.py` (via `scripts/load_graph.py`) and, as of the unified lifecycle, into `runs_db` as real runs.
- `scripts/load_graph.py` — idempotent bootstrap loader for `graphdb.py`: seed Services/Software/Owners/Vulnerabilities, a synthetic `DEPENDS_ON` topology, and 8 starter Categories. Run directly (`python -m app.scripts.load_graph`) or via `/api/reset`.
- `llm.py` — the single boundary where the Anthropic API is called (`llm_reason`, model `claude-sonnet-5`). Falls back to a deterministic offline string (`_offline_fallback`) if `ANTHROPIC_API_KEY` is unset or the call throws (including TLS/network errors — logs the real exception to stderr rather than swallowing it, since "offline mode" and "live call silently failing" look identical to the frontend otherwise). Uses `truststore.inject_into_ssl()` so the OS certificate store is trusted, not just `certifi`'s bundled list — needed behind a TLS-inspecting corporate proxy (e.g. Netskope) whose root cert isn't in `certifi` but is trusted system-wide.
- `kpis.py` — `compute_kpis()`, fed by `main.py`'s `_all_ready_results()` (every run that's reached governance). **Not everything here is computed from data** — see Known constraints.
- `layer1/context_graph.py` — deterministic entity resolution (primary service selection, owner/policy matching) and attack-path synthesis from static templates, backed by `graphdb.get_service_software_owner()`.
- `layer2/reasoning_engine.py` — pure deterministic scoring engine, no LangGraph/Anthropic dependency. Same finding → same Risk Priority, always.
- `layer3/triage_agent.py` — deterministic suppression (`not exploitable and not runtime_reachable`) plus one narrative LLM call appended to the reasoning chain.
- `layer3/planning_agent.py` — deterministic fix-approach/target-version/effort lookup, narrative LLM call for the mitigation recipe. Has a `suppressed_planning_stub()` for the skip path (no LLM call).
- `layer3/implementation_agent.py` — deterministic stub PR/test-suite generation (`sandboxTestResult` and `selfAssessedConfidence` are hardcoded, not the result of real sandbox execution — see Known constraints), narrative LLM call for rationale. Has `suppressed_implementation_stub()`.
- `layer3/governance_agent.py` — fully deterministic policy checks and approval routing, no LLM.
- `settings_store.py` — persistence for the Settings > Risk Model form (app criticality, severity weights, thresholds). Note: **this form is a wireframe** — see Known constraints, it does not yet change `reasoning_engine.py`'s actual behavior.
- `verification.py` — the independent closure verifier (see "Live code-remediation scenario" in README). Re-checks, for every evidence artifact regardless of who produced it: issuer is on the `_ISSUERS` allowlist for its `source` (`simulated-adapter` or `live-integration`) and is never `implementation-agent` itself, `subjectFindingId` matches, the SHA-256 `artifactDigest` recomputes correctly, and `result == "pass"`. Only then is `verifiedClosed` true. **Adding a new live strategy/issuer (e.g. a new ecosystem) requires adding its issuer string(s) to `_ISSUERS["live-integration"]` here too** — evidence from an unlisted issuer fails closed (correctly, but silently looks like "verification failed" rather than a config gap if you forget this step).
- `remediation/` — the live-remediation subsystem invoked by `graph.py`'s `execute_remediation` node, structured as an **orchestrator + named sub-agents** (Scanner → Planner → Implementer → Tester) with a bounded self-correcting loop — "agentic execution, deterministic guardrails". `live_adapter.py` (`run_live_remediation`) is the orchestrator for npm targets: it delegates the finding-specific steps to a strategy, loops Planner→Implementer→Tester (up to `_MAX_AGENTIC_ATTEMPTS` for agentic strategies; deterministic strategies converge in one shot), gates every attempt on the deterministic validation gate (contract tests pass + re-scan shows the tracked finding absent + runtime exploit probe closed), and records an `AgentTrace` (`orchestrator.py`, persisted via `runs_db.save_agent_trace`, served at `/api/incidents/{run_id}/agent-trace`, rendered on `/remediation/[id]`). Each trace step is tagged **deterministic** (rule/lookup) or **agentic** (model decision). A demo-integrity guard aborts loudly (no vacuous "closed") if the before-scan finds the tracked finding absent from the target baseline. The `maven` target (`log4j`) instead pushes the branch and drives a real GitHub Actions run via `actions_ci.py` since this demo host has no local JDK/Maven. `strategies/` holds the `RemediationStrategy` implementations selected by `select_strategy()`: `DeterministicDependencyStrategy` (SCA, npm dep bump — deterministic), `AgenticCodeStrategy` (SAST, first-party source fix via an LLM — agentic), `DastWebStrategy` (DAST, reflected-XSS fix; detection and post-fix verification are **black-box HTTP probes** against the running app — see `dast_probe.py`; fix is agentic), and `MavenCiDependencyStrategy` (SCA Maven/log4j, CI-verified). `scanner.py` has the npm-audit-shaped and Maven-POM scan/mutate logic; `github_pr.py` clones/branches/pushes/opens real PRs; `workspace.py` prepares the clone. The three npm scenarios (`live`=SCA, `agentic`=SAST, `dast`=DAST) all run against one target app, `remediation_targets/node-payments-api`, which carries all three independent vulns.

### Frontend (`frontend/pages/`)
- `dashboard.tsx` — KPI grid, two charts (risk-posture trend — synthetic, no real time-series data; open-by-tier donut), and the unified **Findings** table (`#findings`) — every run, seeded or imported, one set of columns and a Triage action available regardless of run status. Demo mutation controls are command-line only.
- `review/[id].tsx` — the single per-run detail page (replaces the earlier separate `incidents/[id].tsx` telemetry view and `alerts/[id].tsx` triage view, merged after it became clear the Triage Agent already runs automatically — there was no live decision left for a separate "Alert Triage" screen to make, and its Approve/Override/Suppress buttons were non-functional demo stubs, since removed). Shows: the ontology/governance review panel when paused (the two *real* human-in-the-loop actions in the app); once the Governance Agent has run, a risk-summary strip (score/tier/KEV/blast-radius) plus a one-line route path and a "Create remediation →" link; and always, a per-node **pipeline timeline** (`lib/telemetryExplanations.ts` for the human-readable one-liner) whose "show details" expand renders each node's own output *formatted* — services/owner for Context Graph, the factor-chip formula breakdown for the Reasoning Engine, the reasoning chain for Triage, fix plan for Planning, PR/sandbox result for Implementation, policy checks/provenance for Governance — with raw input/output JSON available a level deeper for debugging. Each field appears in exactly one place (the timeline entry for the node that produced it) rather than being repeated in a separate summary panel. Streams via SSE (`/api/incidents/{id}/stream`).
- `remediation/[id].tsx` — the ITSM-style remediation workflow view (ticket id, guardrails, Auto-remediate/Send for approval — demo-only, not persisted), addressed by run UUID, reached from `/review/[id]`'s "Create remediation →" link once a finding isn't suppressed.
- `queues/ontology.tsx` / `queues/governance.tsx` — the two human-review queues; approve/reject resumes the paused run.
- `history.tsx` — filterable remediation history + accepted-risk register + MTTR chart, sourced from `fetchIncidentResults()` (bulk, ready-only — same dataset as the KPI cards).
- `settings.tsx` — the Ontology visual (`components/OntologyGraphView.tsx`, `/api/ontology/graph` — Services/Software/Owners/Categories grouped into cards with their real edges; Vulnerability nodes intentionally excluded, they're transient findings, not stable ontology components) plus the Risk Model wireframe form.
- `demo.tsx` — a scripted, presenter-controlled walkthrough of one finding at a time (narration in `lib/demoScript.ts`), picks a finding by its seed id via `fetchSeedFindingResult`.
- `lib/api.ts` — typed fetch wrappers with hand-written TS interfaces mirroring the backend's Pydantic models (no shared/generated types).

## Known constraints (do not silently fix without flagging)

- **Several KPI/output values are hardcoded, not computed from data** — do not treat these as live signals without checking first:
  - `kpis.py`: `falsePositiveRateByAgent` for Planning (0.04), Implementation (0.02), and Governance (0.01) are literal constants; only Triage's is derived from actual suppression data.
  - `kpis.py`: `controlEfficacy` is a fully static 3-item list, unrelated to the findings dataset.
  - `layer3/implementation_agent.py`: `sandboxTestResult` is always `"pass"`; `selfAssessedConfidence` is always `0.87` — this is planning-stage narrative only, produced before governance approval. **This is superseded for the three live-remediation scenarios** (`live`, `agentic`, `log4j` — see README): for those, real execution happens later, in the `execute_remediation` graph node (`app/remediation/live_adapter.py`), gated behind governance approval, and produces genuine evidence (real `npm test`/`mvn test`, a real pushed PR, a real re-scan, a real runtime exploit probe) independently re-verified by `app/verification.py`. All other findings still close on simulated evidence with no real execution.
  - PR generation only drafts a title/rationale string during planning — it does not open a real GitHub PR at that stage (no GitHub App integration). The `live`/`agentic`/`log4j` scenarios open a real PR later, via `app/remediation/github_pr.py`, once `execute_remediation` runs.
- **KPIs/charts only reflect runs that have reached the Governance Agent.** Right after a fresh `/api/reset`, most (sometimes all but one) of the 7 seed findings sit paused at `ontology_review_gate` on a cold `graph.db` (only the 8 starter Categories exist, so match confidence is often below the 0.4 threshold) — so the Dashboard's KPI cards and charts can look sparse until someone works through `/queues/ontology`. This is intentional (seed findings follow the exact same lifecycle as live-injected ones, no shortcuts), not a bug.
- **The Settings > Risk Model form does not yet change the backend's scoring behavior** — staged pending a formula reconciliation between the reference architecture and the wireframe (see `reasoning_engine.py`).
- **The likelihood coefficients, impact weights, and thresholds are governed demo defaults, not production-calibrated client values.** Preserve the separation among calculated risk, evidence quality, explicit policy overrides, and automation authority. Attached policy count must never be treated as validated control effectiveness.
- CORS in `main.py` is hardcoded to `allow_origins=["*"]` — appropriate for a demo, not for anything beyond it.
- No auth in front of the FastAPI server. `runs_db`/`graphdb` persist to SQLite files on disk (not in-memory), but nothing is backed up or migrated — `/api/reset` deletes rows outright.
- Service/owner/policy names in `data/seed.py` are deliberately synthetic and domain-neutral (no real CMDB data) so the demo carries no client branding — the formula, tiers, agents, and KPI *definitions* are the substance; the entity names are illustrative.
- The backend has 32 tests (`backend/tests/`, see Commands); they require a seeded `graph.db`. **The frontend has no automated tests.**
