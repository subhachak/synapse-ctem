# Mphasis Synapse CTEM

A working, runnable demo of a **3-layer CTEM (Continuous Threat Exposure Management) stack** — Context Graph & Threat Ontology, Adversarial Reasoning Engine, and Agentic AI (Triage / Planning / Implementation / Governance).

It is **client-agnostic by design**, built for GTM demos across verticals: every service, owner, and policy name is synthetic and domain-neutral, and nothing in the repo is specific to any one customer's estate. The substance — the scoring formula, the action tiers, the four agents, the KPI definitions, the human-in-the-loop gates — is what the demo is actually showing.

**Stack: Python + FastAPI + LangGraph backend, Next.js frontend.** This is the only backend — there is no parallel Node/TypeScript version (an earlier pass built one; it's been fully replaced).

## Why LangGraph, and where the state machine actually branches

This isn't a single straight-line pipeline wrapped in LangGraph for show. Findings pass through deterministic data-quality and scoring controls, a bounded AI plausibility assessment, and genuine checkpointed human gates. Every node appends to `route_path`, providing the audit trail the Governance Agent needs:

```
context_graph -> parallel_enrichment -> enrichment_join
                  |        |        |            |
            evidence   ontology  approved        |
            quality     match    knowledge   confident match?
                                                 |        |
                                                NO       YES
                                                 v        |
                        ontology_review_gate (pause)      |
                                 |                        |
          (approve: re-match / reject: proceed)           |
                                 v                        v
                            reasoning_engine <------------+
                                 |
                          plausibility_judge
                                 |
              flagged? -- YES --> score_review_gate (pause)
                                 |          |
                                 NO         | (confirm / reclassify tier)
                                 v          v
                            triage_agent <--+
                                 |
        suppressed? -- YES --> skip_remediation -> governance_agent -> auto_close
                                 |
                                 NO
                                 v
                   planning_agent -> implementation_agent -> governance_agent
                                                                    |
                                       auto-approved? -- YES --> execute_remediation
                                       else -----------------> governance_review_gate (pause)
                                                                           |
                                                  approve? -- YES --> execute_remediation
                                                  else ------------> blocked_review

          execute_remediation -> independent_verification -> finalize_closure
```

Only the three enrichment branches run concurrently, and only because they are read-only; an
explicit join blocks scoring until all three have landed. Every authoritative decision stays
sequential.

- **Category match (`ontology_review_gate`):** a finding that doesn't confidently match a known vulnerability category pauses for a human reviewer to approve or reject a new category before scoring continues — the ontology curation loop.
- **Score plausibility (`score_review_gate`):** a bounded advisory assessment can flag contradictory or inferred evidence, but cannot change the deterministic score. A human may confirm or explicitly reclassify the action tier, with the override persisted in the decision record.
- **Triage (`skip_remediation`):** implements "suppressions for unreachable / unexploitable" — findings with no active exploit signal and no runtime reachability skip Planning/Implementation entirely (and skip their LLM calls).
- **Governance (`governance_review_gate`):** implements policy-driven approval routing — auto-approved findings close immediately; anything blocked or pending approval genuinely pauses for a human, who resolves it to either `auto_close` or `blocked_review`.

Remediation is also a persisted state machine rather than a browser presentation: planning, assignment, authorization, sandbox execution, deployment, and verification transitions are stored with timestamps and actor provenance. Failed sandbox execution remains failed until explicitly returned to planning.

There is exactly one graph — the 7 seed findings and anything injected through the command-line control utility both run through it, with the same pause/resume semantics, so they end up indistinguishable in the queue once they have run.

## What's real vs. what's illustrative

| Piece | Status |
|---|---|
| Layer 1 entities: Services, Software, Vulns, Owners, Policies, Reachability | Real graph store and entity resolution; the entity *names* are synthetic |
| Layer 2 signals and action tiers | Real — explainable likelihood × business impact with explicit policy overlays, deterministic Python |
| Action tiers: Tier 0 (auto-contain) / Tier 1 (<24h) / Tier 2 (<72h) / Tier 3 (backlog) | Real tiering logic |
| 4 agents: Triage, Planning, Implementation, Governance | Real, orchestrated by one checkpointed LangGraph state machine with genuine human gates |
| KPIs: MTTCx, MTTV, MTTR, exploit-path closure, % auto-correlated, % verified reachable, % remediations verified closed, % auto-remediated vs human, false-positive rate, exception debt, control efficacy | Definitions are real; some values are static demo constants — see "Known constraints" in `CLAUDE.md` |
| Live code remediation (SCA / SAST / DAST) | Real — clones a repo, fixes, runs tests, re-scans, probes at runtime, opens a real PR, independently re-verifies |
| Data sources shown as integration points: Qualys VMDR, Veracode, Tanium, ServiceNow, Snowflake, GitHub | Labeled placeholders — not connected |

**What's synthetic (and marked as such in the code):** the 7 seed findings and all service/owner/policy names (Customer Portal Gateway, Order Intake API, Pricing Engine, …). They stand in for a real asset graph so the demo runs anywhere, against no customer data.

## Architecture

```
backend/app/layer1/context_graph.py     Layer 1: fuses Services/Software/Owners/Policies/Reachability
backend/app/graphdb.py                  Layer 1: SQLite graph store (Neo4j stand-in) + category matching
backend/app/layer2/reasoning_engine.py  Layer 2: Risk Priority formula, action tiering
backend/app/layer3/*_agent.py           Layer 3: Triage, Planning, Implementation, Governance agents
backend/app/graph.py                    The one LangGraph StateGraph, with three checkpointed review gates
backend/app/data/runs_db.py             SQLite persistence: runs, telemetry, review queues, remediation state
backend/app/main.py                     FastAPI app exposing it all
```

The Triage, Planning, and Implementation agents run offline with deterministic narrative text by default, including when an API key is present. Live Anthropic narrative calls are an explicit opt-in: set both `ANTHROPIC_API_KEY` and `CTEM_LIVE_LLM=true`. Presentation reset always uses deterministic narratives for speed and repeatability.

## Running it

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env              # all optional; empty = fully offline and deterministic
python -m uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
cp .env.example .env
npm run dev                        # http://localhost:3000
```

Open http://localhost:3000 — you'll see:
- A KPI strip and two charts, computed over every finding that's reached the Governance Agent
- A unified **Findings** queue — the 7 seed findings alongside cases injected through `democtl.sh`, with no structural difference between them
- Click "Review ->" on any finding — while it's still running or paused, you'll see its live telemetry timeline and the relevant ontology, score, or governance review panel; once it reaches Governance, the same page adds a risk summary, the route it took, and a link into the persisted remediation workflow
- **Settings** has a visual of the underlying ontology graph (Services/Software/Owners/Categories and their real relationships), the risk-model form (draft vs. activate — activating changes scoring for subsequent runs, never retroactively), a shadow backtest that replays a candidate model over immutable decision snapshots, and the learning summary
- **Demo Mode** (`/demo`) is a scripted, presenter-controlled walkthrough of one finding at a time, for a live client demo — nothing runs until you click through it

FastAPI's interactive docs are also available at http://localhost:8000/docs once the backend is running.

## Live code-remediation scenario (real scan → fix → test → PR → verified closure)

Most findings close with **simulated** evidence. Two scenarios are different: a real
scan finds a real vulnerability in a real app, the pipeline performs a **real
remediation**, and it closes with **live** evidence. After governance approval the live
adapter (`backend/app/remediation/`) **clones a GitHub repo you own**, works on a
branch, runs the app's real `npm test`, re-scans, **pushes the branch and opens a real
pull request**, probes the exploit at runtime, and an independent verifier re-checks all
four evidence artifacts before certifying closure.

Remediation is routed to one of two **strategies** (a classifier picks based on the
finding class), both closed by the *same* validation gate:

| `inject-code` variant | Finding | Strategy | Fix |
|---|---|---|---|
| `live` | lodash `4.17.4` prototype pollution (CVE-2019-10744), reachable via `/merge` | **deterministic dependency bump** | edits the manifest to `4.17.21`; `npm audit` re-scan proves the advisory gone |
| `agentic` | first-party OS command injection (CWE-78) in `/diagnostics` | **AI coding agent** rewrites the source (`cp.exec` → `cp.execFile`); SAST re-scan + a runtime shell-injection probe prove it closed | offline uses a recorded fix; `CTEM_LIVE_LLM=true` uses the real model |
| `blocked` | (dependency, un-installable target version) | — | demonstrates the safe-failure path: an unsafe change is never certified closed |
| `log4j` | Log4Shell (CVE-2021-44228) in `log4j-core`, unauthenticated RCE via JNDI lookup | **deterministic dependency bump (Maven), GitHub-Actions-verified** | bumps the `log4j.version` POM property `2.14.1` → `2.17.1`; a real `mvn test` and the actual `${jndi:ldap://...}` exploit probe run on GitHub Actions (not locally) — see below |

The agent is the catch-all for the unbounded tail of code fixes no rule covers: it
synthesizes the change, and it is accepted **only if the deterministic gate passes**.
The target app (both npm vulnerabilities) is committed at
`backend/app/remediation_targets/node-payments-api/` (also the offline/test fallback).
The log4j target app is committed at
`backend/app/remediation_targets/log4j-vulnerable-app/`.

### The log4j scenario runs its verification on GitHub Actions, not locally

The other two scenarios build/test/probe as local subprocesses (`npm test`, a local Node
runtime probe). This demo host has no local JDK/Maven, and — more importantly — Log4Shell's
JNDI-lookup exploit is a real outbound network callback, which is a better fit for a
disposable remote runner than a laptop anyway. So the log4j scenario's live adapter
(`backend/app/remediation/actions_ci.py`) instead: pushes the fix branch, dispatches the
target repo's `.github/workflows/ctem-verify.yml` via the GitHub Actions API
(`workflow_dispatch`), polls the run to completion, and parses `CTEM_*_RESULT=` marker
lines out of the plain-text job log. That workflow does a real `mvn package` + `mvn test`,
then runs `scripts/jndi_probe.py` — which launches the built jar with an actual
`${jndi:ldap://127.0.0.1:<port>/a}` payload in a logged message and checks, with a real
ephemeral TCP listener, whether the JVM tries to open an outbound connection to look the
class up. `OPEN` on the vulnerable `2.14.1` baseline, `CLOSED` once the POM property is
bumped to `2.17.1` — the same probe, run for real, before and after the fix.

### One-time setup (`run.sh setup`)

1. Put a GitHub PAT (classic, `repo` scope) in `backend/.env` — same file as
   `ANTHROPIC_API_KEY`, read at backend startup:

   ```bash
   GITHUB_TOKEN=<your PAT>
   ```

2. Let `run.sh` provision the target repo — it creates a private
   `ctem-node-payments-api` under your account, pushes the vulnerable baseline to
   `main`, and pins `CTEM_REMEDIATION_REPO` back into `backend/.env`:

   ```bash
   ./run.sh setup
   ./run.sh restart      # reload backend with the new .env values
   ```

   `setup` is idempotent — re-running it just re-seeds `main`. (To use an existing
   repo instead, set `CTEM_REMEDIATION_REPO=<owner>/<repo>` in `backend/.env` before
   running it.)

3. The log4j scenario is a **separate** GitHub repo (`ctem-log4j-demo` by default) with
   its own env var, provisioned by a separate setup command — because GitHub Actions has
   to actually build/test/probe it, the PAT needs `workflow` scope in addition to `repo`:

   ```bash
   ./run.sh setup-log4j
   ./run.sh restart      # reload backend with CTEM_LOG4J_REMEDIATION_REPO
   ```

### Run it

```bash
./run.sh inject-code live       # deterministic dependency-bump scenario (npm)
./run.sh inject-code agentic    # AI coding agent fixes a first-party code vuln
./run.sh inject-code log4j      # Log4Shell, GitHub-Actions-verified (Maven)
```

Either injects the scenario AND opens `/review/<id>` in Chrome. Approve the run at
`/queues/governance` (the agentic finding also passes a score-review gate first), then
watch the timeline show **LIVE** evidence, a verified closure, and the real **PR URL**
on the `deployment-proof` evidence. `./run.sh inject-code blocked` demonstrates the
safe-failure path (an un-installable bump is never certified closed). The `log4j` run
takes noticeably longer than the others — governance approval triggers a real GitHub
Actions workflow_dispatch and waits for it to complete (typically ~1-2 minutes) before
the pipeline can certify closure.

### Reset between runs (`run.sh reset`)

```bash
./run.sh reset                 # or: ./run.sh reset technical
```

Resets the backend demo state (runs, queues, graph — same control API as before) **and**
closes any open `ctem/fix-*` PRs and deletes those branches on **both** GitHub repos
(`CTEM_REMEDIATION_REPO` and `CTEM_LOG4J_REMEDIATION_REPO`, whichever are configured), so
each demo starts from a clean slate.

If `CTEM_REMEDIATION_REPO`/`GITHUB_TOKEN` are not set, `inject-code` falls back to an
**offline local mode** (clone is replaced by the committed snapshot; real fix + diff +
tests + rescan, but no push/PR) — useful for a laptop with no repo configured yet.

## What this demo does NOT claim

- It does not claim the Context Graph / ontology synthesis layer is production-implemented anywhere. This demo builds a working version of that layer as a proof of concept; in most estates the *underlying data sources* exist while the synthesis layer does not.
- It does not connect to real enterprise systems (Qualys, Snowflake, ServiceNow, etc.) — those integrations are labeled placeholders in Layer 1's data-source list, ready to be wired up once access and credentials exist.
- Service/owner names are synthetic, domain-neutral placeholders, not any customer's asset data.
- The likelihood coefficients, impact weights, and tier thresholds are governed demonstration defaults, not calibrated to any client. The model separates exploitation likelihood from business impact, then applies KEV as an explicit Tier-0 policy floor. Production activation requires backtesting against that client's own outcomes and versioned human approval.

## Next steps to make this real

1. Replace `backend/app/data/seed.py` with a real feed from the client's scanner / data warehouse (Qualys VMDR, Snowflake, …) once access is available.
2. Replace the synthetic Services/Owners with actual CMDB (ServiceNow) data.
3. ~~Wire the Implementation Agent's PR generation to a real GitHub App.~~ Done for the live code-remediation scenario — see "Live code-remediation scenario" above; it clones your GitHub repo, pushes a fix branch, and opens a real PR via the GitHub API when `CTEM_REMEDIATION_REPO`/`GITHUB_TOKEN` are set. Other findings still use the simulated path.
4. Validate the Risk Priority formula's weighting with the client's security leadership, including the Tier-vs-KEV interaction noted above.
5. ~~Add checkpointed human review.~~ Done — ontology, score, and governance decisions now pause and resume through persisted review queues.
6. Calibrate the active, versioned Risk Model settings against the client's own outcome data before treating coefficients as production policy.
