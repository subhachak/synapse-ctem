# CTEM Demo — Detailed Presenter Script

## Operating model

The browser is presentation-only. Reset and test-data injection are deliberately available only from the local command line through `democtl.sh`. The control utility calls hidden backend control endpoints; neither action is exposed in the application UI.

The backend should report `live (Anthropic)` for newly injected cases. Presentation reset and seed bootstrapping deliberately force deterministic narratives for speed and repeatability; scoring, policy, workflow state, and verification contracts are deterministic in every mode. All scanner, ticketing, deployment, rescan, runtime, asset, owner, policy, and topology data is simulated and visibly labeled.

## Pre-demo setup — 2 minutes before the meeting

```bash
cd ctem-platform
./run.sh restart
./democtl.sh health
./democtl.sh reset presentation
```

Expected health output: `live (Anthropic)`. If it reports offline, confirm that both `ANTHROPIC_API_KEY` and `CTEM_LIVE_LLM=true` are set in `backend/.env`, then restart. The reset produces seven reference findings and stages **Privilege Escalation Chains** at Governance Review; reset-generated narratives remain deterministic by design and display **DETERMINISTIC ADVISORY**. Newly injected live narratives display **ANTHROPIC ADVISORY** when the API call succeeds.

Reset is intentionally independent of Anthropic and should complete in well under a second on the demo laptop (validated at approximately 0.20 seconds on 2026-07-14). Live advisory calls have a 10-second per-call ceiling with SDK retries disabled; a timeout degrades that narrative to a visibly labeled deterministic fallback while the authoritative pipeline continues.

Open `http://localhost:3000/dashboard`. Confirm:

- Seven findings are visible.
- One case is paused for Governance Review.
- No ontology or score-review case is unexpectedly pending.
- The trend is labeled illustrative.
- Closure counts are labeled as measured from simulated evidence.

Keep a second terminal open in the repo root. For every injected case, use:

```bash
RUN_ID=$(./democtl.sh inject-json demo-data/FILE.json)
./democtl.sh open "$RUN_ID"
```

Optional engineering view:

```bash
./democtl.sh watch "$RUN_ID"
```

This shows the same persisted events consumed by the live Alert Triage UI.

---

## Main narrative — 10 minutes

### 1. Executive opening: reduce findings to governed action — 60 seconds

**Action:** Start on Dashboard.

**Notice in the UI:**

- The four headline KPIs distinguish workflow state, governed model output, policy state, and verified closure.
- Open-by-tier shows the final policy tier, not raw scanner severity.
- The findings table combines all sources into one governed queue.
- The volume funnel is explicitly illustrative; operational KPIs are measured.
- The 30-day trend carries an **ILLUSTRATIVE** badge; it is not historical telemetry.
- Source labels carry **SIMULATED** provenance.

Dashboard actions reflect current state rather than always saying “Triage”:

| State | Action shown |
|---|---|
| Running | **View live pipeline** |
| Ontology review | **Review category** |
| Score review | **Review score** |
| Governance review | **Review approval** |
| Suppressed | **View decision** |
| Verified closed | **View closure evidence** |
| Sandbox failed | **Review failure** |
| Other completed outcome | **View result** |

**Narrative:**

> “This is the decision and control layer between vulnerability signals and verified exposure reduction. We are not asking another agent to summarize scanner output. We are correlating the finding to business context, making a versioned decision, routing the right authority, and requiring evidence before closure.”

**Principal-level point:** The architecture separates authoritative decisions from generative assistance. Deterministic code owns scoring, policy, state transitions, and closure contracts.

### 2. Deterministic prioritization and explicit policy override — 90 seconds

**Test data:** Reference finding `find-1`.

```bash
RUN_ID=$(./democtl.sh inject-preset find-1)
./democtl.sh open "$RUN_ID"
```

**Notice in Alert Triage:**

- Evidence Quality identifies present, inferred, missing, and simulated inputs.
- Governed Model shows exploitation likelihood, business impact, evidence quality, and residual risk.
- Governed Model calculates the designated case as **53.6 / Tier 2** before policy using governed demo coefficients.
- Final Policy Decision records `POL-ACTIVE-EXPLOIT-001` changing **Tier 2 → Tier 0**.
- AI Assurance is marked advisory and cannot change the authoritative result.
- Pipeline Timeline shows deterministic and AI-assisted stages as auditable events.

**Narrative:**

> “The model answers two questions separately: how likely exploitation is, and how damaging it would be here. Likelihood times impact produces residual risk. KEV is then applied as an explicit policy floor, not buried inside an opaque prompt. We retain both the calculated disposition and the governed final disposition, so an auditor can reconstruct exactly why action changed.”

**Point out:** The likelihood calculation includes EPSS, exposure, runtime reachability, exploit maturity, attack-path chainability, and threat activity. Business impact includes technical severity, application criticality, data sensitivity, blast radius, and regulatory or safety consequence. Independently validated controls are applied once as a bounded residual-risk dampener. The demo coefficients are governed defaults pending client backtesting; they are not represented as production-calibrated values.

The override label is outcome-sensitive: a KEV case already calculated as Tier 0 remains `deterministic-model` and does not falsely claim that policy changed its tier.

**Validated live profile (2026-07-14):** the KEV case reached its Governance gate and verified closure in approximately 27 seconds, including live Anthropic narratives. The score-review case took approximately 60 seconds end to end because it deliberately traverses ontology review, score review, and Governance. Treat these as demo-laptop observations, not production SLAs. Prefer the KEV path in the main narrative; keep score review optional.

**Do not say:** “AI scored this vulnerability.” The authoritative score is deterministic.

### 3. Human governance at the consequential boundary — 90 seconds

**Action:** Return to Dashboard and select **Review approval** for **Privilege Escalation Chains**, which is paused at Governance Review.

**Notice:**

- The route already contains context, scoring, planning, implementation drafting, and policy checks.
- The human gate explains why authorization is required.
- Approving resumes the existing checkpoint; it does not start a separate workflow.
- The decision is persisted with the reviewer identity.

**Action:** Select **Approve controlled execution**.

**Narrative:**

> “Human-in-the-loop is not a decorative approval button. The graph is checkpointed before the authorization boundary. The reviewer’s decision is persisted, the same run resumes, and downstream evidence retains the authorization source.”

**After approval:** Select **View closure evidence**.

### 4. Evidence-backed closure — 90 seconds

**Notice in Remediation:**

- Plan → Assign → Approve → Execute → Verify derives from persisted remediation state.
- The ticket is a simulated adapter artifact stored by the backend, not invented by the browser.
- Owner and authorization survive refresh.
- Closure requires four evidence types: sandbox test, deployment proof, post-change rescan, and runtime-path check.
- Every artifact says `simulated-adapter`.

**Narrative:**

> “Approval is not closure, and a generated patch is not closure. This control contract requires execution and verification evidence. The demo adapters are simulated, but the state machine and evidence requirements are real implementation boundaries.”

**Action:** Refresh the page to prove remediation state persists.

### 5. Reporting integrity — 60 seconds

**Action:** Open **History & Reports**.

**Notice:**

- MTTCx, MTTV, MTTR, and closure timings show event-derived sample counts.
- Metric provenance explains the start and stop event for each measurement.
- Unavailable false-positive and control-efficacy metrics are labeled not measured.
- Display dates carry an **ILLUSTRATIVE** label.
- Settings identifies service, owner, dependency, criticality, and ontology data as **SYNTHETIC DEMO CONTEXT**.
- Modeled blast radius and predictive risk are explicitly named as modeled outputs.

**Narrative:**

> “The reporting contract is as important as the workflow contract. If a metric is derived, we show its event provenance and sample count. If the demo lacks the client outcome data needed to measure it, we say so rather than manufacturing precision.”

### 6. Close — 45 seconds

> “The differentiator is governed decision velocity: explainable likelihood and impact, explicit policy, bounded AI, human control at the consequential boundary, persisted remediation state, and evidence-backed closure. External integrations can change without changing those control contracts.”

### 7. Ground, observe, learn, govern — optional 90 seconds

**Action:** Expand any Triage, Planning, Implementation, or Governance event and point out **BOUNDED RETRIEVAL**. Then open **Settings** and scroll to **Observe → Learn → Govern**.

**Narrative:**

> “The language model does not search the open internet or invent organizational policy. It retrieves a small, cited set of approved policies, runbooks, and resolved precedents. With a Voyage key this is semantic vector retrieval; without one the UI explicitly labels the deterministic lexical fallback. Retrieval informs the narrative and plan, but it cannot change the deterministic score or grant execution authority.”

> “The learning loop starts with outcomes, not autonomous retraining. Human reclassifications, remediation outcomes, suppression escapes, and reason codes become calibration evidence. Every decision preserves its point-in-time normalized inputs; a candidate model runs in shadow on immutable snapshots and uses a later outcome-labelled holdout when enough history exists. It can propose a new version, but only a human-approved activation changes future decisions.”

Select **Backtest current draft**. Point out that the active result is preserved and the screen reports only candidate deltas.

For a suppressed finding, the decision page shows a 14-day lease rather than a terminal close. Select **Reopen on context change** to create a successor run and re-evaluate current graph and threat context. The equivalent CLI controls are:

```bash
./democtl.sh suppressions
./democtl.sh reopen RUN_ID reachability-change
./democtl.sh outcome RUN_ID observed failed suppression-escape
./democtl.sh learning
```

**Do not say:** “The system retrains itself.” Say: “It collects governed calibration evidence and shadow-tests proposed model versions.”

### 8. Orchestration: parallel where safe, sequential where authoritative — optional 60 seconds

**Action:** Open a newly completed finding and scroll through **Pipeline timeline**.

Point out the overlapping **Evidence Quality · Parallel**, **Ontology Match · Parallel**, and **Approved Knowledge · Parallel** events, followed by **Enrichment Join**. Then point out the ordered **Reasoning Engine → Triage → Planning → Implementation → Governance → Authorized Execution → Independent Verification → Closure Gate** path.

**Narrative:**

> “This is an orchestrator with bounded specialists, not an unrestricted agent swarm. Independent, read-only enrichment fans out concurrently to reduce latency. The join requires all three contracts before deterministic scoring begins. Authority remains sequential: the model scores, policy routes, a human approves where required, execution occurs, and an independent verifier—not the implementation agent—decides whether the evidence is sufficient for closure.”

**Do not say:** “All agents run in parallel.” Say: “Independent enrichment runs in parallel; dependent decisions and authorization gates remain ordered.”

The complete flow includes two governed feedback loops:

```text
Context → Parallel Enrichment → Join → Score → Triage → Governed Action
   ▲                                              │              │
   │                                              │              └─→ Outcome telemetry
   │                                              │                         ↓
   └─ successor run ← TTL/context trigger ← Suppression lease       Backtest candidate
                                                                          ↓
                                                           Human-approved version only
                                                                          │
                                                                          └─→ future scores
```

**Speaker note:**

> “There are two loops, and neither rewrites history. The fast operational loop reopens a suppression as a new correlated run when its lease expires or material context changes. The slower learning loop aggregates outcomes, tests a candidate model in shadow, and influences future scoring only after versioned human approval.”

---

## Optional use case A: score-quality challenge and human reclassification — 3 minutes

**Fixture:** `demo-data/score-review.json`. It deliberately omits `cvssBase`; the backend records CVSS as severity-inferred.

```bash
RUN_ID=$(./democtl.sh inject-json demo-data/score-review.json)
./democtl.sh open "$RUN_ID"
```

The custom taxonomy match may pause first at Ontology Review. Select **Reject — use best available**. This is intentional: it demonstrates that unfamiliar input cannot silently mutate the ontology.

The run then pauses at Score Review.

**Notice:**

- The deterministic score has already been preserved.
- AI identifies the inferred high-severity evidence as a concern but cannot change the tier.
- The reviewer can confirm or explicitly reclassify.

**Action:** Choose Tier 1 and select **Reclassify and resume**.

**Narrative:**

> “The advisory judge can challenge a result, not rewrite it. Reclassification is a named human decision with its own provenance. The final record identifies the method as deterministic model plus human override.”

**Expected final evidence:** `deterministic-model+human-override` and a `HUMAN-SCORE-REVIEW` policy-history entry.

## Optional use case B: safe failure blocks production — 3 minutes

**Fixture:** `demo-data/safe-failure.json`.

```bash
RUN_ID=$(./democtl.sh inject-json demo-data/safe-failure.json)
./democtl.sh open "$RUN_ID"
```

Resolve Ontology Review with **Reject — use best available** if it appears. Resolve any required governance approval.

**Notice in Remediation:**

- Sandbox test is `fail`.
- Deployment, rescan, and runtime-path evidence are `not-run`.
- State is `sandbox_failed`, never `verified_closed`.
- **Return to planning** is the only forward action.

**Narrative:**

> “The autonomy objective is not maximum action. It is maximum safe decision velocity. A failed contract test stops the boundary before production and leaves an explicit, recoverable state.”

## Optional use case C: suppress low-value work — 2 minutes

**Fixture:** `demo-data/suppression.json`.

```bash
RUN_ID=$(./democtl.sh inject-json demo-data/suppression.json)
./democtl.sh open "$RUN_ID"
```

Resolve Ontology Review with **Reject — use best available** if needed.

**Notice:**

- Runtime reachability is false and exploitation probability is low.
- Triage suppresses the finding.
- Planning and implementation are skipped.
- The CTA reads **No remediation required**.
- No remediation is falsely counted as verified closure.

**Narrative:**

> “Value also comes from work avoided. Suppression is a governed, auditable outcome—not deletion. The pipeline records why remediation was unnecessary and avoids spending agent or engineering capacity on it.”

---

## Recovery commands

```bash
# Inspect the current run and persisted events.
./democtl.sh status "$RUN_ID"

# Reopen its live UI.
./democtl.sh open "$RUN_ID"

# Restore the known presentation state.
./democtl.sh reset presentation

# Verify both processes.
./run.sh status
./democtl.sh health
```

If a custom case pauses at Ontology Review, that is expected. Rejecting the candidate means “continue with best available taxonomy,” not “reject the vulnerability.”

## Claims discipline

Safe claims:

- The workflow, checkpoints, review decisions, remediation states, telemetry, metric provenance, and evidence contracts are implemented.
- The demo degrades safely to deterministic narratives if Anthropic is unavailable; authoritative decisions remain deterministic.
- Settings activate a versioned risk model for subsequent decisions.
- Chainability, criticality, and validated controls affect the calculation exactly as displayed; attached policy count alone receives no control credit.

Do not claim:

- Live scanner, ITSM, source-control, CI/CD, runtime, or CMDB connectivity.
- Real production patching or verified client outcomes.
- Production-calibrated coefficients.
