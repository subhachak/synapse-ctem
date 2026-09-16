# CTEM Executive Demo Runbook

## Reset and health check

1. Run `./run.sh restart`.
2. Run `./democtl.sh reset presentation`, then open the Dashboard.
3. Confirm the baseline: seven findings, no ontology review items, and one Governance review item for Privilege Escalation Chains.
4. Confirm health reports `live (Anthropic)`. Reset and seed bootstrapping still force narratives labeled **DETERMINISTIC ADVISORY**; successful live narratives on newly injected cases are labeled **ANTHROPIC ADVISORY**. Authoritative scoring and policy remain deterministic.

Presentation reset is deterministic and was validated at approximately 0.20 seconds on the demo laptop. Live narrative calls are bounded to 10 seconds each with no SDK retry delay; timeout fallback is explicitly labeled and does not block deterministic scoring or policy.

## Command-line control

The local backend can be controlled without touching the UI:

```bash
cd ctem-platform

# Return to the repeatable presentation baseline.
./democtl.sh reset presentation

# Inject a known finding; the command prints the run ID and UI URL.
RUN_ID=$(./democtl.sh inject-preset find-1)

# Or inject a custom case (use `failure` for the safe-failure route).
RUN_ID=$(./democtl.sh inject-example normal)

# Stream each pipeline node and run-state transition from the backend.
./democtl.sh watch "$RUN_ID"

# Open the live Alert Triage page, which consumes the same SSE stream.
./democtl.sh open "$RUN_ID"
```

For arbitrary cases, use `./democtl.sh inject-json payload.json` or pipe the JSON with `inject-json -`. The underlying control endpoint is deliberately hidden from the browser and OpenAPI surface. The Dashboard polls the shared run store, so command-line injections appear automatically. Use the state-aware row action—such as **View live pipeline**, **Review score**, or **Review approval**—to open the live node-by-node pipeline and any human gate.

## Eight-minute narrative

### 1. Frame the problem — 45 seconds

“This is not another scanner. It is the decision and control layer between findings and verified exposure reduction.”

Point out the unified queue, SLA-at-risk count, and Tier distribution. State that source connectors are simulated for the demo and the workflow contracts are the intended integration boundary.

If you open **History & Reports**, distinguish measured event-derived timings from the clearly labeled illustrative 30-day trend. Point out the sample counts and metric provenance; do not present illustrative targets as observed client outcomes.

### 2. Show governed prioritization — 2 minutes

Open **Sandbox Escape + Browser Exploit Chain**.

- Show the evidence-quality stage: present, inferred, and simulated inputs are explicit.
- Show the active risk-model version and calculated score/tier.
- Show `POL-ACTIVE-EXPLOIT-001`: the designated case calculates as 53.6 / Tier 2, then KEV changes the final policy tier to Tier 0 without hiding the calculated result.
- Show the AI plausibility stage and emphasize that it is advisory and cannot alter the authoritative decision.

### 3. Show bounded agents — 90 seconds

Walk through Triage, Planning, Implementation, and Governance in the timeline.

Say: “Deterministic components own scoring and policy. AI produces explanations and plans. Human authorization remains explicit. Every stage leaves an audit event.”

### 4. Show closure evidence — 90 seconds

Expand **Auto-Close**.

- Show sandbox test, deployment proof, rescan, and runtime-path evidence.
- Point out the `SIMULATED` label on every adapter artifact.
- Explain that verified closure requires all four artifacts; governance approval or a generated test plan alone is insufficient.

### 5. Show the intentional human gate — 90 seconds

Open **Privilege Escalation Chains**, the one staged Governance case.

- Show Tier 0, four-service blast radius, and business-critical context.
- Approve it.
- Show the resumed route and resulting closure evidence.
- Return to the Dashboard and note the updated state.

### 6. Close — 45 seconds

“The differentiator is not the number of agents. It is governed decision velocity: versioned scoring, explicit policy overrides, bounded AI, human control at the right boundary, and evidence-backed closure.”

## Optional safe-failure scenario

1. Run `RUN_ID=$(./democtl.sh inject-json demo-data/safe-failure.json)` and `./democtl.sh open "$RUN_ID"`.
2. Resolve the ontology gate with **use best available** if prompted.
3. Open Remediation and show that the sandbox test failed.
4. Confirm deployment, rescan, and runtime closure are all `not-run`, the case is not verified, and the UI states that production deployment was blocked.

Narrative: “The control objective is not maximum autonomy. It is maximum safe decision velocity. A failed contract test stops the agent boundary before production.”

## Optional score-review scenario

1. Run `RUN_ID=$(./democtl.sh inject-json demo-data/score-review.json)` and `./democtl.sh open "$RUN_ID"`.
2. Resolve ontology review with **use best available** if prompted.
3. Open the finding when it pauses at **Score Review**. Show that inferred severity evidence triggered review, while the deterministic score remains unchanged.
4. Either confirm the calculated decision or select a different action tier and **Reclassify and resume**.
5. Show the persisted human decision, selected tier, and `deterministic-model+human-override` provenance in the completed record.

Narrative: “AI can surface a contradiction, but it cannot silently rewrite the authoritative score. A named human decision is checkpointed, persisted, and auditable.”

## Persisted remediation walkthrough

On any remediated finding, open **Remediation** and show the backend-persisted ticket, owner, authorization source, current state, and transition history. Refresh the page to demonstrate that state is not browser-derived. For a failed sandbox case, use **Return to planning** to restart from a controlled state; failure never advances to verified closure.

## Claims discipline

Safe claims:

- The state machine, checkpoints, policy routing, model versioning, three human-review queues, remediation transition history, telemetry, and evidence contract are implemented.
- Scoring is deterministic and Settings controls new decisions after model activation.
- The demo runs repeatably without network access.
- Headline timing and closure KPIs are derived from persisted workflow events, with sample counts and provenance shown in the UI.

Do not claim:

- Live Qualys, ServiceNow, GitHub, CI/CD, eBPF, or CMDB connectivity.
- Real patch execution, deployment, scanning, or runtime verification.
- Production-calibrated coefficients or measured client outcomes.

## Recovery

- If a screen has stale data, return to Dashboard and refresh.
- If a finding unexpectedly pauses in ontology review, run `./democtl.sh reset presentation`; presentation mode resolves seed taxonomy pauses.
- If the backend is unavailable, run `./run.sh restart`, wait for health, and reset again.
