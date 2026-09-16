# CTEM Agentic Remediation — 10–15 min Demo Runsheet

**Thesis (say this twice — open and close):**
> "This is an *agentic* remediation platform with *deterministic bones*. The AI agents do the creative work — finding, planning, writing, and testing fixes autonomously. But every number, every routing decision, and every closure is guarded by deterministic logic and human gates the AI cannot override. That's what makes it safe enough to point at production."

**The three-layer stack (one breath):** Context Graph (what & who) → deterministic Reasoning Engine (how bad, in Python — never an LLM) → Agentic Layer 3 (an orchestrator delegating to Scanner / Planner / Implementer / Tester sub-agents).

**What you'll show:** one service (`node-payments-api`), three exposure classes — **SCA, SAST, DAST** — each remediated end-to-end with a real PR, and each tripping a *different* guardrail.

---

## PRE-FLIGHT — 2 min before the call (do NOT skip)

```bash
./run.sh reset
```
Wait for the green checklist:
```
  ✅ backend  :8000 up — ... "llmMode":"live (Anthropic)" ...
  ✅ frontend :3000 up
  baseline: OK — subhachak/ctem-node-payments-api carries SCA+SAST+DAST vulns.
  READY.
```
If you want a **zero-risk predictable run**, pre-stage the two agentic scenarios so they're already sitting at their gates when you start talking (recommended for a tight 15 min):
```bash
./run.sh inject-code agentic    # SAST — will pause at score-review
./run.sh inject-code dast       # DAST — will pause at ontology review
```
Leave SCA to inject live (it's fast). Keep the browser open on **Dashboard**.

> **Presenter tip:** every detail page does a client-side fetch and flashes *"Loading…"* for ~1 second. Open the page a beat before you narrate it, or hit refresh once. Don't talk to a Loading screen.

**Timings you can rely on (measured, live):** SCA ≈ 30s end-to-end · SAST ≈ 40s · DAST ≈ 55s. The wait is the agents *actually working* — narrate over it, it's the best part.

---

## RUNSHEET (target ~13 min + 2 min buffer)

### 0:00 – 2:00 · Frame the problem (Dashboard)
**SAY:**
- "Every enterprise has the same backlog problem: thousands of findings, no context on which matter, and remediation that's still a human ticket-chase. Everyone's answer this year is 'make it agentic.'"
- "I'm an architect, so my question is the one your security team will ask: *if an AI is changing my code, how do I trust it?* This platform's answer is the demo."
- "Three layers. Layer 1 fuses each finding with the service, owner, and reachability — context. Layer 2 scores risk with **deterministic Python** — the same finding always gets the same score, and no LLM ever touches that number. Layer 3 is where the agents live."

**DO:** gesture at the Findings table + KPI cards.

### 2:00 – 5:00 · SCA — the *known* path (deterministic)
**DO:** `./run.sh inject-code live` → it opens `/review/{id}`.
**SAY (while it runs):**
- "Vulnerable lodash — CVE-2019-10744, prototype pollution. A *known* CVE with a *known* fixed version. There's nothing to be clever about, so the platform doesn't engage the AI at all — it routes to a **deterministic** version-bump recipe. Right tool for the job."
- Open the **review** page: "Scoring is deterministic — here's the exact formula and the factor breakdown. The LLM's *only* job here is to write the plain-English explanation next to it. It explains; it doesn't decide."
- "One human gate — governance approval — because we're changing a production dependency." → **approve** it.
- Open **remediation** page → **Agent orchestration** panel: "Watch the sub-agents. Every step is tagged **DETERMIN.** — Scanner confirmed it, Planner looked up the fixed version, Implementer bumped the manifest, Tester ran the *real* test suite and re-scanned."
**SHOW:** Closure evidence — 4 green artifacts + the **real GitHub PR** link. "That's a real pull request. Real `npm test`. A real re-scan proving the CVE is gone, and a runtime probe that actually fired a prototype-pollution payload at the fixed library."

### 5:00 – 8:30 · SAST — the AI writes code, and a guardrail *challenges* it
**DO:** open the pre-staged SAST run (or `./run.sh inject-code agentic`). It's paused at **score-review**.
**SAY:**
- "Now a first-party bug — OS command injection in our own code. No 'upgrade to version X' exists. This is where you need an agent."
- **The guardrail moment:** "Notice it paused — not at governance, at **score review**. A separate AI *plausibility judge* looked at the deterministic result and said 'a critical, runtime-reachable finding landing in the backlog tier doesn't sit right — a human should confirm.' The AI can *challenge* the deterministic score and escalate to a person. It still can't *change* the number — only flag it." → **confirm/approve.**
- Open **remediation** → orchestration panel: "Same four sub-agents, but now tagged **AGENTIC**. The Implementer made a real model call —" point at the **LLM** badge and the ~15-second duration "— and rewrote the source to remove the shell call."
- **The trust line:** "Here's the guardrail: whatever the agent writes only survives if it passes the **deterministic validation gate** — contract tests green, a fresh scan showing the pattern gone, and a **runtime exploit probe** that literally tries to inject a shell command and confirms it no longer executes. If the fix were wrong, the gate fails, the agent re-plans and retries — up to three times — and if it still can't, nothing closes and it goes to a human. The agent is creative; the scanner and the probe are the judge."
**SHOW:** the real PR + the 4 evidence artifacts.

### 8:30 – 12:00 · DAST — a *novel* class, found live, fixed by the agent
**DO:** open the pre-staged DAST run (or `./run.sh inject-code dast`). Paused at **ontology review**.
**SAY:**
- "Third class: a reflected XSS. And notice how it was *found* — not by reading code, but by a **black-box probe that booted the app and sent a real HTTP request** with an attack payload and saw it reflected back unescaped. That's DAST."
- **The guardrail moment:** "It paused at the **ontology gate**. The platform had never seen this vulnerability class before — it's genuinely novel — so instead of guessing, it asked a human to confirm the new category before proceeding. *Known* things run deterministically; *unknown* things get a human in the loop. That routing split is the whole philosophy." → **approve** the new category, then approve governance.
- Orchestration panel: "Agent rewrites the code to encode the output —" LLM badge "— and then the Tester **re-runs the exact same black-box HTTP probe**. Found dynamically, proven fixed dynamically."
**SHOW:** evidence — post-change re-probe shows the payload now returns HTML-encoded; verified closed.

### 12:00 – 13:30 · The bones (close strong)
**SAY:**
- "Recap the guardrails you just saw, because they're the product: **deterministic scoring** the AI can't touch; **routing** that only hands novel cases to the agent, with a human gate; a **deterministic validation gate** every agentic fix must pass; **bounded self-correction** so it can't loop forever; **independent verification** — a separate verifier re-checks every piece of evidence, its issuer, and a cryptographic digest before certifying closure; and a **full audit trail** of who did what."
- **THESIS AGAIN:** "Agentic execution, deterministic bones. Your team gets the autonomy — findings fixed, tested, and PR'd without a human writing the patch — and keeps the control. That's the version of 'agentic' that survives a security review."

### 13:30 – 15:00 · Buffer / Q&A

---

## IF ASKED (defensive talking points)

- **"Is the AI deciding severity/priority?"** → No. Risk and tier are pure deterministic Python (`reasoning_engine.py`), versioned and reproducible. The LLM writes the *explanation* and can *flag* a result for human review — it can never set or change the score, the tier, or an approval.
- **"What happens if the agent writes a broken or insecure fix?"** → It fails the deterministic validation gate (tests + re-scan + runtime exploit probe). A failed gate never closes — the agent re-plans with the failure as feedback and retries up to 3 times; if it still can't, the case stays open for a human. You saw the gate is what certifies, not the agent.
- **"Is this real or theatre?"** → Real. Real cloned repos, real `npm test`, real re-scans, a real runtime exploit probe, and real pull requests on GitHub. Independent verification checks each evidence artifact's issuer and SHA-256 digest — the agent literally cannot self-certify.
- **"How does it handle something it's never seen?"** → That's the DAST case. Novel class → agentic synthesis path *plus* a human ontology gate. It doesn't pretend to know; it asks, then learns the category.
- **"Why did some fixes not need the AI?"** → The SCA case. Known CVE with a known fix = deterministic recipe, no generative risk, faster and cheaper. We only spend agent capability where it's actually needed.
- **"Where's the human in control?"** → Three real gates you saw: ontology (novel classes), score-review (AI-flagged results), and governance (production changes). All are true pause/resume checkpoints, not cosmetic.

---

## BACKUP / TROUBLESHOOTING

- **Page stuck on "Loading…":** refresh once (client-side fetch race). Not a failure.
- **A scenario didn't reach a gate / looks stuck:** re-run `./run.sh reset` (≈20s) and re-inject. Reset also cleans up old PRs/branches and re-verifies the baseline.
- **No network / API key wobble on the day:** unset `CTEM_REMEDIATION_REPO` in `backend/.env` and `./run.sh restart` — the identical flow runs against a local snapshot with deterministic recorded fixes (no live model, no GitHub). Same screens, same story, zero external dependencies. *(Trade-off: no real PR link, and the agentic steps won't show the LLM badge.)*
- **Reset the whole thing to pristine at any point:** `./run.sh reset` → wait for the green READY checklist.

## QUICK REFERENCE

| Command | What it does |
|---|---|
| `./run.sh reset` | Ensures servers up, wipes state, cleans PRs/branches, verifies baseline, prints READY |
| `./run.sh inject-code live` | SCA scenario (deterministic dependency bump) |
| `./run.sh inject-code agentic` | SAST scenario (agentic code fix) |
| `./run.sh inject-code dast` | DAST scenario (black-box probe + agentic fix) |
| `./run.sh demo-scenarios` | Inject all three back-to-back |
| `./run.sh status` | Check both servers |

**Gate → who approves it:** ontology = "new vulnerability class" · score-review = "AI flagged the score" · governance = "approve a production change." Approve from the finding's `/review/{id}` page or the `/queues/*` pages.
