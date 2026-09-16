# Broadcom Spring GTM: Demo Runsheet

Internal prep for the joint Mphasis + Broadcom GTM session. Audience is
Broadcom's UK/Europe sales team. Subh joins ~6am ET (late morning UK) to set up
before the call.

Presenters: Subh (driver) + Phani. Decide who narrates vs who drives before you
start; the notes below assume one driver, one narrator.

---

## 1. The one-line story

CTEM finds a real Spring vulnerability, proves it is actually exploitable, fixes
it, opens a real pull request, and proves the exploit is closed. Automated, but
with human sign-off at the points that matter.

**Why it matters for this audience (say this out loud):**

- Mphasis automates the whole loop: find, fix, and *evidence* the fix.
- The only legitimate patch for end-of-life Spring comes through Broadcom's
  Spring Enterprise subscription. That is the commercial handoff: we surface the
  need and the exact fix version, Broadcom supplies the supported patch.
- UK/Europe angle: DORA and NIS2 require *demonstrable* remediation, not "we
  patched it." The audit trail and independent verification are the
  differentiator, not the patch itself.

---

## 2. What we are demoing

- **Scenario:** Spring Cloud Function SpEL RCE (CVE-2022-22963). An
  unauthenticated single-request remote code execution in a real Spring Boot
  app.
- **The fix:** a one-property dependency bump (spring-cloud-function 3.2.2 ->
  3.2.3), verified on real GitHub Actions CI.
- **The proof:** the actual exploit is re-run against the patched build and
  confirmed closed before anything is called "remediated."

This is a live run against a real repo (`subhachak/ctem-spring-demo`), not a
mock or a slideware walkthrough.

---

## 3. Pre-flight (build + verify the morning of, before the call)

Do this fresh so nothing is stale. Budget ~20 minutes.

**a. Network / environment**

- [ ] Run from the network + VPN you will actually present on. The backend has
      proxy-aware TLS handling (Netskope), but confirm live, not assume.
- [ ] `backend/.env` present with `ANTHROPIC_API_KEY`, `CTEM_LIVE_LLM=true`,
      `GITHUB_TOKEN`, and the three repo vars.

**b. Build + seed the Spring target**

```bash
cd ~/Projects/synapse-ctem
./run.sh setup-spring     # seeds subhachak/ctem-spring-demo with the vulnerable baseline
./run.sh start            # backend :8000 + frontend :3000, opens the dashboard
curl -s localhost:8000/api/health   # confirm "llmMode":"live (Anthropic)"
```

**c. Dry run the exact demo path once (this is also the backup, see section 6)**

```bash
./run.sh reset presentation   # clean seed data, queues auto-worked
./run.sh inject-code spring    # kicks off the live scenario
```

Then work the two gates (section 5) and confirm it reaches
**verified closed (live evidence)** with a real PR. Leave that finished run and
its PR tab open as the fallback.

- [ ] Dry run reached verified-closed
- [ ] PR is visible at `github.com/subhachak/ctem-spring-demo/pulls`
- [ ] A second fallback scenario works: `./run.sh inject-code log4j`
      (Log4Shell, same Java/CI shape) OR any npm one (`live`/`agentic`/`dast`,
      fully local, no CI dependency)

**d. Reset clean right before the call**

```bash
./run.sh reset presentation
```

---

## 4. Screen setup before you share

- Browser tab 1: dashboard (`localhost:3000`)
- Browser tab 2: the target repo on GitHub (`ctem-spring-demo`), Pull Requests
  view, so a real PR appearing lands visually
- Browser tab 3 (backup): the finished dry-run PR + its evidence page, ready to
  fall back to if CI lags
- Terminal visible, in the repo dir, font large enough to read

---

## 5. Live demo sequence

Roughly 6 to 8 minutes of screen time. The live CI step is ~1 to 2 minutes;
narrate through it, do not wait in silence.

| Beat | Action | What to say |
|---|---|---|
| **1. The finding** | `./run.sh inject-code spring` | "A scanner flagged a critical RCE in a Spring service. CTEM pulls in the context: which service, who owns it, is it internet-facing, is it actually reachable." |
| **2. Context + score** | Show the review page | "This isn't just a CVSS number. It scores exploitation likelihood against business impact deterministically. Same finding, same score, every time. No LLM guessing the risk." |
| **3. Ontology gate (pause)** | Approve in the ontology queue | "It hit something it hadn't classified before, so it stopped and asked a human to confirm the category. Governed, not a black box." |
| **4. Governance gate (pause)** | Approve in the governance queue | "This is KEV, critical, internet-facing. Policy says a human authorizes before any production change. This is the DORA / NIS2 control regulators want to see." |
| **5. Autonomous remediation** | Watch it run | "Now the agent takes over: branches the repo, applies the fix, and this is the important part, it re-runs the actual exploit on CI against the patched build." |
| **6. Verified closed** | Show evidence page + the real PR | "Four independent pieces of evidence, all green: build, test, re-scan, and the live exploit probe coming back closed. Only now is it called remediated. And here is the real pull request." |

**Landing line:** "The fix was a supported Spring version. That is where
Broadcom's Spring Enterprise comes in. We find it, prove it, and route it to the
patch only you can supply."

---

## 6. If something breaks (have this ready, do not improvise)

- **CI is slow / queued on the day:** stop waiting. Switch to browser tab 3 and
  walk the finished dry-run PR and its evidence page. Same story, pre-baked.
  Say: "here's one I ran earlier so we don't wait on GitHub's queue."
- **Network / VPN issue with GitHub:** switch to an npm scenario
  (`./run.sh inject-code live` or `agentic` or `dast`). Fully local, no CI, runs
  in seconds. You lose the "real PR" visual but keep the full find-fix-prove
  loop.
- **Backend won't start:** `./run.sh restart`, check `.run/backend.log`. If the
  venv is missing: `cd backend && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`.
- **Total failure:** have a screen recording of the successful dry run saved
  locally. For a sales audience a recording that works beats a live run that
  doesn't.

---

## 7. The Tanzu question

If asked whether this runs on / integrates with Tanzu:

> "No direct Tanzu integration in the POC today, and I won't pretend otherwise.
> The CTEM layer is platform-agnostic. It works against any Spring codebase and
> CI, so it sits naturally alongside Tanzu Application Catalog and Spring
> Enterprise. Wiring it to Tanzu's inventory and supported-build feeds is a
> concrete next step, not a rebuild."

Do not overclaim. A Broadcom sales audience will include people who know Tanzu
well.

---

## 8. Likely questions + crisp answers

- **"Is the fix AI-generated? Can we trust it?"** For dependency CVEs like this
  one, the fix is a deterministic version bump, not model output. For code-level
  fixes we do use an agent, but nothing is accepted until it passes tests, a
  re-scan, and the live exploit probe. The model proposes; deterministic gates
  decide.
- **"What if the AI is wrong?"** It cannot self-certify. Closure requires four
  independent pieces of evidence and a human authorization gate. A failed check
  blocks the change, it does not close it.
- **"Does it touch production?"** No. It opens a pull request. A human approves
  the merge. We surface and prove; the client's own change process ships.
- **"How is this different from Dependabot / Snyk?"** Those tell you a fix
  exists. This proves the specific exploit is actually closed on your build, with
  an audit trail, and routes end-of-life Spring to the only supported patch.
- **"What does it cost to run?"** The scoring and gates are deterministic, no
  per-finding model cost. The LLM is used only for narrative and for code-level
  fixes, and it runs offline-deterministic when no key is set.

---

## 9. Fast command reference

```bash
./run.sh start                 # bring everything up
./run.sh setup-spring          # (re)seed the Spring target repo
./run.sh reset presentation    # clean state before the call
./run.sh inject-code spring    # THE demo
./run.sh inject-code log4j     # Java/CI fallback
./run.sh inject-code live      # local npm fallback (no CI)
./run.sh stop                  # shut down
curl -s localhost:8000/api/health   # confirm live mode
```

Gates are worked in the UI (ontology + governance queues on the dashboard), or
via the review page for the injected run.
