# Broadcom Spring GTM: Spoken Demo Script

Presenter narration for the live CTEM demo. Read it out loud a couple of times
so it sounds like you, not like a script. `[ACTION]` cues are what you do; the
plain text is what you say. Runs about 7 minutes.

Pair with `BROADCOM_SPRING_DEMO_RUNSHEET.md` for setup, gates, and fallbacks.

---

## Open (before you touch anything, ~40 sec)

> Quick bit of context before I click anything. Every one of your clients has
> the same problem right now: hundreds of known vulnerabilities, and no real way
> to know which ones actually matter, or to prove they've been fixed once
> someone says they are.
>
> What I'll show you is our CTEM platform doing that whole loop on a real Spring
> vulnerability. It finds it, it proves it's actually exploitable, it fixes it,
> and then, the part everyone skips, it proves the fix worked. Live, against a
> real repository. Nothing pre-recorded.
>
> And you'll see exactly where Broadcom fits, because the only legitimate fix
> here is a supported Spring version.

---

## 1. The finding (~30 sec)

`[ACTION] Run: ./run.sh inject-code spring`

> So a scanner has just flagged a critical issue in a Spring service. This is a
> real one: Spring Cloud Function, CVE-2022-22963. A single unauthenticated HTTP
> request gets you remote code execution.
>
> The first thing the platform does isn't score it. It builds context. Which
> service is this, who owns it, is it internet-facing, is it actually reachable
> at runtime. A CVE on a dev sandbox and the same CVE on your payments gateway
> are not the same risk, and most tools treat them as if they are.

---

## 2. Context and score (~40 sec)

`[ACTION] Open the review page for the run`

> Here's the score. And the important thing is how it got here. This is
> deterministic. It weighs exploitation likelihood against business impact with
> a fixed model. Same finding, same score, every time. No language model
> guessing a risk number it can't explain.
>
> That matters for your regulated clients. When an auditor asks why something
> was ranked critical, "the AI said so" is not an answer. This is.

---

## 3. The ontology gate (~30 sec)

`[ACTION] Go to the ontology queue, approve the item`

> Now watch this. It stopped. It hit a type of finding it hadn't classified
> before, and instead of guessing, it's asking a human to confirm the category
> before it goes any further.
>
> That's the theme you'll see throughout: the machine does the work, but it
> pauses at the points where judgment matters. I'll approve it.

---

## 4. The governance gate (~40 sec)

`[ACTION] Go to the governance queue, approve the item`

> It stopped again, and this is the one that matters most. This finding is on
> the known-exploited list, it's critical, and the service is internet-facing.
> Policy says a change like that needs a human to authorize it before anything
> touches production.
>
> This is exactly the control DORA and NIS2 are asking your UK and Europe
> clients to demonstrate. Not "we have automation," but "automation with a human
> accountable at the decision point, and a record of it." I'll authorize it.

---

## 5. Remediation running (~60 to 90 sec, fill the wait)

`[ACTION] Approve. The live CI run kicks off. Keep talking.`

> Now the agent takes over. It's branching the repository, applying the fix, and
> here's the part I want you to watch for. It is re-running the actual exploit
> against the patched build. On real CI, right now.
>
> Most tools stop at "we bumped the version." That's a hope, not a proof. The
> difference between a vulnerable and a fixed build is whether the exploit still
> works, so that's what we test. If it still fires, this does not close. Full
> stop.
>
> `[if it's still running]` This is running on GitHub Actions as we speak. Give
> it a moment. While it runs, notice what we have not done: we haven't touched
> production. This opens a pull request. Your team still owns the merge.

---

## 6. Verified closed (~40 sec)

`[ACTION] Show the evidence page, then switch to the real PR on GitHub`

> There it is. Verified closed. Four independent pieces of evidence, all green:
> it built, the tests pass, the re-scan shows the vulnerable version gone, and
> the exploit probe came back closed. Only now does the platform call this
> remediated.
>
> `[ACTION] switch to the PR tab]`
>
> And this is a real pull request, on a real repository, opened by the agent.
> One-line change: the vulnerable Spring version, bumped to the fixed one. Your
> engineer reviews it and merges it. Nothing magic, fully auditable.

---

## 7. Close and the Broadcom handoff (~30 sec)

> So step back and look at what that was. Find it, prove it's real, fix it, and
> prove the fix holds. With a human in control at every point that matters, and
> a complete record for the auditor.
>
> And the fix itself was a supported Spring version. That is the handoff. We
> find the exposure, we prove it, and we route it straight to the patch only
> Broadcom's Spring Enterprise can supply. For every one of your clients still
> running end-of-life Spring, that's the conversation: we make the risk
> undeniable, you provide the fix.
>
> Happy to take questions, or run it again on a different vulnerability class.

---

## 60-second version (if time gets cut)

> This is our CTEM platform on a real Spring vulnerability, a critical remote
> code execution in Spring Cloud Function.
>
> `[ACTION] inject-code spring, approve both gates]`
>
> It scores the risk deterministically, stops for human sign-off because it's
> critical and internet-facing, then fixes it and re-runs the actual exploit to
> prove it's closed.
>
> `[ACTION] show verified-closed + the PR]`
>
> Verified closed, on real evidence, with a real pull request your team merges.
> And the fix is a supported Spring version, which is where Broadcom comes in. We
> prove the risk, you supply the patch.

---

## Delivery notes

- Slow down on the two gates and on "it re-runs the actual exploit." Those are
  the three moments that separate this from every scanner they've seen.
- Say the Broadcom handoff line like you mean it. It's the reason you're both in
  the room.
- Do not mention Tanzu unless asked. If asked, use the answer in the runsheet.
- If CI lags past comfortable, stop narrating the wait and switch to the
  pre-baked PR: "here's one I ran earlier so we're not waiting on a queue."
