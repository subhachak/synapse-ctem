"""
Orchestrates a real remediation and emits live, digest-signed evidence.

The orchestrator is strategy-agnostic. It owns everything universal — clone a clean
workspace, branch, apply the strategy's mutation, install, commit, diff, run the
real tests, re-scan, push + open a PR, run the strategy's runtime probe, and assemble
the four evidence artifacts — and delegates only scan / mutate / runtime_probe (and
the change's naming/PR text) to the selected RemediationStrategy.

Sequence (post-authorization, driven from graph.py's execute_remediation node):
  prepare -> scan(before) -> branch -> mutate -> install -> commit -> diff
          -> test  (a failed test blocks all downstream evidence)
          -> deploy (push+PR, or local branch) -> scan(after) -> runtime probe
A failing gate is never certified closed — same contract for every strategy.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field

from app.models import AgentTrace, RawFinding, VerificationEvidence
from app.remediation import actions_ci, code_fix, github_pr
from app.remediation import workspace as ws_mod
from app.remediation.orchestrator import TraceBuilder, _Timer, classify
from app.remediation.strategies import select_strategy
from app.verification import make_evidence

_RESCAN_ISSUER = {
    "npm-audit": "live-scanner-npm-audit",
    "offline-osv-db": "live-scanner-osv-offline",
    "sast-pattern": "live-scanner-sast",
    "dast-http-probe": "live-scanner-dast",
}
# Max Planner->Implementer->Tester attempts for agentic strategies. Deterministic
# strategies converge in one shot (a known recipe), so they never loop.
_MAX_AGENTIC_ATTEMPTS = 3


def _rescan_issuer(scanner_name: str) -> str:
    return _RESCAN_ISSUER.get(scanner_name, "live-scanner-osv-offline")


@dataclass
class LiveRemediationResult:
    evidence: list[VerificationEvidence]
    sandboxPassed: bool
    strategy: str = ""
    diff: str = ""
    prUrl: str = ""
    branch: str = ""
    scannerName: str = ""
    beforeSummary: str = ""
    afterSummary: str = ""
    notes: list[str] = field(default_factory=list)
    trace: AgentTrace | None = None


def _ev(finding, etype, result, detail, issuer, **extra) -> VerificationEvidence:
    return make_evidence(finding, etype, result, detail, issuer=issuer, source="live-integration", **extra)


def run_live_remediation(finding: RawFinding, run_id: str) -> LiveRemediationResult:
    """Dispatches by ecosystem. npm targets (node-payments-api) run
    build/test/runtime-probe as local subprocesses, unchanged from the
    original implementation. maven targets (log4j) have no local-JDK
    assumption -- see run_live_remediation_ci."""
    target = finding.remediationTarget
    if target is not None and target.ecosystem == "maven":
        return run_live_remediation_ci(finding, run_id)
    return _run_live_remediation_npm(finding, run_id)


def _run_live_remediation_npm(finding: RawFinding, run_id: str) -> LiveRemediationResult:
    """Local-subprocess orchestrator for npm targets.

    An orchestrator delegates to named sub-agents — Scanner, Planner, Implementer,
    Tester — and, for agentic strategies, loops Planner->Implementer->Tester until
    the deterministic validation gate (contract tests pass + the tracked finding is
    gone on re-scan + the runtime exploit probe is closed) is satisfied, or a
    bounded attempt budget is spent. Deterministic strategies (SCA) run the same
    shape but converge in a single attempt. Every step is recorded on an AgentTrace.
    """
    strategy = select_strategy(finding)
    target = finding.remediationTarget
    notes: list[str] = []

    scenario_class, exec_mode, classification = classify(strategy.name)
    is_agentic = exec_mode == "agentic"
    max_attempts = _MAX_AGENTIC_ATTEMPTS if is_agentic else 1
    tb = TraceBuilder(run_id, strategy.name, scenario_class, max_attempts=max_attempts)

    # Orchestrator: classify the finding — the deterministic-vs-agentic routing.
    tb.step("orchestrator", "Orchestrator", "classify + route",
            f"{classification} (execution mode: {exec_mode}, attempt budget: {max_attempts}).",
            mode=exec_mode)

    with _Timer() as t:
        workspace = ws_mod.prepare(run_id, target)
    tb.step("orchestrator", "Orchestrator", "prepare workspace",
            f"Cloned a clean git workspace ({workspace.mode} mode) and installed the vulnerable baseline.",
            duration_ms=t.ms)

    suffix = re.sub(r"[^0-9a-z]+", "", run_id.lower())[:8]
    branch = code_fix.branch_name(strategy.branch_slug(finding), suffix)
    ws_mod.git(workspace, "checkout", "-B", branch)
    diff = ""
    attempt = 0
    converged = False

    def _finish(sandbox_ok: bool, ev: list[VerificationEvidence], summary: str | None = None,
                **extra) -> LiveRemediationResult:
        text = summary or (f"{scenario_class} · {strategy.name}: "
                           + ("converged" if converged else "did NOT converge")
                           + f" after {attempt} attempt(s).")
        tb.step("orchestrator", "Orchestrator", "hand off to governance",
                f"{text} Evidence assembled for independent verification; no closure certified here.",
                mode=exec_mode)
        trace = tb.build(attempts_used=attempt, converged=converged, summary=text)
        return LiveRemediationResult(evidence=ev, sandboxPassed=sandbox_ok, strategy=strategy.name,
                                     diff=diff, branch=branch, trace=trace, **extra)

    # Scanner sub-agent: confirm the finding is really present (deterministic
    # evidence — SCA reads the manifest, SAST pattern-matches source, DAST probes
    # the running app over HTTP; none of them make an LLM decision).
    with _Timer() as t:
        before = strategy.scan(finding, workspace.path)
    tb.step("scanner", "Scanner Agent", "confirm finding present",
            before.summary(), status="ok" if before.targetPresent else "fail", duration_ms=t.ms)

    # Demo-integrity guard: if the tracked finding is NOT present in the cloned
    # target, there is nothing to remediate — never manufacture a vacuous "closed".
    # In live PR-mode this almost always means the target repo predates this
    # vulnerability; refresh it with ./run.sh setup.
    if not before.targetPresent:
        where = workspace.remote_repo or "the local snapshot"
        tb.step("orchestrator", "Orchestrator", "abort — nothing to remediate",
                f"The tracked {scenario_class} finding was NOT present in {where}. No fix was synthesised and "
                f"no closure is claimed. If you expected it here, the target baseline is stale — refresh it "
                f"(./run.sh setup) so it carries this vulnerability.",
                mode=exec_mode, status="fail")
        ev = [
            _ev(finding, "sandbox-test", "not-run",
                f"Not run: the tracked finding was absent from {where}; nothing to remediate.", issuer="live-sandbox-npm"),
            _ev(finding, "deployment-proof", "not-run", "Not run: nothing to remediate.", issuer="live-scm-git-branch"),
            _ev(finding, "post-change-rescan", "not-run", "Not run: nothing to remediate.",
                issuer=_rescan_issuer(before.scannerName)),
            _ev(finding, "runtime-path-check", "not-run", "Not run: nothing to remediate.", issuer="live-runtime-node"),
        ]
        return _finish(False, ev,
                       summary=f"{scenario_class} · {strategy.name}: finding not present in target baseline — aborted, nothing to remediate.",
                       scannerName=before.scannerName, beforeSummary=before.summary(),
                       notes=["finding not present in target baseline"])

    # --- Planner -> Implementer -> Tester loop ---
    mutation = install = tests = after = runtime = None
    feedback = ""
    while attempt < max_attempts:
        attempt += 1
        if attempt > 1:
            # Discard the previous failed attempt so the synthesizer re-plans from
            # the pristine baseline, not from broken output.
            ws_mod.git(workspace, "checkout", "--", ".")

        # Planner sub-agent.
        plan_detail = (
            f"Deterministic recipe: bump {target.vulnerablePackage} {target.currentVersion} -> {target.fixedVersion}."
            if not is_agentic else
            (f"Re-plan (attempt {attempt}) using the prior failure: {feedback}" if attempt > 1
             else f"Synthesize a minimal, behaviour-preserving fix for {target.vulnClass or 'the weakness'} in {target.filePath}.")
        )
        tb.step("planner", "Planner Agent", "select fix approach", plan_detail,
                mode=exec_mode, attempt=attempt)

        # Implementer sub-agent (the actual code/manifest change).
        with _Timer() as t:
            mutation = strategy.mutate(finding, workspace.path, attempt=attempt, feedback=feedback)
        llm_used = mutation.method.startswith("anthropic")
        tb.step("implementer", "Implementer Agent", "apply fix",
                f"{mutation.detail} [{mutation.method}]",
                mode=exec_mode, attempt=attempt, llm_used=llm_used, duration_ms=t.ms,
                status="ok" if mutation.applied else "info")

        # Tester sub-agent, part 1: install + real contract tests.
        install = code_fix.npm_install(workspace.path)
        tests = code_fix.run_tests(workspace.path, target.testCommand) if install.ok else install
        if not (install.ok and tests.ok):
            reason = f"install failed (exit {install.code})" if not install.ok else "contract tests failed"
            feedback = f"the change {reason}."
            can_retry = is_agentic and attempt < max_attempts
            tb.step("tester", "Tester Agent", "contract tests",
                    f"Build/tests did not pass after the change: {reason}.",
                    attempt=attempt, status="retry" if can_retry else "fail")
            if can_retry:
                continue
            break

        # Tester sub-agent, part 2: the deterministic validation gate —
        # re-scan for the tracked finding + run the runtime exploit probe.
        after = strategy.scan(finding, workspace.path)
        runtime = strategy.runtime_probe(finding, workspace.path)
        closed = (not after.targetPresent) and runtime.ok
        if closed:
            converged = True
            tb.step("tester", "Tester Agent", "validation gate",
                    f"PASS — contract tests green, re-scan shows the finding absent, and the runtime "
                    f"exploit probe is closed. {strategy.runtime_detail(True)}",
                    attempt=attempt, status="ok")
            break
        feedback = (f"tests passed but the vulnerability was not closed "
                    f"(re-scan present={after.targetPresent}, runtime probe closed={runtime.ok}).")
        can_retry = is_agentic and attempt < max_attempts
        tb.step("tester", "Tester Agent", "validation gate",
                f"Fix did not close the exposure: {feedback}",
                attempt=attempt, status="retry" if can_retry else "fail")
        if not can_retry:
            break

    # Commit the (last) attempt so a diff and PR can be produced.
    code_fix.commit_all(workspace, strategy.commit_message(finding))
    diff = code_fix.diff_tree(workspace, branch)
    sandbox_passed = bool(install and install.ok and tests and tests.ok)

    if not (install and install.ok):
        sandbox_detail = f"Build/install failed (exit {install.code if install else '?'}); no validated change to deploy. {mutation.detail}"
        sandbox_command = "npm install"
    elif sandbox_passed:
        sandbox_detail = f"Real test suite passed after the change: {mutation.detail} [{mutation.method}]"
        sandbox_command = target.testCommand
    else:
        sandbox_detail = f"Contract tests failed after the change; deployment blocked. {mutation.detail}"
        sandbox_command = target.testCommand

    evidence: list[VerificationEvidence] = [
        _ev(finding, "sandbox-test", "pass" if sandbox_passed else "fail", sandbox_detail,
            issuer="live-sandbox-npm", command=sandbox_command, log_excerpt=(tests.tail() if tests else ""))
    ]

    if not sandbox_passed:
        for etype, issuer in (
            ("deployment-proof", "live-scm-git-branch"),
            ("post-change-rescan", _rescan_issuer(before.scannerName)),
            ("runtime-path-check", "live-runtime-node"),
        ):
            evidence.append(_ev(finding, etype, "not-run",
                                "Not run: sandbox contract tests failed, so no change was deployed.", issuer=issuer))
        return _finish(False, evidence, scannerName=before.scannerName, beforeSummary=before.summary(),
                       notes=[mutation.detail, f"install exit={install.code if install else '?'}"])

    # --- deployment: push + PR in clone mode, else the local fix branch ---
    pr_url = ""
    if workspace.mode == "pr":
        push = github_pr.push_branch(workspace.path, branch)
        if push.ok:
            pr = github_pr.open_pull_request(
                workspace.remote_repo, workspace.base_branch, branch,
                strategy.pr_title(finding), strategy.pr_body(finding, diff),
            )
            if pr["ok"]:
                pr_url = pr["url"]
                deploy_result, deploy_issuer, deploy_detail = "pass", "live-cicd-github", pr["detail"]
            else:
                deploy_result, deploy_issuer, deploy_detail = "pass", "live-scm-git-branch", \
                    f"Branch {branch} pushed to {workspace.remote_repo}; PR API deferred ({pr['detail']})."
                notes.append(pr["detail"])
        else:
            deploy_result, deploy_issuer, deploy_detail = "fail", "live-scm-git-branch", \
                f"git push to {workspace.remote_repo} failed: {push.tail(300)}"
    else:
        deploy_result, deploy_issuer, deploy_detail = "pass", "live-scm-git-branch", \
            (f"Fix committed to branch {branch} (local snapshot mode; configure CTEM_REMEDIATION_REPO "
             f"+ GITHUB_TOKEN to clone from GitHub and open a PR).")

    evidence.append(_ev(finding, "deployment-proof", deploy_result, deploy_detail,
                        issuer=deploy_issuer, command=f"git commit + {'PR' if pr_url else 'branch'}",
                        log_excerpt=diff[:1500], pr_url=pr_url))

    # --- post-change re-scan + runtime probe: reuse the Tester sub-agent's own
    #     validation-gate results (already run in the loop above) so we don't
    #     re-boot the app or re-scan a second time. ---
    rescan_pass = not after.targetPresent
    evidence.append(_ev(finding, "post-change-rescan", "pass" if rescan_pass else "fail", after.summary(),
                        issuer=_rescan_issuer(after.scannerName), command=after.scannerName,
                        log_excerpt=after.raw[-1500:]))

    evidence.append(_ev(finding, "runtime-path-check", "pass" if runtime.ok else "fail",
                        strategy.runtime_detail(runtime.ok), issuer="live-runtime-node",
                        command=strategy.runtime_command, log_excerpt=runtime.tail(300)))

    return _finish(True, evidence, prUrl=pr_url, scannerName=after.scannerName,
                   beforeSummary=before.summary(), afterSummary=after.summary(), notes=notes)


def run_live_remediation_ci(finding: RawFinding, run_id: str) -> LiveRemediationResult:
    """
    Maven/log4j path: build/test and the JNDI runtime-probe run for real on
    GitHub Actions (see actions_ci.py), not as local subprocesses -- this
    demo host has no local JDK/Maven. Necessarily a different step order
    than the npm path: the branch must be PUSHED before a CI verdict is
    available at all, so push happens before we know whether the fix
    actually works, and the PR only opens once CI confirms it does. Same
    "a failing gate is never certified closed" contract either way.
    """
    strategy = select_strategy(finding)
    target = finding.remediationTarget
    notes: list[str] = []

    workspace = ws_mod.prepare(run_id, target)
    before = strategy.scan(finding, workspace.path)

    suffix = re.sub(r"[^0-9a-z]+", "", run_id.lower())[:8]
    branch = code_fix.branch_name(strategy.branch_slug(finding), suffix)
    ws_mod.git(workspace, "checkout", "-B", branch)

    mutation = strategy.mutate(finding, workspace.path)
    code_fix.commit_all(workspace, strategy.commit_message(finding))
    diff = code_fix.diff_tree(workspace, branch)

    if workspace.mode != "pr":
        # No remote repo configured (CTEM_LOG4J_REMEDIATION_REPO / the
        # finding's remoteRepo) -- GitHub Actions can't verify a branch that
        # was never pushed. Degrade honestly rather than fabricate a result.
        evidence = [_ev(finding, "sandbox-test", "not-run",
                        "No GitHub repo configured for this target -- GitHub Actions verification "
                        "requires a real remote branch to check out. Run ./run.sh setup-log4j.",
                        issuer="live-ci-github-actions")]
        for etype in ("deployment-proof", "post-change-rescan", "runtime-path-check"):
            evidence.append(_ev(finding, etype, "not-run", "Not run: no remote repo configured.",
                                issuer="live-ci-github-actions"))
        return LiveRemediationResult(evidence=evidence, sandboxPassed=False, strategy=strategy.name,
                                      diff=diff, branch=branch, beforeSummary=before.summary(),
                                      notes=["local-only workspace; GitHub Actions verification requires a remote repo"])

    push = github_pr.push_branch(workspace.path, branch)
    if not push.ok:
        evidence = [_ev(finding, "sandbox-test", "not-run", f"git push failed: {push.tail(300)}",
                        issuer="live-scm-git-branch")]
        for etype in ("deployment-proof", "post-change-rescan", "runtime-path-check"):
            evidence.append(_ev(finding, etype, "not-run", "Not run: branch push failed.",
                                issuer="live-scm-git-branch"))
        return LiveRemediationResult(evidence=evidence, sandboxPassed=False, strategy=strategy.name,
                                      diff=diff, branch=branch, beforeSummary=before.summary())

    ci = actions_ci.run_and_wait(workspace.remote_repo, target.ciWorkflow, branch)
    build_ok = ci.markers.get("BUILD_RESULT") == "PASS"
    test_ok = ci.markers.get("TEST_RESULT") == "PASS"
    probe_closed = ci.markers.get("JNDI_PROBE_RESULT") == "CLOSED"
    sandbox_passed = ci.ok and build_ok and test_ok

    if ci.ok:
        sandbox_detail = (
            f"GitHub Actions run {ci.run_id} ({ci.conclusion}): build={ci.markers.get('BUILD_RESULT','?')}, "
            f"test={ci.markers.get('TEST_RESULT','?')}, log4j-core version={ci.markers.get('LOG4J_VERSION','?')}. "
            f"{mutation.detail} [{mutation.method}]"
        )
    else:
        sandbox_detail = f"GitHub Actions verification did not complete: {ci.detail}"

    evidence: list[VerificationEvidence] = [
        _ev(finding, "sandbox-test", "pass" if sandbox_passed else "fail", sandbox_detail,
            issuer="live-ci-github-actions", command=f"workflow_dispatch: {target.ciWorkflow}",
            log_excerpt=ci.log_excerpt)
    ]

    if not sandbox_passed:
        for etype, issuer in (
            ("deployment-proof", "live-scm-git-branch"),
            ("post-change-rescan", "live-scanner-osv-offline-maven"),
            ("runtime-path-check", "live-runtime-github-actions"),
        ):
            evidence.append(_ev(finding, etype, "not-run",
                                "Not run: GitHub Actions build/test did not pass, so no change was certified.",
                                issuer=issuer))
        return LiveRemediationResult(
            evidence=evidence, sandboxPassed=False, strategy=strategy.name, diff=diff, branch=branch,
            beforeSummary=before.summary(), notes=[mutation.detail, ci.detail],
        )

    # --- deployment: open the PR now that CI has confirmed the fix builds/tests clean ---
    pr = github_pr.open_pull_request(
        workspace.remote_repo, workspace.base_branch, branch,
        strategy.pr_title(finding), strategy.pr_body(finding, diff),
    )
    if pr["ok"]:
        pr_url = pr["url"]
        deploy_result, deploy_issuer, deploy_detail = "pass", "live-cicd-github", pr["detail"]
    else:
        pr_url = ""
        deploy_result, deploy_issuer, deploy_detail = "pass", "live-scm-git-branch", \
            f"Branch {branch} pushed to {workspace.remote_repo}; PR API deferred ({pr['detail']})."
        notes.append(pr["detail"])

    evidence.append(_ev(finding, "deployment-proof", deploy_result, deploy_detail,
                        issuer=deploy_issuer, command=f"git push + PR (verified by {target.ciWorkflow})",
                        log_excerpt=diff[:1500], pr_url=pr_url))

    # --- post-change re-scan: real parse of the pushed pom.xml ---
    after = strategy.scan(finding, workspace.path)
    rescan_pass = not after.targetPresent
    evidence.append(_ev(finding, "post-change-rescan", "pass" if rescan_pass else "fail", after.summary(),
                        issuer="live-scanner-osv-offline-maven", command="pom.xml parse",
                        log_excerpt=after.raw[-1500:]))

    # --- runtime probe: the actual Log4Shell JNDI-lookup check, from the same CI run ---
    evidence.append(_ev(finding, "runtime-path-check", "pass" if probe_closed else "fail",
                        strategy.runtime_detail(probe_closed), issuer="live-runtime-github-actions",
                        command=strategy.runtime_command, log_excerpt=ci.log_excerpt))

    return LiveRemediationResult(
        evidence=evidence, sandboxPassed=True, strategy=strategy.name, diff=diff, prUrl=pr_url, branch=branch,
        scannerName=after.scannerName, beforeSummary=before.summary(), afterSummary=after.summary(), notes=notes,
    )


def safe_run_live_remediation(finding: RawFinding, run_id: str) -> LiveRemediationResult:
    """Never let a live-adapter error break the pipeline; degrade to a failed-sandbox record."""
    try:
        return run_live_remediation(finding, run_id)
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[live_adapter] live remediation failed, recording as blocked: {exc}", file=sys.stderr)
        target = finding.remediationTarget
        issuer = "live-ci-github-actions" if target and target.ecosystem == "maven" else "live-sandbox-npm"
        ev = [
            _ev(finding, "sandbox-test", "fail", f"Live adapter error: {exc}", issuer=issuer),
            _ev(finding, "deployment-proof", "not-run", "Not run after adapter error.", issuer="live-scm-git-branch"),
            _ev(finding, "post-change-rescan", "not-run", "Not run after adapter error.", issuer="live-scanner-osv-offline"),
            _ev(finding, "runtime-path-check", "not-run", "Not run after adapter error.", issuer="live-runtime-node"),
        ]
        return LiveRemediationResult(evidence=ev, sandboxPassed=False, notes=[str(exc)])
