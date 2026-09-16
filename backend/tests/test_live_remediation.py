import os
import shutil
import subprocess
import tempfile
import unittest

from app.llm import offline_reasoning
from app.models import RawFinding, RemediationTarget
from app.remediation import workspace as ws_mod
from app.remediation.live_adapter import run_live_remediation
from app.remediation.strategies import (
    AgenticCodeStrategy, DeterministicDependencyStrategy, select_strategy,
)
from app.verification import make_evidence, verify_adapter_evidence

_HAS_NODE = shutil.which("npm") is not None and shutil.which("node") is not None
_SNAPSHOT = "remediation_targets/node-payments-api"
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(ws_mod.__file__)))  # backend/app


def _target(**overrides) -> RemediationTarget:
    base = dict(
        repoSnapshot=_SNAPSHOT, vulnerablePackage="lodash", currentVersion="4.17.4",
        fixedVersion="4.17.21", targetAdvisory="GHSA-jf85-cpcp-j695", targetCve="CVE-2019-10744",
    )
    base.update(overrides)
    return RemediationTarget(**base)


def _finding(target: RemediationTarget) -> RawFinding:
    return RawFinding(
        id="test-live-1", cve="CVE-2019-10744", name="lodash prototype pollution",
        affectedComponent="lodash", severityLabel="Critical", discoveredBy="Scanner",
        affectedServiceIds=["svc-5"], softwareId="sw-x", epss=0.85, cisaKev=False,
        runtimeReachable=True, chainedWith=[], raOnBooks=False, remediationTarget=target,
    )


class _EnvIsolation(unittest.TestCase):
    """Keep runtime env from steering the adapter into an unintended mode."""

    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in ("CTEM_REMEDIATION_REPO", "GITHUB_TOKEN")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
        ws_mod.reset_workspaces()


@unittest.skipUnless(_HAS_NODE, "node/npm not available")
class LiveRemediationSnapshotTests(_EnvIsolation):
    """Offline fallback path: work from the committed snapshot, no remote."""

    def test_full_loop_verifies_closed_with_live_evidence(self):
        finding = _finding(_target())
        result = run_live_remediation(finding, "test-run-ok")

        self.assertTrue(result.sandboxPassed)
        self.assertIn("PRESENT", result.beforeSummary)
        self.assertIn("absent", result.afterSummary)
        self.assertIn("4.17.21", result.diff)

        record = verify_adapter_evidence(finding, result.evidence)
        self.assertTrue(record.verifiedClosed)
        self.assertEqual(record.evidenceMode, "LIVE")
        self.assertEqual({e.source for e in result.evidence}, {"live-integration"})

    def test_nonexistent_fix_version_blocks_closure(self):
        finding = _finding(_target(fixedVersion="4.99.99"))
        result = run_live_remediation(finding, "test-run-blocked")

        self.assertFalse(result.sandboxPassed)
        record = verify_adapter_evidence(finding, result.evidence)
        self.assertFalse(record.verifiedClosed)
        self.assertEqual(record.status, "failed")


@unittest.skipUnless(_HAS_NODE, "node/npm not available")
class LiveRemediationCloneTests(_EnvIsolation):
    """
    Primary path: clone a remote, branch, fix, push. Uses a local bare repo as a
    stand-in for GitHub (no network/token). The PR API call is skipped for a
    non-github remote, so deployment evidence comes from the pushed branch.
    """

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.mkdtemp(prefix="ctem-clone-test-")
        self.bare = os.path.join(self._tmp, "target.git")
        subprocess.run(["git", "init", "--bare", "-b", "main", self.bare], check=True, capture_output=True)
        seed = os.path.join(self._tmp, "seed")
        shutil.copytree(os.path.join(_APP_DIR, _SNAPSHOT), seed,
                        ignore=shutil.ignore_patterns("node_modules", ".git"))
        env = ["-c", "user.email=t@t", "-c", "user.name=t"]
        subprocess.run(["git", "init", "-b", "main", seed], check=True, capture_output=True)
        subprocess.run(["git", *env, "-C", seed, "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", *env, "-C", seed, "commit", "-m", "seed"], check=True, capture_output=True)
        subprocess.run(["git", "-C", seed, "remote", "add", "origin", self.bare], check=True, capture_output=True)
        subprocess.run(["git", *env, "-C", seed, "push", "origin", "main"], check=True, capture_output=True)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        super().tearDown()

    def test_clone_branch_fix_push_verifies_closed(self):
        finding = _finding(_target(remoteRepo=self.bare))
        result = run_live_remediation(finding, "test-run-clone")

        self.assertTrue(result.sandboxPassed)
        self.assertTrue(result.branch.startswith("ctem/fix-cve-2019-10744"))

        record = verify_adapter_evidence(finding, result.evidence)
        self.assertTrue(record.verifiedClosed)

        # The per-run fix branch was actually pushed back to the "remote".
        refs = subprocess.run(["git", "ls-remote", "--heads", self.bare],
                              check=True, capture_output=True, text=True).stdout
        self.assertIn(result.branch, refs)


class LiveEvidenceVerifierTests(unittest.TestCase):
    """No node/git required — exercises the verifier's live-issuer allowlist directly."""

    def _live_bundle(self, finding):
        return [
            make_evidence(finding, "sandbox-test", "pass", "tests passed", issuer="live-sandbox-npm", source="live-integration"),
            make_evidence(finding, "deployment-proof", "pass", "branch pushed", issuer="live-scm-git-branch", source="live-integration"),
            make_evidence(finding, "post-change-rescan", "pass", "advisory absent", issuer="live-scanner-npm-audit", source="live-integration"),
            make_evidence(finding, "runtime-path-check", "pass", "no pollution", issuer="live-runtime-node", source="live-integration"),
        ]

    def test_valid_live_bundle_verifies_closed(self):
        finding = _finding(_target())
        record = verify_adapter_evidence(finding, self._live_bundle(finding))
        self.assertTrue(record.verifiedClosed)
        self.assertEqual(record.evidenceMode, "LIVE")

    def test_self_issued_live_evidence_is_rejected(self):
        finding = _finding(_target())
        bundle = self._live_bundle(finding)
        bundle[0] = bundle[0].model_copy(update={"issuedBy": "implementation-agent"})
        self.assertFalse(verify_adapter_evidence(finding, bundle).verifiedClosed)

    def test_unknown_issuer_live_evidence_is_rejected(self):
        finding = _finding(_target())
        bundle = self._live_bundle(finding)
        bundle[2] = bundle[2].model_copy(update={"issuedBy": "totally-made-up-scanner"})
        self.assertFalse(verify_adapter_evidence(finding, bundle).verifiedClosed)


def _agentic_target() -> RemediationTarget:
    return RemediationTarget(
        strategy="agentic-code", repoSnapshot=_SNAPSHOT, filePath="src/server.js",
        vulnClass="command-injection", targetCve="CWE-78",
    )


class StrategySelectionTests(unittest.TestCase):
    def test_dependency_finding_routes_to_dependency_strategy(self):
        self.assertIsInstance(select_strategy(_finding(_target())), DeterministicDependencyStrategy)

    def test_code_finding_routes_to_agentic_strategy(self):
        self.assertIsInstance(select_strategy(_finding(_agentic_target())), AgenticCodeStrategy)


@unittest.skipUnless(_HAS_NODE, "node/npm not available")
class AgenticCodeStrategyTests(_EnvIsolation):
    """Offline (recorded-fallback) agentic fix of a first-party command injection."""

    def test_agentic_fix_verifies_closed(self):
        finding = _finding(_agentic_target())
        with offline_reasoning():  # force the deterministic recorded fix, no live model
            result = run_live_remediation(finding, "test-run-agentic")

        self.assertEqual(result.strategy, "agentic-code-fix")
        self.assertTrue(result.sandboxPassed)
        self.assertIn("PRESENT", result.beforeSummary)   # command-injection present before
        self.assertIn("absent", result.afterSummary)      # gone after
        self.assertIn("execFile", result.diff)            # a real source rewrite

        record = verify_adapter_evidence(finding, result.evidence)
        self.assertTrue(record.verifiedClosed)
        self.assertEqual(record.evidenceMode, "LIVE")
        runtime = next(e for e in result.evidence if e.evidenceType == "runtime-path-check")
        self.assertEqual(runtime.result, "pass")  # the injected command did not execute


if __name__ == "__main__":
    unittest.main()
