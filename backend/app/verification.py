"""Adapter-issued evidence and independent closure verification.

Two evidence sources share one verifier:
  - "simulated-adapter": deterministic demo evidence (collect_demo_adapter_evidence).
  - "live-integration": real evidence produced by app/remediation/live_adapter.py
    (npm test, real scanner rescan, real git/PR deployment, real runtime check).

The verifier is independent of whoever produced the evidence: it re-checks that
all four evidence types are present, each was issued by an allowlisted adapter
for its source (never the implementation agent itself), names the right finding,
carries a matching integrity digest, and reports "pass". Only then is a
remediation certified closed. This is the same contract regardless of source.
"""

from datetime import datetime, timezone
import hashlib

from app.models import ImplementationAgentOutput, RawFinding, VerificationEvidence, VerificationRecord

EVIDENCE_TYPES = ("sandbox-test", "deployment-proof", "post-change-rescan", "runtime-path-check")

# Expected issuer(s) per (source, evidence-type). A verifier accepts evidence
# only from these adapters; deployment-proof has two acceptable live issuers
# because a live remediation may deploy via a real GitHub PR or, in local mode,
# a pushed git branch.
_ISSUERS = {
    "simulated-adapter": {
        "sandbox-test": {"demo-sandbox-adapter"},
        "deployment-proof": {"demo-cicd-adapter"},
        "post-change-rescan": {"demo-scanner-adapter"},
        "runtime-path-check": {"demo-runtime-adapter"},
    },
    "live-integration": {
        "sandbox-test": {"live-sandbox-npm", "live-ci-github-actions"},
        "deployment-proof": {"live-cicd-github", "live-scm-git-branch"},
        "post-change-rescan": {"live-scanner-npm-audit", "live-scanner-osv-offline", "live-scanner-sast", "live-scanner-dast", "live-scanner-osv-offline-maven"},
        "runtime-path-check": {"live-runtime-node", "live-runtime-github-actions"},
    },
}

# Back-compat: the simulated issuer map the rest of the codebase referenced as ISSUERS.
ISSUERS = {etype: next(iter(issuers)) for etype, issuers in _ISSUERS["simulated-adapter"].items()}


def _digest(evidence_type: str, artifact_id: str, result: str, issuer: str, finding_id: str, observed_at: str) -> str:
    value = "|".join((evidence_type, artifact_id, result, issuer, finding_id, observed_at))
    return hashlib.sha256(value.encode()).hexdigest()


def make_evidence(
    finding: RawFinding,
    evidence_type: str,
    result: str,
    detail: str,
    *,
    issuer: str,
    source: str = "simulated-adapter",
    artifact_id: str | None = None,
    command: str = "",
    log_excerpt: str = "",
    pr_url: str = "",
) -> VerificationEvidence:
    """Build one signed evidence artifact. Shared by the simulated and live adapters."""
    observed_at = datetime.now(timezone.utc).isoformat()
    artifact_id = artifact_id or f"{source}-{finding.id}-{evidence_type}"
    return VerificationEvidence(
        evidenceType=evidence_type,
        artifactId=artifact_id,
        result=result,
        source=source,
        detail=detail,
        issuedBy=issuer,
        subjectFindingId=finding.id,
        observedAt=observed_at,
        artifactDigest=_digest(evidence_type, artifact_id, result, issuer, finding.id, observed_at),
        command=command,
        logExcerpt=log_excerpt,
        prUrl=pr_url,
    )


def _evidence(finding: RawFinding, evidence_type: str, result: str, detail: str) -> VerificationEvidence:
    return make_evidence(
        finding, evidence_type, result, detail,
        issuer=ISSUERS[evidence_type], source="simulated-adapter",
        artifact_id=f"demo-{finding.id}-{evidence_type}",
    )


def collect_demo_adapter_evidence(finding: RawFinding, implementation: ImplementationAgentOutput) -> list[VerificationEvidence]:
    """Execute the draft through typed adapters; the implementation agent supplies no result."""
    sandbox_result = "fail" if finding.demoScenario == "sandbox-failure" else "pass"
    downstream = "pass" if sandbox_result == "pass" else "not-run"
    return [
        _evidence(finding, "sandbox-test", sandbox_result, "Sandbox adapter executed the drafted characterization and contract tests."),
        _evidence(finding, "deployment-proof", downstream, "CI/CD adapter recorded deployment proof." if downstream == "pass" else "Deployment blocked after sandbox failure."),
        _evidence(finding, "post-change-rescan", downstream, "Scanner adapter found the vulnerable signature absent." if downstream == "pass" else "Rescan not run because deployment did not occur."),
        _evidence(finding, "runtime-path-check", downstream, "Runtime adapter observed the modeled exploit path closed." if downstream == "pass" else "Runtime closure not asserted because deployment did not occur."),
    ]


def verify_adapter_evidence(finding: RawFinding, evidence: list[VerificationEvidence]) -> VerificationRecord:
    by_type = {item.evidenceType: item for item in evidence}
    valid = len(by_type) == len(EVIDENCE_TYPES)
    for evidence_type in EVIDENCE_TYPES:
        item = by_type.get(evidence_type)
        if not item:
            valid = False
            continue
        allowed = _ISSUERS.get(item.source, {}).get(evidence_type, set())
        issuer_ok = item.issuedBy in allowed and item.issuedBy != "implementation-agent"
        # Recompute with the claimed issuer only if it is allowlisted; otherwise a
        # sentinel guarantees the digest cannot match, so tampered/self-issued
        # evidence fails on both the issuer check and the integrity check.
        digest_issuer = item.issuedBy if issuer_ok else "__unauthorized-issuer__"
        expected_digest = _digest(evidence_type, item.artifactId, item.result, digest_issuer, finding.id, item.observedAt)
        valid = valid and issuer_ok
        valid = valid and item.subjectFindingId == finding.id
        valid = valid and item.artifactDigest == expected_digest
        valid = valid and item.result == "pass"
    mode = "LIVE" if any(item.source == "live-integration" for item in evidence) else "SIMULATED"
    return VerificationRecord(
        findingId=finding.id,
        status="verified-closed" if valid else "failed",
        evidence=evidence,
        verifiedClosed=valid,
        evidenceMode=mode,
    )


def verify_demo_remediation(finding: RawFinding, implementation: ImplementationAgentOutput) -> VerificationRecord:
    """Compatibility helper used by tests/callers; collection and verification remain separate."""
    return verify_adapter_evidence(finding, collect_demo_adapter_evidence(finding, implementation))


def verification_not_run(finding: RawFinding) -> VerificationRecord:
    return VerificationRecord(findingId=finding.id, status="not-run")
