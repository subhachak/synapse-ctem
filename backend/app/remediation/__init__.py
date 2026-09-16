"""
Live code-remediation adapter.

Turns the pipeline's execute_remediation / independent_verification stage from
simulated evidence into real actions against a real git repository: scan the
dependency, bump the manifest to the fixed version, run the real test suite,
re-scan to prove the tracked advisory is gone, (optionally) open a real GitHub
PR, and probe the fixed library at runtime. Every step produces a real,
digest-signed VerificationEvidence artifact tagged source="live-integration".

Design mirrors app/llm.py and app/retrieval.py: prefer the real external tool
(npm, npm audit, GitHub API), fall back deterministically when it is
unavailable, and never let the enrichment hold the authoritative pipeline
hostage. No LLM decides whether the fix worked — that is deterministic re-checked
evidence.
"""
from app.remediation.live_adapter import run_live_remediation, LiveRemediationResult
from app.remediation.workspace import reset_workspaces

__all__ = ["run_live_remediation", "LiveRemediationResult", "reset_workspaces"]
