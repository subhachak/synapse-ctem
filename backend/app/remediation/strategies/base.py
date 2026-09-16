"""
Remediation strategy interface.

A finding is classified to exactly one strategy. The orchestrator owns everything
universal (clone/branch, install, commit, diff, tests, push, PR, evidence, the
closure contract); the strategy owns only the three finding-specific steps:
  - scan(finding, ws)         -> is the finding present in this workspace?
  - mutate(finding, ws)       -> edit files in place to remediate (Synthesis)
  - runtime_probe(finding, ws)-> attempt the exploit against the fixed code
plus the naming/PR text for the change.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.models import RawFinding
from app.remediation._util import ProcResult
from app.remediation.scanner import ScanResult


@dataclass
class MutationResult:
    applied: bool
    detail: str
    method: str = "deterministic"  # or "anthropic-agent" / "recorded-agent-fallback"


class RemediationStrategy(ABC):
    name: str = "base"
    runtime_command: str = ""

    @abstractmethod
    def applies(self, finding: RawFinding) -> bool: ...

    @abstractmethod
    def scan(self, finding: RawFinding, ws_path: str) -> ScanResult: ...

    @abstractmethod
    def mutate(self, finding: RawFinding, ws_path: str, attempt: int = 1, feedback: str = "") -> MutationResult:
        """Edit files in place to remediate. `attempt`/`feedback` let the
        orchestrator re-drive an agentic synthesizer with the reason a prior
        attempt failed validation (the self-correcting loop); deterministic
        strategies ignore them."""
        ...

    @abstractmethod
    def runtime_probe(self, finding: RawFinding, ws_path: str) -> ProcResult: ...

    @abstractmethod
    def branch_slug(self, finding: RawFinding) -> str: ...

    @abstractmethod
    def commit_message(self, finding: RawFinding) -> str: ...

    @abstractmethod
    def pr_title(self, finding: RawFinding) -> str: ...

    @abstractmethod
    def pr_body(self, finding: RawFinding, diff: str) -> str: ...

    @abstractmethod
    def runtime_detail(self, passed: bool) -> str: ...
