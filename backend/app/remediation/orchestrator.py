"""
Remediation orchestration trace + classification.

The orchestrator (in live_adapter.py) decomposes a remediation into named
sub-agents — Scanner, Planner, Implementer, Tester — and, for agentic strategies,
loops Planner -> Implementer -> Tester until the deterministic validation gate is
satisfied or a bounded attempt budget is exhausted. This module holds the pieces
that describe that orchestration:

  - CLASSIFICATION: is this a KNOWN class with a deterministic recipe (SCA version
    bump), or a NOVEL one that needs agentic synthesis (SAST/DAST code fix)? This
    is the "routing: deterministic for the known, agentic for the unknown" split.
  - the AgentTrace/AgentStep builder the sub-agents append to.

Nothing here computes a risk score or an approval outcome — those stay in the
deterministic engine and the governance agent. This is execution telemetry only.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.models import AgentStep, AgentTrace

# strategy.name -> (scenarioClass, executionMode, human classification narrative)
_CLASSIFICATION = {
    "dependency-version-bump": (
        "SCA", "deterministic",
        "Known vulnerable dependency with a published fixed version. A deterministic "
        "version-bump recipe fully covers it — no generative step needed; the agent path is not engaged.",
    ),
    "maven-dependency-version-bump": (
        "SCA", "deterministic",
        "Known vulnerable dependency (Maven) with a published fixed version. Deterministic "
        "pom.xml version bump; build/test/exploit-probe verified on CI.",
    ),
    "agentic-code-fix": (
        "SAST", "agentic",
        "First-party source weakness with no canned fix recipe. Routed to the agentic synthesis "
        "path: a coding agent proposes the fix, bounded by a deterministic validation gate and "
        "self-correcting retries.",
    ),
    "maven-spring-cf-bump": (
        "SCA", "deterministic",
        "Known Spring Cloud Function SpEL RCE (CVE-2022-22963) with a published fixed version. "
        "Deterministic pom.xml property bump; build/test/exploit-probe verified on CI.",
    ),
    "agentic-dast-fix": (
        "DAST", "agentic",
        "Runtime-observable web weakness found by a black-box probe, no canned recipe. Routed to the "
        "agentic synthesis path with the same deterministic validation gate and self-correcting retries.",
    ),
}


def classify(strategy_name: str) -> tuple[str, str, str]:
    return _CLASSIFICATION.get(
        strategy_name,
        ("generic", "deterministic", "Unclassified strategy; treated as a deterministic single-shot fix."),
    )


@dataclass
class TraceBuilder:
    run_id: str
    strategy: str
    scenario_class: str
    max_attempts: int = 1
    _steps: list[AgentStep] = field(default_factory=list)
    _seq: int = 0

    def step(self, role: str, agent: str, action: str, detail: str, *,
             mode: str = "deterministic", status: str = "ok", attempt: int = 1,
             llm_used: bool = False, duration_ms: float = 0.0) -> None:
        self._seq += 1
        self._steps.append(AgentStep(
            seq=self._seq, role=role, agent=agent, attempt=attempt, mode=mode,
            action=action, detail=detail, status=status, llmUsed=llm_used,
            durationMs=round(duration_ms, 1),
        ))

    def build(self, attempts_used: int, converged: bool, summary: str) -> AgentTrace:
        return AgentTrace(
            runId=self.run_id, strategy=self.strategy, scenarioClass=self.scenario_class,
            maxAttempts=self.max_attempts, attemptsUsed=attempts_used, converged=converged,
            steps=self._steps, summary=summary,
        )


class _Timer:
    """Context manager returning elapsed milliseconds via .ms."""
    def __enter__(self):
        self._t0 = time.time()
        self.ms = 0.0
        return self

    def __exit__(self, *exc):
        self.ms = (time.time() - self._t0) * 1000.0
        return False
