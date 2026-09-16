"""Remediation strategy registry + classifier."""
from app.models import RawFinding
from app.remediation.strategies.agentic_code import AgenticCodeStrategy
from app.remediation.strategies.base import MutationResult, RemediationStrategy
from app.remediation.strategies.dast_web import DastWebStrategy
from app.remediation.strategies.dependency import DeterministicDependencyStrategy
from app.remediation.strategies.maven_ci_dependency import MavenCiDependencyStrategy
from app.remediation.strategies.spring_cf_ci import SpringCloudFunctionCiStrategy

# Order matters only for the fallthrough default (dependency).
_STRATEGIES: list[RemediationStrategy] = [
    DeterministicDependencyStrategy(),
    AgenticCodeStrategy(),
    DastWebStrategy(),
    MavenCiDependencyStrategy(),
    SpringCloudFunctionCiStrategy(),
]


def select_strategy(finding: RawFinding) -> RemediationStrategy:
    """Route a finding to its remediation strategy (a classifier hint on the finding)."""
    for strategy in _STRATEGIES:
        if strategy.applies(finding):
            return strategy
    return _STRATEGIES[0]  # default: dependency bump


__all__ = ["RemediationStrategy", "MutationResult", "select_strategy",
           "DeterministicDependencyStrategy", "AgenticCodeStrategy", "DastWebStrategy",
           "MavenCiDependencyStrategy", "SpringCloudFunctionCiStrategy"]
