import unittest

from app.data.seed import FINDINGS
from app.decision_assurance import assess_data_quality, judge_plausibility
from app.layer1.context_graph import build_context_graph_record
from app.models import ReasoningEngineRecord


class DecisionAssuranceTests(unittest.TestCase):
    def test_demo_runtime_evidence_is_disclosed(self):
        finding = FINDINGS[0]
        result = assess_data_quality(finding, build_context_graph_record(finding))

        self.assertEqual(result.fieldStatus["runtimeReachability"], "simulated")
        self.assertTrue(any("not a live eBPF" in issue for issue in result.issues))

    def test_plausibility_judge_flags_critical_reachable_backlog(self):
        finding = FINDINGS[0]
        ctx = build_context_graph_record(finding)
        quality = assess_data_quality(finding, ctx)
        implausible = ReasoningEngineRecord(
            findingId=finding.id,
            exploitability=1,
            exposure=1,
            criticality=1,
            chainability=1,
            runtimeReachability=1,
            controlStrength=0,
            riskPriority=10,
            exploitableIssue=True,
            chainedVulns=[],
            businessCriticalAsset=False,
            blastRadius=1,
            predictiveRisk="rising",
            remediationApproach="emergency patch",
            actionTier="Tier 3",
            actionTierLabel="Backlog / preventive hardening",
        )

        result = judge_plausibility(finding, ctx, implausible, quality)

        self.assertEqual(result.assessment, "inconsistent")
        self.assertEqual(result.recommendedAction, "human-score-review")
        self.assertFalse(result.authoritative)


if __name__ == "__main__":
    unittest.main()
