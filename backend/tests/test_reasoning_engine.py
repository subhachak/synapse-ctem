import unittest
from unittest.mock import patch

from pydantic import ValidationError

from app.data.seed import FINDINGS
from app.layer1.context_graph import build_context_graph_record
from app.layer2.reasoning_engine import run_reasoning_engine
from app.models import RiskModelSettings, RiskTierThresholds


class GovernedReasoningEngineTests(unittest.TestCase):
    def run_finding(self, finding, settings=None):
        settings = settings or RiskModelSettings(status="active", version="test-v1")
        with patch("app.layer2.reasoning_engine.load_active_risk_model_settings", return_value=settings):
            return run_reasoning_engine(finding, build_context_graph_record(finding))

    def test_kev_is_an_explicit_tier_zero_policy_override(self):
        result = self.run_finding(FINDINGS[0])

        self.assertEqual(result.calculatedActionTier, "Tier 2")
        self.assertEqual(result.actionTier, "Tier 0")
        self.assertEqual(result.decisionMethod, "deterministic-model+policy-override")
        self.assertEqual(result.riskModelVersion, "test-v1")
        self.assertTrue(any("POL-ACTIVE-EXPLOIT-001" in value for value in result.policyOverrides))

    def test_kev_policy_is_not_called_an_override_when_tier_zero_is_already_calculated(self):
        settings = RiskModelSettings(
            status="active",
            version="test-tier-zero",
            thresholds=RiskTierThresholds(tier0=70, tier1=50, tier2=20),
        )
        result = self.run_finding(FINDINGS[1], settings)

        self.assertEqual(result.calculatedActionTier, "Tier 0")
        self.assertEqual(result.actionTier, "Tier 0")
        self.assertEqual(result.decisionMethod, "deterministic-model")
        self.assertEqual(result.policyOverrides, [])

    def test_override_can_be_disabled_by_the_active_model(self):
        settings = RiskModelSettings(status="active", kevOverridesToTier0=False, version="test-no-override")
        result = self.run_finding(FINDINGS[0], settings)

        self.assertEqual(result.actionTier, result.calculatedActionTier)
        self.assertEqual(result.decisionMethod, "deterministic-model")
        self.assertEqual(result.policyOverrides, [])

    def test_thresholds_from_active_model_control_non_kev_tiering(self):
        settings = RiskModelSettings(
            status="active",
            version="test-thresholds",
            thresholds=RiskTierThresholds(tier0=70, tier1=50, tier2=20),
        )
        result = self.run_finding(FINDINGS[3], settings)

        self.assertEqual(result.actionTier, result.calculatedActionTier)
        self.assertIn(result.actionTier, ("Tier 0", "Tier 1", "Tier 2"))
        self.assertEqual(result.riskModelVersion, "test-thresholds")

    def test_validated_controls_dampen_residual_risk(self):
        finding = FINDINGS[3]
        ctx = build_context_graph_record(finding)
        baseline = RiskModelSettings(status="active")
        with patch("app.layer2.reasoning_engine.load_active_risk_model_settings", return_value=baseline), patch(
            "app.layer2.reasoning_engine._validated_control_effectiveness", return_value=0.5
        ):
            controlled = run_reasoning_engine(finding, ctx)
        with patch("app.layer2.reasoning_engine.load_active_risk_model_settings", return_value=baseline):
            uncontrolled = run_reasoning_engine(finding, ctx)

        self.assertLess(controlled.riskPriority, uncontrolled.riskPriority)
        self.assertEqual(controlled.validatedControlEffectiveness, 0.5)
        self.assertAlmostEqual(
            controlled.riskPriority,
            round(
                100
                * controlled.exploitationLikelihood
                * controlled.businessImpact
                * (1 - controlled.validatedControlEffectiveness),
                1,
            ),
        )

    def test_policy_count_is_not_treated_as_control_effectiveness(self):
        result = self.run_finding(FINDINGS[3])
        self.assertEqual(result.validatedControlEffectiveness, 0)

    def test_chainability_changes_exploitation_likelihood(self):
        finding = FINDINGS[3]
        with patch("app.layer2.reasoning_engine._score_chainability", return_value=0.1):
            low = self.run_finding(finding)
        with patch("app.layer2.reasoning_engine._score_chainability", return_value=1.0):
            high = self.run_finding(finding)
        self.assertGreater(high.exploitationLikelihood, low.exploitationLikelihood)

    def test_impact_weights_must_total_one_hundred(self):
        from app.models import ImpactWeights

        with self.assertRaises(ValidationError):
            RiskModelSettings(impactWeights=ImpactWeights(cvssSeverity=1))

    def test_seed_scenarios_have_complete_governed_decisions(self):
        for finding in FINDINGS:
            with self.subTest(finding=finding.id):
                result = self.run_finding(finding)
                self.assertGreaterEqual(result.riskPriority, 0)
                self.assertLessEqual(result.riskPriority, 100)
                self.assertTrue(result.riskModelVersion)
                self.assertAlmostEqual(
                    result.riskPriority,
                    round(
                        100
                        * result.exploitationLikelihood
                        * result.businessImpact
                        * (1 - result.validatedControlEffectiveness),
                        1,
                    ),
                )
                self.assertIn(result.actionTier, ("Tier 0", "Tier 1", "Tier 2", "Tier 3"))
                if finding.cisaKev:
                    self.assertEqual(result.actionTier, "Tier 0")


if __name__ == "__main__":
    unittest.main()
