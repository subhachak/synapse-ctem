import unittest

from app.data.seed import FINDINGS
from app.layer3.implementation_agent import suppressed_implementation_stub
from app.verification import collect_demo_adapter_evidence, verification_not_run, verify_adapter_evidence, verify_demo_remediation


class VerificationTests(unittest.TestCase):
    def test_verified_closure_requires_all_four_evidence_types(self):
        finding = FINDINGS[0]
        implementation = suppressed_implementation_stub(finding)
        record = verify_demo_remediation(finding, implementation)

        self.assertTrue(record.verifiedClosed)
        self.assertEqual(record.status, "verified-closed")
        self.assertEqual(len(record.evidence), 4)
        self.assertEqual({item.source for item in record.evidence}, {"simulated-adapter"})

    def test_blocked_or_suppressed_work_is_not_verified(self):
        record = verification_not_run(FINDINGS[0])

        self.assertFalse(record.verifiedClosed)
        self.assertEqual(record.status, "not-run")
        self.assertEqual(record.evidence, [])

    def test_sandbox_failure_blocks_all_downstream_evidence(self):
        finding = FINDINGS[0].model_copy(update={"demoScenario": "sandbox-failure"})
        implementation = suppressed_implementation_stub(finding).model_copy(
            update={"rationale": "Controlled contract-test failure"}
        )

        record = verify_demo_remediation(finding, implementation)

        self.assertEqual(record.status, "failed")
        self.assertFalse(record.verifiedClosed)
        self.assertEqual(record.evidence[0].result, "fail")
        self.assertEqual([item.result for item in record.evidence[1:]], ["not-run", "not-run", "not-run"])

    def test_verifier_rejects_self_issued_or_tampered_evidence(self):
        finding = FINDINGS[0]
        implementation = suppressed_implementation_stub(finding)
        evidence = collect_demo_adapter_evidence(finding, implementation)
        evidence[0] = evidence[0].model_copy(update={"issuedBy": "implementation-agent"})

        record = verify_adapter_evidence(finding, evidence)

        self.assertFalse(record.verifiedClosed)
        self.assertEqual(record.status, "failed")


if __name__ == "__main__":
    unittest.main()
