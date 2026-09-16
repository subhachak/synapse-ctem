import os
import tempfile
import unittest
from unittest.mock import patch

from app.data import runs_db


class WorkflowPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tempdir.name, "runs.db")
        self.patch = patch.object(runs_db, "DB_PATH", self.db_path)
        self.patch.start()
        runs_db.init_db()
        runs_db.create_run("run-1", "test", "{}")

    def tearDown(self):
        self.patch.stop()
        self.tempdir.cleanup()

    def test_score_review_records_reclassification(self):
        runs_db.create_score_review_item("score-1", "run-1", '{"assessment":"questionable"}', '{"actionTier":"Tier 3"}')
        runs_db.resolve_score_review_item("score-1", "reclassified", "reviewer", "High business impact", "Tier 1")

        item = runs_db.get_score_review_item("score-1")
        self.assertEqual(item["status"], "reclassified")
        self.assertEqual(item["selected_tier"], "Tier 1")
        self.assertEqual(item["resolved_by"], "reviewer")

    def test_remediation_transitions_and_owner_are_persisted(self):
        runs_db.ensure_remediation_case("run-1", "owner-a")
        runs_db.transition_remediation("run-1", "awaiting_approval", "governance_agent")
        runs_db.transition_remediation(
            "run-1", "approved", "reviewer", "Approved", authorization="human-approved"
        )
        runs_db.assign_remediation_owner("run-1", "owner-b", "reviewer")

        result = runs_db.get_remediation_case("run-1")
        self.assertEqual(result["case"]["state"], "approved")
        self.assertEqual(result["case"]["authorization"], "human-approved")
        self.assertEqual(result["case"]["owner_id"], "owner-b")
        self.assertEqual([row["to_state"] for row in result["transitions"][:3]], [
            "planned", "awaiting_approval", "approved"
        ])


if __name__ == "__main__":
    unittest.main()
