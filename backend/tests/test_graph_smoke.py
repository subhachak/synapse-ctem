import unittest
from unittest.mock import patch


class GraphSmokeTests(unittest.TestCase):
    def test_compiled_graph_imports(self):
        from app.graph import COMPILED_INCIDENT_GRAPH

        self.assertIsNotNone(COMPILED_INCIDENT_GRAPH)

    def test_orchestrator_parallel_join_and_independent_verification_are_explicit(self):
        from app.graph import COMPILED_INCIDENT_GRAPH

        graph = COMPILED_INCIDENT_GRAPH.get_graph()
        edges = {(edge.source, edge.target) for edge in graph.edges}
        self.assertIn(("context_graph", "parallel_enrichment"), edges)
        self.assertIn(("parallel_enrichment", "enrichment_join"), edges)
        self.assertIn(("enrichment_join", "reasoning_engine"), edges)
        self.assertIn(("execute_remediation", "independent_verification"), edges)
        self.assertIn(("independent_verification", "finalize_closure"), edges)
        self.assertNotIn(("implementation_agent", "independent_verification"), edges)

    def test_each_run_uses_an_independent_checkpointer_and_lock(self):
        from app.graph import _graph_for_run

        graph_a, lock_a = _graph_for_run("concurrency-test-a")
        graph_b, lock_b = _graph_for_run("concurrency-test-b")
        self.assertIsNot(graph_a, graph_b)
        self.assertIsNot(lock_a, lock_b)

    def test_staged_governance_seed_matches_starter_taxonomy(self):
        from app.data.seed import FINDINGS
        from app.graph import CATEGORY_MATCH_THRESHOLD
        from app.graphdb import finding_match_text
        from app.retrieval import cosine, embed_texts

        finding = next(f for f in FINDINGS if f.id == "find-2")
        vectors, mode = embed_texts(
            [
                finding_match_text(finding.name, finding.affectedComponent, finding.severityLabel),
                "Linux Kernel Privilege Escalation",
            ],
            "document",
        )

        self.assertGreaterEqual(
            cosine(vectors[0], vectors[1]),
            CATEGORY_MATCH_THRESHOLD,
            f"find-2 must reach its intended governance demo gate in {mode} mode without an ontology detour",
        )

    def test_all_seed_findings_use_governed_taxonomy_before_similarity(self):
        from app import graphdb
        from app.data.seed import FINDINGS
        from app.scripts.load_graph import STARTER_CATEGORIES

        nodes = [
            {"id": category_id, "name": name, "definition_text": definition, "source_taxonomy": "seed"}
            for category_id, name, definition in STARTER_CATEGORIES
        ]
        expected = {
            "find-1": "cat-browser-sandbox",
            "find-2": "cat-kernel-privesc",
            "find-3": "cat-oss-rce",
            "find-4": "cat-crypto-overflow",
            "find-5": "cat-cert-parsing",
            "find-6": "cat-cert-parsing",
            "find-7": "cat-crypto-overflow",
        }
        with patch("app.graphdb.list_nodes", return_value=nodes):
            for finding in FINDINGS:
                category, confidence, method = graphdb.governed_category_match(finding)
                self.assertEqual(category["id"], expected[finding.id], finding.id)
                self.assertGreaterEqual(confidence, 0.9)
                self.assertIn(method, {"exact-component", "governed-alias", "taxonomy-rule"})

    def test_novel_component_still_routes_to_similarity_or_review(self):
        from app import graphdb
        from app.models import RawFinding
        from app.scripts.load_graph import STARTER_CATEGORIES

        nodes = [
            {"id": category_id, "name": name, "definition_text": definition, "source_taxonomy": "seed"}
            for category_id, name, definition in STARTER_CATEGORIES
        ]
        finding = RawFinding(
            id="novel-1", cve="CVE-DEMO-NOVEL", name="Quantum widget temporal state corruption",
            affectedComponent="QuantumWidget Runtime", severityLabel="High", cvssBase=7.5,
            discoveredBy="Scanner", affectedServiceIds=["svc-1"], softwareId="sw-oss-deps",
            epss=0.2, cisaKev=False, runtimeReachable=True, chainedWith=[], raOnBooks=False,
        )
        with patch("app.graphdb.list_nodes", return_value=nodes):
            category, confidence, method = graphdb.governed_category_match(finding)
        self.assertIsNone(category)
        self.assertEqual(confidence, 0.0)
        self.assertEqual(method, "unmatched")


if __name__ == "__main__":
    unittest.main()
