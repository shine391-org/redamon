"""agentic/auth_profile.py is_roe_excluded against the shared RoE vectors.

The agent image carries no recon/, so it keeps its own copy of
recon/helpers/roe_scope.py's matcher. It runs the same table as recon
(recon/tests/test_roe_exclusion_vectors.py) and the webapp
(webapp/src/lib/roeScope.test.ts), so none of the three can drift alone.
"""
import json
import os
import sys
import unittest

AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(AGENTIC_DIR)
VECTORS = os.path.join(REPO_ROOT, "recon", "tests", "fixtures", "roe_exclusion_vectors.json")

sys.path.insert(0, AGENTIC_DIR)


class TestAgentRoeExclusionVectors(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(VECTORS):
            self.skipTest(f"recon fixtures not present ({VECTORS})")
        with open(VECTORS, "r", encoding="utf-8") as f:
            self.vectors = json.load(f)["vectors"]

    def test_the_table_is_a_real_set(self):
        self.assertGreaterEqual(len(self.vectors), 40)

    def test_vectors(self):
        from auth_profile import is_roe_excluded

        for v in self.vectors:
            with self.subTest(v["name"]):
                self.assertIs(is_roe_excluded(v["host"], v["excluded"]), v["result"])


if __name__ == "__main__":
    unittest.main()
