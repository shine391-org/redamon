"""The triage score formula answers the shared vectors (drift-map #17).

The Priority Board keeps a TypeScript mirror of the formula
(webapp/src/app/graph/components/Triage/triageLayers.ts: the tier bands of
tierForScore, the tier labels and order, the factor keys and names). Both sides
read the same table, triageScore.vectors.json next to it: a change to the
weights, the tier levels or the labels here fails this test until the table
moves, and the moved table fails triageLayers.parity.test.ts until the mirror
follows.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest

AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(AGENTIC_DIR)
VECTORS = os.path.join(REPO_ROOT, "webapp", "src", "app", "graph", "components",
                       "Triage", "triageScore.vectors.json")

sys.path.insert(0, AGENTIC_DIR)

from cypherfix_triage import score_model as sm  # noqa: E402


class TestTriageScoreVectors(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(VECTORS):
            self.skipTest(f"webapp sources not present ({VECTORS})")
        with open(VECTORS, "r", encoding="utf-8") as f:
            self.vectors = json.load(f)

    def test_the_table_covers_every_tier(self):
        tiers = {case["tier"] for case in self.vectors["scores"]}
        self.assertEqual(tiers, set(sm.TIER_LEVELS))

    def test_tier_levels_and_labels(self):
        self.assertEqual(sm.TIER_LEVELS, self.vectors["tierLevels"])
        self.assertEqual(sm.TIER_LABELS, self.vectors["tierLabels"])

    def test_score_for(self):
        for case in self.vectors["scores"]:
            with self.subTest(tier=case["tier"], risk=case["risk"]):
                self.assertEqual(sm.score_for(case["tier"], case["risk"]), case["score"])

    def test_factor_keys(self):
        self.assertEqual(list(sm.factor_values({})), self.vectors["factorKeys"])

    def test_factor_names_are_the_explanation_words(self):
        f = sm.Factor(0.5, "")
        result = sm.ScoreResult(state=sm.STATE_OPEN, confidence=f, likelihood=f, impact=f, reach=f,
                                risk=0.0625, tier="T3", tier_rule="",
                                score=sm.score_for("T3", 0.0625))
        words = re.findall(r"(?:^| x )([a-z]+) ", result.explanation)
        names = self.vectors["factorNames"]
        self.assertEqual(words, [names[k] for k in self.vectors["factorKeys"]])


if __name__ == "__main__":
    unittest.main()
