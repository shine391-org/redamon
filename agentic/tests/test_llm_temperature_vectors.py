"""The agent's no-temperature rules answer the shared vectors (drift-map #14).

The webapp's preset generator calls providers itself and keeps a TS copy of
these rules (webapp/src/lib/llmTemperature.ts). Both implementations read the
same table, webapp/src/lib/llmTemperature.vectors.json: a change to one side's
behaviour without the other fails on one of them. The constants themselves are
compared by webapp/src/lib/llmTemperature.test.ts.
"""

from __future__ import annotations

import json
import os
import sys
import unittest

AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(AGENTIC_DIR)
VECTORS = os.path.join(REPO_ROOT, "webapp", "src", "lib", "llmTemperature.vectors.json")

sys.path.insert(0, AGENTIC_DIR)


class TestTemperatureVectors(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(VECTORS):
            self.skipTest(f"webapp sources not present ({VECTORS})")
        with open(VECTORS, "r", encoding="utf-8") as f:
            self.vectors = json.load(f)

    def test_the_table_is_a_real_set(self):
        self.assertGreaterEqual(len(self.vectors["anthropic"]), 10)
        self.assertGreaterEqual(len(self.vectors["openai"]), 10)

    def test_anthropic_rule(self):
        from orchestrator_helpers.llm_setup import _anthropic_supports_temperature

        for case in self.vectors["anthropic"]:
            with self.subTest(model=case["model"]):
                self.assertIs(_anthropic_supports_temperature(case["model"]),
                              case["supportsTemperature"])

    def test_openai_rule(self):
        from orchestrator_helpers.llm_setup import _openai_supports_temperature

        for case in self.vectors["openai"]:
            with self.subTest(model=case["model"]):
                self.assertIs(_openai_supports_temperature(case["model"]),
                              case["supportsTemperature"])


if __name__ == "__main__":
    unittest.main()
