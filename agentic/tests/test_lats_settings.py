"""Step 5 — LATS settings mapping + the camelCase<->Prisma contract.

Covers fetch_agent_settings mapping (camelCase agentLats* -> LATS_* keys, the
two-boolean phase assembly, default fallback) and asserts that the column
AGENT_SETTING_COLUMNS gives each scalar LATS_* key is a real Prisma agentLats*
column, the name both fetch_agent_settings and /defaults use (§19.0/§20).
"""

from __future__ import annotations

import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import project_settings  # noqa: E402


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA_PATH = os.path.join(REPO_ROOT, "webapp", "prisma", "schema.prisma")


def _fetch_with_project(project: dict) -> dict:
    resp = MagicMock()
    resp.json.return_value = project
    resp.raise_for_status.return_value = None
    with patch("requests.get", return_value=resp):
        return project_settings.fetch_agent_settings("proj1", "http://webapp")


class TestLatsSettingsMapping(unittest.TestCase):
    def test_bool_int_float_mapping(self):
        s = _fetch_with_project({
            "agentLatsEnabled": True,
            "agentLatsShadowMode": False,
            "agentLatsMaxRollouts": 40,
            "agentLatsMaxDepth": 8,
            "agentLatsBranching": 2,
            "agentLatsUctC": 2.0,
            "agentLatsPruneFloor": 0.25,
        })
        self.assertIs(s["LATS_ENABLED"], True)
        self.assertIs(s["LATS_SHADOW_MODE"], False)
        self.assertEqual(s["LATS_MAX_ROLLOUTS"], 40)
        self.assertEqual(s["LATS_MAX_DEPTH"], 8)
        self.assertEqual(s["LATS_BRANCHING"], 2)
        self.assertAlmostEqual(s["LATS_UCT_C"], 2.0)
        self.assertAlmostEqual(s["LATS_PRUNE_FLOOR"], 0.25)

    def test_phase_assembly_both(self):
        s = _fetch_with_project({
            "agentLatsPhaseExploitation": True,
            "agentLatsPhasePostExpl": True,
        })
        self.assertEqual(s["LATS_ALLOWED_PHASES"], ["exploitation", "post_exploitation"])

    def test_phase_assembly_exploitation_only(self):
        s = _fetch_with_project({
            "agentLatsPhaseExploitation": True,
            "agentLatsPhasePostExpl": False,
        })
        self.assertEqual(s["LATS_ALLOWED_PHASES"], ["exploitation"])

    def test_phase_assembly_empty_falls_back(self):
        s = _fetch_with_project({
            "agentLatsPhaseExploitation": False,
            "agentLatsPhasePostExpl": False,
        })
        # Never assemble an empty phase list; fall back to the default.
        self.assertEqual(s["LATS_ALLOWED_PHASES"], list(project_settings.DEFAULT_AGENT_SETTINGS["LATS_ALLOWED_PHASES"]))

    def test_defaults_when_keys_absent(self):
        s = _fetch_with_project({})   # project has no agentLats* fields
        self.assertIs(s["LATS_ENABLED"], False)
        self.assertIs(s["LATS_SHADOW_MODE"], False)  # default is drive, not observe-only
        self.assertEqual(s["LATS_MAX_DEPTH"], 6)
        self.assertEqual(s["LATS_ALLOWED_PHASES"], ["exploitation"])


class TestCamelCaseContract(unittest.TestCase):
    def setUp(self):
        with open(SCHEMA_PATH, "r") as f:
            self.schema = f.read()
        self.columns = set(re.findall(r"\b(agentLats\w+)\b", self.schema))

    def test_scalar_lats_keys_map_to_prisma_columns(self):
        # Each scalar LATS_* setting must map to a real Prisma column, or it
        # silently drops on project create.
        scalar_keys = [
            "LATS_ENABLED", "LATS_SHADOW_MODE", "LATS_MIN_HYPOTHESES",
            "LATS_BRANCHING", "LATS_MAX_DEPTH", "LATS_MAX_ROLLOUTS",
            "LATS_MAX_TREE_NODES", "LATS_UCT_C", "LATS_PRUNE_FLOOR",
        ]
        for k in scalar_keys:
            camel = project_settings.AGENT_SETTING_COLUMNS[k]
            self.assertIn(camel, self.columns, f"{k} -> {camel} missing from Prisma")

    def test_phase_booleans_exist(self):
        self.assertIn("agentLatsPhaseExploitation", self.columns)
        self.assertIn("agentLatsPhasePostExpl", self.columns)

    def test_lats_keys_take_agent_prefix(self):
        self.assertEqual(project_settings.AGENT_SETTING_COLUMNS["LATS_ENABLED"], "agentLatsEnabled")


if __name__ == "__main__":
    unittest.main()
