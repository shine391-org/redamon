"""AGENT_SETTING_COLUMNS is the one name map between agent settings and Project columns.

fetch_agent_settings reads every column through it, so a column missing from it is
never loaded: the SQLi settings were edited in the form and ignored by the agent
for exactly that reason (drift-map #4). These tests fail when the map names a column
Prisma does not have, or when an agent column exists that nothing reads.
"""
import json
import os
import re
import sys
import unittest
from unittest import mock

_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_AGENTIC)
sys.path.insert(0, _AGENTIC)

import project_settings as ps  # noqa: E402

_SCHEMA = os.path.join(_REPO, "webapp", "prisma", "schema.prisma")
_REGISTRY = os.path.join(_REPO, "recon_settings", "registry.json")

# Registry `tool` values whose fields only the agent consumes.
_AGENT_TOOLS = {
    "agent", "roe", "ssrf", "fireteam", "hydra", "deserialization",
    "path_traversal", "dos", "rce", "sqli", "phishing",
}

# Agent-tool columns that are not read through AGENT_SETTING_COLUMNS, each with
# where it is read instead.
_READ_ELSEWHERE = {
    "agentLatsPhaseExploitation": "assembled into LATS_ALLOWED_PHASES by fetch_agent_settings",
    "agentLatsPhasePostExpl": "assembled into LATS_ALLOWED_PHASES by fetch_agent_settings",
    "roeEnabled": "derived by recon_settings.engagement.derive_roe_enabled, never read",
    "roeDocumentData": "the uploaded RoE document, webapp only",
    "roeDocumentMimeType": "the uploaded RoE document, webapp only",
    "roeDocumentName": "the uploaded RoE document, webapp only",
    "roeParsedJson": "the parsed RoE document, webapp only",
    "triageReviewBudget": "agentic/cypherfix_triage/project_settings.py",
}

# DEFAULT_AGENT_SETTINGS keys that share a name with a column but are not loaded
# from it.
_NOT_LOADED = {"ROE_ENABLED": "derived from the engagement fields"}


def _project_columns() -> set[str]:
    """Scalar and enum fields of model Project; relation fields are not columns."""
    src = open(_SCHEMA, encoding="utf-8").read()
    models = set(re.findall(r"^model (\w+) \{", src, re.M))
    body = re.search(r"^model Project \{(.*?)^\}", src, re.S | re.M).group(1)
    return {
        m.group(1)
        for m in re.finditer(r"^\s+([a-z]\w*)\s+([A-Z]\w*)", body, re.M)
        if m.group(2) not in models
    }


def _camel(key: str, prefix: str = "") -> str:
    parts = (f"{prefix}_{key}" if prefix else key).lower().split("_")
    return parts[0] + "".join(p.title() for p in parts[1:])


@unittest.skipUnless(os.path.exists(_SCHEMA), "webapp/prisma/schema.prisma not in this checkout")
class TestAgentSettingColumns(unittest.TestCase):
    def setUp(self):
        self.columns = _project_columns()

    def test_every_mapped_column_is_a_project_column(self):
        missing = sorted(c for c in ps.AGENT_SETTING_COLUMNS.values() if c not in self.columns)
        self.assertEqual(missing, [], "AGENT_SETTING_COLUMNS names columns Prisma does not have")

    def test_every_mapped_key_has_a_default(self):
        missing = sorted(k for k in ps.AGENT_SETTING_COLUMNS if k not in ps.DEFAULT_AGENT_SETTINGS)
        self.assertEqual(missing, [])

    def test_no_column_is_mapped_twice(self):
        cols = list(ps.AGENT_SETTING_COLUMNS.values())
        self.assertEqual(sorted({c for c in cols if cols.count(c) > 1}), [])

    def test_a_default_named_like_a_column_is_loaded_from_it(self):
        unloaded = sorted(
            k for k in ps.DEFAULT_AGENT_SETTINGS
            if k not in ps.AGENT_SETTING_COLUMNS and k not in _NOT_LOADED
            and (_camel(k) in self.columns or _camel(k, "agent") in self.columns)
        )
        self.assertEqual(unloaded, [], "add these to AGENT_SETTING_COLUMNS or the agent never reads them")

    @unittest.skipUnless(os.path.exists(_REGISTRY), "recon_settings/registry.json not in this checkout")
    def test_every_agent_column_is_read(self):
        fields = json.load(open(_REGISTRY, encoding="utf-8"))["fields"]
        mapped = set(ps.AGENT_SETTING_COLUMNS.values())
        unread = sorted(
            name for name, spec in fields.items()
            if spec.get("tool") in _AGENT_TOOLS and name in self.columns
            and name not in mapped and name not in _READ_ELSEWHERE
        )
        self.assertEqual(unread, [], "agent columns nothing loads: map them or say where they are read")
        stale = sorted(n for n in _READ_ELSEWHERE if n not in self.columns)
        self.assertEqual(stale, [], "_READ_ELSEWHERE names columns that no longer exist")


class TestFetchAgentSettingsReadsTheMap(unittest.TestCase):
    def _fetch(self, project: dict) -> dict:
        response = mock.Mock()
        response.json.return_value = project
        response.raise_for_status.return_value = None
        with mock.patch("requests.get", return_value=response):
            return ps.fetch_agent_settings("p1", "http://webapp")

    def test_sqli_columns_reach_the_settings(self):
        settings = self._fetch({"sqliLevel": 4, "sqliRisk": 3, "sqliTamperScripts": "space2comment"})
        self.assertEqual(settings["SQLI_LEVEL"], 4)
        self.assertEqual(settings["SQLI_RISK"], 3)
        self.assertEqual(settings["SQLI_TAMPER_SCRIPTS"], "space2comment")

    def test_every_mapped_column_is_read(self):
        sentinel = object()
        project = {column: (key, sentinel) for key, column in ps.AGENT_SETTING_COLUMNS.items()
                   if key not in ps._AGENT_SETTING_CASTS}
        settings = self._fetch(project)
        for key, column in ps.AGENT_SETTING_COLUMNS.items():
            if key in ps._AGENT_SETTING_CASTS:
                continue
            self.assertEqual(settings[key], (key, sentinel), f"{column} not read into {key}")

    def test_casts_still_apply(self):
        settings = self._fetch({"fireteamTimeoutSec": "900", "agentLatsUctC": "2", "fireteamEnabled": 1})
        self.assertEqual(settings["FIRETEAM_TIMEOUT_SEC"], 900)
        self.assertEqual(settings["LATS_UCT_C"], 2.0)
        self.assertIs(settings["FIRETEAM_ENABLED"], True)

    def test_a_missing_column_keeps_the_default(self):
        settings = self._fetch({})
        self.assertEqual(settings["SQLI_LEVEL"], ps.DEFAULT_AGENT_SETTINGS["SQLI_LEVEL"])
        self.assertEqual(settings["AUTH_PROFILE"], ps.DEFAULT_AGENT_SETTINGS["AUTH_PROFILE"])


if __name__ == "__main__":
    unittest.main()
