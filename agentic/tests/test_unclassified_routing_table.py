"""The unclassified agent's routing table names exactly the built-in skill ids.

Drift-map #15: the table in prompts/unclassified_prompts.py predated two skills.
It called `deserialization` "NOT a valid skill ID" and sent that class to `rce`,
and never offered `crypto_attack`, although both are in KNOWN_ATTACK_PATHS. An
unclassified agent on a project with deserialization enabled was routed away
from it. A `to_skill` outside KNOWN_ATTACK_PATHS is rejected by the switch
validator, so the table must name every id and nothing else.
"""
from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC_DIR))

from prompts.unclassified_prompts import UNCLASSIFIED_EXPLOIT_TOOLS  # noqa: E402
from state import KNOWN_ATTACK_PATHS  # noqa: E402

_ROW = re.compile(r"^\|(?P<cls>[^|]+)\|\s*`(?P<skill>[^`]+)`\s*\|\s*$", re.MULTILINE)


def _routed_ids() -> list[str]:
    return [m.group("skill") for m in _ROW.finditer(UNCLASSIFIED_EXPLOIT_TOOLS)]


def _invalid_synonyms() -> set[str]:
    """The ids the prompt gives as examples of names that are NOT skill ids."""
    m = re.search(r"descriptive synonym \(e\.g\. (?P<names>[^)]*)\)", UNCLASSIFIED_EXPLOIT_TOOLS)
    assert m, "the invalid-synonym example list could not be read"
    return set(re.findall(r"`([^`]+)`", m.group("names")))


class TheRoutingTable(unittest.TestCase):
    def test_the_table_could_be_read(self):
        self.assertGreater(len(_routed_ids()), 5)

    def test_every_known_skill_is_offered(self):
        missing = sorted(KNOWN_ATTACK_PATHS - set(_routed_ids()))
        self.assertEqual(missing, [], "skills an unclassified agent is never told to switch to")

    def test_no_row_routes_outside_known_skills(self):
        unknown = sorted(set(_routed_ids()) - KNOWN_ATTACK_PATHS)
        self.assertEqual(unknown, [], "the switch validator rejects these to_skill values")

    def test_each_skill_has_one_row(self):
        ids = _routed_ids()
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual(dupes, [])

    def test_no_real_skill_is_called_an_invalid_synonym(self):
        self.assertEqual(sorted(_invalid_synonyms() & KNOWN_ATTACK_PATHS), [])


if __name__ == "__main__":
    unittest.main()
