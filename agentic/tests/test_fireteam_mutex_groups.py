"""The fireteam mutex check matches the canonical tool names TOOL_MUTEX_GROUPS uses.

Drift-map #10: `_validate_mutex_groups` matched only the group name and the
suffixes of its tools (`metasploit`, `console`, `restart`), while the member
spec requires canonical TOOL_REGISTRY names (`metasploit_console`). Two members
declaring `metasploit_console` both deployed and shared one msfconsole, which
the prompt promises the validator refuses.
"""
from __future__ import annotations

import itertools
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.nodes.fireteam_deploy_node import _validate_mutex_groups  # noqa: E402
from project_settings import TOOL_MUTEX_GROUPS  # noqa: E402
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402


def _member(name, *tools):
    return {"name": name, "tools": list(tools)}


class EveryGroupIsEnforced(unittest.TestCase):
    def test_two_members_sharing_any_group_tool_are_rejected(self):
        for group, tools in TOOL_MUTEX_GROUPS.items():
            for a, b in itertools.product(sorted(tools), repeat=2):
                with self.subTest(group=group, a=a, b=b):
                    err = _validate_mutex_groups([
                        _member("A", a, "execute_curl"), _member("B", "kali_shell", b),
                    ])
                    self.assertIsNotNone(err, f"two members claiming {group!r} both deployed")
                    self.assertIn(group, err)

    def test_one_claimer_per_group_is_fine(self):
        for group, tools in TOOL_MUTEX_GROUPS.items():
            with self.subTest(group=group):
                self.assertIsNone(_validate_mutex_groups([
                    _member("A", *sorted(tools)), _member("B", "execute_curl"),
                ]))

    def test_metasploit_console_twice_is_rejected(self):
        """The case the prompt (prompts/base.py, fireteam phase patterns) promises."""
        err = _validate_mutex_groups([
            _member("Exploiter", "metasploit_console"),
            _member("Post-ex", "metasploit_console", "kali_shell"),
        ])
        self.assertIsNotNone(err)

    def test_matching_ignores_case_and_surrounding_space(self):
        self.assertIsNotNone(_validate_mutex_groups([
            _member("A", "Metasploit_Console"), _member("B", " metasploit_console "),
        ]))

    def test_unrelated_tools_are_never_a_claim(self):
        self.assertIsNone(_validate_mutex_groups([
            _member("A", "execute_playwright", "execute_curl"),
            _member("B", "execute_playwright", "execute_curl"),
        ]))


class TheGroupsNameRealTools(unittest.TestCase):
    def test_every_mutex_tool_is_a_registry_key(self):
        unknown = {
            group: sorted(set(tools) - set(TOOL_REGISTRY))
            for group, tools in TOOL_MUTEX_GROUPS.items()
            if set(tools) - set(TOOL_REGISTRY)
        }
        self.assertEqual(unknown, {}, "TOOL_MUTEX_GROUPS names tools the agent does not have, "
                                      "so no member can ever claim them")


if __name__ == "__main__":
    unittest.main()
