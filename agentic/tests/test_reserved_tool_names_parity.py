"""The webapp's reserved tool names equal the set the agent derives.

The MCP Servers form refuses a user tool whose name is in
BUILTIN_RESERVED_TOOL_NAMES (webapp/src/lib/mcp/schema.ts); the agent refuses
the whole manifest at load when a tool name is in _builtin_tool_names()
(agentic/mcp_registry.py, derived from TOOL_REGISTRY). The TS set is a copy,
because the webapp build cannot import Python, so this test parses it and
compares it with the derived set in both directions. A name only the agent
reserves means the form accepts a server the agent then drops; a name only the
webapp reserves blocks a legal tool name.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(AGENTIC_DIR)
SCHEMA_TS = os.path.join(REPO_ROOT, "webapp", "src", "lib", "mcp", "schema.ts")

sys.path.insert(0, AGENTIC_DIR)


def _ts_reserved_names() -> set:
    with open(SCHEMA_TS, "r", encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        r"export const BUILTIN_RESERVED_TOOL_NAMES\b[^=]*=\s*new Set\(\[(.*?)\]\)",
        src, re.S,
    )
    if not m:
        raise AssertionError(f"BUILTIN_RESERVED_TOOL_NAMES not found in {SCHEMA_TS}")
    body = re.sub(r"//[^\n]*", "", m.group(1))
    return set(re.findall(r"'([^']+)'", body))


def _agent_reserved_names() -> set:
    # Imported directly as well, because _builtin_tool_names() swallows an
    # import error into an empty set, which would make this test vacuous.
    from prompts.tool_registry import TOOL_REGISTRY  # noqa: F401
    import mcp_registry

    mcp_registry._BUILTIN_NAME_CACHE = None
    return set(mcp_registry._builtin_tool_names())


class TestReservedToolNamesParity(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(SCHEMA_TS):
            self.skipTest(f"webapp sources not present ({SCHEMA_TS})")

    def test_ts_set_equals_agent_derived_set(self):
        agent = _agent_reserved_names()
        self.assertTrue(agent, "the agent derived no reserved names")
        ts = _ts_reserved_names()
        self.assertEqual(
            ts, agent,
            "BUILTIN_RESERVED_TOOL_NAMES drifted from the agent: "
            f"agent-only={sorted(agent - ts)}, webapp-only={sorted(ts - agent)}",
        )

    def test_ts_set_has_no_duplicates(self):
        with open(SCHEMA_TS, "r", encoding="utf-8") as f:
            src = f.read()
        m = re.search(r"BUILTIN_RESERVED_TOOL_NAMES\b[^=]*=\s*new Set\(\[(.*?)\]\)", src, re.S)
        names = re.findall(r"'([^']+)'", re.sub(r"//[^\n]*", "", m.group(1)))
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
