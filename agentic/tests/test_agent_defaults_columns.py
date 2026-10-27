"""Every key the agent's /defaults emits is a real Project column.

The form starts from /defaults and a preset apply resets to it. A key named by a
prefix rule instead of the column (agentSsrfGopherEnabled for ssrfGopherEnabled)
matched no field, so 31 agent columns never took the Python default (drift-map
#13). The real endpoint is called, so its own naming is what is checked.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

_AGENTIC = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC))

_SCHEMA = _AGENTIC.parent / "webapp" / "prisma" / "schema.prisma"

pytestmark = pytest.mark.skipif(
    not _SCHEMA.exists(), reason="webapp/prisma/schema.prisma not in this checkout"
)


def _scalar_project_columns() -> set[str]:
    src = _SCHEMA.read_text(encoding="utf-8")
    models = set(re.findall(r"^model (\w+) \{", src, re.M))
    body = re.search(r"^model Project \{(.*?)^\}", src, re.S | re.M).group(1)
    return {
        m.group(1)
        for m in re.finditer(r"^\s+([a-z]\w*)\s+([A-Z]\w*)", body, re.M)
        if m.group(2) not in models
    }


@pytest.fixture(scope="module")
def defaults():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with patch("api.lifespan", fake_lifespan):
        import api as api_module
    return asyncio.run(api_module.get_defaults())


def test_every_emitted_key_is_a_project_column(defaults):
    columns = _scalar_project_columns()
    assert sorted(k for k in defaults if k not in columns) == []


def test_each_value_is_the_python_default_of_that_column(defaults):
    from project_settings import AGENT_SETTING_COLUMNS, DEFAULT_AGENT_SETTINGS

    key_of = {column: key for key, column in AGENT_SETTING_COLUMNS.items()}
    wrong = sorted(
        column for column, value in defaults.items()
        if value != DEFAULT_AGENT_SETTINGS[key_of[column]]
    )
    assert wrong == []


def test_families_outside_any_prefix_rule_are_served(defaults):
    for column in ("ssrfGopherEnabled", "rceOobCallbackEnabled", "pathTraversalOobProvider",
                   "deserializationRuntimes", "sqliLevel", "agentGuardrailEnabled"):
        assert column in defaults, column


def test_engagement_limits_and_stealth_mode_are_not_served(defaults):
    from recon_settings.engagement import engagement_limit_columns

    assert "stealthMode" not in defaults, "served by the recon /defaults"
    assert sorted(set(engagement_limit_columns()) & set(defaults)) == []
