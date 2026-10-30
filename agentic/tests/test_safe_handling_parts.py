"""access_control and path_traversal carry the handling rules on every project.

With the route exposure module off, a live session (AG2) printed an export's
e-mails, a `.env` password, a `.git` blob's token and a session cookie, and
requested `/logout` and `/account/reset` in the informational phase: the RoE
said "do not display", but no part said how to prove a finding without it.
`safe_values` (unless the RoE allows full access) and `safe_state` (always)
follow each skill's `tools` part, module on or off.

Run: ./agentic/run_tests.sh tests/test_safe_handling_parts.py
"""

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from record_skill_golden import ALL_TOOLS, render_workflow  # noqa: E402

from prompts import (ACCESS_CONTROL_SAFE_STATE, ACCESS_CONTROL_SAFE_VALUES,  # noqa: E402
                     PATH_TRAVERSAL_SAFE_STATE, PATH_TRAVERSAL_SAFE_VALUES)

PARTS = {"access_control": (ACCESS_CONTROL_SAFE_VALUES, ACCESS_CONTROL_SAFE_STATE),
         "path_traversal": (PATH_TRAVERSAL_SAFE_VALUES, PATH_TRAVERSAL_SAFE_STATE)}
ALL_PARTS = [t for pair in PARTS.values() for t in pair]

REAL_TOOLS = {"execute_curl", "execute_code", "execute_playwright", "fs_write", "fs_list", "fs_delete",
              "job_spawn", "kali_shell", "query_graph", "graph_summary", "proxy_brain", "switch_skill"}


def _render(skill, settings):
    return render_workflow(skill, settings, ALL_TOOLS, False, [])


@pytest.mark.parametrize("skill", ["access_control", "path_traversal"])
@pytest.mark.parametrize("module", [False, True])
def test_both_parts_follow_tools_with_the_module_on_or_off(skill, module):
    values, state = PARTS[skill]
    parts = _render(skill, {"ROUTE_EXPOSURE_ENABLED": module})
    assert parts[1] is values and parts[2] is state


@pytest.mark.parametrize("skill", ["access_control", "path_traversal"])
@pytest.mark.parametrize("handling,values", [
    ("no_access", True), ("prove_access_only", True), ("limited_collection", True), ("full_access", False),
])
def test_values_follow_the_roe_and_state_rules_always_apply(skill, handling, values):
    values_part, state_part = PARTS[skill]
    parts = _render(skill, {"ROE_SENSITIVE_DATA_HANDLING": handling})
    assert (values_part in parts) is values
    assert state_part in parts


@pytest.mark.parametrize("skill", ["rce", "sql_injection", "ssrf"])
def test_other_skills_are_unchanged(skill):
    parts = _render(skill, {})
    assert not any(p in parts for p in ALL_PARTS)


@pytest.mark.parametrize("skill", sorted(PARTS))
def test_the_values_part_is_a_recipe_not_a_prohibition(skill):
    text = PARTS[skill][0]
    # The curl write-out braces survive the f-string that builds the part.
    assert "-o /tmp/<name>.body -w '%{http_code} %{size_download} %{content_type}'" in text
    assert "8-character SHA-256 prefixes" in text
    assert "`-H @/tmp/<name>.hdr`" in text
    assert "`-v`, `-i`, `--trace`, `-D -` and `-o -` are\n  FORBIDDEN" in text


@pytest.mark.parametrize("skill", sorted(PARTS))
def test_the_state_part_names_what_the_live_session_requested(skill):
    text = PARTS[skill][1]
    for route in ("logout", "password or account reset"):
        assert route in text
    assert "Informational phase: read-only" in text
    assert "Exploitation phase: a write" in text
    # A live exploitation turn fuzzed with a stock wordlist and hit /logout, then
    # requested /account/reset: the ban holds in every phase.
    assert "In every phase, never request a route that ends or changes a session" in text
    assert "grep -viE 'logout|sign-?out|reset|delete|remove|deactivate|unsubscribe|cancel'" in text


@pytest.mark.parametrize("text", ALL_PARTS)
def test_real_tools_only_and_no_em_dash(text):
    assert "—" not in text
    named = set(re.findall(r"\b(execute_[a-z_]+|fs_[a-z]+|job_spawn|kali_shell|query_graph|graph_summary|"
                           r"proxy_brain|switch_skill)\b", text))
    assert named <= REAL_TOOLS
