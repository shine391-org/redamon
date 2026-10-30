"""The attack-path behaviour text for the three route-exposure skills (plan §23.12).

With recon's route exposure module off, build_attack_path_behavior returns the
generic line byte for byte, so a project that never ran the scan sees no
change. With it on, the three skills get one sentence pointing at their part;
every other skill is untouched. The text-to-Cypher prompt names the source.
"""

import contextvars
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import project_settings  # noqa: E402
from prompts.base import TEXT_TO_CYPHER_SYSTEM, build_attack_path_behavior  # noqa: E402

SKILLS = ("access_control", "path_traversal", "rce")


def _behavior(skill, settings):
    def run():
        project_settings._settings_ctx.set(dict(settings))
        return build_attack_path_behavior(skill)
    return contextvars.copy_context().run(run)


def _generic(skill):
    return f"Follow the workflow guidance in the Available Tools section for attack path: {skill}"


@pytest.mark.parametrize("skill", SKILLS)
def test_module_off_is_byte_identical(skill):
    assert _behavior(skill, {}) == _generic(skill)
    assert _behavior(skill, {"ROUTE_EXPOSURE_ENABLED": False}) == _generic(skill)


@pytest.mark.parametrize("skill,marker", [
    ("access_control", "Route exposure leads steps"),
    ("path_traversal", "Exposed files steps"),
    ("rce", "Debug consoles steps"),
])
def test_module_on_adds_one_sentence(skill, marker):
    text = _behavior(skill, {"ROUTE_EXPOSURE_ENABLED": True})
    head, _, sentence = text.partition("\n")
    assert head == _generic(skill)
    assert "\n" not in sentence
    assert marker in sentence
    assert "same response" in sentence and "CONFIRMS edge" in sentence


@pytest.mark.parametrize("skill", ["ssrf", "xxe", "http_request_smuggling", "user_skill:abc", "x-unclassified", ""])
def test_other_attack_paths_are_unaffected(skill):
    assert _behavior(skill, {"ROUTE_EXPOSURE_ENABLED": True}) == _behavior(skill, {})


def test_the_cypher_prompt_names_the_source():
    line = next(ln for ln in TEXT_TO_CYPHER_SYSTEM.splitlines() if 'source="route_exposure"' in ln)
    assert "needs_agent_confirmation" in line and "HAS_VULNERABILITY" in line
