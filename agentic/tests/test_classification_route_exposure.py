"""The classifier's sections for the three skills that work recon's route
exposure results (plan §23.12): new wording only, no new skill, no new letter.
A skill the project turned off still leaves the classifier prompt.
"""

import contextvars
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import project_settings  # noqa: E402
from prompts import classification  # noqa: E402
from state import KNOWN_ATTACK_PATHS  # noqa: E402


@pytest.mark.parametrize("skill,wording,keywords", [
    ("access_control", "recon's route-exposure leads: unauthenticated internal/admin/debug/old-version/export/upload routes",
     ("unauthenticated endpoint", "route exposure", "excessive data exposure", "old API version")),
    ("path_traversal", "files recon found served directly from the web root: .git, .svn, .hg, .env, web.config, backups",
     ("exposed .git", "git dump", "exposed env file", "backup file")),
    ("rce", "debug consoles, actuator and Ignition endpoints recon's route exposure scan flagged",
     ("Werkzeug debugger", "debug console", "actuator env", "heapdump")),
])
def test_sections_carry_the_recon_wording(skill, wording, keywords):
    section = classification._BUILTIN_SKILL_MAP[skill][0]
    assert wording in section
    keyword_line = next(ln for ln in section.splitlines() if ln.startswith("- Keywords:"))
    for word in keywords:
        assert word in keyword_line


def test_path_traversal_says_a_served_file_is_still_its_own():
    section = classification._BUILTIN_SKILL_MAP["path_traversal"][0]
    assert "a directly served file is still this skill when recon flagged it" in section


def test_no_new_skill_letter_or_list_entry():
    assert "route_exposure" not in KNOWN_ATTACK_PATHS
    assert "route_exposure" not in classification._BUILTIN_SKILL_MAP
    letters = [letter for _, letter, _ in classification._BUILTIN_SKILL_MAP.values()]
    assert len(letters) == len(set(letters)) == 14
    assert set(classification._BUILTIN_SKILL_MAP) <= KNOWN_ATTACK_PATHS
    assert set(classification._BUILTIN_SKILL_MAP) == set(classification._CLASSIFICATION_INSTRUCTIONS)


def _prompt(builtin):
    def run():
        project_settings._settings_ctx.set({"ATTACK_SKILL_CONFIG": {"builtIn": builtin, "user": {}},
                                            "USER_ATTACK_SKILLS": []})
        return classification.build_classification_prompt("look at what recon found")
    return contextvars.copy_context().run(run)


def test_a_disabled_skill_still_leaves_the_prompt():
    on = {"access_control": True, "path_traversal": True, "rce": True}
    text = _prompt(on)
    for skill in on:
        assert classification._BUILTIN_SKILL_MAP[skill][0].splitlines()[0] in text
    text = _prompt({**on, "access_control": False})
    assert classification._BUILTIN_SKILL_MAP["access_control"][0].splitlines()[0] not in text
    assert "recon's route-exposure leads" not in text
    assert classification._BUILTIN_SKILL_MAP["rce"][0].splitlines()[0] in text
