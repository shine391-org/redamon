"""F09 — partial settings override allowlist: only allowlisted keys override,
unrelated settings preserved, enum validated with off default."""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.partial_recon_modules.helpers import apply_settings_overrides  # noqa: E402


def _silent(_msg: str) -> None:  # collect rejections without printing
    pass


def test_unknown_override_key_is_rejected_unrelated_preserved():
    settings = {"PLANNER_MODE": "shadow", "NUCLEI_RATE_LIMIT": 4, "UNRELATED": "keep"}
    out = apply_settings_overrides(settings, {"PLANNER_MODE": "enforce",
                                              "NOT_ALLOWED": "nope",
                                              "PLANNER_CONSUMER_AI_TAGS": True},
                                   log=_silent)
    assert out["PLANNER_MODE"] == "enforce"
    assert out["PLANNER_CONSUMER_AI_TAGS"] is True
    assert out["NUCLEI_RATE_LIMIT"] == 4
    assert out["UNRELATED"] == "keep"
    assert "NOT_ALLOWED" not in out


def test_planner_mode_invalid_falls_back_to_off():
    settings = {}
    out = apply_settings_overrides(settings, {"PLANNER_MODE": "not-a-mode"}, log=_silent)
    assert out["PLANNER_MODE"] == "off"
    out = apply_settings_overrides(settings, {"PLANNER_MODE": 7}, log=_silent)
    assert out["PLANNER_MODE"] == "off"


def test_planner_mode_invalid_preserves_saved_value():
    # An invalid enum must not clobber a saved setting: the original wins.
    settings = {"PLANNER_MODE": "shadow"}
    out = apply_settings_overrides(settings, {"PLANNER_MODE": "not-a-mode"}, log=_silent)
    assert out["PLANNER_MODE"] == "shadow"
    out = apply_settings_overrides(settings, {"PLANNER_MODE": 7}, log=_silent)
    assert out["PLANNER_MODE"] == "shadow"


def test_booleans_strict_no_truthiness_coercion_and_original_not_mutated():
    settings = {"PLANNER_MANIFEST_ENABLED": False}
    out = apply_settings_overrides(settings, {"PLANNER_MANIFEST_ENABLED": True},
                                   log=_silent)
    assert out["PLANNER_MANIFEST_ENABLED"] is True
    assert settings["PLANNER_MANIFEST_ENABLED"] is False  # input not mutated
    # A string is NOT a boolean: truthiness coercion is the G2 defect.
    out = apply_settings_overrides(settings, {"PLANNER_MANIFEST_ENABLED": "false"},
                                   log=_silent)
    assert out["PLANNER_MANIFEST_ENABLED"] is False  # saved value wins
    out = apply_settings_overrides({}, {"PLANNER_MANIFEST_ENABLED": 1}, log=_silent)
    assert out["PLANNER_MANIFEST_ENABLED"] is False  # absent -> default


def test_rejections_are_observable():
    seen: list[str] = []
    apply_settings_overrides({"PLANNER_MODE": "shadow"},
                             {"NOT_ALLOWED": 1, "PLANNER_MODE": "bogus",
                              "NUCLEI_ENABLED": "yes"},
                             log=seen.append)
    text = "\n".join(seen)
    assert "NOT_ALLOWED" in text
    assert "PLANNER_MODE" in text
    assert "NUCLEI_ENABLED" in text
    assert len(seen) == 3
