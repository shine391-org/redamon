"""F09 — partial settings override allowlist: only allowlisted keys override,
unrelated settings preserved, enum validated with off default."""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.partial_recon_modules.helpers import apply_settings_overrides  # noqa: E402


def test_unknown_override_key_is_rejected_unrelated_preserved():
    settings = {"PLANNER_MODE": "shadow", "NUCLEI_RATE_LIMIT": 4, "UNRELATED": "keep"}
    out = apply_settings_overrides(settings, {"PLANNER_MODE": "enforce",
                                              "NOT_ALLOWED": "nope",
                                              "PLANNER_CONSUMER_AI_TAGS": True})
    assert out["PLANNER_MODE"] == "enforce"
    assert out["PLANNER_CONSUMER_AI_TAGS"] is True
    assert out["NUCLEI_RATE_LIMIT"] == 4
    assert out["UNRELATED"] == "keep"
    assert "NOT_ALLOWED" not in out


def test_planner_mode_invalid_falls_back_to_off():
    settings = {"PLANNER_MODE": "shadow"}
    out = apply_settings_overrides(settings, {"PLANNER_MODE": "not-a-mode"})
    assert out["PLANNER_MODE"] == "off"
    out = apply_settings_overrides(settings, {"PLANNER_MODE": 7})
    assert out["PLANNER_MODE"] == "off"


def test_booleans_coerced_and_original_not_mutated():
    settings = {"PLANNER_MANIFEST_ENABLED": False}
    out = apply_settings_overrides(settings, {"PLANNER_MANIFEST_ENABLED": "true"})
    assert out["PLANNER_MANIFEST_ENABLED"] is True
    assert settings["PLANNER_MANIFEST_ENABLED"] is False  # input not mutated
