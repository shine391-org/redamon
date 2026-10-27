"""Stealth mode never raises a rate above the RoE ceiling (plan 12.2).

The RoE capper ran inside fetch_project_settings, and get_settings applied
the stealth profile afterwards. For the roe_capped keys stealth uses `set`,
not `ceiling`, so it overwrote the capped value: an operator who turned
stealth on to be careful ran naabu at 10 rps against a ceiling of 1.
get_settings now caps again after the stealth and AI passes, before the
memory governor, and CLI mode (which never fetched) is capped too.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_REPO = Path(__file__).resolve().parents[2]
for p in (str(_REPO), str(_REPO / "recon")):
    if p not in sys.path:
        sys.path.insert(0, p)

from recon import project_settings as ps  # noqa: E402
from recon import settings_registry as _registry  # noqa: E402

# The roe_capped keys the stealth profile `set`s above 1, with the value it sets.
STEALTH_SET = {
    "NAABU_RATE_LIMIT": 10, "TAKEOVER_RATE_LIMIT": 10, "NUCLEI_RATE_LIMIT": 5,
    "HTTPX_RATE_LIMIT": 2, "KATANA_RATE_LIMIT": 2, "GRAPHQL_RATE_LIMIT": 2,
    "GAU_VERIFY_RATE_LIMIT": 2, "GAU_METHOD_DETECT_RATE_LIMIT": 2,
}


def _fetched(**overrides):
    """What fetch_project_settings answers: the row, already capped once."""
    def fetch(_project_id, _webapp_url):
        return ps.apply_roe_rate_cap(dict(ps.DEFAULT_SETTINGS, **overrides))
    return fetch


def _settings(**overrides):
    env = {"PROJECT_ID": "p1", "WEBAPP_API_URL": "http://mocked", "REDAMON_MEM_GOVERNOR": "0"}
    with patch.dict(os.environ, env), \
            patch.object(ps, "fetch_project_settings", _fetched(**overrides)):
        return ps.get_settings()


def test_the_profile_under_test_still_sets_these_rates():
    profile = _registry.stealth_profile()
    capped = set(_registry.roe_capped_runtime_keys())
    for key, value in STEALTH_SET.items():
        assert profile[key] == {"set": value}, key
        assert key in capped, key


def test_stealth_with_a_ceiling_of_one_runs_every_capped_rate_at_one_or_less():
    s = _settings(STEALTH_MODE=True, ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=1)
    for key in STEALTH_SET:
        assert s[key] == 1, key
    for key in _registry.roe_capped_runtime_keys():
        value = s.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            assert 0 < value <= 1, key


def test_a_ceiling_above_the_stealth_values_leaves_them_standing():
    s = _settings(STEALTH_MODE=True, ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=20)
    for key, value in STEALTH_SET.items():
        assert s[key] == value, key


def test_no_ceiling_leaves_the_stealth_values_standing():
    s = _settings(STEALTH_MODE=True, ROE_ENABLED=False, ROE_GLOBAL_MAX_RPS=1)
    for key, value in STEALTH_SET.items():
        assert s[key] == value, key


def test_the_cap_runs_before_the_memory_governor():
    seen = {}

    def governor(settings):
        seen.update(settings)
        return settings

    env = {"PROJECT_ID": "p1", "WEBAPP_API_URL": "http://mocked"}
    with patch.dict(os.environ, env), \
            patch.object(ps, "fetch_project_settings",
                         _fetched(STEALTH_MODE=True, ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=1)), \
            patch.object(ps, "apply_memory_governor", governor):
        ps.get_settings()
    assert seen["NAABU_RATE_LIMIT"] == 1


def test_cli_mode_is_capped_too(monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.delenv("WEBAPP_API_URL", raising=False)
    monkeypatch.setenv("REDAMON_MEM_GOVERNOR", "0")
    monkeypatch.setattr(ps, "DEFAULT_SETTINGS", dict(
        ps.DEFAULT_SETTINGS, ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=3, NAABU_RATE_LIMIT=1000))
    assert ps.get_settings()["NAABU_RATE_LIMIT"] == 3


@pytest.mark.parametrize("stealth", [True, False])
def test_the_second_cap_is_idempotent(stealth):
    s = _settings(STEALTH_MODE=stealth, ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=3)
    assert ps.apply_roe_rate_cap(dict(s)) == s
