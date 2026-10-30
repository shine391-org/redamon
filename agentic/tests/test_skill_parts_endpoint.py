"""The agent's skill-parts endpoints for the plugin platform.

GET /plugins/skill-parts publishes the overridable built-in parts (the webapp's
reconciliation compares their hashes with stored overrides); POST
/plugins/skill-parts/validate checks proposed values with the same validator the seam
applies at use. Master key only, refused outright when that key is weak, and neither
reads any project's settings.
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "m" * 40
SCANNER = "s" * 40


@pytest.fixture(scope="module")
def api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with patch("api.lifespan", fake_lifespan):
        import api as api_module
    return api_module


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    import llm_guard
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    monkeypatch.setenv("SCANNER_API_KEY", SCANNER)
    monkeypatch.delenv("PLUGIN_SKILL_TEXT_MAX_GROWTH", raising=False)
    llm_guard.reset_state()
    yield
    llm_guard.reset_state()


@pytest.fixture(autouse=True)
def no_project_settings():
    """Neither endpoint may read a project's settings: any read fails the test."""
    def tripwire(*_a, **_k):
        raise AssertionError("project settings read by a skill-parts endpoint")

    with patch("project_settings.get_setting", side_effect=tripwire), \
         patch("project_settings.get_settings", side_effect=tripwire), \
         patch("prompts.get_setting", side_effect=tripwire):
        yield


def _client(api):
    from fastapi.testclient import TestClient
    return TestClient(api.app)


def _get(api, query="", key=MASTER):
    return _client(api).get(f"/plugins/skill-parts{query}", headers={"x-internal-key": key})


def _validate(api, body, key=MASTER):
    return _client(api).post("/plugins/skill-parts/validate", json=body,
                             headers={"x-internal-key": key})


def _part(skill_id, part_id):
    from prompts import skill_parts
    return skill_parts.get_part(skill_id, part_id)


# ── auth ────────────────────────────────────────────────────────────────────

def test_master_key_lists_every_skill(api):
    from prompts import skill_parts
    res = _get(api)
    assert res.status_code == 200, res.text
    skills = res.json()["skills"]
    assert [s["id"] for s in skills] == list(skill_parts.skill_ids())
    assert sum(len(s["parts"]) for s in skills) == 58


@pytest.mark.parametrize("key", [SCANNER, "", "wrong"])
def test_other_keys_are_refused(api, key):
    assert _get(api, key=key).status_code == 401
    assert _validate(api, {"skillId": "ssrf", "parts": {}}, key=key).status_code == 401


@pytest.mark.parametrize("weak", ["", "changeme"])
def test_a_weak_master_key_is_refused(api, monkeypatch, weak):
    monkeypatch.setenv("INTERNAL_API_KEY", weak)
    for res in (_get(api, key=weak), _validate(api, {"skillId": "ssrf", "parts": {}}, key=weak)):
        assert res.status_code == 503
        assert "INTERNAL_API_KEY" in res.json()["error"]


# ── listing ─────────────────────────────────────────────────────────────────

def test_skill_filter_and_part_fields(api):
    res = _get(api, "?skill=ssrf")
    assert res.status_code == 200
    skills = res.json()["skills"]
    assert [s["id"] for s in skills] == ["ssrf"]
    parts = skills[0]["parts"]
    assert [p["partId"] for p in parts] == [
        "tools", "oob_workflow", "gopher_chains", "dns_rebinding", "payload_reference"]
    tools = parts[0]
    registered = _part("ssrf", "tools")
    assert tools == {
        "partId": "tools",
        "constant": registered.constant,
        "kind": "template",
        "placeholders": sorted(registered.placeholders),
        "sha256": registered.sha256,
        "chars": len(registered.text),
        "maxChars": max(2 * len(registered.text), len(registered.text) + 20_000),
        "order": 1,
        "gate": registered.gate,
        "text": registered.text,
    }
    assert parts[1]["kind"] == "plain" and parts[1]["placeholders"] == []


def test_every_skill_and_part_carries_the_validators_limits(api):
    """The plugin platform shows these limits to plugins (override.get) so a proposal can
    stay within them; they must be the validator's own, not a copy that can drift."""
    from prompts import skill_parts
    for skill in _get(api).json()["skills"]:
        assert skill["maxChars"] == skill_parts.skill_total_limit(skill["id"])
        assert skill["maxChars"] == int(sum(len(p["text"]) for p in skill["parts"]) * 1.5)
        for part in skill["parts"]:
            assert part["maxChars"] == skill_parts.max_part_chars(_part(skill["id"], part["partId"]))


def test_the_skill_limit_follows_the_growth_setting(api, monkeypatch):
    monkeypatch.setenv("PLUGIN_SKILL_TEXT_MAX_GROWTH", "2")
    skill = _get(api, "?skill=xxe").json()["skills"][0]
    assert skill["maxChars"] == 2 * sum(len(p["text"]) for p in skill["parts"])


def test_unknown_skill_is_a_404(api):
    assert _get(api, "?skill=nope").status_code == 404
    assert _validate(api, {"skillId": "nope", "parts": {}}).status_code == 404


# ── validation ──────────────────────────────────────────────────────────────

def test_a_good_template_is_ok(api):
    tools = _part("sql_injection", "tools")
    res = _validate(api, {"skillId": "sql_injection",
                          "parts": {"tools": tools.text + "\nLevel: {sqli_level}"}})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["parts"]["tools"]["errors"] == []
    assert body["parts"]["tools"]["chars"] == len(tools.text) + len("\nLevel: {sqli_level}")
    assert body["parts"]["tools"]["maxChars"] == max(2 * len(tools.text), len(tools.text) + 20_000)
    assert body["skill"]["errors"] == []
    assert body["skill"]["maxChars"] >= body["skill"]["chars"]


def test_a_bad_template_returns_its_errors(api):
    tools = _part("sql_injection", "tools")
    res = _validate(api, {"skillId": "sql_injection",
                          "parts": {"tools": tools.text + "\nTarget: {target_host}"}})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is False
    assert any("target_host" in e for e in body["parts"]["tools"]["errors"])


@pytest.mark.parametrize("heading", [
    "## SCOPE GUARDRAIL", "## RULES OF ENGAGEMENT (MANDATORY)", "## SKILL FIT CHECK",
    "## RoE TIMING WARNINGS",
])
def test_reserved_headings_are_refused(api, heading):
    oob = _part("ssrf", "oob_workflow")
    res = _validate(api, {"skillId": "ssrf", "parts": {"oob_workflow": oob.text + "\n" + heading}})
    body = res.json()
    assert body["ok"] is False
    assert body["parts"]["oob_workflow"]["errors"]


def test_unknown_part_is_an_error_not_a_crash(api):
    res = _validate(api, {"skillId": "ssrf", "parts": {"ghost": "text"}})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is False
    assert body["parts"]["ghost"]["errors"]


def test_whole_skill_over_its_limit(api):
    from prompts import skill_parts
    limit = skill_parts.skill_total_limit("ssrf")
    factory = sum(len(p.text) for p in skill_parts.parts_of("ssrf"))
    oob, gopher = _part("ssrf", "oob_workflow"), _part("ssrf", "gopher_chains")
    grow = (limit - factory) // 2 + 10
    res = _validate(api, {"skillId": "ssrf", "parts": {
        "oob_workflow": oob.text + "a" * grow, "gopher_chains": gopher.text + "b" * grow}})
    body = res.json()
    assert body["parts"]["oob_workflow"]["errors"] == []
    assert body["parts"]["gopher_chains"]["errors"] == []
    assert body["ok"] is False
    assert body["skill"]["errors"]
    assert body["skill"]["chars"] == factory + 2 * grow
    assert body["skill"]["maxChars"] == limit


@pytest.mark.parametrize("body", [
    {"skillId": "ssrf", "parts": {"oob_workflow": 5}},
    {"skillId": "ssrf", "parts": ["x"]},
    {"parts": {}},
])
def test_malformed_bodies_are_refused(api, body):
    assert _validate(api, body).status_code == 422
