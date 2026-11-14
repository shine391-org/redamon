"""Actual partial start handler: strict three-key public ingress, no real spawn.

PLANNER_* is saved configuration, not an expansion of request overrides. Every
case uses a disposable manager and project row; the real scope/RoE gates run.
"""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import api
from models import PartialReconStartRequest
from tests.job_credentials import job_credential, use_keys

KEYS = ("CVE_LOOKUP_ENABLED", "MITRE_ENABLED", "SECURITY_CHECK_ENABLED")


@pytest.fixture
def boundary(monkeypatch):
    use_keys(monkeypatch)
    calls = []
    saved = {"targetDomain": "example.test", "subdomainList": [],
             "plannerMode": "shadow", "plannerConsumerTwoPass": False,
             "nucleiRateLimit": 42}
    monkeypatch.setattr(api, "_fetch_project_for_preflight", lambda _pid: dict(saved))

    async def start(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(run_id="fixture-run", roots=["example.test"], status="running")

    monkeypatch.setattr(api, "container_manager", SimpleNamespace(start_partial_recon=start))
    return calls, saved


def invoke(overrides):
    request = PartialReconStartRequest(
        project_id="p1", user_id="fixture-owner", webapp_api_url="http://localhost:3000",
        tool_id="Nuclei", graph_inputs={}, settings_overrides=overrides,
        job_credential=job_credential("p1", "fixture-owner"),
    )
    return asyncio.run(api.start_partial_recon("p1", request))


@pytest.mark.parametrize("value", [False, True])
def test_modal_booleans_reach_dispatch_unchanged(boundary, value):
    calls, saved = boundary
    before = dict(saved)
    requested = dict.fromkeys(KEYS, value)
    invoke(requested)
    assert calls[0]["config"]["settings_overrides"] == requested
    assert saved == before


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("value", ["false", "true", 0, 1, None, [], {}])
def test_non_boolean_is_observably_refused_before_dispatch(boundary, key, value):
    calls, _ = boundary
    with pytest.raises(HTTPException) as exc:
        invoke({key: value})
    assert exc.value.status_code == 400
    assert key in exc.value.detail
    assert calls == []


@pytest.mark.parametrize("key", ["PLANNER_MODE", "PLANNER_CONSUMER_TWO_PASS", "plannerMode",
                                 "ROE_ENABLED", "TARGET_DOMAIN", "NUCLEI_RATE_LIMIT", "UNKNOWN"])
def test_no_saved_control_or_scope_key_becomes_public_override(boundary, key):
    calls, _ = boundary
    with pytest.raises(HTTPException) as exc:
        invoke({key: False})
    assert exc.value.status_code == 400
    assert key in exc.value.detail
    assert calls == []


def test_absent_overrides_do_not_inject_planner_defaults(boundary):
    calls, saved = boundary
    invoke({})
    assert calls[0]["config"]["settings_overrides"] == {}
    assert saved["plannerMode"] == "shadow"
    assert saved["nucleiRateLimit"] == 42
