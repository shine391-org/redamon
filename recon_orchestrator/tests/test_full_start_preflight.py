"""
The full-start pre-flight (hard guardrail, RoE window) runs on every start.

It used to sit behind `if request.webapp_api_url:`, and the model allows an
empty string, so a start with an empty URL skipped the one check that cannot be
switched off. The fetch never used that URL anyway: it goes to the trusted
webapp base.
"""
import asyncio

import pytest
from fastapi import HTTPException

import api
from models import ReconStartRequest, ReconState, ReconStatus


class _SpyManager:
    def __init__(self):
        self.calls = []

    async def start_recon(self, **kw):
        self.calls.append(kw)
        return ReconState(project_id="p1", status=ReconStatus.STARTING)


@pytest.fixture
def spy(monkeypatch):
    s = _SpyManager()
    monkeypatch.setattr(api, "container_manager", s)
    return s


def _start(webapp_api_url, monkeypatch, project):
    fetched = []

    def _fetch(pid):
        fetched.append(pid)
        return project

    monkeypatch.setattr(api, "_fetch_project_for_preflight", _fetch)
    req = ReconStartRequest(project_id="p1", user_id="u1", webapp_api_url=webapp_api_url)
    return fetched, (lambda: asyncio.run(api.start_recon("p1", req)))


@pytest.mark.parametrize("url", ["", "http://localhost:3000"])
def test_the_preflight_runs_whatever_the_request_url(url, monkeypatch, spy):
    fetched, run = _start(url, monkeypatch, {"targetDomain": "agency.gov.uk"})
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 403
    assert fetched == ["p1"] and spy.calls == []


def test_a_batch_host_under_a_government_name_is_refused(monkeypatch, spy):
    project = {"domainBatchMode": True, "domainBatchGroups": [
        {"rootDomain": "example.com", "prefixes": ["www."], "hosts": ["www.example.com"]},
        {"rootDomain": "org.jm", "prefixes": ["www.isa."], "hosts": ["www.isa.org.jm"]},
    ]}
    _, run = _start("", monkeypatch, project)
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 403
    assert "www.isa.org.jm" in ei.value.detail
    assert spy.calls == []


def test_a_clean_project_starts(monkeypatch, spy):
    _, run = _start("", monkeypatch, {"targetDomain": "example.com"})
    run()
    assert len(spy.calls) == 1


def test_a_scope_the_webapp_could_not_derive_refuses_the_start(monkeypatch, spy):
    _, run = _start("", monkeypatch, {"targetDomain": "co.uk", "scopeGroups": []})
    with pytest.raises(HTTPException) as ei:
        run()
    assert ei.value.status_code == 400
    assert spy.calls == []
