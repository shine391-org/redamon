"""Pause freezes the run's tools too, and Resume re-checks the RoE window (plan 12.5).

`docker pause` froze the recon container only. The tools run in their own
sibling containers, outside its cgroup, so a paused scan's Nuclei kept sending
requests to the target until it finished: Pause, and Emergency Pause All, are
what an operator presses when the client says "stop now". Resume never looked
at the time window, so a scan paused at 17:55 in a 09:00-18:00 window and
resumed at 21:00 carried on outside it, where a new start is refused.
"""
import asyncio
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi import HTTPException

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import api  # noqa: E402
import container_manager as cm_mod  # noqa: E402
from models import ReconState, ReconStatus  # noqa: E402
from tests.fake_docker import FakeClient, FakeContainer, tool  # noqa: E402

RUN_A, RUN_B = "run-a-0001", "run-b-0002"


class Recorded(FakeContainer):
    def _record(self, verb):
        self.thread = threading.current_thread().name
        super()._record(verb)


@pytest.fixture
def world():
    log = []
    recon = Recorded("recon-a", "redamon-recon:latest", {
        "redamon.run_id": RUN_A, "redamon.project_id": "proj-a",
        "redamon.run_kind": "full_recon"}, log=log)
    nuclei = tool("a-nuclei", RUN_A, log=log)
    tlsx = tool("a-tlsx", RUN_A, "projectdiscovery/tlsx:latest", log=log)
    done = tool("a-done", RUN_A, "projectdiscovery/httpx:latest", status="exited", log=log)
    other = tool("b-nuclei", RUN_B, project="proj-b", log=log)
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = FakeClient([recon, nuclei, tlsx, done, other])
    m.running_states = {"proj-a": ReconState(project_id="proj-a", status=ReconStatus.RUNNING,
                                             container_id="recon-a")}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="docker-op")
    return m, log, recon, nuclei, tlsx, done, other


class TestPause:
    def test_it_freezes_the_recon_container_then_the_runs_tools(self, world):
        m, log, recon, nuclei, tlsx, done, other = world
        state = asyncio.run(m.pause_recon("proj-a"))
        assert state.status == ReconStatus.PAUSED
        assert log[0] == ("recon-a", "pause")
        assert {("a-nuclei", "pause"), ("a-tlsx", "pause")} <= set(log)
        assert nuclei.status == tlsx.status == "paused"

    def test_another_run_and_a_finished_tool_are_left_alone(self, world):
        m, log, recon, nuclei, tlsx, done, other = world
        asyncio.run(m.pause_recon("proj-a"))
        assert other.status == "running"
        assert not [v for cid, v in log if cid in ("b-nuclei", "a-done")]

    def test_every_docker_call_runs_off_the_event_loop(self, world):
        m, _log, recon, nuclei, *_ = world
        asyncio.run(m.pause_recon("proj-a"))
        assert recon.thread.startswith("docker-op")

    def test_a_run_without_labels_still_pauses_its_recon_container(self, world):
        m, log, recon, nuclei, *_ = world
        recon.labels = {}
        state = asyncio.run(m.pause_recon("proj-a"))
        assert state.status == ReconStatus.PAUSED
        assert nuclei.status == "running"


class TestResume:
    def _paused(self, world):
        m, log, recon, nuclei, tlsx, done, other = world
        asyncio.run(m.pause_recon("proj-a"))
        log.clear()
        return world

    def test_it_unpauses_the_tools_then_the_recon_container(self, world):
        m, log, recon, nuclei, tlsx, done, other = self._paused(world)
        state = asyncio.run(m.resume_recon("proj-a"))
        assert state.status == ReconStatus.RUNNING
        assert log[-1] == ("recon-a", "unpause")
        assert {("a-nuclei", "unpause"), ("a-tlsx", "unpause")} <= set(log[:-1])
        assert recon.status == nuclei.status == tlsx.status == "running"

    def test_a_tool_that_finished_meanwhile_is_ignored(self, world):
        m, log, recon, nuclei, tlsx, done, other = self._paused(world)
        tlsx.status = "exited"
        state = asyncio.run(m.resume_recon("proj-a"))
        assert state.status == ReconStatus.RUNNING
        assert ("a-tlsx", "unpause") not in log


class TestTheResumeEndpoint:
    @pytest.fixture
    def paused(self, world, monkeypatch):
        m, log, recon, nuclei, *_ = world
        asyncio.run(m.pause_recon("proj-a"))
        log.clear()
        monkeypatch.setattr(api, "container_manager", m)
        return m, log, recon, nuclei

    WINDOW = {"roeEnabled": True, "roeTimeWindowEnabled": True, "roeTimeWindowTimezone": "UTC",
              "roeTimeWindowStartTime": "00:00", "roeTimeWindowEndTime": "23:59",
              "roeTimeWindowDays": ["monday", "tuesday", "wednesday", "thursday", "friday",
                                    "saturday", "sunday"]}

    def test_inside_the_window_it_resumes(self, paused, monkeypatch):
        m, log, recon, nuclei = paused
        monkeypatch.setattr(api, "_fetch_project_for_preflight", lambda pid, **k: dict(self.WINDOW))
        state = asyncio.run(api.resume_recon("proj-a"))
        assert state.status == ReconStatus.RUNNING
        assert recon.status == nuclei.status == "running"

    def test_outside_the_window_it_answers_403_and_stays_paused(self, paused, monkeypatch):
        m, log, recon, nuclei = paused
        closed = dict(self.WINDOW, roeTimeWindowDays=[])
        monkeypatch.setattr(api, "_fetch_project_for_preflight", lambda pid, **k: closed)
        with pytest.raises(HTTPException) as ei:
            asyncio.run(api.resume_recon("proj-a"))
        assert ei.value.status_code == 403
        assert "RoE time window" in ei.value.detail
        assert log == []
        assert recon.status == nuclei.status == "paused"
        assert m.running_states["proj-a"].status == ReconStatus.PAUSED

    def test_a_webapp_outage_answers_503_and_stays_paused(self, paused, monkeypatch):
        m, log, recon, nuclei = paused

        def down(pid, **k):
            raise HTTPException(status_code=503, detail="Cannot verify scan scope")

        monkeypatch.setattr(api, "_fetch_project_for_preflight", down)
        with pytest.raises(HTTPException) as ei:
            asyncio.run(api.resume_recon("proj-a"))
        assert ei.value.status_code == 503
        assert log == []
        assert recon.status == "paused"

    def test_the_outage_message_says_the_scan_stays_paused(self, monkeypatch):
        import urllib.request

        def refuse(*a, **k):
            raise OSError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", refuse)
        with pytest.raises(HTTPException) as ei:
            api._fetch_project_for_preflight("proj-a", refusal="The scan stays paused.")
        assert ei.value.status_code == 503
        assert ei.value.detail.endswith("The scan stays paused.")

    def test_a_scan_that_is_not_paused_is_not_checked(self, world, monkeypatch):
        m, *_ = world
        monkeypatch.setattr(api, "container_manager", m)
        monkeypatch.setattr(api, "_fetch_project_for_preflight",
                            lambda pid, **k: pytest.fail("no fetch for a running scan"))
        state = asyncio.run(api.resume_recon("proj-a"))
        assert state.status == ReconStatus.RUNNING
