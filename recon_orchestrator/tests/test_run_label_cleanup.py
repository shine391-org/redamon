"""Stopping a run removes that run's tool containers and nobody else's (plan 12.4).

The old clean-up listed every container on the host and removed any whose image
name contained a tool name, so stopping project A's scan killed project B's
naabu, httpx and nuclei, and partial recons too, while every tool not in the
list (the supply-chain analyzer, the alpine helpers) ran on. Tool containers
now carry their run as labels (stamped by the broker), and a stop removes only
the containers labelled with its run AND created by the broker.
"""
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import PartialReconState, PartialReconStatus, ReconState, ReconStatus  # noqa: E402
from tests.fake_docker import FakeClient, FakeContainer, tool  # noqa: E402

RUN_A, RUN_B = "run-a-0001", "run-b-0002"


@pytest.fixture
def setup():
    log = []
    recon_a = FakeContainer("recon-a", "redamon-recon:latest", {
        "redamon.run_id": RUN_A, "redamon.project_id": "proj-a",
        "redamon.run_kind": "full_recon"}, log=log)
    a_tools = [
        tool("a-nuclei", RUN_A, log=log),
        tool("a-tlsx", RUN_A, "projectdiscovery/tlsx:latest", log=log),
        tool("a-analyzer", RUN_A, "redamon-supply-chain-analyzer:latest", log=log),
        tool("a-alpine", RUN_A, "alpine:latest", status="exited", log=log),
        tool("a-paused", RUN_A, "projectdiscovery/katana:latest", status="paused", log=log),
    ]
    b_tools = [tool("b-nuclei", RUN_B, project="proj-b", log=log),
               tool("b-partial", RUN_B, "projectdiscovery/httpx:latest", project="proj-b",
                    kind="partial_recon", log=log)]
    others = [
        FakeContainer("unlabelled-naabu", "projectdiscovery/naabu:latest", log=log),
        # Labels are advisory: a container that claims the run but was not made
        # by the broker is never touched.
        FakeContainer("forged", "projectdiscovery/nuclei:latest",
                      {"redamon.run_id": RUN_A}, log=log),
    ]
    client = FakeClient([recon_a, *a_tools, *b_tools, *others])
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = client
    m.running_states = {"proj-a": ReconState(project_id="proj-a", status=ReconStatus.RUNNING,
                                             container_id="recon-a")}
    m.partial_recon_states = {}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    return m, client, log, a_tools, b_tools, others


def _removed(client):
    return {cid for cid, c in client.containers.items.items() if c.removed}


async def _stop_full(m):
    state = await m.stop_recon("proj-a")
    task = getattr(m, "_stop_tasks", {}).get(("full_recon", "proj-a"))
    if task is not None:
        await task
    return state


def test_stopping_a_run_removes_its_tools_of_any_image(setup):
    m, client, _log, a_tools, _b, _o = setup
    with patch.object(cm_mod, "RECON_STOP_GRACE_S", 0.2, create=True):
        asyncio.run(_stop_full(m))
    assert {c.id for c in a_tools} <= _removed(client)


def test_it_leaves_other_runs_and_unlabelled_containers_alone(setup):
    m, client, log, _a, b_tools, others = setup
    with patch.object(cm_mod, "RECON_STOP_GRACE_S", 0.2, create=True):
        asyncio.run(_stop_full(m))
    untouched = {c.id for c in (*b_tools, *others)}
    assert not untouched & _removed(client)
    assert not [verb for cid, verb in log if cid in untouched]


def test_the_listing_requires_the_broker_label_and_the_run(setup):
    m, client, *_ = setup
    with patch.object(cm_mod, "RECON_STOP_GRACE_S", 0.2, create=True):
        asyncio.run(_stop_full(m))
    labels = [set(call.get("filters", {}).get("label", [])) for call in client.containers.list_calls]
    assert labels, "no labelled listing was made"
    assert all(ls == {"redamon.broker-owned=1", f"redamon.run_id={RUN_A}"} for ls in labels)


def test_a_paused_tool_is_unpaused_before_it_is_removed(setup):
    m, client, log, *_ = setup
    with patch.object(cm_mod, "RECON_STOP_GRACE_S", 0.2, create=True):
        asyncio.run(_stop_full(m))
    verbs = [verb for cid, verb in log if cid == "a-paused"]
    assert verbs.index("unpause") < verbs.index("remove:force")


def test_a_container_from_before_the_upgrade_removes_nothing_by_image(setup):
    m, client, log, *_ = setup
    client.containers.items["recon-a"].labels = {}
    with patch.object(cm_mod, "RECON_STOP_GRACE_S", 0.2, create=True):
        asyncio.run(_stop_full(m))
    assert _removed(client) <= {"recon-a"}
    assert not any("redamon.run_id=" in str(c) for c in client.containers.list_calls)


def test_a_partial_stop_removes_its_own_run_only(setup):
    m, client, log, a_tools, b_tools, others = setup
    partial = FakeContainer("partial-b", "redamon-recon:latest", {
        "redamon.run_id": RUN_B, "redamon.project_id": "proj-b",
        "redamon.run_kind": "partial_recon"}, log=log)
    client.containers.add(partial)
    m.running_states = {}
    m.partial_recon_states = {"proj-b": {RUN_B: PartialReconState(
        project_id="proj-b", run_id=RUN_B, status=PartialReconStatus.RUNNING,
        container_id="partial-b")}}

    async def stop():
        await m.stop_partial_recon("proj-b", RUN_B)
        task = getattr(m, "_stop_tasks", {}).get(("partial_recon", "proj-b", RUN_B))
        if task is not None:
            await task

    with patch.object(cm_mod, "RECON_STOP_GRACE_S", 0.2, create=True):
        asyncio.run(stop())
    removed = _removed(client)
    assert {c.id for c in b_tools} <= removed
    assert not {c.id for c in (*a_tools, *others)} & removed


def test_the_image_list_is_gone():
    assert not hasattr(cm_mod, "SUB_CONTAINER_IMAGES")
    assert not hasattr(cm_mod, "sub_container_image_of")


class TestTheSpawnLabelsTheRun:
    def _manager(self):
        m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
        m.client = MagicMock()
        m.client.containers.get.side_effect = cm_mod.NotFound("none")
        m.client.containers.run.return_value = MagicMock(id="cid")
        m.running_states = {}
        m.partial_recon_states = {}
        m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
        m.recon_image = "redamon-recon:latest"
        m.supply_chain_osv_db_volume = "osv"
        m.sca_intel_volume = "intel"
        for name in ("_admit_scan",):
            async def _ok(*a, **k):
                return "key"
            setattr(m, name, _ok)
        m._warm_feeds_in_background = lambda: None
        m._count_active_partial_recons = lambda pid: 0
        m._recon_settings_mount = lambda: {}
        m._graph_db_mount = lambda *a, **k: {}
        m._scanner_env = lambda: {}
        m._analyzer_env = lambda: {}
        m._container_mem_limit = lambda kind: "1g"
        m._container_pids_limit = lambda: 100
        m._container_cpu_limit = lambda: 1
        m._scanner_hardening = lambda **k: {}
        return m

    def test_a_full_recon_container_carries_its_run(self):
        m = self._manager()
        asyncio.run(m.start_recon("proj-a", "u1", "http://webapp", "/host/recon"))
        labels = m.client.containers.run.call_args.kwargs["labels"]
        env = m.client.containers.run.call_args.kwargs["environment"]
        assert labels == {"redamon.project_id": "proj-a", "redamon.run_kind": "full_recon",
                          "redamon.run_id": env["RECON_RUN_ID"]}

    def test_a_partial_recon_container_carries_its_run(self, tmp_path):
        m = self._manager()
        with patch.object(cm_mod, "Path", lambda p: tmp_path / Path(p).name):
            state = asyncio.run(m.start_partial_recon(
                "proj-b", "Naabu", {"user_id": "u1", "webapp_api_url": "http://webapp"},
                "/host/recon"))
        labels = m.client.containers.run.call_args.kwargs["labels"]
        assert labels == {"redamon.project_id": "proj-b", "redamon.run_kind": "partial_recon",
                          "redamon.run_id": state.run_id}
