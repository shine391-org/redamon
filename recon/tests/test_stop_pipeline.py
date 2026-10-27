"""The pipeline's side of a stop, and the graph writer's order (plan 12.3).

Once the stop flag is up, no new graph write is queued and the prune refuses
(the killed tools returned empty results, which would read as "gone"). On the
normal paths the one background writer is drained before it is replaced and
before the node-filter sweep reads what it wrote.

Every scanner and Neo4j is a fake.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import shutdown  # noqa: E402


@pytest.fixture(autouse=True)
def _no_stop_left_behind():
    yield
    shutdown._STOP.clear()


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        yield rm
        rm._graph_wait_all()


class _Graph:
    def __init__(self):
        self.prunes = []

    def __call__(self, *a, **k):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, *a):
        return None

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
        self.prunes.append(list(sources))


class TestAfterTheFlag:
    def test_no_new_graph_write_is_queued(self, recon_main, monkeypatch):
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        recon_main._graph_reset()
        shutdown._STOP.set()
        recon_main._graph_update_bg("update_graph_from_vuln_scan", {"x": 1}, "u1", "p1")
        assert recon_main._graph_futures == []

    def test_the_prune_refuses(self, recon_main, monkeypatch, capsys):
        graph = _Graph()
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        monkeypatch.setattr(recon_main, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
        monkeypatch.setattr(recon_main, "_COVERAGE_WRITE_FAILED", False)
        shutdown._STOP.set()
        recon_main._prune_recon_findings()
        assert graph.prunes == []
        assert "the run was stopped" in capsys.readouterr().out

    def test_without_the_flag_the_same_prune_runs(self, recon_main, monkeypatch):
        graph = _Graph()
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        monkeypatch.setattr(recon_main, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
        monkeypatch.setattr(recon_main, "_COVERAGE_WRITE_FAILED", False)
        recon_main._prune_recon_findings()
        assert graph.prunes

    def test_a_batch_starts_no_further_group(self, recon_main, monkeypatch):
        ran = []

        def group(g, start_time=None):
            ran.append(g["scanRoot"])
            shutdown._STOP.set()
            return 0

        monkeypatch.setattr(recon_main, "run_domain_group", group)
        monkeypatch.setattr(recon_main, "clear_batch_outputs", lambda *a, **k: 0)
        monkeypatch.setattr(recon_main, "initialize_batch_canonical", lambda *a, **k: None)
        monkeypatch.setattr(recon_main, "merge_batch_outputs", lambda *a, **k: None)
        monkeypatch.setattr(recon_main, "_eligible_batch_roots", lambda groups: [])
        prunes = []
        monkeypatch.setattr(recon_main, "_prune_recon_findings", lambda: prunes.append(1))
        groups = [{"scanRoot": r, "orgDomain": r, "mode": "enumerate", "includeRoot": True,
                   "exactHosts": []} for r in ("a.example.com", "b.example.com", "c.example.com")]
        rc = recon_main.run_domain_batch(groups, start_time=__import__("datetime").datetime.now())
        assert ran == ["a.example.com"]
        assert prunes == []
        assert rc == 0


class TestTheWriterOrder:
    def test_a_live_writer_is_drained_before_it_is_replaced(self, recon_main, monkeypatch):
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        recon_main._graph_reset()
        landed = threading.Event()
        recon_main._graph_executor.submit(lambda: (time.sleep(0.2), landed.set()))
        recon_main._graph_reset()
        assert landed.is_set()

    def test_main_lands_the_queued_writes_before_the_sweep(self, recon_main, monkeypatch):
        landed = threading.Event()
        seen_at_sweep = []

        def pipeline():
            recon_main._graph_reset()
            recon_main._graph_executor.submit(lambda: (time.sleep(0.2), landed.set()))
            return 0

        monkeypatch.setattr(recon_main, "_run_pipeline", pipeline)
        monkeypatch.setattr(recon_main, "_apply_node_filters",
                            lambda: seen_at_sweep.append(landed.is_set()))
        assert recon_main.main() == 0
        assert seen_at_sweep == [True]

    def test_main_sweeps_after_a_crash_too(self, recon_main, monkeypatch):
        swept = []

        def pipeline():
            raise RuntimeError("boom")

        monkeypatch.setattr(recon_main, "_run_pipeline", pipeline)
        monkeypatch.setattr(recon_main, "_apply_node_filters", lambda: swept.append(1))
        with pytest.raises(RuntimeError):
            recon_main.main()
        assert swept == [1]

    def test_main_registers_its_drain_with_the_stopper(self, recon_main, monkeypatch):
        monkeypatch.setattr(recon_main, "_run_pipeline", lambda: 0)
        monkeypatch.setattr(recon_main, "_apply_node_filters", lambda: None)
        recon_main.main()
        assert recon_main._drain_graph_writes in shutdown._drains


class TestTheStopperDrain:
    def test_it_waits_for_the_queued_writes(self, recon_main, monkeypatch):
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        recon_main._graph_reset()
        landed = threading.Event()
        recon_main._graph_futures.append(
            recon_main._graph_executor.submit(lambda: (time.sleep(0.2), landed.set())))
        recon_main._drain_graph_writes(time.monotonic() + 5)
        assert landed.is_set()

    def test_it_gives_up_at_the_deadline(self, recon_main, monkeypatch, capsys):
        monkeypatch.setattr(recon_main, "UPDATE_GRAPH_DB", True)
        recon_main._graph_reset()
        release = threading.Event()
        recon_main._graph_futures.append(recon_main._graph_executor.submit(release.wait))
        started = time.monotonic()
        recon_main._drain_graph_writes(started + 0.2)
        assert time.monotonic() - started < 2
        assert "did not land before the deadline" in capsys.readouterr().out
        release.set()


class TestPartialRecon:
    def test_run_per_root_starts_no_root_after_the_flag(self):
        from recon.partial_recon_modules import helpers
        seen = []

        def fn(root):
            seen.append(root)
            shutdown._STOP.set()
            return helpers.STATUS_OK

        statuses = helpers.run_per_root(["a.example.com", "b.example.com", "c.example.com"],
                                        fn, "Tool")
        assert seen == ["a.example.com"]
        assert statuses == {"a.example.com": "ok", "b.example.com": "stopped",
                            "c.example.com": "stopped"}

    def test_the_stopper_sweeps_with_the_job_start_stamp(self, monkeypatch):
        import recon.partial_recon as pr
        swept = []
        monkeypatch.setattr(pr, "_apply_node_filters", lambda started_at: swept.append(started_at))
        monkeypatch.setattr(pr, "load_config", lambda: (_ for _ in ()).throw(RuntimeError("stop here")))
        with pytest.raises(RuntimeError):
            pr.main()
        monkeypatch.setattr(pr, "_STARTED_AT", "2026-01-01T00:00:00+00:00")
        assert shutdown.sweep_once() is True
        assert swept == ["2026-01-01T00:00:00+00:00"]
