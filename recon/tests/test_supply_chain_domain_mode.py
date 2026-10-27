"""Supply chain runs in domain-mode full scans, and IP mode checks the RoE window (plan 12.7).

GROUP 5.5 (run_supply_chain_recon) existed only in run_ip_recon, so a domain
project with SUPPLY_CHAIN_RECON_ENABLED never ran it in a full scan, although
domain scans are where the web apps and their JavaScript are. And the IP-mode
branch of _run_pipeline returned before the container's own RoE window check,
so a container that started late (image pulls) after the window closed scanned
anyway.

Every scanner and Neo4j is a fake.
"""
from __future__ import annotations

import inspect
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))



def _stub(**over):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    stub.update(over)
    return stub


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    with mock.patch('recon.project_settings.get_settings', return_value=_stub()):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        yield rm


class TestTheSupplyChainSlot:
    def _run(self, rm, monkeypatch, tmp_path, enabled, boom=False):
        calls, queued = [], []

        def fake(combined, settings=None):
            calls.append(dict(combined))
            if boom:
                raise RuntimeError("analyzer exploded")
            combined["supply_chain"] = {"packages": 3}
            return combined

        # The real module needs supply_chain_common, mounted only in the scan container.
        fake_module = types.ModuleType("recon.main_recon_modules.supply_chain_recon")
        fake_module.run_supply_chain_recon = fake
        monkeypatch.setitem(sys.modules, "recon.main_recon_modules.supply_chain_recon", fake_module)
        monkeypatch.setattr(rm, "_graph_update_bg", lambda name, data, *a: queued.append(name))
        combined = {"domain": "example.com", "metadata": {"modules_executed": []}}
        out = rm._maybe_run_supply_chain(
            combined, {"SUPPLY_CHAIN_RECON_ENABLED": enabled}, tmp_path / "r.json")
        return out, calls, queued

    def test_on_it_runs_once_and_queues_its_graph_update(self, recon_main, monkeypatch, tmp_path):
        out, calls, queued = self._run(recon_main, monkeypatch, tmp_path, True)
        assert len(calls) == 1
        assert out["supply_chain"] == {"packages": 3}
        assert out["metadata"]["modules_executed"] == ["supply_chain_recon"]
        assert queued == ["update_graph_from_supply_chain_recon"]
        assert (tmp_path / "r.json").exists()

    def test_off_it_does_nothing(self, recon_main, monkeypatch, tmp_path):
        out, calls, queued = self._run(recon_main, monkeypatch, tmp_path, False)
        assert calls == [] and queued == []
        assert out["metadata"]["modules_executed"] == []

    def test_a_crash_never_stops_the_scan(self, recon_main, monkeypatch, tmp_path):
        out, calls, queued = self._run(recon_main, monkeypatch, tmp_path, True, boom=True)
        assert len(calls) == 1 and queued == []
        assert "supply_chain_recon" in out["metadata"]["phase_errors"]


@pytest.mark.parametrize("fn", ["run_domain_recon", "run_ip_recon"])
def test_both_pipelines_run_it_after_the_serialized_scan_and_before_phase_a(recon_main, fn):
    body = inspect.getsource(getattr(recon_main, fn))
    serialized = body.index("run_serialized_scan(")
    slot = body.index("_maybe_run_supply_chain(combined_result")
    phase_a = body.index("_run_phase_a_fan_out(")
    assert serialized < slot < phase_a
    assert body.count("_maybe_run_supply_chain(") == 1
    # Outside the `if not skip_active_scans` block: it sends no traffic to the target.
    gate = body.index("if not skip_active_scans")
    assert slot < gate


class TestTheIpModeWindow:
    def test_a_closed_window_refuses_before_the_clear(self, tmp_path, monkeypatch):
        with mock.patch('recon.project_settings.get_settings',
                        return_value=_stub(IP_MODE=True, TARGET_IPS=['192.0.2.10'])):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
        cleared, scanned = [], []
        monkeypatch.setattr(rm, "_check_roe_time_window", lambda s: (False, "outside 09:00-18:00"))
        monkeypatch.setattr(rm, "_clear_recon_graph", lambda: cleared.append(1))
        monkeypatch.setattr(rm, "run_ip_recon", lambda *a, **k: scanned.append(1))
        assert rm._run_pipeline() == 1
        assert cleared == [] and scanned == []

    def test_an_open_window_runs_ip_mode(self, tmp_path, monkeypatch):
        with mock.patch('recon.project_settings.get_settings',
                        return_value=_stub(IP_MODE=True, TARGET_IPS=['192.0.2.10'])):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
        order = []
        monkeypatch.setattr(rm, "_check_roe_time_window", lambda s: (order.append("window"), (True, ""))[1])
        monkeypatch.setattr(rm, "_clear_recon_graph", lambda: order.append("clear"))
        monkeypatch.setattr(rm, "run_ip_recon", lambda *a, **k: order.append("scan") or {})
        monkeypatch.setattr(rm, "_write_coverage_record", lambda *a, **k: None)
        monkeypatch.setattr(rm, "_prune_recon_findings", lambda: None)
        assert rm._run_pipeline() == 0
        assert order == ["window", "clear", "scan"]
