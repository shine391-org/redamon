"""Nuclei's empty-selection and execution accounting (review blockers 3 and 4).

A run that selected no target re-checked none of Nuclei's findings, so its
earlier findings must be kept: the run records a failed pass BEFORE
record_execution, names the live hosts it could not check in coverage, and
degrades the source so the prune leaves it alone. ``record_execution`` never
counts a ``complete`` verdict on a pass that did not run, and ``merge_plans``
aggregates every group's execution instead of keeping the first group's.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.coverage_stamps import base_url_key  # noqa: E402
from recon.helpers.selection_coverage import (  # noqa: E402
    KEY as SELECTION_KEY, build_plan, merge_plans, record_execution,
)
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402


def _settings(**extra):
    base = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"],
            "NUCLEI_AUTO_UPDATE_TEMPLATES": False, "CVE_LOOKUP_ENABLED": False,
            "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0}
    base.update(extra)
    return base


@pytest.fixture
def pipeline(monkeypatch):
    """Docker present, one host resolved, but build_target_urls selects nothing."""
    calls = {"passes": 0}

    def fake_pass(*a, **kw):
        calls["passes"] += 1
        return [], [], 1.0, 0

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon",
                        lambda rd: ([], ["www.example.com"], {}))
    monkeypatch.setattr(vs, "build_target_urls",
                        lambda h, i, rd, scan_all_ips=False,
                        admission_report=None, declared_report=None: [])
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    return calls


def _recon():
    return {"domain": "example.com",
            "http_probe": {"by_url": {"https://www.example.com": {"status_code": 200}}}}


@pytest.fixture(autouse=True)
def _reset_accumulator():
    cb.reset_registry()
    yield
    cb.reset_registry()


class TestEmptySelectedTargets:
    def test_the_run_keeps_earlier_findings_and_agrees_across_plan_and_coverage(self, pipeline):
        out = vs.run_vuln_scan(_recon(), settings=_settings())
        # No pass launched: the selection was empty.
        assert pipeline["passes"] == 0

        report = cb.coverage_report()
        assert {"nuclei", "vuln_scan"} <= report.degraded_sources
        assert any("no selected Nuclei targets" in (g.get("reason") or "")
                   for g in report.gaps)

        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["total_urls_scanned"] == 0 and meta["total_urls_selected"] == 0
        row = meta["coverage"]["hosts"][base_url_key("https://www.example.com")]
        assert row == {"status": "failed", "inputs": 0, "outputs": 0,
                       "reason": "no selected targets"}

        plan = out[SELECTION_KEY]
        assert plan["status"] == "failed"
        assert plan["execution"]["status"] == "failed"
        assert plan["execution"]["completed_passes"] == 0
        assert plan["execution"]["attempted_urls"] == 0
        assert plan["execution"]["passes"] == [
            {"status": "failed", "reason": "no selected targets",
             "attempted": False, "targets": 1}]

    def test_an_empty_selection_without_live_hosts_still_keeps_findings(self, pipeline):
        out = vs.run_vuln_scan({"domain": "example.com", "http_probe": {"by_url": {}}},
                               settings=_settings())
        assert {"nuclei", "vuln_scan"} <= cb.coverage_report().degraded_sources
        assert out[SELECTION_KEY]["status"] == "failed"


    def test_no_routed_chunks_records_failure_before_execution(self, pipeline, monkeypatch):
        target = "https://www.example.com"
        monkeypatch.setattr(vs, "build_target_urls", lambda *a, **k: [target])
        monkeypatch.setattr(vs, "resolve_routing_mode", lambda settings: vs.MODE_ENFORCE)
        monkeypatch.setattr(vs, "_classify_and_route_templates", lambda **k: {
            "by_category": {}, "target_sets": {}, "compatibility_templates": [],
            "routing_metadata": {}})
        monkeypatch.setattr(vs, "_build_routed_nuclei_commands", lambda **k: [])
        monkeypatch.setattr(vs, "_execute_routed_passes", lambda **k: ([], [], 0, []))
        out = vs.run_vuln_scan(_recon(), settings=_settings())
        plan = out[SELECTION_KEY]
        assert plan["status"] == "failed"
        assert plan["outcomes"]["failed"] == 1
        assert plan["execution"]["attempted_passes"] == 0
        assert plan["execution"]["passes"][0]["reason"] == "no selected chunks executed"
        assert {"nuclei", "vuln_scan"} <= cb.coverage_report().degraded_sources
        coverage = out["vuln_scan"]["scan_metadata"]["coverage"]["hosts"][base_url_key(target)]
        assert coverage["status"] == "failed"


class TestRecordExecutionHonesty:
    def test_a_complete_verdict_on_an_unexecuted_pass_is_not_completion(self):
        plan = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                          exhaustive=True)
        executed = record_execution(plan, [(["https://a.example/x"], "complete", None, True)])
        assert executed["status"] == "complete"
        assert executed["outcomes"]["completed"] == 1

        unrun = record_execution(plan, [(["https://a.example/x"], "complete", None, False)])
        assert unrun["status"] != "complete"
        assert unrun["outcomes"]["completed"] == 0
        assert unrun["outcomes"]["unknown"] == 1
        assert unrun["execution"]["completed_passes"] == 0
        assert unrun["execution"]["urls_in_completed_passes"] == 0
        assert unrun["execution"]["urls_with_all_selected_passes_completed"] == 0

    def test_an_unexecuted_failure_still_fails(self):
        plan = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                          exhaustive=True)
        out = record_execution(plan, [(["https://a.example/x"], "failed",
                                        "policy_empty", False)])
        assert out["status"] == "failed"
        assert out["outcomes"]["failed"] == 1
        assert out["execution"]["completed_passes"] == 0


class TestMergePlansExecution:
    def _plan(self, urls, status, *, first=False):
        plan = build_plan(module="vuln_scan", targets=list(urls), exhaustive=True,
                          reason="r1" if first else "r2")
        return record_execution(plan, [(list(urls), status, None, True)])

    def test_execution_is_aggregated_across_groups_not_first_group_wins(self):
        a = self._plan(["https://a.example/x"], "complete", first=True)
        b = self._plan(["https://b.example/x"], "partial")
        merged = merge_plans([a, b])
        assert merged["execution"]["status"] == "partial"  # worst, not a's complete
        assert merged["execution"]["attempted_passes"] == 2
        assert merged["execution"]["completed_passes"] == 1
        assert len(merged["execution"]["passes"]) == 2
        assert merged["execution"]["attempted_urls"] == 2

    def test_a_failed_second_group_makes_the_batch_failed(self):
        a = self._plan(["https://a.example/x"], "complete", first=True)
        b = self._plan(["https://b.example/x"], "failed")
        merged = merge_plans([a, b])
        assert merged["execution"]["status"] == "failed"
        assert merged["status"] == "failed"
        assert merged["execution"]["completed_passes"] == 1  # a's real completion stays

    def test_a_merged_plan_keeps_working_when_merged_again(self):
        a = self._plan(["https://a.example/x"], "complete", first=True)
        b = self._plan(["https://b.example/x"], "complete")
        once = merge_plans([a, b])
        c = self._plan(["https://c.example/x"], "partial")
        twice = merge_plans([once, c])
        assert twice["execution"]["attempted_passes"] == 3
        assert twice["execution"]["completed_passes"] == 2
        assert len(twice["execution"]["passes"]) == 3


class TestBatchMergeExecution:
    """The real caller: a Domain batch merges every group's plan into one."""

    def test_the_canonical_plan_carries_every_group_execution(self, tmp_path):
        import json
        from recon.helpers.output_paths import merge_batch_outputs, recon_output_file
        from recon.main import save_recon_file

        plans = {
            "a.example": record_execution(
                build_plan(module="vuln_scan", targets=["https://a.example/x"],
                           exhaustive=True),
                [(["https://a.example/x"], "complete", None, True)]),
            "b.example": record_execution(
                build_plan(module="vuln_scan", targets=["https://b.example/x"],
                           exhaustive=False, reason="partial scope"),
                [(["https://b.example/x"], "failed", "nuclei exited 125", False)]),
        }
        for root, plan in plans.items():
            combined = {"domain": root,
                        "metadata": {"root_domain": root, "modules_executed": []},
                        SELECTION_KEY: plan}
            path = recon_output_file(tmp_path, "p1", root)
            path.parent.mkdir(parents=True, exist_ok=True)
            save_recon_file(combined, path)

        canonical = merge_batch_outputs(tmp_path, "p1")
        assert canonical is not None
        data = json.loads(Path(canonical).read_text())
        merged = data[SELECTION_KEY]
        assert merged["execution"]["status"] == "failed"
        # Only the group that actually ran a pass attempted one; the empty
        # selection's synthetic failure is recorded but not an attempt.
        assert merged["execution"]["attempted_passes"] == 1
        assert merged["execution"]["completed_passes"] == 1
        assert len(merged["execution"]["passes"]) == 2
        assert merged["targets"]["count"] == 2


@pytest.fixture
def recon_main():
    import copy as _copy
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=_copy.deepcopy(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        yield rm


class TestPruneKeepsUncheckedNucleiFindings:
    def test_an_empty_selection_prunes_nothing_of_nuclei(self, pipeline, recon_main, monkeypatch):
        prunes = []

        class _Graph:
            def __call__(self, *a, **k):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def verify_connection(self):
                return True

            def prune_unseen_findings(self, user_id, project_id, sources, since,
                                      keep_hosts=(), keep_unproven=False):
                prunes.append(list(sources))

        monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
        vs.run_vuln_scan(_recon(), settings=_settings())
        recon_main._prune_recon_findings()
        assert prunes
        assert all("nuclei" not in sources and "vuln_scan" not in sources
                   for sources in prunes)
