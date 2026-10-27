"""The CVE lookup's answer survives the Group 6 fan-out in domain mode (plan 12.1).

run_vuln_scan writes two top-level keys: vuln_scan, and the CVE lookup's
technology_cves. Its _isolated wrapper used to hand back vuln_scan only, so in
domain mode the lookup's NVD calls were made and their Technology -> CVE ->
MitreData -> Capec chain never reached the graph. The wrapper now declares a
multi-key answer (TopLevelKeys), and the fan-out merges every key it carries
before it queues the graph update.

Every scanner and Neo4j is a fake.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.isolated_result import TopLevelKeys  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

TECH_CVES = {"by_technology": {"nginx/1.18.0": {"cves": [{"id": "CVE-2021-23017"}]}},
             "summary": {"total_cves": 1}}
VULN = {"findings": ["marker"], "summary": {"total_findings": 1}}


def _both_keys(recon_data, output_file=None, settings=None):
    recon_data["vuln_scan"] = dict(VULN)
    recon_data["technology_cves"] = copy.deepcopy(TECH_CVES)
    return recon_data


def _vuln_only(recon_data, output_file=None, settings=None):
    recon_data["vuln_scan"] = dict(VULN)
    return recon_data


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['vuln_scan'],
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


class TestTheWrapper:
    def test_it_hands_back_the_cve_lookup_with_the_scan(self, monkeypatch):
        monkeypatch.setattr(vs, "run_vuln_scan", _both_keys)
        result = vs.run_vuln_scan_isolated({"domain": "example.com", "http_probe": {}}, {})
        assert isinstance(result, TopLevelKeys)
        assert result == {"vuln_scan": VULN, "technology_cves": TECH_CVES}

    def test_no_lookup_means_no_technology_cves_key(self, monkeypatch):
        monkeypatch.setattr(vs, "run_vuln_scan", _vuln_only)
        result = vs.run_vuln_scan_isolated({"domain": "example.com"}, {})
        assert result == {"vuln_scan": VULN}

    def test_it_leaves_the_input_alone(self, monkeypatch):
        monkeypatch.setattr(vs, "run_vuln_scan", _both_keys)
        combined = {"domain": "example.com", "http_probe": {}}
        vs.run_vuln_scan_isolated(combined, {})
        assert combined == {"domain": "example.com", "http_probe": {}}


class TestTheMerge:
    def test_a_declared_answer_writes_every_key(self, recon_main):
        combined = {"domain": "example.com"}
        recon_main._merge_isolated_result(
            combined, "vuln_scan", TopLevelKeys(vuln_scan=VULN, technology_cves=TECH_CVES))
        assert combined["vuln_scan"] == VULN
        assert combined["technology_cves"] == TECH_CVES

    def test_without_the_lookup_only_vuln_scan_is_written(self, recon_main):
        combined = {"domain": "example.com"}
        recon_main._merge_isolated_result(combined, "vuln_scan", TopLevelKeys(vuln_scan=VULN))
        assert combined == {"domain": "example.com", "vuln_scan": VULN}

    def test_a_plain_payload_is_never_read_as_keys(self, recon_main):
        # graphql_scan's payload is a dict too, with keys of its own: only the
        # declared type spreads, never a dict that happens to name a pipeline key.
        payload = {"technology_cves": "not mine", "summary": {}}
        combined = {"domain": "example.com"}
        recon_main._merge_isolated_result(combined, "graphql_scan", payload)
        assert combined == {"domain": "example.com", "graphql_scan": payload}

    def test_a_declared_answer_without_its_own_key_still_sets_it(self, recon_main):
        combined = {}
        recon_main._merge_isolated_result(combined, "vuln_scan", TopLevelKeys())
        assert combined == {"vuln_scan": {}}


class TestTheFanOut:
    def _run(self, rm, monkeypatch, tools):
        queued = []
        monkeypatch.setattr(rm, "_graph_update_bg",
                            lambda name, data, *a: queued.append((name, copy.deepcopy(data))))
        monkeypatch.setattr(rm, "save_recon_file", lambda *a, **k: None)
        combined = {"domain": "example.com", "metadata": {"modules_executed": []}}
        rm._run_phase_a_fan_out(tools, combined, {}, None)
        return combined, queued

    def test_the_vuln_scan_graph_update_sees_the_cve_lookup(self, recon_main, monkeypatch):
        monkeypatch.setattr(vs, "run_vuln_scan", _both_keys)
        combined, queued = self._run(
            recon_main, monkeypatch, {"vuln_scan": vs.run_vuln_scan_isolated})
        assert combined["technology_cves"] == TECH_CVES
        assert combined["metadata"]["modules_executed"] == ["vuln_scan"]
        [(name, snapshot)] = queued
        assert name == "update_graph_from_vuln_scan"
        assert snapshot["technology_cves"] == TECH_CVES
        assert snapshot["vuln_scan"] == VULN

    def test_a_crashed_tool_is_a_phase_error_and_writes_nothing(self, recon_main, monkeypatch):
        def boom(*_a, **_k):
            raise RuntimeError("nuclei exploded")

        combined, queued = self._run(recon_main, monkeypatch, {"vuln_scan": boom})
        assert queued == []
        assert "vuln_scan" not in combined
        assert combined["metadata"]["phase_errors"] == {"vuln_scan": "nuclei exploded"}


def test_both_pipelines_merge_phase_a_through_the_helper(recon_main):
    import inspect
    for fn in (recon_main.run_domain_recon, recon_main.run_ip_recon):
        body = inspect.getsource(fn)
        assert "_run_phase_a_fan_out(" in body, fn.__name__
        assert "combined_result[key] = fut.result()" not in body, fn.__name__
