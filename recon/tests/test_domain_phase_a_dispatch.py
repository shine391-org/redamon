"""Regression: the Phase-A fan-out runs on the normal (live-URL) path.

The 7.8.0 merge nested ``_run_phase_a_fan_out`` under the ``elif takeover``
fallback in both ``run_domain_recon`` and ``run_ip_recon``. A run whose httpx
found live URLs therefore populated ``phase_a_tools`` and never dispatched it:
no Phase A, no vuln_scan, no Nuclei captures. The live khotaikhoan.net run's
log recorded 33 multi-source prunes, but the log does not prove those prunes
were caused by the missing dispatch. Both merge parents call the runner on the
normal path.

The fan-out now returns the tool keys it accounted for (dispatched, failed, or
already complete on resume), and the caller records an enabled tool that was
never dispatched as a coverage cut, so the prune keeps its findings even if a
future merge drops the dispatch call again.

Every scanner, DNS resolver and Neo4j is a fake; run_domain_recon, run_ip_recon
and the fan-out are real.
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

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import domain_recon  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402
import recon.graphql_scan as gql  # noqa: E402

ORG = "example.com"
HOST = f"db.{ORG}"
IP = "192.0.2.10"

PORT_SCAN = {
    "scan_metadata": {"ports_config": "80"},
    "by_host": {HOST: {"ip": IP, "ports": [80], "port_details": []}},
    "all_ports": [80], "summary": {"total_open_ports": 1}, "ip_to_hostnames": {},
    "by_ip": {IP: {"ip": IP, "hostnames": [HOST], "ports": [80], "port_details": []}},
}
NO_LIVE_URL = {"by_url": {}, "by_host": {}, "summary": {"live_urls": 0, "total_hosts": 0}}
LIVE_URL = {
    "by_url": {f"http://{IP}:80": {}}, "by_host": {},
    "summary": {"live_urls": 1, "total_hosts": 1},
}

# Everything that is not under test is off, so a run reaches Phase A with fakes.
SETTINGS = {
    "DNS_ENABLED": True, "WHOIS_ENABLED": False, "SHODAN_ENABLED": False,
    "NAABU_ENABLED": True, "MASSCAN_ENABLED": False, "NMAP_ENABLED": False,
    "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False, "UNCOVER_ENABLED": False,
    "HTTPX_ENABLED": True, "IP_ATTRIBUTION_ENABLED": False, "URLSCAN_ENABLED": False,
    "SECURITY_CHECK_ENABLED": False, "CERT_HYGIENE_ENABLED": False,
    "AI_SURFACE_RECON_ENABLED": False, "JS_RECON_ENABLED": False,
    "SERIALIZED_SCAN_ENABLED": False, "SUPPLY_CHAIN_RECON_ENABLED": False,
    "MITRE_ENABLED": False, "CHUNK_CHECKPOINT_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": True, "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROUTE_EXPOSURE_ENABLED": False,
    "ROE_ENABLED": False,
}
SCAN_MODULES = ["port_scan", "http_probe", "resource_enum", "vuln_scan"]

STUB = {
    'TARGET_DOMAIN': ORG, 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
    'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
    'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': list(SCAN_MODULES),
    'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
    'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
    'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
}


@pytest.fixture
def domain_main(tmp_path, monkeypatch):
    cb.reset_registry()
    with mock.patch('recon.project_settings.get_settings', return_value=dict(STUB)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(rm, "SCAN_MODULES", list(SCAN_MODULES))
    monkeypatch.setattr(rm, "_settings", dict(SETTINGS))
    monkeypatch.setattr(rm, "_graph_update_bg", lambda *a, **k: None)
    monkeypatch.setattr(domain_recon, "resolve_all_dns", lambda root, subs, **k: {
        "domain": {}, "subdomains": {HOST: {
            "has_records": True, "ips": {"ipv4": [IP], "ipv6": []},
            "records": {"A": [IP]}}}})
    yield rm
    cb.reset_registry()


class _Run:
    """One pipeline run with every scanner faked; what ran and what it got."""

    def __init__(self, rm, monkeypatch, *, live=True, fail=(), defer=()):
        self.rm = rm
        self.result: dict = {}
        self.calls: list = []
        self.settings_seen: list = []
        self.live = live
        self.fail = set(fail)
        self.defer = set(defer)
        if self.defer:
            # Budget deferral: the fan-out is called, but no worker runs these.
            monkeypatch.setattr(rm, "_checkpoint_budget_admit",
                                lambda origin, key: key not in self.defer)
        monkeypatch.setattr(rm, "run_port_scan_isolated",
                            lambda combined, settings=None: {
                                **combined, "port_scan": copy.deepcopy(PORT_SCAN)})
        monkeypatch.setattr(rm, "run_http_probe", self._httpx)
        monkeypatch.setattr(rm, "run_resource_enum", self._resource)
        monkeypatch.setattr(vs, "run_vuln_scan_isolated", self._tool("vuln_scan"))
        monkeypatch.setattr(st, "run_subdomain_takeover_isolated",
                            self._tool("subdomain_takeover"))
        monkeypatch.setattr(gql, "run_graphql_scan_isolated", self._tool("graphql_scan"))
        monkeypatch.setattr(rm, "run_vuln_scan", self._tool("vuln_scan_legacy"))

    def _httpx(self, combined, output_file=None, settings=None):
        combined["http_probe"] = copy.deepcopy(LIVE_URL if self.live else NO_LIVE_URL)
        return combined

    @staticmethod
    def _resource(combined, output_file=None, settings=None):
        combined["resource_enum"] = {"summary": {"total_endpoints": 0}}
        return combined

    def _tool(self, key):
        def tool(snapshot, settings=None, output_file=None):
            self.calls.append(key)
            self.settings_seen.append(settings)
            if key in self.fail:
                raise RuntimeError(f"{key} boom")
            snapshot[key] = {"findings": [], "summary": {"total_findings": 0}}
            return snapshot
        return tool


def _domain_run(rm, monkeypatch, *, live=True, fail=(), defer=(),
                scan_modules=None, **overrides):
    run = _Run(rm, monkeypatch, live=live, fail=fail, defer=defer)
    if scan_modules is not None:
        monkeypatch.setattr(rm, "SCAN_MODULES", list(scan_modules))
    if overrides:
        monkeypatch.setattr(rm, "_settings", dict(SETTINGS, **overrides))
    target_info = rm.parse_target(ORG, ["db."])
    run.result = rm.run_domain_recon(ORG, target_info=target_info, discovery_enabled=False)
    return run


def _prune_batches(rm, monkeypatch):
    """Run the real prune against a fake graph; return the source batches."""
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

        def backfill_passive_cve_hosts(self, *a):
            return 0

        def backfill_security_check_domains(self, *a):
            return 0

        def prune_unseen_findings(self, user_id, project_id, sources, since, **kw):
            prunes.append(list(sources))
            return {"pruned": 0, "stale": 0, "revived": 0}

    monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
    monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", True)
    monkeypatch.setattr(rm, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
    monkeypatch.setattr(rm, "_COVERAGE_WRITE_FAILED", False)
    rm._prune_recon_findings()
    return prunes


class TestNormalPathDispatch:
    def test_a_live_url_dispatches_every_enabled_phase_a_tool(self, domain_main, monkeypatch):
        run = _domain_run(domain_main, monkeypatch, live=True)
        assert set(run.calls) == {"vuln_scan", "subdomain_takeover", "graphql_scan"}
        executed = run.result["metadata"]["modules_executed"]
        assert {"vuln_scan", "subdomain_takeover", "graphql_scan"} <= set(executed)

    def test_the_normal_path_dispatches_without_takeover(self, domain_main, monkeypatch):
        run = _domain_run(domain_main, monkeypatch, live=True,
                          SUBDOMAIN_TAKEOVER_ENABLED=False)
        assert set(run.calls) == {"vuln_scan", "graphql_scan"}

    def test_the_planner_context_reaches_the_tools(self, domain_main, monkeypatch):
        monkeypatch.setenv("RECON_RUN_ID", "run-123")
        monkeypatch.setenv("USER_ID", "u1")
        run = _domain_run(domain_main, monkeypatch, live=True)
        assert run.settings_seen
        for settings in run.settings_seen:
            assert settings["PLANNER_GROUP_ID"] == f"domain:{ORG}"
            assert settings["PLANNER_RUN_ID"] == "run-123"
            assert settings["PLANNER_PROJECT_ID"] == "p1"
            assert settings["PLANNER_TENANT"] == "u1"


class TestSkipPathDispatch:
    def test_no_live_url_runs_only_takeover(self, domain_main, monkeypatch):
        run = _domain_run(domain_main, monkeypatch, live=False)
        assert run.calls == ["subdomain_takeover"]
        assert run.result["metadata"]["active_scans_skipped"] is True
        report = cb.coverage_report()
        # The live-URL tools that did not run keep their earlier findings.
        assert set(report.keep_hostnames("graphql_scan")) == {IP, HOST}
        assert set(report.keep_hostnames("nuclei")) == {IP, HOST}
        # Takeover ran, so its findings are not kept.
        assert report.keep_hostnames("takeover_scan") == ()

    def test_no_live_url_without_takeover_runs_no_phase_a(self, domain_main, monkeypatch):
        run = _domain_run(domain_main, monkeypatch, live=False,
                          SUBDOMAIN_TAKEOVER_ENABLED=False)
        assert run.calls == []
        report = cb.coverage_report()
        assert set(report.keep_hostnames("graphql_scan")) == {IP, HOST}
        assert set(report.keep_hostnames("nuclei")) == {IP, HOST}


class TestEnabledButNotDispatched:
    def test_no_enabled_tool_is_a_noop(self, domain_main, monkeypatch):
        run = _domain_run(domain_main, monkeypatch, live=True,
                          scan_modules=["port_scan", "http_probe"],
                          GRAPHQL_SECURITY_ENABLED=False,
                          SUBDOMAIN_TAKEOVER_ENABLED=False)
        assert run.calls == []
        assert cb.coverage_report().degraded_sources == frozenset()

    def test_vuln_scan_out_of_the_modules_is_not_dispatched(self, domain_main, monkeypatch):
        monkeypatch.setattr(domain_main, "SCAN_MODULES", ["port_scan", "http_probe"])
        run = _domain_run(domain_main, monkeypatch, live=True)
        assert set(run.calls) == {"subdomain_takeover", "graphql_scan"}
        # Switched off by configuration: its findings prune as before.
        assert cb.coverage_report().keep_hostnames("nuclei") == ()

    def test_a_failed_tool_keeps_its_findings(self, domain_main, monkeypatch):
        run = _domain_run(domain_main, monkeypatch, live=True, fail=["graphql_scan"])
        assert "graphql_scan" in run.result["metadata"]["phase_errors"]
        report = cb.coverage_report()
        assert "graphql_scan" in report.degraded_sources
        assert "graphql_cop" in report.degraded_sources

    def test_an_undispatched_tool_keeps_its_findings(self, domain_main, monkeypatch):
        # Budget deferral: the fan-out is called, but no worker runs vhost_sni.
        run = _domain_run(domain_main, monkeypatch, live=True,
                          VHOST_SNI_ENABLED=True, defer=["vhost_sni"])
        assert "vhost_sni" not in run.calls
        report = cb.coverage_report()
        assert "vhost_sni_enum" in report.degraded_sources
        assert "vhost_sni_enum" in {g["source"] for g in report.gaps}

    def test_a_missing_dispatch_keeps_every_enabled_source(self, domain_main, monkeypatch):
        # The merged defect: the fan-out is never called. The completion
        # accounting must still record the enabled tools as not re-checked.
        monkeypatch.setattr(domain_main, "_run_phase_a_fan_out", lambda *a, **k: set())
        run = _domain_run(domain_main, monkeypatch, live=True)
        assert run.calls == []
        report = cb.coverage_report()
        assert {"nuclei", "security_check", "vuln_scan",
                "graphql_scan", "graphql_cop"} <= set(report.degraded_sources)
        assert "takeover_scan" in report.degraded_sources

    def test_the_prune_excludes_failed_and_undispatched_sources(self, domain_main, monkeypatch):
        _domain_run(domain_main, monkeypatch, live=True, fail=["graphql_scan"],
                    VHOST_SNI_ENABLED=True, defer=["vhost_sni"])
        pruned = {s for batch in _prune_batches(domain_main, monkeypatch) for s in batch}
        assert "graphql_scan" not in pruned
        assert "graphql_cop" not in pruned
        assert "vhost_sni_enum" not in pruned
        # A tool that ran is still pruned as usual.
        assert "nuclei" in pruned


class TestMixedGroups:
    def test_a_live_group_and_a_skipped_group_each_keep_what_they_did_not_check(
            self, domain_main, monkeypatch):
        live = _domain_run(domain_main, monkeypatch, live=True)
        assert set(live.calls) == {"vuln_scan", "subdomain_takeover", "graphql_scan"}
        skipped = _domain_run(domain_main, monkeypatch, live=False)
        assert skipped.calls == ["subdomain_takeover"]
        report = cb.coverage_report()
        # The skipped group's live-URL sources are kept on its hosts.
        assert set(report.keep_hostnames("graphql_scan")) == {IP, HOST}
        # The live group re-checked them, so they are not cut as a whole.
        assert "graphql_scan" not in report.degraded_sources
        assert "nuclei" not in report.degraded_sources


class TestIpModeDispatch:
    @pytest.fixture
    def ip_main(self, tmp_path, monkeypatch):
        stub = dict(STUB, IP_MODE=True, TARGET_IPS=[IP], TARGET_DOMAIN="")
        cb.reset_registry()
        with mock.patch('recon.project_settings.get_settings', return_value=stub):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", list(SCAN_MODULES))
        monkeypatch.setattr(rm, "_settings", dict(SETTINGS))
        monkeypatch.setattr(rm, "_graph_update_bg", lambda *a, **k: None)
        yield rm
        cb.reset_registry()

    def test_ip_mode_dispatches_the_live_url_tools(self, ip_main, monkeypatch):
        run = _Run(ip_main, monkeypatch, live=True)
        run.result = ip_main.run_ip_recon([IP], dict(SETTINGS))
        assert {"subdomain_takeover", "graphql_scan"} <= set(run.calls)
        assert "vuln_scan_legacy" in run.calls  # IP mode runs vuln_scan directly

    def test_ip_mode_still_runs_takeover_with_no_live_url(self, ip_main, monkeypatch):
        run = _Run(ip_main, monkeypatch, live=False)
        run.result = ip_main.run_ip_recon([IP], dict(SETTINGS))
        assert run.calls == ["subdomain_takeover"]
