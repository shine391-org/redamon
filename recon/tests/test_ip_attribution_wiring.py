"""IP attribution runs at the right point of both pipelines (plan 11.3).

After DNS, the port scan, tlsx and http_probe, whose CDN flags, ASN and headers
it reads; before vhost/SNI and origin discovery (GROUP 6), which read its tag.
Shodan's CVEs used to be written at GROUP 3, before any tag existed, so the
GROUP 3 write now holds them back and they are written right after the step.

Source-order checks plus the helpers themselves; no traffic, no Neo4j.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

import recon.main as rm  # noqa: E402

PIPELINES = (rm.run_ip_recon, rm.run_domain_recon)


@pytest.mark.parametrize("fn", PIPELINES, ids=lambda f: f.__name__)
def test_the_step_runs_after_http_probe_and_before_group_6(fn):
    body = inspect.getsource(fn)
    http = body.index("run_http_probe(combined_result")
    step = body.index("_run_ip_attribution(combined_result")
    cves = body.index("_write_shodan_cves(combined_result)")
    vhost = body.index("run_vhost_sni_enrichment_isolated")
    origin = body.index("run_origin_discovery_enrichment_isolated")
    assert http < step < cves < vhost
    assert step < origin


def test_the_domain_step_follows_the_certificate_san_feedback():
    body = inspect.getsource(rm.run_domain_recon)
    assert body.index('source="certificate_san"') < body.index("_run_ip_attribution(combined_result")


@pytest.mark.parametrize("fn", PIPELINES, ids=lambda f: f.__name__)
def test_group_3_holds_the_shodan_cves_back(fn):
    body = inspect.getsource(fn)
    assert '_graph_update_bg("update_graph_from_shodan", _without_shodan_cves(combined_result)' in body
    assert body.count('"update_graph_from_shodan"') == 1


CVE = {"cve_id": "CVE-2018-15473", "ip": "198.51.100.30", "source": "shodan_api"}


def _combined():
    return {"domain": "example.com", "metadata": {"modules_executed": []},
            "shodan": {"hosts": [{"ip": "198.51.100.30"}], "reverse_dns": {}, "cves": [CVE]}}


def test_without_shodan_cves_keeps_everything_else_and_leaves_the_input():
    combined = _combined()
    held = rm._without_shodan_cves(combined)
    assert held["shodan"]["cves"] == []
    assert held["shodan"]["hosts"] == [{"ip": "198.51.100.30"}]
    assert combined["shodan"]["cves"] == [CVE]


def test_without_shodan_cves_is_a_no_op_without_cves():
    combined = {"domain": "example.com"}
    assert rm._without_shodan_cves(combined) is combined


def test_write_shodan_cves_queues_the_cves_alone():
    with mock.patch.object(rm, "_graph_update_bg") as bg:
        rm._write_shodan_cves(_combined())
    (method, payload, *_), = [c.args for c in bg.call_args_list]
    assert method == "update_graph_from_shodan"
    assert payload["shodan"] == {"cves": [CVE]}


@pytest.mark.parametrize("shodan", [None, {}, {"cves": []}])
def test_write_shodan_cves_queues_nothing_without_cves(shodan):
    with mock.patch.object(rm, "_graph_update_bg") as bg:
        rm._write_shodan_cves({"shodan": shodan})
    bg.assert_not_called()


def test_the_step_tags_and_queues_its_graph_write(tmp_path):
    combined = {"domain": "example.com", "metadata": {"modules_executed": []},
                "dns": {"domain": {"ips": {"ipv4": ["198.51.100.30"], "ipv6": []}}, "subdomains": {}}}
    with mock.patch.object(rm, "_graph_update_bg") as bg:
        rm._run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": True}, tmp_path / "out.json")
    assert combined["ip_attribution"]["by_ip"]["198.51.100.30"]["ownership"] == "unknown"
    assert "ip_attribution" in combined["metadata"]["modules_executed"]
    assert [c.args[0] for c in bg.call_args_list] == ["update_graph_from_ip_attribution"]


def test_the_step_off_writes_nothing(tmp_path):
    combined = {"metadata": {"modules_executed": []}}
    with mock.patch.object(rm, "_graph_update_bg") as bg:
        rm._run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": False}, tmp_path / "out.json")
    assert "ip_attribution" not in combined
    bg.assert_not_called()


def test_the_step_never_raises(tmp_path):
    combined = {"metadata": {"modules_executed": []}}
    with mock.patch("recon.main_recon_modules.ip_attribution.run_ip_attribution",
                    side_effect=RuntimeError("boom")), \
         mock.patch.object(rm, "_graph_update_bg") as bg:
        rm._run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": True}, tmp_path / "out.json")
    assert combined["metadata"]["phase_errors"]["ip_attribution"] == "boom"
    bg.assert_not_called()
