"""The scanners read the IP attribution tag (plan 11.4).

- vhost/SNI skips its wordlist on a shared_edge IP. The tag replaces plan 07's
  CDN heuristic, which stays the fallback for an IP with no tag.
- Origin discovery never reports a shared_edge candidate as an origin.
- Shodan and Netlas write no CVE finding on a shared_edge IP. In a full run the
  tag exists only after http_probe, so both writes wait for the step.
- A partial run reads the tag from the graph (IP.ownership).

No traffic, no Neo4j. Addresses are RFC 5737; the Cloudflare one sits in its
published edge range (infrastructure, not target data).
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

from recon.helpers import cdn_ranges as cr  # noqa: E402
from recon.main_recon_modules import netlas_enrich as ne  # noqa: E402
from recon.main_recon_modules import origin_discovery as od  # noqa: E402
from recon.main_recon_modules import shodan_enrich as se  # noqa: E402
from recon.main_recon_modules import vhost_sni_enum as vsm  # noqa: E402

EDGE = "198.51.100.20"       # tagged shared_edge (e.g. an edge ASN, no CDN flag)
OWN = "198.51.100.21"        # tagged dedicated
PLAIN = "198.51.100.22"      # tagged unknown
UNTAGGED = "104.16.0.1"      # no tag: Cloudflare's published range is the fallback


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setattr(cr, "_fetch_prefix_list", lambda *a, **k: [])
    monkeypatch.setattr(cr, "_cloudflare_networks_cache", None)


def _tagged(**extra):
    return {
        "ip_attribution": {"by_ip": {
            EDGE: {"ownership": "shared_edge"},
            OWN: {"ownership": "dedicated"},
            PLAIN: {"ownership": "unknown"},
        }},
        **extra,
    }


# ---------------------------------------------------------------------------
# vhost/SNI
# ---------------------------------------------------------------------------
class TestVhostReadsTheTag:
    def test_a_shared_edge_is_skipped_and_dedicated_or_unknown_is_not(self):
        assert vsm._shared_edge_ips(_tagged(), [EDGE, OWN, PLAIN]) == {EDGE}

    def test_the_tag_wins_over_the_old_heuristic(self):
        combined = _tagged(port_scan={"by_ip": {PLAIN: {"is_cdn": True, "cdn": "cloudflare"}}})
        assert PLAIN not in vsm._shared_edge_ips(combined, [PLAIN])

    def test_an_untagged_ip_falls_back_to_the_cdn_checks(self):
        combined = _tagged(port_scan={"by_ip": {"198.51.100.23": {"is_cdn": True, "cdn": "fastly"}}})
        got = vsm._shared_edge_ips(combined, [UNTAGGED, "198.51.100.23", "198.51.100.24"])
        assert got == {UNTAGGED, "198.51.100.23"}

    def test_no_payload_is_the_old_behaviour(self):
        assert vsm._shared_edge_ips({}, [UNTAGGED, PLAIN]) == {UNTAGGED}


# ---------------------------------------------------------------------------
# Origin discovery
# ---------------------------------------------------------------------------
class TestOriginNeverReportsASharedEdge:
    def test_a_shared_edge_candidate_is_dropped_as_cdn(self, monkeypatch):
        # RFC 5737 addresses count as non-routable; the SSRF guard is not under test.
        monkeypatch.setattr(od, "is_non_routable_ip", lambda ip: False)
        ctx = mock.Mock(max_candidates=25, roe_enabled=False, roe_excluded=[])
        meta: dict = {}
        flagged = od._cdn_flagged_ips(_tagged())
        kept = od._dedup_and_filter({EDGE: "shodan", PLAIN: "shodan"}, {"resolved_ips": set()},
                                    ctx, meta, flagged=flagged)
        assert kept == [(PLAIN, "shodan")]
        assert meta["dropped"]["cdn"] == 1

    def test_dedicated_and_unknown_candidates_are_kept(self):
        assert od._cdn_flagged_ips(_tagged()) == {EDGE}


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------
def _cve(ip, cve="CVE-2018-15473"):
    return {"cve_id": cve, "ip": ip, "source": "shodan_api", "port": 22}


class TestShodanWritesNoCveOnASharedEdge:
    def test_drop_shared_edge_cves(self):
        data = {"cves": [_cve(EDGE), _cve(OWN), _cve(PLAIN)], "hosts": [{"ip": EDGE}]}
        assert se.drop_shared_edge_cves(data, {EDGE}) == 1
        assert [c["ip"] for c in data["cves"]] == [OWN, PLAIN]
        assert data["hosts"] == [{"ip": EDGE}]      # only the CVEs go

    def test_nothing_to_drop(self):
        data = {"cves": [_cve(OWN)]}
        assert se.drop_shared_edge_cves(data, set()) == 0
        assert se.drop_shared_edge_cves({}, {EDGE}) == 0

    def test_the_held_back_cves_are_written_without_the_shared_edge(self):
        import recon.main as rm
        combined = _tagged(shodan={"hosts": [], "cves": [_cve(EDGE), _cve(OWN)]})
        with mock.patch.object(rm, "_graph_update_bg") as bg:
            rm._write_shodan_cves(combined)
        (method, payload, *_), = [c.args for c in bg.call_args_list]
        assert method == "update_graph_from_shodan"
        assert [c["ip"] for c in payload["shodan"]["cves"]] == [OWN]
        assert [c["ip"] for c in combined["shodan"]["cves"]] == [OWN]


# ---------------------------------------------------------------------------
# Netlas
# ---------------------------------------------------------------------------
def _row(ip, attribution=None):
    row = {"ip": ip, "port": 443, "cve_list": [{"id": "CVE-2021-44228"}]}
    if attribution:
        row["attribution"] = attribution
    return row


class TestNetlasWritesNoCveOnASharedEdge:
    def test_retag_marks_a_shared_edge_row(self):
        data = {"results": [_row(EDGE), _row(OWN), _row(EDGE, "historical")]}
        assert ne.retag_shared_edge(data, {EDGE}) == 1
        assert [r.get("attribution") for r in data["results"]] == ["shared_edge", None, "historical"]

    def test_attribute_rows_reads_a_tag_loaded_from_the_graph(self):
        rows = [_row(EDGE), _row(OWN)]
        ne._attribute_rows(rows, [EDGE, OWN], _tagged())
        assert rows[0]["attribution"] == "shared_edge"
        assert "attribution" not in rows[1]

    def test_the_held_back_netlas_write_carries_the_tag(self):
        import recon.main as rm
        combined = _tagged(netlas={"results": [_row(EDGE), _row(OWN)]})
        with mock.patch.object(rm, "_graph_update_bg") as bg:
            rm._write_netlas(combined)
        (method, payload, *_), = [c.args for c in bg.call_args_list]
        assert method == "update_graph_from_netlas"
        assert [r.get("attribution") for r in payload["netlas"]["results"]] == ["shared_edge", None]

    def test_no_netlas_data_writes_nothing(self):
        import recon.main as rm
        with mock.patch.object(rm, "_graph_update_bg") as bg:
            rm._write_netlas({"netlas": {}})
            rm._write_netlas({})
        bg.assert_not_called()


@pytest.mark.parametrize("fn_name", ["run_ip_recon", "run_domain_recon"])
def test_the_netlas_write_waits_for_the_step(fn_name):
    import recon.main as rm
    body = inspect.getsource(getattr(rm, fn_name))
    assert 'if name == "netlas":' in body
    assert body.index("_run_ip_attribution(combined_result") < body.index("_write_netlas(combined_result)")


# ---------------------------------------------------------------------------
# Partial runs read the tag from the graph
# ---------------------------------------------------------------------------
class _Session:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        return iter(self.rows)


def _fake_graph_db(rows, connected=True):
    client = mock.MagicMock()
    client.verify_connection.return_value = connected
    session = _Session(rows)
    client.driver.session.return_value = session
    cls = mock.MagicMock()
    cls.return_value.__enter__ = mock.MagicMock(return_value=client)
    cls.return_value.__exit__ = mock.MagicMock(return_value=False)
    return mock.MagicMock(Neo4jClient=cls), session


def _recon_data():
    return {"dns": {"domain": {"ips": {"ipv4": [EDGE], "ipv6": []}},
                    "subdomains": {"www.example.com": {"ips": {"ipv4": [OWN], "ipv6": []}}}},
            "port_scan": {"by_ip": {PLAIN: {"ports": [22]}}}}


class TestPartialReadsTheGraphTag:
    def test_the_tag_is_loaded_for_the_runs_ips(self):
        from recon.partial_recon_modules import graph_builders as gb
        fake, session = _fake_graph_db([{"ip": EDGE, "ownership": "shared_edge"},
                                        {"ip": OWN, "ownership": "dedicated"}])
        recon_data = _recon_data()
        with mock.patch.dict("sys.modules", {"graph_db": fake}):
            gb.attach_graph_ownership(recon_data, "u1", "p1")
        assert recon_data["ip_attribution"]["by_ip"] == {
            EDGE: {"ownership": "shared_edge"}, OWN: {"ownership": "dedicated"}}
        query, params = session.calls[0]
        assert "MATCH (i:IP {user_id: $uid, project_id: $pid})" in query
        assert sorted(params["ips"]) == sorted([EDGE, OWN, PLAIN])
        assert (params["uid"], params["pid"]) == ("u1", "p1")

    def test_a_graph_failure_loads_nothing_and_never_raises(self):
        from recon.partial_recon_modules import graph_builders as gb
        broken = mock.MagicMock()
        broken.Neo4jClient.side_effect = RuntimeError("down")
        recon_data = _recon_data()
        with mock.patch.dict("sys.modules", {"graph_db": broken}):
            gb.attach_graph_ownership(recon_data, "u1", "p1")
        assert "ip_attribution" not in recon_data

    def test_no_ip_asks_nothing(self):
        from recon.partial_recon_modules import graph_builders as gb
        fake, session = _fake_graph_db([])
        recon_data = {"dns": {}}
        with mock.patch.dict("sys.modules", {"graph_db": fake}):
            gb.attach_graph_ownership(recon_data, "u1", "p1")
        assert session.calls == []
        assert "ip_attribution" not in recon_data

    @pytest.mark.parametrize("module, fn", [
        ("recon.partial_recon_modules.osint_enrichment", "_root_recon_data"),
        ("recon.partial_recon_modules.vulnerability_scanning", "run_vhost_sni_partial"),
        ("recon.partial_recon_modules.origin_enrichment", "run_origin_discovery"),
    ])
    def test_the_partial_entry_points_load_it(self, module, fn):
        import importlib
        body = inspect.getsource(getattr(importlib.import_module(module), fn))
        assert "attach_graph_ownership(" in body

    def test_partial_shodan_drops_the_shared_edge_cves(self):
        from recon.partial_recon_modules import osint_enrichment as oe
        body = inspect.getsource(oe.run_shodan)
        assert body.index("run_shodan_enrichment(combined_result") < body.index("drop_shared_edge_cves(")
