"""Partial port data rebuilt from the graph keeps each IP's CDN tag.

Partial tlsx (and partial httpx / nmap) rebuild port_scan from the graph and
later write it back through update_graph_from_port_scan, which sets
IP.is_cdn from by_ip / by_host. The rebuilt entries carried no CDN fields, so
that write reset is_cdn to false on every IP naabu or tlsx had tagged, and tlsx
re-attributed a tagged IP as if it were its own finding.

The fake session answers the builder's two row queries; fixture addresses are
RFC 5737 documentation IPs.
"""

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import graph_builders as gb  # noqa: E402
from recon.main_recon_modules import tls_scan  # noqa: E402

TAGGED_IP = "192.0.2.20"
PLAIN_IP = "192.0.2.21"
ROWS = [
    # (subdomain, ip, is_cdn, cdn_name)
    ("www.example.com", TAGGED_IP, True, "fastly"),
    ("mail.example.com", PLAIN_IP, None, None),
]


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self.calls.append(cypher)
        rows = _Result()
        if "HAS_SUBDOMAIN" in cypher:
            for sub, ip, is_cdn, cdn in ROWS:
                rows.append({"root": "example.com", "subdomain": sub, "ip": ip, "version": "ipv4",
                             "ports": [{"number": 993, "protocol": "tcp"}],
                             "is_cdn": is_cdn, "cdn_name": cdn})
        return rows


class _Client:
    calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda: _Session(_Client.calls)
        return driver


@pytest.fixture
def built(monkeypatch):
    _Client.calls = []
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    return gb._build_port_scan_data_from_graph(["example.com"], "u1", "p1")


def test_the_query_reads_the_ips_cdn_tag(built):
    sub_query = next(c for c in _Client.calls if "HAS_SUBDOMAIN" in c)
    assert "i.is_cdn AS is_cdn" in sub_query and "i.cdn_name AS cdn_name" in sub_query


def test_a_tagged_ip_keeps_its_tag_in_by_ip_and_by_host(built):
    ps = built["port_scan"]
    assert ps["by_ip"][TAGGED_IP]["is_cdn"] is True
    assert ps["by_ip"][TAGGED_IP]["cdn"] == "fastly"
    assert ps["by_host"]["www.example.com"]["is_cdn"] is True
    assert ps["by_host"]["www.example.com"]["cdn"] == "fastly"


def test_an_untagged_ip_stays_untagged(built):
    ps = built["port_scan"]
    assert ps["by_ip"][PLAIN_IP]["is_cdn"] is False
    assert ps["by_ip"][PLAIN_IP]["cdn"] is None


def test_tlsx_does_not_claim_a_tag_the_graph_already_holds(built):
    by_target = {
        f"{TAGGED_IP}:993": {"scanned_ip": TAGGED_IP, "probe_status": True,
                             "issuer_dn": "CN=Cloudflare Inc ECC CA-3"},
    }
    tls_scan._attribute_cdn(built, by_target)
    assert built["port_scan"]["by_ip"][TAGGED_IP]["cdn"] == "fastly"
    assert tls_scan._cdn_attributions(built) == {}


def test_rows_without_cdn_fields_still_build(monkeypatch):
    # A graph written before the fields existed returns no such keys.
    class _Bare(_Session):
        def run(self, cypher, **params):
            rows = _Result()
            if "HAS_SUBDOMAIN" in cypher:
                rows.append({"root": "example.com", "subdomain": "www.example.com", "ip": PLAIN_IP,
                             "version": "ipv4", "ports": [{"number": 993, "protocol": "tcp"}]})
            return rows

    class _BareClient(_Client):
        @property
        def driver(self):
            driver = mock.MagicMock()
            driver.session.side_effect = lambda: _Bare([])
            return driver

    monkeypatch.setattr("graph_db.Neo4jClient", _BareClient)
    data = gb._build_port_scan_data_from_graph(["example.com"], "u1", "p1")
    assert data["port_scan"]["by_ip"][PLAIN_IP]["is_cdn"] is False
