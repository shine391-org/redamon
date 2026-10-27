"""One CDN list: recon/helpers/cdn_ranges.py answers "is this a CDN edge?" for
every module.

Origin discovery kept its own CIDR and header lists (Fastly as one /16, two
Akamai blocks, part of CloudFront), ip_filter knew Cloudflare only, and
cdn_ranges knew Cloudflare's ASN only. Now cdn_ranges holds the static edge
prefixes, the edge ASNs and the response-header signatures, and origin
discovery, ip_filter and vhost/SNI import them.

Sample addresses are inside the providers' own published edge prefixes (the
lists in recon/helpers/cdn_edge_prefixes.py), which are CDN infrastructure,
not target data.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import cdn_ranges as cr
from recon.main_recon_modules import ip_filter
from recon.main_recon_modules import origin_discovery as od
from recon.main_recon_modules import vhost_sni_enum as vsm


@pytest.fixture(autouse=True)
def _no_fetch(monkeypatch):
    """The static list must answer without the Cloudflare live fetch."""
    def _boom(*_a, **_k):
        raise AssertionError("edge lookup made a network request")
    monkeypatch.setattr(cr, "_fetch_prefix_list", _boom)
    monkeypatch.setattr(cr, "_cloudflare_networks_cache", None)


# ---------------------------------------------------------------------------
# Static edge prefixes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ip, cdn", [
    ("151.101.1.1", "fastly"),
    ("199.232.10.10", "fastly"),
    ("2a04:4e42::10", "fastly"),
    ("13.32.0.1", "cloudfront"),
    ("54.230.0.1", "cloudfront"),
    ("2600:9000:1000::1", "cloudfront"),
    ("13.107.246.10", "azurefrontdoor"),
    ("45.60.1.1", "imperva"),
    ("2a02:e980::1", "imperva"),
    ("192.88.134.1", "sucuri"),
    ("104.16.0.1", "cloudflare"),
    ("2606:4700::1", "cloudflare"),
])
def test_an_address_in_a_published_edge_prefix_names_its_cdn(ip, cdn):
    assert cr.edge_cdn_for_ip(ip) == cdn


@pytest.mark.parametrize("ip", [
    "8.8.8.8",          # a resolver, no CDN
    "104.64.0.1",       # Akamai compute (AKAMAI-COMPUTE), a customer's server
    "52.95.110.1",      # generic Amazon range: EC2 / ALB origins live here
    "not-an-ip", "", None,
])
def test_anything_else_is_not_an_edge(ip):
    assert cr.edge_cdn_for_ip(ip) is None


def test_every_shipped_prefix_parses():
    import ipaddress
    from recon.helpers.cdn_edge_prefixes import EDGE_PREFIXES
    for cdn, prefixes in EDGE_PREFIXES.items():
        assert prefixes, cdn
        for p in prefixes:
            ipaddress.ip_network(p)
        assert cr.is_reliable_edge_cdn_name(cdn), cdn


def test_the_prefix_collector_covers_every_cdn(monkeypatch):
    # It still asks is_cloudflare_ip, which may fetch Cloudflare's live list;
    # a failed fetch falls back to the shipped copy.
    monkeypatch.setattr(cr, "_fetch_prefix_list", lambda *_a, **_k: [])
    assert cr.collect_prefix_cdn_ips(["151.101.1.1", "8.8.8.8", "104.16.0.5"]) == {
        "151.101.1.1", "104.16.0.5"}


# ---------------------------------------------------------------------------
# Edge ASNs
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("asn, cdn", [
    (13335, "cloudflare"), ("AS54113 Fastly", "fastly"), (20940, "akamai"),
    (16625, "akamai"), (19551, "imperva"), (30148, "sucuri"),
])
def test_edge_asns(asn, cdn):
    assert cr.cdn_name_from_asn(asn) == cdn


@pytest.mark.parametrize("asn", [
    16509,   # Amazon: EC2 / ALB origins
    8075,    # Microsoft: Azure VMs
    15169,   # Google
    396982,  # Google Cloud
    63949,   # Akamai's Linode compute
])
def test_cloud_asns_that_host_origins_are_not_edges(asn):
    assert cr.cdn_name_from_asn(asn) is None


# ---------------------------------------------------------------------------
# Response-header signatures
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("headers, cdn", [
    ({"X-Served-By": "cache-fra-etou8220036-FRA"}, "fastly"),
    ({"x-cache": "Hit from cloudfront"}, "cloudfront"),
    ({"Via": "1.1 3b1c4f.cloudfront.net (CloudFront)"}, "cloudfront"),
    ({"via": "1.1 varnish"}, "fastly"),
    ({"via": "1.1 google"}, "google"),
    ({"x-amz-cf-id": "Hd8kQxYz=="}, "cloudfront"),
    ({"X-Akamai-Request-ID": "1a2b3c"}, "akamai"),
    ({"x-akamai-transformed": "9 - 0 pmb=mRUM,1"}, "akamai"),
    ({"cf-ray": "8c1f2e3d4a5b6c00-FRA"}, "cloudflare"),
    ({"server": "AkamaiGHost"}, "akamai"),
])
def test_a_header_signature_names_the_edge(headers, cdn):
    assert cr.edge_from_headers(headers) == cdn


@pytest.mark.parametrize("headers", [
    {"x-served-by": "web-01"},            # an app's own server name
    {"x-cache": "HIT"},                   # nginx/Squid on an origin
    {"via": "1.1 proxy.internal"},
    {"server": "nginx"},
    {},
    None,
])
def test_ordinary_origin_headers_are_not_an_edge(headers):
    assert cr.edge_from_headers(headers) is None


# ---------------------------------------------------------------------------
# The modules read the one list
# ---------------------------------------------------------------------------
def test_origin_discovery_keeps_no_list_of_its_own():
    for name in ("_WAF_CDN_CIDRS", "_WAF_HEADER_SIGNATURES", "_WAF_SERVER_TOKENS", "_PARSED_CDN_NETS"):
        assert not hasattr(od, name), name


def test_origin_discovery_sees_every_edge_range():
    assert od._ip_in_cdn_ranges("151.101.1.1")     # Fastly beyond the old single /16 too
    assert od._ip_in_cdn_ranges("199.232.10.10")
    assert od._ip_in_cdn_ranges("13.107.246.10")   # Azure Front Door
    assert not od._ip_in_cdn_ranges("104.64.0.1")  # Akamai compute can be an origin


def test_origin_discovery_rejects_a_candidate_answering_through_an_edge():
    assert od._response_has_waf_headers({"headers": {"x-served-by": "cache-fra-etou8220036-FRA"}})
    assert od._response_has_waf_headers({"headers": {"x-akamai-request-id": "1"}})
    assert not od._response_has_waf_headers({"headers": {"server": "nginx", "x-cache": "HIT"}})


def test_ip_filter_skips_every_published_edge():
    assert ip_filter.in_published_cdn_range("151.101.1.1")
    assert ip_filter.in_published_cdn_range("104.16.0.1")
    assert not ip_filter.in_published_cdn_range("8.8.8.8")


def test_vhost_counts_an_unflagged_address_in_an_edge_prefix_as_an_edge():
    assert vsm._shared_edge_ips({}, ["151.101.1.1", "8.8.8.8"]) == {"151.101.1.1"}


# ---------------------------------------------------------------------------
# Origin discovery: an IP a scanner flagged as an edge is never an origin
# ---------------------------------------------------------------------------
def _ctx():
    return od._RunCtx({"ORIGIN_DISCOVERY_ENABLED": True, "ROE_ENABLED": False,
                       "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25})


def test_a_candidate_flagged_as_an_edge_is_dropped():
    combined = {"port_scan": {"by_ip": {
        "9.9.9.9": {"is_cdn": True, "cdn": "cloudflare", "cdn_source": "tls_certificate"},
        "149.112.112.112": {"is_cdn": True, "cdn": "aws"},
    }}, "http_probe": {"by_url": {
        "https://a.example.com": {"ip": "8.8.4.4", "is_cdn": True, "cdn": "fastly"},
    }}}
    flagged = od._cdn_flagged_ips(combined)
    assert flagged == {"9.9.9.9", "8.8.4.4"}
    meta = {}
    kept = od._dedup_and_filter({"9.9.9.9": "dns", "8.8.4.4": "otx", "149.112.112.112": "crtsh"},
                                {"resolved_ips": set()}, _ctx(), meta, flagged=flagged)
    # Plain cloud hosting is where real origins live: it stays a candidate.
    assert kept == [("149.112.112.112", "crtsh")]
    assert meta["dropped"]["cdn"] == 2


def test_the_flagged_set_reaches_the_filter_in_a_run():
    combined = {"http_probe": {"by_url": {"https://www.example.com": {
        "host": "www.example.com", "ip": "104.16.1.1", "is_cdn": True, "cdn": "cloudflare"}}},
        "port_scan": {"by_ip": {"9.9.9.9": {"is_cdn": True, "cdn": "cloudflare"}}}}
    settings = {"ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_SCANNERS": False,
                "ORIGIN_DISCOVERY_PASSIVE_DNS": False, "ROE_ENABLED": False}
    with patch.object(od, "_resolve_ips", return_value=set()), \
         patch.object(od, "_favicon_hash_for_host", return_value=None), \
         patch.object(od, "_discover_via_subdomains", return_value=["9.9.9.9"]), \
         patch.object(od, "_discover_via_email_records", return_value=[]), \
         patch.object(od, "_discover_via_crtsh", return_value=[]), \
         patch.object(od, "_fetch") as fetch:
        out = od.run_origin_discovery_enrichment_isolated(combined, settings)
    assert out["candidates_meta"]["www.example.com"]["dropped"]["cdn"] == 1
    fetch.assert_not_called()
