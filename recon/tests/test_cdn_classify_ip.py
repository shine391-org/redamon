"""classify_ip: one answer to "is this IP a shared CDN edge?" (plan 11.1).

The IP attribution step labels every IP of a run from it, so its four signals
are pinned here per provider: a published edge prefix, a CDN name a scanner
reported, a response header an edge sets, and an edge-only ASN. A generic cloud
provider is never an edge: real origins run there.

Sample addresses are inside the providers' own published edge prefixes (the
lists in recon/helpers/cdn_edge_prefixes.py), which are CDN infrastructure, not
target data; the "none" rows use RFC 5737 documentation addresses.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import cdn_ranges as cr

PLAIN = "192.0.2.10"


@pytest.fixture(autouse=True)
def _no_fetch(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("classify_ip made a network request")
    monkeypatch.setattr(cr, "_fetch_prefix_list", _boom)
    monkeypatch.setattr(cr, "_cloudflare_networks_cache", None)


@pytest.mark.parametrize("ip, provider", [
    ("104.16.0.1", "cloudflare"),
    ("151.101.1.1", "fastly"),
    ("13.32.0.1", "cloudfront"),
    ("45.60.1.1", "imperva"),
    ("192.88.134.1", "sucuri"),
    ("13.107.246.10", "azurefrontdoor"),
])
def test_in_a_published_range(ip, provider):
    assert cr.classify_ip(ip) == (True, provider, [cr.EDGE_REASON_RANGE])


@pytest.mark.parametrize("asn, provider", [
    ("AS13335", "cloudflare"),
    ("13335", "cloudflare"),
    (54113, "fastly"),
    ("AS20940 Akamai International B.V.", "akamai"),
    ("AS19551", "imperva"),
    ("AS30148", "sucuri"),
    # httpx -asn reports an object, not a string.
    ({"as_number": "AS16625", "as_name": "AKAMAI-AS"}, "akamai"),
])
def test_an_edge_only_asn(asn, provider):
    assert cr.classify_ip(PLAIN, asn=asn) == (True, provider, [cr.EDGE_REASON_ASN])


@pytest.mark.parametrize("headers, provider", [
    ({"CF-Ray": "8a1b2c3d4e5f-FRA"}, "cloudflare"),
    # httpx stores header names with underscores.
    ({"cf_ray": "8a1b2c3d4e5f-FRA"}, "cloudflare"),
    ({"x_amz_cf_id": "abc"}, "cloudfront"),
    ({"X-Served-By": "cache-fra-etou8220036-FRA"}, "fastly"),
    ({"Server": "AkamaiGHost"}, "akamai"),
    ({"X-Iinfo": "1-2-3"}, "imperva"),
    ({"X-Sucuri-ID": "11005"}, "sucuri"),
])
def test_edge_response_headers(headers, provider):
    assert cr.classify_ip(PLAIN, headers=headers) == (True, provider, [cr.EDGE_REASON_HEADERS])


@pytest.mark.parametrize("cdn_name, provider", [
    ("cloudflare", "cloudflare"),
    ("Fastly", "fastly"),
    ("akamai", "akamai"),
    ("incapsula", "incapsula"),
])
def test_a_scanner_named_an_edge_cdn(cdn_name, provider):
    assert cr.classify_ip(PLAIN, cdn_name=cdn_name) == (True, provider, [cr.EDGE_REASON_SCANNER])


@pytest.mark.parametrize("kwargs", [
    {},
    {"asn": "AS16509"},                       # Amazon: EC2 and ALB origins live here
    {"asn": "AS15169"},                       # Google
    {"asn": None, "headers": None, "cdn_name": None},
    {"headers": {"server": "nginx", "x_cache": "HIT"}},
    {"headers": {"x-varnish": "123"}},        # an origin's own Varnish
    {"headers": {"x-wa-info": "1"}},          # an on-premises F5 WAF
    {"cdn_name": "aws"},
    {"cdn_name": "google"},
    {"cdn_name": "azure"},
])
def test_none_of_the_signals(kwargs):
    assert cr.classify_ip(PLAIN, **kwargs) == (False, None, [])


def test_every_signal_that_fired_is_a_reason_and_the_range_names_the_provider():
    is_edge, provider, reasons = cr.classify_ip(
        "104.16.0.1", asn="AS54113", headers={"x-served-by": "cache-x"}, cdn_name="akamai")
    assert is_edge is True
    assert provider == "cloudflare"
    assert reasons == [cr.EDGE_REASON_RANGE, cr.EDGE_REASON_SCANNER,
                       cr.EDGE_REASON_HEADERS, cr.EDGE_REASON_ASN]


@pytest.mark.parametrize("ip", ["", None, "not-an-ip", "999.1.1.1"])
def test_a_value_that_is_not_an_address_is_never_an_edge_by_range(ip):
    assert cr.classify_ip(ip) == (False, None, [])


def test_unreadable_headers_name_nothing():
    class _Broken:
        def items(self):
            raise RuntimeError("no")
    assert cr.classify_ip(PLAIN, headers=_Broken()) == (False, None, [])
