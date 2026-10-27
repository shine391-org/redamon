"""IP attribution: every IP of a run is shared_edge, dedicated or unknown (plan 11.3).

Each scanner used to guess on its own whether an IP was the target's. The step
labels every IP once from the signals the run already holds (naabu, tlsx and
httpx CDN flags, httpx's ASN and headers, this run's DNS block) plus one TLS
handshake WITHOUT SNI to :443. That handshake is traffic to the target, so it
skips RoE-excluded and never-scannable addresses and hosts marked down, is
capped per run, is off in stealth mode, and a failed one is never evidence.
The tag is never "not ours".

No traffic and no Neo4j: the handshake is a stub. Addresses are RFC 5737 except
the Cloudflare edge, which sits in Cloudflare's own published prefix
(infrastructure, not target data).
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import cdn_ranges as cr
from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import ip_attribution as ia

OWN = "198.51.100.10"        # 443 open, default certificate *.example.com
OTHER = "198.51.100.11"      # 443 open, someone else's default certificate
NO_TLS = "198.51.100.12"     # no 443
EDGE = "104.16.0.1"          # Cloudflare's published edge range, 443 open
TAGS = {ia.SHARED_EDGE, ia.DEDICATED, ia.UNKNOWN}

CERTS = {
    OWN: {"serial": "1", "cn": "www.example.com", "sans": {"www.example.com", "*.example.com"}},
    OTHER: {"serial": "2", "cn": "shared.hosting.example.net", "sans": {"shared.hosting.example.net"}},
    EDGE: {"serial": "3", "cn": "sni.cloudflaressl.com", "sans": set()},
}


class _Handshake:
    """Stands in for peer_cert.tls_handshake_cert and records every dial."""

    def __init__(self, certs=CERTS, fail=None):
        self.certs = certs
        self.fail = fail or {}
        self.calls = []

    def __call__(self, host, sni, port, timeout):
        self.calls.append((host, sni, port))
        if host in self.fail:
            raise self.fail[host]
        return self.certs.get(host)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("cdn_ranges made a network request")
    monkeypatch.setattr(cr, "_fetch_prefix_list", _boom)
    monkeypatch.setattr(cr, "_cloudflare_networks_cache", None)
    monkeypatch.setattr(cb.host_health, "allow", lambda target: True)
    monkeypatch.setattr(cb.host_health, "record_alive", lambda target: None)
    monkeypatch.setattr(cb.host_health, "record_failure", lambda target, exc: True)
    monkeypatch.setattr(ia, "_TLS_RPS", 0.0)
    hs = _Handshake()
    monkeypatch.setattr(ia, "tls_handshake_cert", hs)
    return hs


def _dns(**names):
    return {name.replace("_", "."): {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}
            for name, ips in names.items()}


def _combined(**over):
    out = {
        "domain": "example.com",
        "metadata": {"root_domain": "example.com", "ip_mode": False},
        "dns": {
            "domain": {"has_records": True, "ips": {"ipv4": [OWN], "ipv6": []}},
            "subdomains": _dns(www_example_com=[OWN], api_example_com=[OWN, OTHER],
                               cdn_example_com=[EDGE], old_example_com=[NO_TLS]),
        },
        "port_scan": {"by_ip": {
            OWN: {"ports": [80, 443]}, OTHER: {"ports": [443]},
            NO_TLS: {"ports": [22]}, EDGE: {"ports": [80, 443]},
        }},
    }
    out.update(over)
    return out


def _run(combined=None, **settings):
    combined = combined if combined is not None else _combined()
    ia.run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": True,
                                     "IP_ATTRIBUTION_TLS_MAX_PROBES": 500, **settings})
    return combined["ip_attribution"]["by_ip"]


# ---------------------------------------------------------------------------
# The rule: one pure function
# ---------------------------------------------------------------------------
RANGE = [cr.EDGE_REASON_RANGE]
ASN = [cr.EDGE_REASON_ASN]


@pytest.mark.parametrize("edge, cert, detail, tag", [
    (RANGE, ia.CERT_FOREIGN, "", ia.SHARED_EDGE),
    (RANGE, ia.CERT_NOT_CHECKED, "stealth mode", ia.SHARED_EDGE),
    # An edge prefix wins over the certificate: the order of the rules.
    (RANGE, ia.CERT_TARGET, "example.com", ia.SHARED_EDGE),
    (ASN, ia.CERT_FOREIGN, "", ia.SHARED_EDGE),
    (ASN, ia.CERT_NOT_CHECKED, "timeout", ia.SHARED_EDGE),
    # An edge ASN serving the target's own default certificate is its dedicated edge.
    (ASN, ia.CERT_TARGET, "example.com", ia.DEDICATED),
    (ASN + [cr.EDGE_REASON_HEADERS], ia.CERT_TARGET, "example.com", ia.SHARED_EDGE),
    ([], ia.CERT_TARGET, "example.com", ia.DEDICATED),
    ([], ia.CERT_FOREIGN, "", ia.UNKNOWN),
    ([], ia.CERT_NOT_CHECKED, "port 443 not found open", ia.UNKNOWN),
])
def test_the_tag_rule(edge, cert, detail, tag):
    got, reasons = ia.ownership_tag(edge, cert, detail)
    assert got == tag
    assert reasons == sorted(reasons)
    assert set(edge) <= set(reasons)
    assert ia.cert_reason(cert, detail) in reasons


def test_the_tag_is_never_anything_but_the_three_values():
    for edge in ([], RANGE, ASN, RANGE + ASN):
        for cert in (ia.CERT_TARGET, ia.CERT_FOREIGN, ia.CERT_NOT_CHECKED):
            assert ia.ownership_tag(edge, cert, "x")[0] in TAGS


def test_no_edge_signal_is_said_in_words():
    _tag, reasons = ia.ownership_tag([], ia.CERT_FOREIGN)
    assert ia.NO_EDGE_SIGNAL in reasons


@pytest.mark.parametrize("cert, detail, text", [
    (ia.CERT_TARGET, "example.com", "default certificate covers example.com"),
    (ia.CERT_FOREIGN, "", "default certificate covers no target domain"),
    (ia.CERT_NOT_CHECKED, "stealth mode", "default certificate not checked (stealth mode)"),
])
def test_the_certificate_reason(cert, detail, text):
    assert ia.cert_reason(cert, detail) == text


# ---------------------------------------------------------------------------
# The step
# ---------------------------------------------------------------------------
def test_every_ip_of_the_run_is_tagged(_offline):
    by_ip = _run()
    assert by_ip[OWN]["ownership"] == ia.DEDICATED
    assert by_ip[OTHER]["ownership"] == ia.UNKNOWN
    assert by_ip[NO_TLS]["ownership"] == ia.UNKNOWN
    assert by_ip[EDGE]["ownership"] == ia.SHARED_EDGE
    assert by_ip[EDGE]["cdn_name"] == "cloudflare"
    assert "cdn_name" not in by_ip[OWN]


def test_the_handshake_sends_no_sni_and_only_where_443_is_open(_offline):
    _run()
    assert sorted(_offline.calls) == sorted((ip, None, 443) for ip in (OWN, OTHER, EDGE))


def test_reasons_and_certificate_names_are_sorted_and_stable(_offline):
    by_ip = _run()
    assert by_ip[OWN]["default_cert_names"] == ["*.example.com", "www.example.com"]
    assert by_ip[OWN]["ownership_reasons"] == sorted(
        ["default certificate covers example.com", ia.NO_EDGE_SIGNAL])
    assert by_ip[EDGE]["ownership_reasons"] == sorted(
        [cr.EDGE_REASON_RANGE, "default certificate covers no target domain"])
    assert by_ip[NO_TLS]["ownership_reasons"] == sorted(
        [ia.NO_EDGE_SIGNAL, "default certificate not checked (port 443 not found open)"])
    assert "default_cert_names" not in by_ip[NO_TLS]


def test_current_dns_names_counts_this_runs_names(_offline):
    by_ip = _run()
    # example.com, www and api point at OWN; api at OTHER.
    assert by_ip[OWN]["current_dns_names"] == 3
    assert by_ip[OTHER]["current_dns_names"] == 1
    assert by_ip[EDGE]["current_dns_names"] == 1


def test_an_ip_no_name_points_at_has_zero_dns_names(_offline):
    combined = _combined()
    combined["port_scan"]["by_ip"]["198.51.100.40"] = {"ports": [8080]}
    assert _run(combined)["198.51.100.40"]["current_dns_names"] == 0


def test_scanner_flags_and_headers_are_edge_signals(_offline):
    combined = _combined()
    combined["port_scan"]["by_ip"][OTHER].update({"is_cdn": True, "cdn": "fastly"})
    combined["http_probe"] = {"by_url": {
        "https://old.example.com": {"ip": NO_TLS, "headers": {"cf_ray": "1-FRA"}},
    }}
    by_ip = _run(combined)
    assert by_ip[OTHER]["ownership"] == ia.SHARED_EDGE
    assert by_ip[OTHER]["cdn_name"] == "fastly"
    assert cr.EDGE_REASON_SCANNER in by_ip[OTHER]["ownership_reasons"]
    assert by_ip[NO_TLS]["ownership"] == ia.SHARED_EDGE
    assert cr.EDGE_REASON_HEADERS in by_ip[NO_TLS]["ownership_reasons"]


def test_a_cloud_label_is_not_an_edge(_offline):
    combined = _combined()
    combined["port_scan"]["by_ip"][OTHER].update({"is_cdn": True, "cdn": "aws"})
    assert _run(combined)[OTHER]["ownership"] == ia.UNKNOWN


def test_an_edge_asn_with_the_targets_certificate_is_dedicated(_offline):
    combined = _combined()
    combined["http_probe"] = {"by_url": {
        "https://www.example.com": {"ip": OWN, "asn": {"as_number": "AS13335"}}}}
    by_ip = _run(combined)
    assert by_ip[OWN]["ownership"] == ia.DEDICATED
    assert cr.EDGE_REASON_ASN in by_ip[OWN]["ownership_reasons"]


def test_an_edge_asn_with_someone_elses_certificate_is_a_shared_edge(_offline):
    combined = _combined()
    combined["http_probe"] = {"by_url": {
        "https://api.example.com": {"ip": OTHER, "asn": "AS13335"}}}
    assert _run(combined)[OTHER]["ownership"] == ia.SHARED_EDGE


def test_a_url_on_443_counts_as_open_without_a_port_scan(_offline):
    combined = _combined()
    del combined["port_scan"]
    combined["http_probe"] = {"by_url": {"https://www.example.com": {"ip": OWN}}}
    by_ip = _run(combined)
    assert _offline.calls == [(OWN, None, 443)]
    assert by_ip[OWN]["ownership"] == ia.DEDICATED


# ---------------------------------------------------------------------------
# Engagement limits on the handshake
# ---------------------------------------------------------------------------
def test_an_roe_excluded_ip_gets_no_handshake(_offline):
    by_ip = _run(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[OWN])
    assert OWN not in [c[0] for c in _offline.calls]
    assert "default certificate not checked (excluded by the rules of engagement)" in \
        by_ip[OWN]["ownership_reasons"]
    assert by_ip[OWN]["ownership"] == ia.UNKNOWN


def test_stealth_mode_makes_no_handshake(_offline):
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides
    settings = apply_stealth_overrides({**DEFAULT_SETTINGS, "STEALTH_MODE": True})
    assert settings["IP_ATTRIBUTION_ENABLED"] is True
    assert settings["IP_ATTRIBUTION_TLS_MAX_PROBES"] == 0
    combined = _combined()
    ia.run_ip_attribution(combined, settings)
    by_ip = combined["ip_attribution"]["by_ip"]
    assert _offline.calls == []
    for ip in (OWN, OTHER, EDGE):
        assert "default certificate not checked (stealth mode)" in by_ip[ip]["ownership_reasons"]
    # The other signals still tag: the edge prefix needs no traffic.
    assert by_ip[EDGE]["ownership"] == ia.SHARED_EDGE
    assert combined["ip_attribution"]["summary"]["tls_handshakes"] == 0


def test_stealth_is_the_reason_even_where_443_was_not_found(_offline):
    # Stealth's port scan is passive: "443 not found open" would claim a look it
    # never took. Found on the FP lab's stealth run (plan 11.E).
    by_ip = _run(STEALTH_MODE=True, IP_ATTRIBUTION_TLS_MAX_PROBES=0)
    assert "default certificate not checked (stealth mode)" in by_ip[NO_TLS]["ownership_reasons"]
    assert not any("port 443" in r for r in by_ip[NO_TLS]["ownership_reasons"])


def test_a_zero_cap_turns_the_probe_off(_offline):
    by_ip = _run(IP_ATTRIBUTION_TLS_MAX_PROBES=0)
    assert _offline.calls == []
    assert "default certificate not checked (the TLS probe is off)" in by_ip[OWN]["ownership_reasons"]


def test_the_cap_bounds_the_handshakes_per_run(_offline):
    by_ip = _run(IP_ATTRIBUTION_TLS_MAX_PROBES=1)
    assert len(_offline.calls) == 1
    capped = [ip for ip in (OWN, OTHER, EDGE)
              if "default certificate not checked (probe cap reached)" in by_ip[ip]["ownership_reasons"]]
    assert len(capped) == 2


def test_a_loopback_or_metadata_address_is_never_dialled(_offline):
    combined = _combined()
    combined["port_scan"]["by_ip"]["127.0.0.1"] = {"ports": [443]}
    combined["port_scan"]["by_ip"]["169.254.169.254"] = {"ports": [443]}
    by_ip = _run(combined)
    dialled = {c[0] for c in _offline.calls}
    assert not dialled & {"127.0.0.1", "169.254.169.254"}
    assert "default certificate not checked (address never scanned)" in \
        by_ip["127.0.0.1"]["ownership_reasons"]


def test_a_private_address_in_an_internal_estate_is_dialled(_offline):
    combined = _combined()
    combined["port_scan"]["by_ip"]["10.0.0.5"] = {"ports": [443]}
    _run(combined)
    assert ("10.0.0.5", None, 443) in _offline.calls


def test_a_host_marked_down_is_skipped(_offline, monkeypatch):
    monkeypatch.setattr(cb.host_health, "allow", lambda target: OWN not in target)
    by_ip = _run()
    assert OWN not in [c[0] for c in _offline.calls]
    assert "default certificate not checked (host marked unreachable)" in by_ip[OWN]["ownership_reasons"]


def test_the_pace_never_exceeds_the_engagement_ceiling(monkeypatch):
    monkeypatch.setattr(ia, "_TLS_RPS", 10.0)
    assert ia.pace_rps({}) == 10.0
    assert ia.pace_rps({"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 3}) == 10.0
    assert ia.pace_rps({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 3}) == 3.0
    assert ia.pace_rps({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 50}) == 10.0
    assert ia.pace_rps({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0}) == 10.0


# ---------------------------------------------------------------------------
# A failed check is never evidence, and the step never raises
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("exc, why", [
    (socket.timeout("t"), "timeout"),
    (ConnectionRefusedError(), "port 443 closed"),
    (OSError("unreachable"), "connection failed"),
])
def test_a_failed_handshake_falls_back_to_the_other_signals(monkeypatch, exc, why):
    hs = _Handshake(fail={OWN: exc, EDGE: exc})
    monkeypatch.setattr(ia, "tls_handshake_cert", hs)
    by_ip = _run()
    assert by_ip[OWN]["ownership"] == ia.UNKNOWN
    assert f"default certificate not checked ({why})" in by_ip[OWN]["ownership_reasons"]
    assert by_ip[EDGE]["ownership"] == ia.SHARED_EDGE


def test_no_certificate_presented_is_not_checked(monkeypatch):
    monkeypatch.setattr(ia, "tls_handshake_cert", _Handshake(certs={}))
    by_ip = _run()
    assert "default certificate not checked (no certificate presented)" in by_ip[OWN]["ownership_reasons"]


def test_a_crash_tags_unknown_with_the_reason_and_never_raises(monkeypatch):
    def _boom(*_a, **_k):
        raise RuntimeError("bad data")
    monkeypatch.setattr(ia, "classify_ip", _boom)
    by_ip = _run()
    assert set(by_ip) == {OWN, OTHER, NO_TLS, EDGE}
    for entry in by_ip.values():
        assert entry["ownership"] == ia.UNKNOWN
        assert entry["ownership_reasons"] == [ia.ATTRIBUTION_FAILED]


def test_unreadable_recon_data_leaves_an_empty_payload():
    combined = {"dns": "not a dict", "port_scan": ["nope"]}
    ia.run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": True})
    assert combined["ip_attribution"]["by_ip"] == {}


def test_disabled_writes_no_payload(_offline):
    combined = _combined()
    ia.run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": False})
    assert "ip_attribution" not in combined
    assert _offline.calls == []


# ---------------------------------------------------------------------------
# IP mode, readers and the isolated wrapper
# ---------------------------------------------------------------------------
def _ip_mode():
    return {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "root_domain": "ip-targets.p1", "expanded_ips": [OWN, OTHER]},
        "dns": {"domain": {}, "subdomains": {
            "198-51-100-10": {"is_mock": True, "has_records": True, "ips": {"ipv4": [OWN], "ipv6": []}},
            "host.example.org": {"has_records": True, "ips": {"ipv4": [OTHER], "ipv6": []}},
        }},
        "port_scan": {"by_ip": {OWN: {"ports": [443]}, OTHER: {"ports": [22]}}},
    }


def test_ip_mode_has_no_target_domain_so_never_dedicated(_offline):
    by_ip = _run(_ip_mode())
    assert by_ip[OWN]["ownership"] == ia.UNKNOWN
    assert "default certificate covers no target domain" in by_ip[OWN]["ownership_reasons"]
    assert by_ip[OWN]["default_cert_names"] == ["*.example.com", "www.example.com"]


def test_a_mock_name_is_not_a_dns_name(_offline):
    by_ip = _run(_ip_mode())
    assert by_ip[OWN]["current_dns_names"] == 0
    assert by_ip[OTHER]["current_dns_names"] == 1


def test_the_targets_registrable_domain_is_matched(_offline):
    combined = _combined(domain="shop.example.com")
    combined["all_project_roots"] = ["shop.example.com"]
    assert _run(combined)[OWN]["ownership"] == ia.DEDICATED


def test_shared_edge_ips_reads_the_payload(_offline):
    combined = _combined()
    _run(combined)
    assert ia.shared_edge_ips(combined) == {EDGE}
    assert ia.shared_edge_ips({}) == set()
    assert ia.shared_edge_ips({"ip_attribution": {"by_ip": {"x": "junk"}}}) == set()


def test_the_isolated_wrapper_returns_the_payload_and_leaves_the_input(_offline):
    combined = _combined()
    payload = ia.run_ip_attribution_isolated(combined, {"IP_ATTRIBUTION_ENABLED": True})
    assert "ip_attribution" not in combined
    assert payload["by_ip"][EDGE]["ownership"] == ia.SHARED_EDGE
    assert payload["summary"] == {"ips": 4, "shared_edge": 1, "dedicated": 1, "unknown": 2,
                                  "tls_handshakes": 3}
