"""False-positive regressions for origin discovery (CDN bypass).

A field report muted origin findings where the host was not behind a CDN at
all (its public A records were plain cloud hosting, which httpx also flags
as is_cdn), and where the public host and the "origin" answered with the
same deny wall: identical 403 pages scored as a near-perfect HTML match. A
real bypass, the origin serving the application the edge refuses or serves,
must still be reported.

Candidate IPs are public resolver addresses: documentation ranges
(203.0.113.0/24, ...) are dropped by the SSRF filter before any other rule.
"""

from __future__ import annotations

import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

import pytest

from recon.main_recon_modules import origin_discovery as od


@pytest.fixture(autouse=True)
def _no_live_tls(monkeypatch):
    """No test here may open a real TLS connection to a public address."""
    def _offline(*_a, **_k):
        raise OSError("network disabled in unit tests")
    monkeypatch.setattr(od, "_tls_handshake_cert", _offline, raising=False)


def _settings(**over):
    s = {
        "ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_KEYLESS": True,
        "ORIGIN_DISCOVERY_SCANNERS": False, "ORIGIN_DISCOVERY_PASSIVE_DNS": False,
        "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25, "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
        "ORIGIN_DISCOVERY_THRESHOLD": 60, "ORIGIN_DISCOVERY_TIMEOUT": 3,
        "ORIGIN_DISCOVERY_WORKERS": 2, "ORIGIN_DISCOVERY_RATE": 0,
        "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [],
    }
    s.update(over)
    return s


def _probe(host="www.example.com", ip="198.51.100.10", cdn="cloudflare", is_cdn=True):
    return {"http_probe": {"by_url": {f"https://{host}": {
        "host": host, "ip": ip, "is_cdn": is_cdn, "cdn": cdn, "status_code": 200}}}}


DENY = {"text": "Access Denied You don't have permission to access this server", "status": 403,
        "headers": {"server": "nginx"}, "cookies": ""}
APP = {"text": "Example Portal Sign in to your account Forgot password", "status": 200,
       "headers": {"server": "nginx"}, "cookies": "session=1"}


class TestFrontedHosts(unittest.TestCase):
    def test_plain_cloud_hosting_is_not_cdn_fronted(self):
        ctx = od._RunCtx(_settings())
        for cdn in ("azure", "aws", "amazon", "gcp", "digitalocean"):
            with self.subTest(cdn=cdn), patch.object(od, "_resolve_ips", return_value=set()):
                self.assertEqual(od._select_fronted_hosts(_probe(cdn=cdn), ctx), {})

    def test_named_edge_cdns_are_fronted(self):
        ctx = od._RunCtx(_settings())
        # "google" is a CDN label in httpx's cdncheck (Google's LB / Cloud CDN edge).
        for cdn in ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "bunnycdn", "keycdn", "google"):
            with self.subTest(cdn=cdn), patch.object(od, "_resolve_ips", return_value=set()):
                self.assertIn("www.example.com", od._select_fronted_hosts(_probe(cdn=cdn), ctx))

    def test_an_ip_in_a_known_waf_range_is_fronted_whatever_the_label(self):
        ctx = od._RunCtx(_settings())
        with patch.object(od, "_resolve_ips", return_value=set()):
            fronted = od._select_fronted_hosts(_probe(ip="104.16.1.1", cdn=None, is_cdn=False), ctx)
        self.assertIn("www.example.com", fronted)

    def test_a_subdomain_a_person_entered_as_fronted_is_fronted(self):
        ctx = od._RunCtx(_settings())
        combined = _probe(cdn=None)
        combined["http_probe"]["by_url"]["https://www.example.com"]["user_fronted"] = True
        with patch.object(od, "_resolve_ips", return_value=set()):
            self.assertIn("www.example.com", od._select_fronted_hosts(combined, ctx))

    def test_only_live_resolution_counts_not_recorded_dns(self):
        # A partial run's recorded DNS comes from the graph, which keeps the
        # pre-CDN addresses: exactly the origins this tool looks for.
        ctx = od._RunCtx(_settings())
        combined = _probe()
        combined["dns"] = {"subdomains": {"www.example.com": {"ips": {"ipv4": ["149.112.112.112"], "ipv6": []}}}}
        with patch.object(od, "_resolve_ips", return_value={"9.9.9.9"}):
            entry = od._select_fronted_hosts(combined, ctx)["www.example.com"]
        self.assertEqual(entry["resolved_ips"], {"198.51.100.10", "9.9.9.9"})
        meta = {}
        kept = od._dedup_and_filter({"9.9.9.9": "dns", "149.112.112.112": "otx"}, entry, ctx, meta)
        self.assertEqual(kept, [("149.112.112.112", "otx")])
        self.assertEqual(meta["dropped"]["current_resolution"], 1)

    def test_direct_cloud_host_produces_no_finding_end_to_end(self):
        with patch.object(od, "_resolve_ips", return_value=set()), \
             patch.object(od, "_discover_via_subdomains", return_value=["8.8.8.8"]), \
             patch.object(od, "_discover_via_email_records", return_value=[]), \
             patch.object(od, "_discover_via_crtsh", return_value=[]), \
             patch.object(od, "_favicon_hash_for_host", return_value=None), \
             patch.object(od, "_fetch") as fetch:
            out = od.run_origin_discovery_enrichment_isolated(_probe(cdn="azure"), _settings())
        self.assertEqual(out["confirmed"], [])
        fetch.assert_not_called()


class TestPartialCdnLabel(unittest.TestCase):
    def test_an_edge_label_wins_over_a_cloud_label_for_the_same_host(self):
        import sys
        from unittest.mock import MagicMock
        from recon.partial_recon_modules import origin_enrichment as oe

        rows = [{"root": "example.com", "host": "www.example.com", "favicon": None,
                 "cdns": ["aws", "cloudflare"], "ip": "104.16.1.1"}]
        session = MagicMock()
        session.__enter__.return_value = session
        session.run.return_value = rows
        client = MagicMock()
        client.__enter__.return_value = client
        client.verify_connection.return_value = True
        client.driver.session.return_value = session
        fake_graph_db = MagicMock(Neo4jClient=MagicMock(return_value=client))
        by_url = {}
        with patch.dict(sys.modules, {"graph_db": fake_graph_db}):
            oe._inject_graph_fronted_hosts(by_url, ["example.com"], "u1", "p1")
        self.assertEqual(by_url["https://www.example.com"]["cdn"], "cloudflare")


class TestDenyWalls(unittest.TestCase):
    def _score(self, reference, candidate, cert=0.0):
        ctx = od._RunCtx(_settings())
        with patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
             patch.object(od, "_compare_certs", return_value=cert), \
             patch.object(od, "_fetch", return_value=candidate):
            return od._score_candidate("www.example.com", reference, "8.8.8.8", ctx)

    def test_identical_deny_walls_are_not_a_bypass(self):
        self.assertIsNone(self._score(DENY, DENY))

    def test_identical_deny_walls_with_a_shared_certificate_are_not_a_bypass(self):
        self.assertIsNone(self._score(DENY, DENY, cert=1.0))

    def test_candidate_deny_wall_against_a_live_site_is_not_a_bypass(self):
        self.assertIsNone(self._score(APP, DENY, cert=1.0))

    def test_empty_reference_and_empty_candidate_need_a_certificate(self):
        empty = {"text": "", "status": 200, "headers": {}, "cookies": ""}
        self.assertIsNone(self._score(empty, empty, cert=0.0))
        self.assertIsNotNone(self._score(empty, APP, cert=1.0))

    def test_origin_serving_the_same_application_is_a_bypass(self):
        match = self._score(APP, APP, cert=1.0)
        self.assertIsNotNone(match)
        self.assertEqual(match["status_code"], 200)
        self.assertGreaterEqual(match["confidence_score"], 80)

    def test_a_server_sharing_a_wildcard_certificate_is_not_the_origin(self):
        # The org's mail server presents the same wildcard certificate and 404s
        # at /, while the site serves its app: a certificate alone cannot pick
        # the origin out of the org's servers.
        not_found = {"text": "404 Not Found nginx", "status": 404, "headers": {}, "cookies": ""}
        self.assertIsNone(self._score(APP, not_found, cert=0.5))
        self.assertIsNone(self._score(APP, not_found, cert=1.0))

    def test_a_blocked_edge_and_a_cert_sharing_server_serving_content_is_not_confirmed(self):
        self.assertIsNone(self._score(DENY, APP, cert=1.0))

    def test_api_origin_answering_401_or_404_confirms_on_body_and_certificate_together(self):
        for status in (401, 404):
            api = {"text": '{"error":"not found"}', "status": status, "headers": {}, "cookies": ""}
            ref = {"text": '{"error":"not found"}', "status": status, "headers": {}, "cookies": ""}
            self.assertIsNotNone(self._score(ref, api, cert=0.5), status)
            self.assertIsNone(self._score(ref, api, cert=0.0), status)

    def test_edge_denies_and_the_origin_has_no_matching_certificate(self):
        self.assertIsNone(self._score(DENY, APP, cert=0.0))


class TestSeverityFollowsConfidence(unittest.TestCase):
    def _confirmed(self, score):
        ctx = od._RunCtx(_settings())
        entry = {"favicon_hash": None, "cdn_name": "cloudflare", "edge_ip": "104.16.1.1", "resolved_ips": set()}
        match = {"matched_ip": "8.8.8.8", "port": 443, "method": "host-header", "confidence_score": score,
                 "html_similarity": 90.0, "cert_match": 50.0, "header_match": 100.0, "status_code": 200,
                 "url": "https://8.8.8.8:443"}
        with patch.object(od, "_gather_candidates", return_value={"8.8.8.8": "dns"}), \
             patch.object(od, "_fetch", return_value=APP), \
             patch.object(od, "_score_candidate", return_value=match):
            confirmed, _ = od._process_host("www.example.com", entry, ctx)
        return confirmed[0]

    def test_strong_match_is_high(self):
        self.assertEqual(self._confirmed(92.5)["severity"], "high")

    def test_threshold_match_is_medium(self):
        self.assertEqual(self._confirmed(64.0)["severity"], "medium")



BRAND_CERT = {"serial": "1", "cn": "www.example.com", "sans": {"www.example.com", "example.com"}}
EDGE_CERT = {"serial": "2", "cn": "edge.cdn-provider.test", "sans": {"*.cdn-provider.test"}}


class _Handshake:
    """Stands in for the TLS dial; records (ip, sni, port) of every handshake."""

    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def __call__(self, host_or_ip, sni, port, timeout):
        self.calls.append((host_or_ip, sni, port))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _match(score=92.5, port=443):
    return {"matched_ip": "8.8.8.8", "port": port, "method": "host-header",
            "confidence_score": score, "html_similarity": 95.0, "cert_match": 100.0,
            "header_match": 100.0, "status_code": 200, "url": f"https://8.8.8.8:{port}"}


def _confirm(answer, match=None, **settings):
    """Run _process_host on one candidate whose score is already decided."""
    ctx = od._RunCtx(_settings(**settings))
    entry = {"favicon_hash": None, "cdn_name": "cloudflare", "edge_ip": "104.16.1.1", "resolved_ips": set()}
    hs = _Handshake(answer)
    with patch.object(od, "_gather_candidates", return_value={"8.8.8.8": "dns"}), \
         patch.object(od, "_fetch", return_value=APP), \
         patch.object(od, "_score_candidate", return_value=match or _match()), \
         patch.object(od, "_tls_handshake_cert", hs):
        confirmed, _ = od._process_host("www.example.com", entry, ctx)
    return confirmed[0], hs


class TestDefaultCertificateTellsOriginFromEdge(unittest.TestCase):
    """A shared edge outside the CDN list, asked with the brand's Host/SNI, serves
    the brand's page and certificate, which scores like the origin. The
    certificate the IP presents to a client that names no host tells them apart."""

    def test_a_default_certificate_of_the_brand_keeps_high(self):
        f, hs = _confirm(BRAND_CERT)
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["confidence_score"], 92.5)
        self.assertIn("default certificate belongs to the target", f["evidence"])
        self.assertEqual(hs.calls, [("8.8.8.8", None, 443)])

    def test_a_generic_default_certificate_caps_the_finding_at_medium(self):
        f, _ = _confirm(EDGE_CERT)
        self.assertEqual(f["severity"], "medium")
        self.assertLess(f["confidence_score"], 80)
        self.assertIn("default certificate does not belong to the target", f["evidence"])

    def test_a_wildcard_for_the_brand_counts_as_the_brand(self):
        f, _ = _confirm({"serial": "3", "cn": None, "sans": {"*.example.com"}})
        self.assertEqual(f["severity"], "high")

    def test_a_lookalike_name_is_not_the_brand(self):
        f, _ = _confirm({"serial": "4", "cn": "example.com.cdn-provider.test", "sans": set()})
        self.assertEqual(f["severity"], "medium")

    def test_a_timed_out_fetch_is_no_evidence_either_way(self):
        f, _ = _confirm(socket.timeout("timed out"))
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["confidence_score"], 92.5)
        self.assertIn("default certificate: not checked (timeout)", f["evidence"])

    def test_a_closed_port_and_a_tls_error_are_not_evidence_either(self):
        for exc, reason in ((ConnectionRefusedError(111, "refused"), "port 443 closed"),
                            (ssl.SSLError(1, "handshake failure"), "TLS error")):
            with self.subTest(reason=reason):
                f, _ = _confirm(exc)
                self.assertEqual(f["severity"], "high")
                self.assertIn(f"default certificate: not checked ({reason})", f["evidence"])

    def test_a_match_on_a_tls_port_is_checked_on_that_port(self):
        _, hs = _confirm(BRAND_CERT, match=_match(port=8443))
        self.assertEqual(hs.calls, [("8.8.8.8", None, 8443)])

    def test_a_match_on_plain_http_is_checked_on_443(self):
        _, hs = _confirm(BRAND_CERT, match=_match(port=8080))
        self.assertEqual(hs.calls, [("8.8.8.8", None, 443)])

    def test_the_empty_body_certificate_path_is_capped_too(self):
        # The fronted host serves no HTML: a certificate match alone confirms,
        # at 100. A generic default certificate must still cap it.
        ctx = od._RunCtx(_settings())
        entry = {"favicon_hash": None, "cdn_name": "cloudflare", "edge_ip": "104.16.1.1", "resolved_ips": set()}
        empty = {"text": "", "status": 200, "headers": {}, "cookies": ""}

        def fetch(url, host_header, ctx, allow_redirects=False):
            return empty if url.startswith("https://www.example.com") else APP

        with patch.object(od, "_gather_candidates", return_value={"8.8.8.8": "dns"}), \
             patch.object(od, "_fetch", side_effect=fetch), \
             patch.object(od, "_port_open", side_effect=lambda ip, port, t: port == 443), \
             patch.object(od, "_compare_certs", return_value=1.0), \
             patch.object(od, "_tls_handshake_cert", _Handshake(EDGE_CERT)):
            confirmed, _ = od._process_host("www.example.com", entry, ctx)
        self.assertEqual(confirmed[0]["severity"], "medium")
        self.assertLess(confirmed[0]["confidence_score"], 80)


class TestDefaultCertificateEngagementLimits(unittest.TestCase):
    def _check(self, ip="8.8.8.8", answer=BRAND_CERT, **settings):
        ctx = od._RunCtx(_settings(**settings))
        ctx.rate = MagicMock()
        hs = _Handshake(answer)
        with patch.object(od, "_tls_handshake_cert", hs):
            result = od._default_cert_check("www.example.com", ip, 443, ctx)
        return result, hs, ctx

    def test_an_roe_excluded_ip_gets_no_handshake(self):
        (status, detail), hs, _ = self._check(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["8.8.8.8"])
        self.assertEqual(hs.calls, [])
        self.assertEqual(status, "not_checked")
        self.assertIn("rules of engagement", detail)

    def test_a_non_routable_ip_gets_no_handshake(self):
        for ip in ("10.0.0.5", "169.254.169.254", "127.0.0.1"):
            with self.subTest(ip=ip):
                (status, _), hs, _ = self._check(ip=ip)
                self.assertEqual(hs.calls, [])
                self.assertEqual(status, "not_checked")

    def test_the_handshake_waits_on_the_modules_rate_limit(self):
        _, hs, ctx = self._check()
        ctx.rate.wait.assert_called_once()
        self.assertEqual(len(hs.calls), 1)

    def test_a_host_marked_unreachable_gets_no_handshake(self):
        from recon.helpers import circuit_breaker as cb
        with patch.object(cb.host_health, "allow", return_value=False):
            (status, detail), hs, _ = self._check()
        self.assertEqual(hs.calls, [])
        self.assertEqual((status, detail), ("not_checked", "host marked unreachable"))

    def test_a_failed_handshake_counts_against_the_host(self):
        from recon.helpers import circuit_breaker as cb
        with patch.object(cb.host_health, "record_failure") as failed:
            self._check(answer=ConnectionRefusedError(111, "refused"))
        failed.assert_called_once()


if __name__ == "__main__":
    unittest.main()
