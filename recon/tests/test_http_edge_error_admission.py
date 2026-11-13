"""CDN edge-error admission: reduce fan-out without discarding real responses.

The target's own raw httpx observation is never mutated. Only the derived
application-target list may omit a proven shared-edge error page. A titled
login page, a content-bearing API error, a supplied seed and an unobserved
target all stay eligible.
"""
import copy

from recon.helpers import target_helpers as th

CDN_IP = "104.21.79.167"
HOST = "https://khotaikhoan.net"


def _data():
    return {
        "http_probe": {"by_url": {
            f"http://{CDN_IP}": {"status_code": 403, "content_length": 17, "content_type": "text/plain",
                                 "headers": {"server": "cloudflare"}},
            f"{HOST}": {"status_code": 403, "content_length": 464, "title": "Login"},
            "https://api.example.test/health": {
                "status_code": 503, "content_length": 41,
                "body": "origin unavailable", "headers": {"server": "envoy"}},
            "https://app.example.test": {"status_code": 200, "title": "App"},
        }},
        "domain": "khotaikhoan.net",
        "dns": {"domain": {"ips": {"ipv4": [CDN_IP]}, "subdomains": {}}},
        "metadata": {"include_root_domain": False},
    }


def test_shared_edge_error_page_is_excluded_and_observed_evidence_remains():
    data = _data()
    before = copy.deepcopy(data)
    hostnames, ips, mapping = th.extract_targets_from_recon(data)
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                admission_report={}, ip_to_hostnames=mapping)
    assert f"https://{CDN_IP}" not in urls
    assert "https://app.example.test" in urls
    assert data == before


def test_titled_application_403_is_not_an_edge_error_page():
    assert th._observed_http_verdict(
        {"status_code": 403, "content_length": 464, "title": "Login",
         "headers": {"server": "cloudflare"}}) is None


def test_real_edge_error_page_evidence_is_a_verdict_not_empty_result():
    assert th._observed_http_verdict(
        {"status_code": 403, "content_length": 17,
         "headers": {"server": "cloudflare"}}) == "edge_error_page_cloudflare"


def test_short_origin_error_without_a_known_edge_signature_is_still_excluded():
    assert th._observed_http_verdict(
        {"status_code": 503, "content_length": 41, "body": "origin unavailable"}) == \
        "edge_error_page_short_body"


def test_success_supplied_and_unobserved_responses_are_never_edge_error_filtered():
    for entry in ({"status_code": 200}, {"status_code": None, "provenance": "supplied"},
                  {"status_code": None, "provenance": "probe"}, {"status_code": 0}):
        assert th._observed_http_verdict(entry) is None


def test_content_bearing_error_body_is_kept():
    assert th._observed_http_verdict(
        {"status_code": 403, "content_length": 900,
         "body": "<html><body>application policy message</body></html>"}) is None


def test_exclusion_is_reported_without_claim_the_route_was_scanned():
    data = _data()
    report = {}
    _h, _ips, _mapping = th.extract_targets_from_recon(data)
    th.build_target_urls(_h, _ips, data, scan_all_ips=True,
                         admission_report=report, ip_to_hostnames=_mapping)
    assert sum(report["httpx_or_supplied"]["excluded"].values()) == 1
    assert data["http_probe"]["by_url"][f"http://{CDN_IP}"]["status_code"] == 403
