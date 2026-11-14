"""CDN edge-error admission: keep real responses, drop only proven CF 1003.

No network. Only an explicit Cloudflare 1003 signature plus Cloudflare
attribution on a measured 4xx/5xx response is excluded. A titled login page,
an untitled application 403, an origin 503, a supplied seed and an unknown
non-supplied observation all stay eligible (unknown is simply unverified).
"""
import copy

from recon.helpers import target_helpers as th

CDN_IP = "104.21.79.167"
HOST = "https://khotaikhoan.net"
CF1003_REASON = "edge_error_page_cloudflare_1003"
CF1003_BODY = ("<html><head><title>Error 1003 | Access forbidden | Cloudflare"
               "</title></head><body>Direct IP access not allowed</body></html>")


def _cf1003(**overrides):
    entry = {
        "status_code": 403,
        "content_type": "text/html",
        "body": CF1003_BODY,
        "headers": {"server": "cloudflare", "cf-ray": "abc-HKG"},
    }
    entry.update(overrides)
    return entry


def _data():
    return {
        "http_probe": {"by_url": {
            f"http://{CDN_IP}": _cf1003(),
            HOST: {"status_code": 403, "content_length": 464, "title": "Login",
                   "headers": {"server": "cloudflare"}},
            "https://api.example.test/health": {
                "status_code": 503, "content_length": 4096,
                "body": "origin unavailable", "headers": {"server": "envoy"}},
            "https://app.example.test": {"status_code": 200, "title": "App"},
        }},
        "domain": "khotaikhoan.net",
        "dns": {"domain": {"ips": {"ipv4": [CDN_IP]}, "subdomains": {}}},
        "metadata": {"include_root_domain": False},
    }


# ---------------------------------------------------------------------------
# Verdict unit tests
# ---------------------------------------------------------------------------

def test_true_cf1003_signature_with_cf_attribution_is_excluded():
    assert th._observed_http_verdict(_cf1003()) == CF1003_REASON


def test_titled_application_403_is_not_an_edge_error_page():
    assert th._observed_http_verdict({
        "status_code": 403, "content_length": 464, "title": "Login",
        "headers": {"server": "cloudflare"}}) is None


def test_untitled_application_403_with_cloudflare_server_is_kept():
    # Content length and Server: cloudflare are not an edge-error signature.
    assert th._observed_http_verdict({
        "status_code": 403, "content_length": 17,
        "headers": {"server": "cloudflare"}}) is None


def test_short_origin_503_is_not_an_edge_error_page():
    assert th._observed_http_verdict({
        "status_code": 503, "content_length": 41,
        "body": "origin unavailable"}) is None


def test_cf_attribution_without_1003_signature_is_kept():
    assert th._observed_http_verdict({
        "status_code": 403, "body": "<html>application policy</html>",
        "headers": {"server": "cloudflare", "cf-ray": "x-HKG"}}) is None


def test_1003_signature_without_cf_attribution_is_kept():
    assert th._observed_http_verdict({
        "status_code": 403, "body": CF1003_BODY,
        "headers": {"server": "envoy"}}) is None


def test_successful_page_mentioning_error_1003_is_kept():
    assert th._observed_http_verdict({
        "status_code": 200, "body": CF1003_BODY,
        "headers": {"server": "cloudflare"}}) is None


def test_unknown_and_unmeasured_responses_are_never_verdicts():
    for entry in ({"status_code": None, "provenance": "supplied"},
                  {"status_code": None, "provenance": "probe"},
                  {"status_code": 0}, {}):
        assert th._observed_http_verdict(entry) is None


# ---------------------------------------------------------------------------
# Admission tests
# ---------------------------------------------------------------------------

def test_exact_ip_cf1003_page_is_excluded_and_observed_evidence_remains():
    data = _data()
    before = copy.deepcopy(data)
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    report = {}
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                admission_report=report, ip_to_hostnames=mapping)
    assert f"http://{CDN_IP}" not in urls
    assert f"https://{CDN_IP}" not in urls
    assert "https://app.example.test" in urls
    assert "https://api.example.test/health" in urls
    assert HOST in urls
    assert data == before
    assert report["httpx_or_supplied"]["excluded"].get(CF1003_REASON) == 1
    assert data["http_probe"]["by_url"][f"http://{CDN_IP}"]["status_code"] == 403


def test_exclusion_is_reported_without_claim_the_route_was_scanned():
    data = _data()
    report = {}
    _ips, _h, mapping = th.extract_targets_from_recon(data)
    th.build_target_urls(_h, _ips, data, scan_all_ips=True,
                         admission_report=report, ip_to_hostnames=mapping)
    assert report["httpx_or_supplied"]["excluded"].get(CF1003_REASON) == 1
    assert data["http_probe"]["by_url"][f"http://{CDN_IP}"]["status_code"] == 403


def test_measured_statuses_one_through_599_are_admitted_including_5xx():
    statuses = [1, 2, 100, 200, 204, 301, 302, 400, 401, 403, 404, 418,
                500, 502, 503, 504, 520, 599]
    by_url = {f"https://app.example.test/{code}": {"status_code": code}
              for code in statuses}
    assert th.build_target_urls_from_httpx({"by_url": by_url}) == sorted(by_url)


def test_out_of_range_and_unknown_non_supplied_are_not_admitted():
    by_url = {
        "https://app.example.test/ok": {"status_code": 200},
        "https://app.example.test/supplied": {"status_code": None,
                                              "provenance": "supplied"},
        "https://app.example.test/probe": {"status_code": None,
                                           "provenance": "probe"},
        "https://app.example.test/zero": {"status_code": 0},
        "https://app.example.test/high": {"status_code": 600},
        "https://app.example.test/negative": {"status_code": -1},
    }
    report = {}
    urls = th.build_target_urls_from_httpx({"by_url": by_url}, report)
    assert urls == ["https://app.example.test/ok",
                    "https://app.example.test/supplied"]
    assert report["httpx_or_supplied"]["admitted"] == 2


def test_admitted_count_is_recorded_once_after_syntax_admission():
    by_url = {f"https://app.example.test/{i}": {"status_code": 200}
              for i in range(2)}
    report = {}
    th.build_target_urls_from_httpx({"by_url": by_url}, report)
    assert report["httpx_or_supplied"]["admitted"] == 2
