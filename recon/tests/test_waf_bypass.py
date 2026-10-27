"""
Unit tests for the class-13 WAF blocked-vs-allowed payload differential in
recon.helpers.security_checks._waf_payload_differential().

The probe compares an edge (hostname, through the WAF) response with the origin
(direct IP + real Host header) response for a canonical WAF-signature string. A
finding is produced ONLY when the edge blocks the probe and the origin SERVES it:
a 2xx page like the one the edge serves for a benign request. A 302 to login, a
401, a 404 or a 421 (the no-SNI default vhost) is the origin refusing, not
serving, and used to be reported as a High bypass.
"""
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks

_IP = "10.10.10.10"


SITE = "<html><head><title>Shop</title></head><body><h1>Spring sale</h1><p>Browse the catalogue.</p></body></html>"


def _resp(status, text="x", headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    r.headers = headers or {}
    return r


def _probe(url):
    return security_checks._WAF_PROBE_PARAM in url


def _patch(side_effect):
    return mock.patch.object(security_checks.requests, "get", side_effect=side_effect)


def test_edge_blocks_origin_serves_is_bypass():
    def fake_get(url, **kw):
        if _IP in url:
            return _resp(200, SITE)                         # origin serves the site to the probe
        return _resp(403) if _probe(url) else _resp(200, SITE)   # edge blocks the probe only
    with _patch(fake_get):
        f = security_checks._waf_payload_differential("shop.test", _IP, timeout=2)
    assert f is not None
    assert f["type"] == "waf_bypass"
    assert f["detection_method"] == "payload_differential"
    assert f["matched_ip"] == _IP
    assert f["severity"] == "high"


def test_both_allow_is_not_a_bypass():
    with _patch(lambda url, **kw: _resp(200)):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_both_block_is_not_a_bypass():
    with _patch(lambda url, **kw: _resp(403)):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_origin_5xx_is_not_allowed():
    # An origin that errors on the probe is not "serving" it -> no bypass claim.
    def fake_get(url, **kw):
        return _resp(500) if _IP in url else _resp(403)
    with _patch(fake_get):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_network_error_is_swallowed():
    with _patch(mock.Mock(side_effect=security_checks.requests.exceptions.RequestException("boom"))):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_block_codes_membership():
    assert security_checks._looks_blocked(403)
    assert security_checks._looks_blocked(406)
    assert not security_checks._looks_blocked(200)
    assert not security_checks._looks_blocked(404)


# --------------------------------------------------------------------------- 2xx + matching body
def _edge_blocks_probes(origin, edge_benign=None):
    """An edge that blocks the probes and serves `edge_benign` otherwise; the
    origin answers the probes with `origin`. Returns (fake get, urls seen)."""
    seen = []

    def get(url, **kw):
        seen.append((url, kw))
        if _IP in url:
            return origin
        if _probe(url):
            return _resp(403, "blocked by edge WAF")
        return edge_benign if edge_benign is not None else _resp(200, SITE)
    return get, seen


def _diff(origin, edge_benign=None):
    get, seen = _edge_blocks_probes(origin, edge_benign)
    with _patch(get):
        return security_checks._waf_payload_differential("shop.test", _IP, timeout=2), seen


def test_an_origin_302_to_login_is_no_bypass():
    f, _ = _diff(_resp(302, "", {"Location": "/login"}))
    assert f is None


def test_an_origin_404_is_no_bypass():
    assert _diff(_resp(404, "<h1>Not Found</h1>"))[0] is None


def test_an_origin_401_or_421_is_no_bypass():
    assert _diff(_resp(401, "Unauthorized"))[0] is None
    assert _diff(_resp(421, "<h1>Misdirected Request</h1>"))[0] is None


def test_an_origin_200_with_the_site_page_is_a_bypass():
    f, _ = _diff(_resp(200, SITE))
    assert f is not None and f["detection_method"] == "payload_differential"
    assert f["control_check"] == "passed"
    assert "edge_status=403" in f["evidence"] and "origin_status=200" in f["evidence"]
    assert "edge_baseline_status=200" in f["evidence"] and "body_similarity=1.00" in f["evidence"]


def test_an_origin_200_with_an_unrelated_default_page_is_no_bypass():
    default = "<html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1>" \
              "<p>If you see this page, the nginx web server is successfully installed.</p></body></html>"
    assert _diff(_resp(200, default))[0] is None


def test_an_origin_page_that_echoes_the_probe_is_still_the_site():
    def origin_get(url, **kw):
        return _resp(200, SITE.replace("</body>", f"<!-- {url.split('?', 1)[1]} --></body>"))
    seen = []

    def get(url, **kw):
        seen.append(url)
        if _IP in url:
            return origin_get(url)
        return _resp(403) if _probe(url) else _resp(200, SITE)
    with _patch(get):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is not None


def test_an_edge_that_does_not_serve_the_site_skips_the_check():
    """No 2xx baseline: nothing to compare the origin with, so no claim."""
    f, seen = _diff(_resp(200, SITE), edge_benign=_resp(403, "blocked"))
    assert f is None
    baselines = [u for u, _ in seen if _IP not in u and not _probe(u)]
    assert baselines == ["https://shop.test/"]       # asked once, then the check stops
    assert len([u for u, _ in seen if _probe(u)]) == 2   # one probe pair, not three


def test_a_baseline_that_errors_skips_the_check():
    def get(url, **kw):
        if _IP in url:
            return _resp(200, SITE)
        if _probe(url):
            return _resp(403)
        raise security_checks.requests.exceptions.ConnectionError("reset")
    with _patch(get):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None


def test_the_baseline_is_one_request_sent_like_the_probes():
    f, seen = _diff(_resp(200, SITE))
    baselines = [(u, kw) for u, kw in seen if _IP not in u and not _probe(u)]
    assert [u for u, _ in baselines] == ["https://shop.test/"]
    probe_kw = next(kw for u, kw in seen if _probe(u) and _IP not in u)
    assert baselines[0][1] == probe_kw          # same UA, timeout, verify, no redirects


def test_no_baseline_is_sent_when_the_edge_blocks_nothing():
    """The baseline costs a request only when there is a candidate to judge."""
    seen = []

    def get(url, **kw):
        seen.append(url)
        return _resp(200, SITE)
    with _patch(get):
        assert security_checks._waf_payload_differential("shop.test", _IP, timeout=2) is None
    assert all(_probe(u) for u in seen)


def test_the_baseline_and_probes_go_through_host_health():
    get, _ = _edge_blocks_probes(_resp(200, SITE))
    with _patch(get), mock.patch.object(security_checks, "_hh_alive") as alive:
        security_checks._waf_payload_differential("shop.test", _IP, timeout=2)
    urls = [c.args[0] for c in alive.call_args_list]
    assert "https://shop.test/" in urls and any(_IP in u for u in urls)


# --------------------------------------------------------------------------- engagement limits
def _recon():
    return {"domain": "shop.test", "dns": {"domain": {}, "subdomains": {
        "www.shop.test": {"has_records": True, "ips": {"ipv4": [_IP], "ipv6": []}}}}}


ONLY_WAF = {"waf_bypass": True, "direct_ip_http": False, "direct_ip_https": False,
            "ip_api_exposed": False, "cache_purge_exposed": False}


def test_stealth_turns_the_check_off_and_with_it_the_baseline():
    from recon.project_settings import apply_stealth_overrides
    settings = apply_stealth_overrides({"STEALTH_MODE": True, "SECURITY_CHECK_WAF_BYPASS": True})
    assert settings["SECURITY_CHECK_WAF_BYPASS"] is False
    seen = []
    with _patch(lambda url, **kw: seen.append(url) or _resp(200, SITE)):
        security_checks.run_security_checks(
            _recon(), {**ONLY_WAF, "waf_bypass": settings["SECURITY_CHECK_WAF_BYPASS"]},
            timeout=1, max_workers=1)
    assert not [u for u in seen if "shop.test" in u]


def test_a_run_with_the_check_on_sends_the_baseline():
    get, seen = _edge_blocks_probes(_resp(200, SITE))
    with _patch(get):
        out = security_checks.run_security_checks(_recon(), ONLY_WAF, timeout=1, max_workers=1)
    assert "https://www.shop.test/" in [u for u, _ in seen]
    assert [f["type"] for f in out["security_checks"]["findings"]] == ["waf_bypass"]
