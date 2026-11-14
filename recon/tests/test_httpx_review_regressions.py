"""Cross-cutting regressions for the httpx/target-admission review blockers.

These are fixture-only tests (no network, no live target): mixed-source caller
scenarios plus the scope/admission invariants restored on top of 201868cd.
They exercise the real ``extract_targets_from_recon`` / ``build_target_urls``
call path rather than isolated helpers.
"""
import copy

from recon.helpers import target_helpers as th

APEX_IP = "192.0.2.10"
WWW_IP = "198.51.100.23"
SHARED_IP = "203.0.113.7"
MAPPING_ONLY_IP = "198.51.100.99"

CF1003_REASON = "edge_error_page_cloudflare_1003"


def _cf1003(**overrides):
    entry = {
        "status_code": 403,
        "content_type": "text/html",
        "body": ("<html><head><title>Error 1003 | Access forbidden | Cloudflare"
                 "</title></head><body>Direct IP access not allowed</body></html>"),
        "headers": {"server": "cloudflare", "cf-ray": "abc-HKG"},
    }
    entry.update(overrides)
    return entry


def _ip_urls(ip):
    return {f"http://{ip}", f"https://{ip}"}


def _mixed_data():
    return {
        "domain": "example.test",
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []},
                       "has_records": True},
            "subdomains": {
                "www.example.test": {"has_records": True,
                                     "ips": {"ipv4": [WWW_IP], "ipv6": []}},
                "shared.example.test": {"has_records": True,
                                        "ips": {"ipv4": [SHARED_IP], "ipv6": []}},
            },
        },
        "metadata": {"include_root_domain": False},
        "resource_enum": {"by_base_url": {
            "https://api.example.test": {"endpoints": {
                "/health": {"sources": ["katana"], "methods": ["GET"]}}},
        }},
        "http_probe": {"by_url": {
            "https://www.example.test": {"status_code": 200, "title": "WWW"},
            "https://app.example.test": {"status_code": 503,
                                         "body": "origin unavailable"},
            f"http://{SHARED_IP}": _cf1003(),
        }},
    }


# ---------------------------------------------------------------------------
# Excluded-root extraction (restored e45004b6 semantics)
# ---------------------------------------------------------------------------

def test_excluded_root_adds_neither_apex_hostname_nor_apex_mapping():
    data = _mixed_data()
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    assert "example.test" not in hostnames
    assert APEX_IP not in ips
    assert APEX_IP not in mapping
    assert "www.example.test" in hostnames
    assert WWW_IP in ips
    assert mapping.get(WWW_IP) == ["www.example.test"]


def test_included_root_keeps_apex_and_its_mapping():
    data = _mixed_data()
    data["metadata"]["include_root_domain"] = True
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    assert "example.test" in hostnames
    assert APEX_IP in ips
    assert mapping.get(APEX_IP) == ["example.test"]


def test_null_and_malformed_dns_is_tolerated():
    assert th.extract_targets_from_recon({"dns": None}) == (set(), set(), {})
    assert th.extract_targets_from_recon(
        {"domain": "example.test",
         "dns": {"domain": None, "subdomains": None}}) == (set(), set(), {})
    ips, hostnames, mapping = th.extract_targets_from_recon({
        "domain": "example.test",
        "metadata": {"include_root_domain": False},
        "dns": {
            "domain": {"ips": {"ipv4": None, "ipv6": None}},
            "subdomains": {
                "www.example.test": None,
                "app.example.test": {"has_records": True, "ips": None},
            },
        },
    })
    assert hostnames == {"app.example.test"}
    assert ips == set()
    assert mapping == {}


# ---------------------------------------------------------------------------
# scan_all_ips must not widen scope through mapping or hostname errors
# ---------------------------------------------------------------------------

def test_scan_all_ips_never_treats_mapping_keys_as_target_ips():
    data = _mixed_data()
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    mapping[MAPPING_ONLY_IP] = ["other.example.test"]
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                ip_to_hostnames=mapping)
    assert not (_ip_urls(MAPPING_ONLY_IP) & set(urls))


def test_hostname_cf1003_error_is_not_extrapolated_to_shared_ip():
    data = {
        "domain": "example.test",
        "dns": {"domain": {"ips": {"ipv4": [SHARED_IP], "ipv6": []}},
                "subdomains": {}},
        "metadata": {"include_root_domain": True},
        "http_probe": {"by_url": {"https://example.test": _cf1003()}},
    }
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    assert mapping.get(SHARED_IP) == ["example.test"]
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                ip_to_hostnames=mapping)
    # The hostname observation is not an exact-IP observation: the address
    # stays eligible, otherwise every unrelated CDN customer loses coverage.
    assert _ip_urls(SHARED_IP) <= set(urls)


def test_exact_ip_cf1003_suppresses_only_that_exact_ip():
    data = {
        "domain": "example.test",
        "dns": {"domain": {"ips": {"ipv4": [SHARED_IP], "ipv6": []}},
                "subdomains": {}},
        "metadata": {"include_root_domain": True},
        "http_probe": {"by_url": {f"http://{SHARED_IP}": _cf1003()}},
    }
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                ip_to_hostnames=mapping)
    assert not (_ip_urls(SHARED_IP) & set(urls))


def test_non_cf1003_cloudflare_403_does_not_suppress_the_ip():
    data = {
        "domain": "example.test",
        "dns": {"domain": {"ips": {"ipv4": [SHARED_IP], "ipv6": []}},
                "subdomains": {}},
        "metadata": {"include_root_domain": True},
        "http_probe": {"by_url": {f"http://{SHARED_IP}": {
            "status_code": 403, "content_length": 17,
            "headers": {"server": "cloudflare"}}}},
    }
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                ip_to_hostnames=mapping)
    # Not a proven edge error: the measured exact-IP route stays eligible.
    assert f"http://{SHARED_IP}" in urls


# ---------------------------------------------------------------------------
# Admission accounting
# ---------------------------------------------------------------------------

def test_measured_5xx_application_response_is_admitted():
    by_url = {
        "https://app.example.test/a": {"status_code": 500},
        "https://app.example.test/b": {"status_code": 503},
    }
    assert th.build_target_urls_from_httpx({"by_url": by_url}) == sorted(by_url)


def test_admitted_count_accumulates_exactly_once_after_syntax_admission():
    by_url = {f"https://app.example.test/{i}": {"status_code": 200}
              for i in range(2)}
    report = {}
    th.build_target_urls_from_httpx({"by_url": by_url}, report)
    assert report["httpx_or_supplied"]["admitted"] == 2


# ---------------------------------------------------------------------------
# Caller-level mixed source, no scope widening
# ---------------------------------------------------------------------------

def test_mixed_sources_do_not_widen_scope_through_mapping_or_excluded_root():
    data = _mixed_data()
    before = copy.deepcopy(data)
    ips, hostnames, mapping = th.extract_targets_from_recon(data)
    mapping[MAPPING_ONLY_IP] = ["other.example.test"]
    report = {}
    urls = th.build_target_urls(hostnames, ips, data, scan_all_ips=True,
                                admission_report=report, ip_to_hostnames=mapping)

    # No excluded-root apex address, no mapping-only address, and no IP whose
    # only "evidence" is a hostname-mapped Cloudflare 403.
    assert not (_ip_urls(APEX_IP) & set(urls))
    assert not (_ip_urls(MAPPING_ONLY_IP) & set(urls))
    assert not (_ip_urls(SHARED_IP) & set(urls))   # exact-IP CF1003 suppression

    # The measured application surface stays: resource_enum base+endpoint,
    # httpx's 200 and 503, plus the unobserved shared hostname fallback and
    # the DNS-derived WWW address.
    assert {
        "https://api.example.test",
        "https://api.example.test/health",
        "https://www.example.test",
        "https://app.example.test",
        "http://shared.example.test",
        "https://shared.example.test",
    } <= set(urls)
    assert _ip_urls(WWW_IP) <= set(urls)

    # Raw observations are never mutated by admission decisions.
    assert data == before
    # httpx's own two admitted URLs are counted once, after syntax admission.
    assert report["httpx_or_supplied"]["admitted"] == 2
    assert report["httpx_or_supplied"]["excluded"].get(CF1003_REASON) == 1
