"""Detection-pass target noise filter.

The DETECTION pass must not spend templates and memory on crawler asset URLs or
on measured CDN edge addresses. The filter is deliberately evidence-based: an
unmeasured address, a real application 403, and a non-CDN 403 all stay targets.
"""
import json

from recon.helpers import target_helpers as th


def _probe(**entry):
    return {"http_probe": {"by_url": entry}}


def test_static_assets_are_dropped_but_api_paths_are_kept():
    urls = [
        "https://app.test",
        "https://app.test/assets/app.js",
        "https://app.test/img/logo.PNG?v=2",
        "https://app.test/fonts/inter.woff2",
        "https://app.test/api/users.json",
        "https://app.test/sitemap.xml",
        "https://app.test/login",
    ]
    kept, report = th.filter_nuclei_detection_targets(urls)
    assert kept == [
        "https://app.test",
        "https://app.test/api/users.json",
        "https://app.test/sitemap.xml",
        "https://app.test/login",
    ]
    assert report["input"] == 7
    assert report["kept"] == 4
    assert report["dropped"] == {"static_asset": 3}
    assert report["dropped_total"] == 3


def test_cdn_origin_error_and_tiny_cdn_denial_are_dropped():
    urls = ["https://app.test", "http://203.0.113.5", "http://203.0.113.5:8080"]
    recon = _probe(
        **{
            "https://app.test": {
                "status_code": 200, "is_cdn": True, "server": "cloudflare",
            },
            "http://203.0.113.5": {
                "status_code": 403, "is_cdn": True, "cdn": "cloudflare",
                "title": None, "content_length": 17,
            },
            "http://203.0.113.5:8080": {
                "status_code": 522, "is_cdn": True, "cdn": "cloudflare",
                "title": "522: Connection timed out", "content_length": 7282,
            },
        }
    )
    kept, report = th.filter_nuclei_detection_targets(urls, recon)
    assert kept == ["https://app.test"]
    assert report["dropped"] == {"cdn_edge_error": 2}


def test_real_cdn_fronted_403_and_non_cdn_403_are_kept():
    urls = ["https://app.test/admin", "https://origin.test/private"]
    recon = _probe(
        **{
            "https://app.test/admin": {
                "status_code": 403, "is_cdn": True, "cdn": "cloudflare",
                "title": "Admin login", "content_length": 4096,
            },
            "https://origin.test/private": {
                "status_code": 403, "is_cdn": False,
                "title": None, "content_length": 9,
            },
        }
    )
    kept, report = th.filter_nuclei_detection_targets(urls, recon)
    assert kept == urls
    assert report["dropped_total"] == 0


def test_origin_entry_applies_to_a_root_url_and_unmeasured_ip_stays():
    urls = ["http://203.0.113.5/", "http://[2001:db8::1]"]
    recon = _probe(
        **{
            "http://203.0.113.5": {
                "status_code": 403, "is_cdn": True, "cdn": "cloudflare",
                "title": None, "content_length": 17,
            },
        }
    )
    kept, report = th.filter_nuclei_detection_targets(urls, recon)
    assert kept == ["http://[2001:db8::1]"]
    assert report["dropped"] == {"cdn_edge_error": 1}


def test_report_does_not_repeat_dropped_urls_and_empty_is_explicit():
    url = "https://app.test/assets/app.js?token=secret"
    kept, report = th.filter_nuclei_detection_targets([url])
    assert kept == []
    assert report["input"] == 1 and report["kept"] == 0
    assert "secret" not in json.dumps(report)
    assert url not in json.dumps(report)


def test_input_order_is_preserved_and_duplicates_collapse():
    urls = ["https://b.test", "https://a.test", "https://b.test"]
    kept, report = th.filter_nuclei_detection_targets(urls)
    assert kept == ["https://b.test", "https://a.test"]
    assert report["input"] == 2
