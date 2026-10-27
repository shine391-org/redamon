"""JS_RECON_INCLUDE_ARCHIVED_JS is honoured (plan 06.8).

_collect_js_urls promised "GAU/Wayback archived URLs (if
JS_RECON_INCLUDE_ARCHIVED_JS)", but the setting was only logged: archived URLs
reached js_recon mixed into discovered_urls whatever it said. resource_enum now
also returns the URLs only web archives reported (GAU, URLScan, ParamSpider)
as "archived_urls", and with the setting off js_recon drops the JS URLs that
appear only there. A URL a crawler or http_probe also saw is always kept.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import js_recon, resource_enum  # noqa: E402

HOST = "app.example.com"
CRAWLED_JS = f"https://{HOST}/static/js/main.4f3a.js"
ARCHIVE_ONLY_JS = f"https://{HOST}/assets/legacy-2019.js"
URLSCAN_ONLY_JS = f"https://{HOST}/assets/old-widget.js"
PROBED_ARCHIVED_JS = f"https://{HOST}/assets/still-served.js"
PAGE = f"https://{HOST}/account"
ARCHIVE_PAGE = f"https://{HOST}/old/promo"

BASE = {
    "KATANA_ENABLED": True, "HAKRAWLER_ENABLED": False, "GAU_ENABLED": True,
    "GAU_PROVIDERS": ["wayback"], "GAU_VERIFY_URLS": False, "GAU_DETECT_METHODS": False,
    "PARAMSPIDER_ENABLED": False, "KITERUNNER_ENABLED": False, "JSLUICE_ENABLED": False,
    "FFUF_ENABLED": False, "ARJUN_ENABLED": False, "ZAP_AJAX_SPIDER_ENABLED": False,
    "OPENAPI_ENABLED": False, "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
}


def _resource_enum():
    patches = [
        mock.patch.object(resource_enum, "run_katana_crawler",
                          return_value=([PAGE], {"external_domains": [], "failed": False, "js_urls": [CRAWLED_JS]})),
        mock.patch.object(resource_enum, "pull_katana_docker_image", return_value=True),
        mock.patch.object(resource_enum, "pull_gau_docker_image", return_value=True),
        mock.patch.object(resource_enum, "run_gau_discovery",
                          return_value=([CRAWLED_JS, ARCHIVE_ONLY_JS, ARCHIVE_PAGE, PAGE], {})),
        mock.patch.object(resource_enum, "_archive_preflight", return_value=None),
        mock.patch.object(resource_enum, "is_docker_installed", return_value=True),
        mock.patch.object(resource_enum, "is_docker_running", return_value=True),
        mock.patch.object(resource_enum, "extract_targets_from_recon", return_value=(set(), {HOST}, {})),
        mock.patch.object(resource_enum, "build_target_urls", return_value=[f"https://{HOST}/"]),
        mock.patch.object(resource_enum, "pull_ffuf_binary_check", return_value=True),
    ]
    recon_data = {"domain": "example.com",
                  "urlscan": {"urls_with_paths": [{"full_url": URLSCAN_ONLY_JS}, {"full_url": PAGE}]}}
    for p in patches:
        p.start()
    try:
        return resource_enum.run_resource_enum(recon_data, settings=dict(BASE))["resource_enum"]
    finally:
        for p in patches:
            p.stop()


def test_resource_enum_returns_the_urls_only_archives_reported():
    out = _resource_enum()
    assert out["archived_urls"] == sorted([ARCHIVE_ONLY_JS, ARCHIVE_PAGE, URLSCAN_ONLY_JS])
    # discovered_urls and the Endpoints are unchanged by the new list.
    for u in (ARCHIVE_ONLY_JS, ARCHIVE_PAGE, URLSCAN_ONLY_JS, PAGE):
        assert u in out["discovered_urls"]


def _combined():
    return {
        "resource_enum": {
            "js_urls": [CRAWLED_JS],
            "discovered_urls": [PAGE, CRAWLED_JS, ARCHIVE_ONLY_JS, URLSCAN_ONLY_JS, PROBED_ARCHIVED_JS],
            "archived_urls": [ARCHIVE_ONLY_JS, URLSCAN_ONLY_JS, PROBED_ARCHIVED_JS],
        },
        "http_probe": {"by_url": {PROBED_ARCHIVED_JS: {"status_code": 200}}},
    }


def test_archive_only_js_is_collected_when_the_setting_is_on():
    got = js_recon._collect_js_urls(_combined(), {"JS_RECON_INCLUDE_ARCHIVED_JS": True})
    assert ARCHIVE_ONLY_JS in got and URLSCAN_ONLY_JS in got


def test_archive_only_js_is_dropped_when_the_setting_is_off():
    got = js_recon._collect_js_urls(_combined(), {"JS_RECON_INCLUDE_ARCHIVED_JS": False})
    assert ARCHIVE_ONLY_JS not in got and URLSCAN_ONLY_JS not in got


def test_a_crawled_or_probed_url_is_collected_either_way():
    for setting in (True, False):
        got = js_recon._collect_js_urls(_combined(), {"JS_RECON_INCLUDE_ARCHIVED_JS": setting})
        assert CRAWLED_JS in got, setting
        assert PROBED_ARCHIVED_JS in got, setting


def test_the_default_keeps_archived_js():
    from recon.project_settings import DEFAULT_SETTINGS
    assert DEFAULT_SETTINGS["JS_RECON_INCLUDE_ARCHIVED_JS"] is True
    assert ARCHIVE_ONLY_JS in js_recon._collect_js_urls(_combined(), {})


def test_an_older_recon_file_without_archived_urls_keeps_everything():
    combined = _combined()
    del combined["resource_enum"]["archived_urls"]
    got = js_recon._collect_js_urls(combined, {"JS_RECON_INCLUDE_ARCHIVED_JS": False})
    assert ARCHIVE_ONLY_JS in got
