"""js_recon gets every in-scope JS URL the crawlers saw, before the exclude filter (plan 06.1).

js_recon cannot browse: it analyzes only the JS URLs it is handed. The crawlers
dropped URLs matching KATANA_EXCLUDE_PATTERNS, and the default list holds
/static/, /_next/static, .min.js, /dist/ and /build/, which is where a React,
Next.js or webpack app keeps its own code. So js_recon never saw the bundle and
"never analyzed" read as "analyzed, nothing found".

The crawlers now return the in-scope JS URLs separately (resource_enum
"js_urls"). discovered_urls and the Endpoint list still honour the excludes; the
JS list goes to js_recon and jsluice only. The crawler and the tools are fakes;
the filter loops and run_resource_enum are real.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.resource_enum import hakrawler_helpers, katana_helpers  # noqa: E402
from recon.main_recon_modules import js_recon, resource_enum  # noqa: E402
from recon.project_settings import DEFAULT_SETTINGS  # noqa: E402

HOST = "app.example.com"
MAIN = f"https://{HOST}/static/js/main.4f3a.js"
NEXT_CHUNK = f"https://{HOST}/_next/static/chunks/pages/app-91c.js"
MIN_JS = f"https://{HOST}/js/app.min.js"
LOGO = f"https://{HOST}/img/logo.png"
PAGE = f"https://{HOST}/account/settings"
FOREIGN_JS = "https://cdn.vendor.example.org/static/lib.js"
CRAWLED = [MAIN, NEXT_CHUNK, MIN_JS, LOGO, PAGE, FOREIGN_JS]
EXCLUDES = DEFAULT_SETTINGS["KATANA_EXCLUDE_PATTERNS"]


def _katana(lines, params_only=False):
    def fake_popen(cmd, *a, **k):
        proc = mock.MagicMock()
        proc.stdout.readline.side_effect = [u + "\n" for u in lines] + [""]
        proc.stderr.read.return_value = ""
        proc.poll.return_value = 0
        proc.returncode = 0
        return proc

    with mock.patch.object(katana_helpers.subprocess, "Popen", side_effect=fake_popen), \
            mock.patch.object(katana_helpers.select, "select", side_effect=lambda r, w, x, t: (r, [], [])):
        return katana_helpers.run_katana_crawler(
            target_urls=[f"https://{HOST}"], docker_image="projectdiscovery/katana:latest",
            depth=2, max_urls=100, rate_limit=10, timeout=30, js_crawl=False,
            params_only=params_only, allowed_hosts={HOST}, custom_headers=[],
            exclude_patterns=EXCLUDES)


def _hakrawler(lines):
    def fake_popen(cmd, **kwargs):
        proc = mock.MagicMock()
        proc.stdout.readline.side_effect = [u + "\n" for u in lines] + [""]
        proc.poll.return_value = None
        proc.wait.return_value = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        return hakrawler_helpers.run_hakrawler_crawler(
            target_urls=[f"https://{HOST}"], docker_image="jauderho/hakrawler:latest",
            depth=2, threads=5, timeout=30, max_urls=500, include_subs=False, insecure=False,
            allowed_hosts={HOST}, custom_headers=[], exclude_patterns=EXCLUDES)


class TestCrawlers:
    def test_katana_returns_the_excluded_js_urls_separately(self):
        urls, meta = _katana(CRAWLED)
        assert sorted(meta["js_urls"]) == sorted([MAIN, NEXT_CHUNK, MIN_JS])
        # The exclude list still keeps the static files out of the crawl list.
        assert urls == [PAGE]

    def test_katana_js_list_is_scoped_and_deduplicated(self):
        _, meta = _katana(CRAWLED + [MAIN, MAIN])
        assert FOREIGN_JS not in meta["js_urls"]
        assert meta["js_urls"].count(MAIN) == 1

    def test_katana_params_only_still_hands_over_js(self):
        urls, meta = _katana(CRAWLED, params_only=True)
        assert urls == []
        assert MAIN in meta["js_urls"]

    def test_hakrawler_returns_the_excluded_js_urls_separately(self):
        urls, meta = _hakrawler(CRAWLED)
        assert sorted(meta["js_urls"]) == sorted([MAIN, NEXT_CHUNK, MIN_JS])
        assert urls == [PAGE]


# ---------------------------------------------------------------------------
# run_resource_enum: discovered_urls as today, js_urls beside it, jsluice fed both
# ---------------------------------------------------------------------------

BASE = {
    "KATANA_ENABLED": True, "HAKRAWLER_ENABLED": False, "GAU_ENABLED": False,
    "PARAMSPIDER_ENABLED": False, "KITERUNNER_ENABLED": False, "JSLUICE_ENABLED": True,
    "JSLUICE_EXTRACT_URLS": True, "JSLUICE_EXTRACT_SECRETS": True, "FFUF_ENABLED": False,
    "ARJUN_ENABLED": False, "ZAP_AJAX_SPIDER_ENABLED": False, "OPENAPI_ENABLED": False,
    "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False, "KATANA_EXCLUDE_PATTERNS": EXCLUDES,
}


def _run_resource_enum(crawled):
    katana_urls = [u for u in crawled if not any(p.lower() in u.lower() for p in EXCLUDES)
                   and HOST in u]
    katana_js = sorted({u for u in crawled if HOST in u and js_recon._is_js_url(u)})
    jsluice = mock.MagicMock(return_value={"urls": [], "secrets": [], "external_domains": []})
    patches = [
        mock.patch.object(resource_enum, "run_katana_crawler",
                          return_value=(katana_urls, {"external_domains": [], "failed": False,
                                                      "js_urls": katana_js})),
        mock.patch.object(resource_enum, "pull_katana_docker_image", return_value=True),
        mock.patch.object(resource_enum, "is_docker_installed", return_value=True),
        mock.patch.object(resource_enum, "is_docker_running", return_value=True),
        mock.patch.object(resource_enum, "extract_targets_from_recon", return_value=(set(), {HOST}, {})),
        mock.patch.object(resource_enum, "build_target_urls", return_value=[f"https://{HOST}/"]),
        mock.patch.object(resource_enum, "run_jsluice_analysis", jsluice),
        mock.patch.object(resource_enum, "pull_ffuf_binary_check", return_value=True),
    ]
    for p in patches:
        p.start()
    try:
        out = resource_enum.run_resource_enum({"domain": "example.com"}, settings=dict(BASE))
    finally:
        for p in patches:
            p.stop()
    return out, jsluice


def test_resource_enum_returns_js_urls_beside_the_filtered_discovered_urls():
    out, _ = _run_resource_enum(CRAWLED)
    re_out = out["resource_enum"]
    assert sorted(re_out["js_urls"]) == sorted([MAIN, NEXT_CHUNK, MIN_JS])
    for u in (MAIN, NEXT_CHUNK, MIN_JS, LOGO):
        assert u not in re_out["discovered_urls"]
    assert PAGE in re_out["discovered_urls"]


def test_js_urls_never_become_endpoints():
    out, _ = _run_resource_enum(CRAWLED)
    paths = {p for data in out["resource_enum"]["by_base_url"].values() for p in data["endpoints"]}
    assert "/account/settings" in paths
    assert not any(p.endswith(".js") for p in paths)


def test_jsluice_reads_the_js_urls_too():
    _, jsluice = _run_resource_enum(CRAWLED)
    fed = jsluice.call_args.args[0]
    for u in (MAIN, NEXT_CHUNK, MIN_JS):
        assert u in fed


# ---------------------------------------------------------------------------
# js_recon's collected list
# ---------------------------------------------------------------------------

def test_js_recon_collects_the_js_urls():
    combined = {"resource_enum": {"discovered_urls": [PAGE], "js_urls": [MAIN, NEXT_CHUNK, MIN_JS]},
                "http_probe": {"by_url": {}}}
    assert sorted(js_recon._collect_js_urls(combined, {})) == sorted([MAIN, NEXT_CHUNK, MIN_JS])


def test_js_recon_drops_roe_excluded_hosts_from_the_list():
    blocked = "https://legacy.example.com/static/js/main.js"
    combined = {"resource_enum": {"discovered_urls": [], "js_urls": [MAIN, blocked]},
                "http_probe": {"by_url": {}}}
    settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["legacy.example.com"]}
    assert js_recon._collect_js_urls(combined, settings) == [MAIN]


def test_stealth_ceiling_on_max_files_caps_the_new_list():
    """Stealth sets JS_RECON_MAX_FILES to 50; the widened list is downloaded under it."""
    from recon.project_settings import apply_stealth_overrides
    stealthy = apply_stealth_overrides({**DEFAULT_SETTINGS, "STEALTH_MODE": True, "JS_RECON_ENABLED": True})
    assert stealthy["JS_RECON_MAX_FILES"] == 50
    urls = [f"https://{HOST}/static/js/chunk-{i}.js" for i in range(120)]
    seen = {}

    def fake_download(js_urls, work_dir, max_files, **kw):
        seen["n"] = len(js_urls[:max_files])
        return []

    combined = {"resource_enum": {"discovered_urls": [], "js_urls": urls}, "http_probe": {"by_url": {}},
                "metadata": {}}
    with mock.patch.object(js_recon, "_download_js_files", side_effect=fake_download):
        js_recon.run_js_recon(combined, {**stealthy, "JS_RECON_SOURCE_MAPS": False})
    assert seen["n"] == 50
    assert cb.coverage_report().keep_hostnames("js_recon") == (HOST,)
