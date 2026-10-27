"""Which URLs js_recon and jsluice treat as JavaScript (plan 06.3).

Only paths ending in .js/.mjs/.jsx/.ts/.tsx (or under /js/) counted, so a
content-hash name such as ``app.js__v_3fa2`` or ``bundle.mjs~1`` was skipped and
the run reported ``files_seen: 0`` as if the site had no JS. jsluice had its own,
narrower copy. Both now read one detector; at download time a JavaScript
Content-Type is accepted and an HTML page answered with 200 on a ``.js`` URL (a
soft 404) is rejected.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import js_recon  # noqa: E402
from recon.helpers.resource_enum import jsluice_helpers  # noqa: E402

BASE = "https://app.example.com"

JS_URLS = [
    "/static/js/main.4f3a.js",
    "/_next/static/chunks/pages/app-91c.js",
    "/js/app.min.js",
    "/js/bundle.js__v_ab12",
    "/assets/app.js__v_3fa2",
    "/assets/bundle.mjs~1",
    "/assets/main.js-1a2b",
    "/assets/app.js?v=12",
    "/assets/app.js?v=12&x=.png",
    "/src/App.jsx",
    "/src/client.ts",
    "/src/View.tsx",
    "/esm/index.mjs",
    "/js/loader",
    "/javascript/widget",
]

NOT_JS_URLS = [
    "/img/logo.png",
    "/static/js/main.4f3a.js.map",
    "/app.js.map",
    "/static/css/site.css",
    "/js/logo.png",
    "/api/vendor.json",
    "/login.jsp",
    "/export/data.tsv",
    "/",
    "",
    "/index.html",
    "/assets/app.js.gz",
]


@pytest.mark.parametrize("path", JS_URLS)
def test_js_recon_counts_hashed_and_suffixed_js(path):
    assert js_recon._is_js_url(BASE + path), path


@pytest.mark.parametrize("path", NOT_JS_URLS)
def test_js_recon_skips_non_js(path):
    assert not js_recon._is_js_url(BASE + path), path


@pytest.mark.parametrize("path", JS_URLS)
def test_jsluice_reads_the_same_detector(path):
    assert jsluice_helpers._is_js_url(BASE + path), path


@pytest.mark.parametrize("path", NOT_JS_URLS)
def test_jsluice_skips_the_same_non_js(path):
    assert not jsluice_helpers._is_js_url(BASE + path), path


def test_extension_versus_directory_kind():
    from recon.helpers.js_recon import urls
    assert urls.js_url_kind(BASE + "/js/app.js__v_1") == "extension"
    assert urls.js_url_kind(BASE + "/js/loader") == "directory"
    assert urls.js_url_kind(BASE + "/img/logo.png") == ""


@pytest.mark.parametrize("ctype,expected", [
    ("application/javascript", True),
    ("text/javascript; charset=utf-8", True),
    ("application/x-javascript", True),
    ("application/ecmascript", True),
    ("text/ecmascript", True),
    ("Application/JavaScript", True),
    ("text/html; charset=utf-8", False),
    ("application/json", False),
    ("application/octet-stream", False),
    ("", False),
    (None, False),
])
def test_javascript_content_types(ctype, expected):
    from recon.helpers.js_recon import urls
    assert urls.is_js_content_type(ctype) is expected


def test_an_http_probe_url_served_as_javascript_is_collected_whatever_its_name():
    combined = {"resource_enum": {"discovered_urls": []}, "http_probe": {"by_url": {
        BASE + "/assets/loader": {"status_code": 200, "content_type": "text/javascript; charset=utf-8"},
        BASE + "/about": {"status_code": 200, "content_type": "text/html"},
    }}}
    assert js_recon._collect_js_urls(combined, {}) == [BASE + "/assets/loader"]


# --- download time -----------------------------------------------------------

SPA_SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'


def _resp(body, ctype):
    r = mock.MagicMock()
    r.status_code = 200
    r.headers = {"Content-Type": ctype} if ctype else {}
    r.text = body
    return r


def _download(url, body, ctype, tmp_path):
    with mock.patch.object(js_recon, "_safe_redirect_get", return_value=_resp(body, ctype)):
        return js_recon._download_js_files([url], tmp_path, max_files=10, concurrency=1, timeout=30)


def test_a_javascript_content_type_is_accepted_on_an_extensionless_url(tmp_path):
    [f] = _download(BASE + "/js/loader", "window.app = 1;", "application/javascript", tmp_path)
    assert f["url"] == BASE + "/js/loader"
    assert f["content"] == "window.app = 1;"


def test_an_html_soft_404_on_a_js_url_is_rejected(tmp_path):
    assert _download(BASE + "/static/js/main.4f3a.js", SPA_SHELL, "text/html; charset=utf-8", tmp_path) == []


def test_an_html_body_mislabelled_as_javascript_is_rejected(tmp_path):
    assert _download(BASE + "/static/js/main.4f3a.js", "\n  " + SPA_SHELL, "application/javascript", tmp_path) == []


def test_a_js_url_served_as_octet_stream_is_kept(tmp_path):
    # S3 and some CDNs label bundles application/octet-stream.
    [f] = _download(BASE + "/static/js/main.4f3a.js", "var a=1;", "application/octet-stream", tmp_path)
    assert f["content"] == "var a=1;"


def test_an_extensionless_url_needs_a_javascript_type(tmp_path):
    assert _download(BASE + "/js/loader", "var a=1;", "application/octet-stream", tmp_path) == []


def test_jsluice_download_rejects_an_html_soft_404(tmp_path):
    class _R:
        status = 200
        headers = {"Content-Type": "application/javascript"}

        def read(self):
            return SPA_SHELL.encode()

    opener = mock.MagicMock()
    opener.open.return_value = _R()
    with mock.patch.object(jsluice_helpers.urllib.request, "build_opener", return_value=opener):
        got = jsluice_helpers._download_js_files([BASE + "/static/js/main.js"], tmp_path)
    assert got == {}


def test_jsluice_download_keeps_real_js(tmp_path):
    class _R:
        status = 200
        headers = {"Content-Type": "application/octet-stream"}

        def read(self):
            return b"var a = 1;"

    opener = mock.MagicMock()
    opener.open.return_value = _R()
    with mock.patch.object(jsluice_helpers.urllib.request, "build_opener", return_value=opener):
        got = jsluice_helpers._download_js_files([BASE + "/static/js/main.js__v_1"], tmp_path)
    assert list(got) == [BASE + "/static/js/main.js__v_1"]
