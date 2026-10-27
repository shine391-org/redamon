"""Endpoint extraction reads the call shapes real bundles use (plan 06.6).

Every pattern needed a quoted literal as the call's first argument and a path
with a leading slash, so these yielded no endpoint at all:
``this.get("/v1/orders")``, minified ``n.get("/users")``, a template literal,
``fetch(API_BASE+"/v2/items")``, ``api.get("v1/accounts")`` and
``r({url:"/api/export",method:"GET"})``. And a run that read many files and
extracted nothing said nothing about it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.js_recon.endpoints import extract_endpoints  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

JS = "https://app.example.com/static/js/main.js"


def _paths(code):
    return {(e["method"], e["path"]) for e in extract_endpoints([{"url": JS, "content": code}], {})}


@pytest.mark.parametrize("code,expected", [
    ('class Api { orders() { return this.get("/v1/orders"); } }', ("GET", "/v1/orders")),
    ('function u(n){return n.get("/users")}', ("GET", "/users")),
    ("const r = n.post('/api/session', body)", ("POST", "/api/session")),
    ("e.delete(`/api/items/9`)", ("DELETE", "/api/items/9")),
    ('fetch(API_BASE+"/v2/items")', ("GET", "/v2/items")),
    ('fetch(config.apiBase + "/v2/stock", {method: "PUT"})', ("PUT", "/v2/stock")),
    ('api.get("v1/accounts")', ("GET", "/v1/accounts")),
    ('r({url:"/api/export",method:"GET"})', ("GET", "/api/export")),
    ('o({method:"POST",url:"/api/import"})', ("POST", "/api/import")),
])
def test_each_call_shape_yields_its_endpoint(code, expected):
    assert expected in _paths(code)


def test_a_template_literal_keeps_its_literal_prefix_and_is_marked_parameterized():
    [ep] = extract_endpoints([{"url": JS, "content": "axios.get(`/api/users/${id}`)"}], {})
    assert (ep["method"], ep["path"]) == ("GET", "/api/users/")
    assert ep["parameterized"] is True
    assert ep["path_template"] == "/api/users/${id}"


def test_a_template_literal_after_a_base_variable_keeps_the_path():
    [ep] = extract_endpoints([{"url": JS, "content": "fetch(`${API}/v3/cart/${cartId}/items`)"}], {})
    assert ep["path"] == "/v3/cart/"
    assert ep["parameterized"] is True


def test_a_plain_literal_is_not_parameterized():
    [ep] = extract_endpoints([{"url": JS, "content": 'fetch("/api/plain")'}], {})
    assert ep["parameterized"] is False
    assert "path_template" not in ep


@pytest.mark.parametrize("code", [
    'const m = new Map(); m.get("key")',
    'const q = new URLSearchParams(location.search); q.get("q")',
    'params.get("q")',
    'res.headers.get("content-type")',
    'cache.get("v1/accounts")',
    'store.get(`theme`)',
    'element.dataset.get("id")',
])
def test_non_http_gets_yield_nothing(code):
    assert _paths(code) == set()


def test_a_bare_relative_string_is_not_an_endpoint():
    assert _paths('const label = "v1/accounts";') == set()


def test_an_express_route_stays_a_route_and_is_not_doubled():
    eps = extract_endpoints([{"url": JS, "content": 'router.get("/health", h)'}], {})
    assert [(e["type"], e["path"]) for e in eps] == [("route", "/health")]


# --- TOOL MISS ---------------------------------------------------------------

SETTINGS = {
    "JS_RECON_MAX_FILES": 100, "JS_RECON_REGEX_PATTERNS": False, "JS_RECON_SOURCE_MAPS": False,
    "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_EXTRACT_ENDPOINTS": True,
    "JS_RECON_FRAMEWORK_DETECT": False, "JS_RECON_DOM_SINKS": False, "JS_RECON_DEV_COMMENTS": False,
    "JS_RECON_AI_SDK_DETECTION_ENABLED": False, "JS_RECON_VALIDATE_KEYS": False,
    "JS_RECON_VALIDATE_ENDPOINTS": False, "JS_RECON_TIMEOUT": 30,
}


def _run(n_files, content="var a = 1;\n", settings=None):
    urls = [f"https://app.example.com/static/js/c{i}.js" for i in range(n_files)]
    files = [{"url": u, "filepath": "", "content": content, "headers": {}, "size": len(content)} for u in urls]
    combined = {"metadata": {}, "http_probe": {"by_url": {}}, "resource_enum": {"discovered_urls": []}}
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=urls), \
            mock.patch.object(js_recon, "_download_js_files", return_value=files):
        return js_recon.run_js_recon(combined, dict(SETTINGS, **(settings or {})))["js_recon"]


def _miss_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "js_endpoint_extraction"]


def test_twenty_files_and_no_endpoint_is_a_tool_miss(capsys):
    data = _run(20)
    assert data["scan_metadata"]["endpoint_extraction_miss"] is True
    [gap] = _miss_gaps()
    assert gap["reason"] == "0 endpoints from 20 files"
    assert gap["skipped"] == 0
    assert re.fullmatch(r"[a-z0-9_]{1,64}", gap["source"])
    assert "endpoint extraction" in capsys.readouterr().out.lower()
    # A note, not a prune cut: the run's other js_recon findings still prune.
    assert "js_recon" not in cb.coverage_report().degraded_sources


def test_fewer_files_is_not_a_miss():
    data = _run(19)
    assert data["scan_metadata"]["endpoint_extraction_miss"] is False
    assert _miss_gaps() == []


def test_files_that_yield_endpoints_are_not_a_miss():
    data = _run(25, content='fetch("/api/ping");\n')
    assert data["scan_metadata"]["endpoint_extraction_miss"] is False
    assert _miss_gaps() == []


def test_extraction_switched_off_is_not_a_miss():
    data = _run(25, settings={"JS_RECON_EXTRACT_ENDPOINTS": False})
    assert data["scan_metadata"]["endpoint_extraction_miss"] is False
    assert _miss_gaps() == []


def test_a_failed_extractor_is_an_analyzer_failure_not_a_miss():
    with mock.patch.object(js_recon, "extract_endpoints", side_effect=RuntimeError("parser")):
        data = _run(25)
    assert data["scan_metadata"]["endpoint_extraction_miss"] is False
    assert _miss_gaps() == []
