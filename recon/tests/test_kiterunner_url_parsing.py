"""Kiterunner route parsing: a wordlist route never mints a foreign BaseURL."""
from __future__ import annotations

import json
import subprocess
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers import request_pacer
from recon.helpers.resource_enum import kiterunner_helpers as kh
from recon.helpers.resource_enum import tool_health as th


@pytest.fixture(autouse=True)
def _clean_state():
    request_pacer.reset()
    th.drain()
    yield
    request_pacer.reset()
    th.drain()


@pytest.fixture
def kr_files(tmp_path):
    binary = tmp_path / "kr"
    binary.write_text("")
    wordlist = tmp_path / "routes.kite"
    wordlist.write_text("")
    return str(binary), str(wordlist)


def _discover(kr_files, hits):
    binary, wordlist = kr_files
    stdout = "\n".join(json.dumps(hit) for hit in hits)

    with mock.patch.object(
        kh, "run_with_heartbeat",
        side_effect=lambda cmd, **_kw: subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr=""),
    ), mock.patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None)):
        return kh.run_kiterunner_discovery(
            ["https://app.example.test"], binary, wordlist, "routes",
            rate_limit=0, connections=1, timeout=1, scan_timeout=1, threads=1,
            ignore_status=[], match_status=[], min_content_length=0, headers=[],
        )


def test_routes_large_entries_stay_on_the_target(kr_files):
    """The standard wordlist carries entries without a leading slash.

    They are routes on the scan target, so the separator is added. A path that
    is an absolute URL or a network-path reference is not a route and is
    dropped instead of becoming a BaseURL for another host.
    """
    hits = [
        {"method": "GET", "target": "https://app.example.test", "path": "/api/users",
         "responses": [{"sc": 200, "len": 1}]},
        {"method": "GET", "target": "https://app.example.test", "path": "returnjet.com",
         "responses": [{"sc": 200, "len": 1}]},
        {"method": "GET", "target": "https://app.example.test",
         "path": "api.calorieninjas.com/v1/nutrition",
         "responses": [{"sc": 200, "len": 1}]},
        {"method": "GET", "target": "https://app.example.test", "path": "https:",
         "responses": [{"sc": 200, "len": 1}]},
        {"method": "GET", "target": "https://app.example.test", "path": "https://evil.test/x",
         "responses": [{"sc": 200, "len": 1}]},
        {"method": "GET", "target": "https://app.example.test", "path": "//evil.test/x",
         "responses": [{"sc": 200, "len": 1}]},
    ]

    found = _discover(kr_files, hits)
    urls = [row["url"] for row in found]

    assert "https://app.example.test/api/users" in urls
    assert "https://app.example.test/returnjet.com" in urls
    assert "https://app.example.test/api.calorieninjas.com/v1/nutrition" in urls
    assert not any("https:" == url or "https://app.example.testhttps:" == url for url in urls)
    assert not any("evil.test" in url for url in urls)
    assert all(url.startswith("https://app.example.test/") for url in urls)


def test_merge_refuses_a_result_from_an_unknown_host():
    by_base_url = {
        "https://app.example.test": {
            "base_url": "https://app.example.test",
            "endpoints": {},
            "summary": {
                "total_endpoints": 0,
                "total_parameters": 0,
                "methods": {},
                "categories": {},
            },
        }
    }
    results = [
        {"url": "https://app.example.test/ok", "path": "/ok", "method": "GET", "status": 200},
        {"url": "https://evil.test/x", "path": "/x", "method": "GET", "status": 200},
    ]

    merged, stats = kh.merge_kiterunner_into_by_base_url(results, by_base_url)

    assert "https://evil.test" not in merged
    assert stats["kr_rejected_unknown_host"] == 1
    assert "/ok" in merged["https://app.example.test"]["endpoints"]
