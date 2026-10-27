"""Recon's own HTTP checks send one full desktop browser User-Agent.

A bare `Mozilla/5.0` or a truncated Chrome string (no AppleWebKit/Safari
tokens) is what a WAF's bot rules match first, and earns a challenge page
instead of the site: a challenged run looks like an empty surface. The checks
now send DEFAULT_BROWSER_UA, the string httpx and katana already default to.
The self-identifying RedAmon-* agents (js_recon, takeover, cache scanner) and
the nuclei / ffuf defaults are product decisions and stay as they are.
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest import mock

import requests

from recon.helpers import security_checks as sc
from recon.helpers.js_recon import sourcemap
from recon.helpers.user_agent import DEFAULT_BROWSER_UA

RECON = Path(__file__).resolve().parents[1]
TRUNCATED = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"


def _resp(status=200, text="", headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode()
    r.headers = headers or {}
    r.history = []
    r.url = ""
    return r


def test_it_is_the_ua_httpx_and_katana_default_to():
    from recon.project_settings import DEFAULT_SETTINGS
    for key in ("HTTPX_CUSTOM_HEADERS", "KATANA_CUSTOM_HEADERS"):
        uas = [h.split(":", 1)[1].strip() for h in DEFAULT_SETTINGS[key] if h.lower().startswith("user-agent:")]
        assert uas == [DEFAULT_BROWSER_UA], key


def test_it_is_a_full_desktop_chrome_string():
    assert re.fullmatch(r"Mozilla/5\.0 \(Windows NT 10\.0; Win64; x64\) AppleWebKit/537\.36 "
                        r"\(KHTML, like Gecko\) Chrome/\d+\.0\.0\.0 Safari/537\.36", DEFAULT_BROWSER_UA)


def test_no_bare_or_truncated_ua_is_left_in_the_checks():
    for rel in ("helpers/security_checks.py", "helpers/js_recon/sourcemap.py"):
        src = (RECON / rel).read_text()
        assert TRUNCATED not in src, rel
        assert not re.search(r"""["']Mozilla/5\.0["']""", src), rel


def test_the_self_identifying_agents_are_unchanged():
    assert "RedAmon-JsRecon/1.0" in (RECON / "main_recon_modules/js_recon.py").read_text()


def _sent_uas(get):
    return {c.kwargs["headers"]["User-Agent"] for c in get.call_args_list}


def test_the_kubernetes_check_sends_the_browser_ua():
    get = mock.MagicMock(return_value=_resp(404, "nf"))
    with mock.patch.object(sc.requests, "get", get):
        sc.check_kubernetes_api_exposed("198.51.100.7", timeout=1)
    assert get.call_args_list and _sent_uas(get) == {DEFAULT_BROWSER_UA}


def test_the_ip_api_and_waf_checks_send_the_browser_ua():
    get = mock.MagicMock(return_value=_resp(404, "nf"))
    with mock.patch.object(sc.requests, "get", get):
        sc.check_ip_api_exposed("198.51.100.7", timeout=1)
        sc.check_waf_bypass("www.example.test", "198.51.100.7", timeout=1)
        sc.check_security_headers("www.example.test", timeout=1)
    assert _sent_uas(get) == {DEFAULT_BROWSER_UA}


def test_the_source_map_fetch_sends_the_browser_ua():
    head = mock.MagicMock(return_value=_resp(404))
    with mock.patch.object(sourcemap, "is_url_safe_to_probe", return_value=True), \
         mock.patch.object(sourcemap.requests, "head", head):
        assert sourcemap._fetch_sourcemap("https://app.example.com/static/main.js.map", 2) is None
    assert head.call_args_list
    assert {c.kwargs["headers"]["User-Agent"] for c in head.call_args_list} == {DEFAULT_BROWSER_UA}
