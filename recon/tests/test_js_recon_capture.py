"""JS downloads use canonical capture routing and report failed responses."""
from unittest import mock
from recon.main_recon_modules import js_recon


class _Resp:
    def __init__(self, status, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


def test_capture_session_routes_explicit_proxy_and_preserves_context(monkeypatch):
    import requests
    fake = requests.Session()
    seen = {}
    def routing(tool, phase="informational"):
        seen["tool"] = tool
        return "http://127.0.0.1:18888", "fixture-context"
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", routing)
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is True and seen["tool"] == "js_recon"
    assert session is fake
    assert session.proxies["http"] == "http://127.0.0.1:18888"
    assert session.headers["X-Redamon-Ctx"] == "fixture-context"
    assert session.trust_env is False


def test_capture_session_refuses_missing_token(monkeypatch):
    import requests
    fake = requests.Session(); seen = {}
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda tool, phase="informational": ("http://127.0.0.1:18888", ""))
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is False and session.proxies == {}


def test_safe_redirect_get_uses_supplied_session(monkeypatch):
    js_recon._OWN_HOSTS = js_recon._OwnHosts(frozenset({"app.example.test"}), frozenset({"app.example.test"}), ())
    calls = []
    class S:
        def get(self, url, **kw):
            calls.append((url, kw["headers"]))
            return _Resp(200, {}, "js")
    session = S()
    resp = js_recon._safe_redirect_get("https://app.example.test/a.js", timeout=5,
                                       headers={"User-Agent": "x"}, session=session)
    assert resp.status_code == 200
    assert calls[0][1]["User-Agent"] == "x"


def test_http_403_outcome_reaches_coverage_as_a_failed_input(tmp_path):
    urls = ["https://app.example.test/a.js", "https://app.example.test/b.js"]
    unreachable = []
    outcomes = []

    def download(urls, work_dir, max_files, unreachable=None, settings=None, outcomes=None, **kw):
        for u in urls[:max_files]:
            if u.endswith("a.js"):
                unreachable.append(u)
                outcomes.append(type(outcomes[0]) if outcomes else None)
        return []
    # Exercise the real coverage classifier with the failure evidence the
    # downloader now forwards.
    cov = js_recon._js_coverage({"metadata": {}, "http_probe": {"by_url": {}}}, {}, "2026-01-01T00:00:00Z",
                                js_urls=urls, selected=urls, unreachable=[urls[0]])
    from recon.helpers.coverage_stamps import base_url_key
    row = cov["hosts"][base_url_key(urls[0])]
    assert row["status"] == "failed"
    assert "host unreachable" in row["reason"]



def test_actual_downloader_records_http_403_as_unreachable(tmp_path):
    from recon.helpers.js_recon.fetch_admission import FetchOutcome
    calls = {}
    class S:
        def get(self, url, **kw):
            calls[url] = kw
            return _Resp(403, {"Content-Type": "text/html"}, "denied")
    session = S()
    # The downloader owns the session at call time; exercise the real routing
    # boundary through the capture factory it calls.
    with mock.patch.object(js_recon, "_capture_session", return_value=(session, True)):
        unreachable = []
        outcomes = []
        out = js_recon._download_js_files(
            ["https://app.example.test/a.js"], tmp_path, max_files=10, concurrency=1,
            timeout=30, unreachable=unreachable, settings={}, outcomes=outcomes,
        )
    assert out == [] and unreachable == ["https://app.example.test/a.js"]
    assert outcomes[0].status == "http_403" and outcomes[0].status_code == 403
    assert calls["https://app.example.test/a.js"]["headers"]["User-Agent"].startswith("Mozilla/")
