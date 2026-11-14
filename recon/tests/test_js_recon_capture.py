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
    import helpers.proxy_routing as proxy_routing
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", routing)
    # The route must name the capture proxy's own publish; make 18888 canonical.
    monkeypatch.setitem(proxy_routing._config, "port", 18888)
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is True and seen["tool"] == "js_recon"
    assert session is fake
    assert session.proxies["http"] == "http://127.0.0.1:18888"
    assert session.headers["X-Redamon-Ctx"] == "fixture-context"
    assert session.trust_env is False


def test_capture_session_always_disables_the_environment(monkeypatch):
    """No route / no token / an unusable route: trust_env is off regardless."""
    import requests
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda tool, phase="informational": (None, None))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")
    fake = requests.Session()
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is False and session.trust_env is False
    assert session.proxies == {} and "X-Redamon-Ctx" not in session.headers


def test_capture_session_never_adopts_an_environment_proxy(monkeypatch):
    """The environment fallback is gone: a proxy named only by HTTPS_PROXY is
    never used, even when it names the capture host. Baseline adopted it."""
    import requests
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda tool, phase="informational": (None, None))
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    fake = requests.Session()
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is False
    assert session.proxies == {}


def test_capture_session_survives_a_failed_routing_import(monkeypatch):
    import requests
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setitem(sys.modules, "helpers.proxy_routing", None)
    fake = requests.Session()
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is False and session.trust_env is False
    assert session.proxies == {}


def test_capture_session_refuses_a_stale_wrong_loopback_port(monkeypatch):
    """A signed context tag must never be sent to a port the capture proxy
    does not own: a stale answer is refused, not routed."""
    import requests
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import helpers.proxy_routing as proxy_routing
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing",
                        lambda tool, phase="informational": ("http://127.0.0.1:9999", "signed-tag"))
    monkeypatch.setitem(proxy_routing._config, "port", 8888)
    fake = requests.Session()
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is False
    assert session.proxies == {}
    assert "X-Redamon-Ctx" not in session.headers


def test_capture_session_refuses_a_remote_route(monkeypatch):
    import requests
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing",
                        lambda tool, phase="informational": ("http://capture.example:8888", "signed-tag"))
    fake = requests.Session()
    monkeypatch.setattr(js_recon.requests, "Session", lambda: fake)
    session, routed = js_recon._capture_session("js_recon")
    assert routed is False and session.proxies == {}
    assert "X-Redamon-Ctx" not in session.headers


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


class _CloseableSession:
    def __init__(self, responses):
        self.responses = responses
        self.closed = False

    def get(self, url, **kw):
        return self.responses[url]

    def close(self):
        self.closed = True


def test_the_download_batch_closes_its_session(tmp_path):
    urls = ["https://app.example.test/a.js"]
    session = _CloseableSession(
        {urls[0]: _Resp(200, {"Content-Type": "application/javascript"}, "var a=1;")})
    with mock.patch.object(js_recon, "_capture_session", return_value=(session, True)):
        out = js_recon._download_js_files(urls, tmp_path, max_files=1, concurrency=1,
                                          timeout=30, settings={})
    assert len(out) == 1 and session.closed is True


def test_a_session_fake_without_close_does_not_break_the_batch(tmp_path):
    class Bare:
        def get(self, url, **kw):
            return _Resp(200, {"Content-Type": "application/javascript"}, "var a=1;")

    with mock.patch.object(js_recon, "_capture_session", return_value=(Bare(), True)):
        out = js_recon._download_js_files(["https://app.example.test/a.js"], tmp_path,
                                          max_files=1, concurrency=1, timeout=30, settings={})
    assert len(out) == 1


def test_outcome_status_feeds_coverage_instead_of_a_blanket_host_reason():
    from recon.helpers.coverage_stamps import base_url_key
    from recon.helpers.js_recon.fetch_admission import FetchOutcome
    urls = ["https://app.example.test/a.js", "https://app.example.test/b.js"]
    outcomes = [
        FetchOutcome(url=urls[0], status="http_403", status_code=403),
        FetchOutcome(url=urls[1], status="too_large", status_code=200),
    ]
    cov = js_recon._js_coverage({"metadata": {}, "http_probe": {"by_url": {}}}, {},
                                "2026-01-01T00:00:00Z", js_urls=urls, selected=urls,
                                unreachable=list(urls), outcomes=outcomes)
    row = cov["hosts"][base_url_key(urls[0])]
    # The old code lumped every loss into "host unreachable"; each outcome now
    # carries its own reason code.
    assert row["status"] == "failed"
    assert "host unreachable" not in (row["reason"] or "")
    assert "http_403" in row["reason"] and "too_large" in row["reason"]
