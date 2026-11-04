"""Route exposure scan, end to end against a loopback app (plan §15, recon unit).

Every test drives the real scanner (harvest, generators, budget, prober,
verdicts) over real sockets, and asserts both the verdicts and the requests the
scanner built: methods, Range, which credentials rode on which request.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import time

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.route_exposure import prober, run_route_exposure, run_route_exposure_isolated, scanner
from recon.tests.route_exposure_fakeapp import (
    BEARER, COOKIE, HEADER, FakeApp, corpus, html_answer, json_answer, settings, slow,
)

# The drawer's phase parser (recon_orchestrator PHASE_PATTERNS) and the host itself.
_DRAWER = re.compile(r"port.*scan|http.*prob|resource.*enum|vuln.*scan|domain.*discovery|"
                     r"nuclei|mitre|cwe|capec|ai_surface_recon", re.I)

USERS = json.dumps([{"id": i, "email": f"user{i}@lab.invalid", "name": f"Lab User {i}"}
                    for i in range(25)]).encode()
ORDER = json.dumps({"id": 42, "item": "widget", "quantity": 3, "notes": "n" * 80}).encode()
DENY = json_answer(401, b'{"error":"authentication required"}')


def _me(hit):
    if hit.headers.get("authorization") == "Bearer lab-token" or "sid=lab-user-1" in hit.headers.get("cookie", "") \
            or hit.headers.get("x-api-key") == "lab-key":
        return json_answer(200, json.dumps({"email": "user1@lab.invalid", "password_hash": "x",
                                            "reset_token": "y", "display": "z" * 40}).encode())
    return DENY


def _orders_v2(hit):
    return json_answer(200, ORDER) if hit.headers.get("authorization") else DENY


MAIN = {
    "/": html_answer(200, b"<html><title>Lab app</title><body>" + b"welcome " * 30 + b"</body></html>"),
    "/internal/users/export": json_answer(200, USERS),
    "/api/v2/reports/export": json_answer(200, json.dumps({"report": [{"total": i} for i in range(9)]}).encode()),
    "/api/v2/orders/42": _orders_v2,
    "/api/v1/orders/42": json_answer(200, ORDER),
    "/api/admin/users": DENY, "/api/admin/roles": DENY, "/api/admin/audit": DENY,
    "/api/admin/export": json_answer(200, json.dumps({"rows": [{"n": i} for i in range(15)]}).encode()),
    "/api/admin/help": html_answer(200, b"<html><title>Admin help</title><body>" + b"how to " * 30 + b"</body></html>"),
    "/api/users/me": _me,
    "/api/status": json_answer(200, b'{"ok":true}'),
    "/uploads/invoice-1001.pdf": (200, {"Content-Type": "application/pdf"}, b"%PDF-1.4\n" + b"0" * 400),
    "/.git/HEAD": (200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n"),
    "/.git/config": (200, {"Content-Type": "text/plain"}, b"[core]\n\trepositoryformatversion = 0\n"),
    "/.env": (200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=LAB-NOT-A-SECRET-1\nAPP_ENV=lab\nDEBUG=true\n"),
    "/web.config": (200, {"Content-Type": "application/xml"}, b"<?xml version='1.0'?><configuration></configuration>"),
    "/config.php": html_answer(403, b"<html><title>403 Forbidden</title></html>"),
    "/config.php.bak": (200, {"Content-Type": "text/plain"}, b"<?php $db = 'lab'; " + b"/*x*/" * 50),
    "/backup.zip": (200, {"Content-Type": "application/zip"}, b"PK\x03\x04" + b"\x00" * 5000),
    "/actuator/env": json_answer(200, json.dumps({"activeProfiles": [], "propertySources": [
        {"name": "server.ports"}, {"name": "systemEnvironment"}]}).encode()),
    "/debug/error": html_answer(500, b"<html><title>Error</title><body>You're seeing this error because "
                                     b"you have <code>DEBUG = True</code> in your Django settings file."
                                     b"</body></html>"),
    "/console": html_answer(200, b"<html><title>Console</title><script>var EVALEX = true; "
                                 b"__debugger__</script>" + b"." * 80 + b"</html>"),
    "/phpinfo.php": html_answer(200, b"<html><head><title>phpinfo()</title></head><body>"
                                     b"<table><tr><td>PHP Version </td><td>8.2</td></tr></table>"
                                     + b"." * 80 + b"</body></html>"),
    "/admin": (302, {"Location": "/login", "Content-Type": "text/html"}, b""),
    "/logout": html_answer(200, b"bye"),
    "/account/reset": html_answer(200, b"reset"),
}

ENDPOINTS = {
    "/api/v2/orders/42": {"methods": ["GET", "DELETE"], "category": "api", "sources": ["openapi"],
                          "openapi": {"GET": {"security": ["bearer"]}}},
    "/api/v2/reports/export": {"methods": ["GET"], "category": "api", "sources": ["openapi"],
                               "declared_only": True, "openapi": {"GET": {"security": ["bearer"]}}},
    "/api/status": {"methods": ["GET"], "category": "api", "sources": ["openapi"],
                    "openapi": {"GET": {"security": []}}},
    "/api/v2/orders/7/cancel": {"methods": ["DELETE"], "category": "api", "sources": ["openapi"]},
    "/uploads/invoice-1001.pdf": {"methods": ["GET"], "category": "upload", "sources": ["katana"]},
    "/config.php": {"methods": ["GET"], "category": "dynamic", "sources": ["ffuf"]},
    "/debug/error": {"method": "GET", "category": "other", "sources": ["katana"]},
    "/api/admin/help": {"methods": ["GET"], "category": "admin", "sources": ["katana"]},
}
JS = ["/internal/users/export", "/api/users/me", "/logout", "/account/reset"]


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()
    cb.reset_registry()


def _run(app, cfg=None, **kw):
    combined = corpus(app.base, endpoints=kw.pop("endpoints", ENDPOINTS), js=kw.pop("js", JS))
    out = run_route_exposure_isolated(combined, cfg or settings(**kw))
    return out["route_exposure"]


def _by(findings, kind=None, path=None):
    return [f for f in findings if (kind is None or f["exposure_kind"] == kind)
            and (path is None or f["path"] == path)]


@pytest.fixture(scope="module")
def main_run():
    """One full run of the lab-shaped app with every v1 generator on and a bearer profile."""
    cb.reset_registry()
    prober._reset_pacer()
    with FakeApp(MAIN) as app:
        result = _run(app, settings(ROUTE_EXPOSURE_SEED_PATHS=True, ROUTE_EXPOSURE_VCS_FILES=True,
                                    ROUTE_EXPOSURE_BACKUP_FILES=True, ROUTE_EXPOSURE_VERSION_VARIANTS=True,
                                    AUTH_PROFILE=BEARER))
        hits = list(app.hits)
    prober._reset_pacer()
    return result, hits


# ---------------------------------------------------------------------------
# Verdicts (plan §14.1, v1 rows)
# ---------------------------------------------------------------------------

def test_disabled_sends_nothing():
    with FakeApp(MAIN) as app:
        combined = corpus(app.base, endpoints=ENDPOINTS)
        out = run_route_exposure(combined, settings(ROUTE_EXPOSURE_ENABLED=False))
    assert "route_exposure" not in out and app.hits == []


def test_internal_export_is_anonymous_access_and_sensitive_data(main_run):
    result, _ = main_run
    anon = _by(result["findings"], "anonymous_access", "/internal/users/export")[0]
    assert anon["needs_agent_confirmation"] is True and anon["severity"] == "info"
    assert "path_word" in anon["auth_expected_by"]
    assert anon["anon_status"] == 200 and anon["generated_by"] == "found"
    sens = _by(result["findings"], "sensitive_data", "/internal/users/export")[0]
    assert sens["pii_types"] == ["email"] and sens["pii_record_estimate"] == 25
    assert "pii_others" in sens["leak_signals"]
    assert sens["vulnerability_type"] == "sensitive_data_exposure"


def test_openapi_secured_route_open_anonymously_is_high_confidence(main_run):
    result, _ = main_run
    f = _by(result["findings"], "anonymous_access", "/api/v2/reports/export")[0]
    assert "openapi" in f["auth_expected_by"] and "declared_only" in f["auth_expected_by"]
    assert f["confidence"] == 0.9 and f["route_class"] == "data_export"


def test_protected_route_gets_no_node_but_its_status(main_run):
    result, _ = main_run
    assert not _by(result["findings"], path="/api/v2/orders/42")
    status = {(e["path"]): e["anon_status"] for e in result["endpoint_status"]}
    assert status["/api/v2/orders/42"] == 401


def test_older_version_open_while_newer_locked(main_run):
    result, _ = main_run
    f = _by(result["findings"], "anonymous_access", "/api/v1/orders/42")[0]
    assert f["generated_by"] == "version" and f["variant_of"] == "/api/v2/orders/42"
    assert "version_locked" in f["auth_expected_by"] and f["route_class"] == "old_version"
    assert f["confidence"] == 0.9


def test_seed_open_among_locked_siblings(main_run):
    result, _ = main_run
    f = _by(result["findings"], "anonymous_access", "/api/admin/export")[0]
    assert f["generated_by"] == "seed" and "siblings_locked" in f["auth_expected_by"]
    for locked in ("/api/admin/users", "/api/admin/roles", "/api/admin/audit"):
        assert not _by(result["findings"], path=locked)


def test_public_help_page_is_low_confidence(main_run):
    result, _ = main_run
    f = _by(result["findings"], "anonymous_access", "/api/admin/help")[0]
    assert f["auth_expected_by"] == ["path_word"] and f["confidence"] == 0.4


def test_logged_in_answer_of_a_denied_route_is_sensitive_data(main_run):
    """T42: the logged-in GET runs whatever the anonymous answer was."""
    result, _ = main_run
    f = _by(result["findings"], "sensitive_data", "/api/users/me")[0]
    assert f["anon_status"] == 401 and f["authed_status"] == 200
    assert any("password_hash" in s for s in f["sensitive_fields"])
    assert any("reset_token" in s for s in f["sensitive_fields"])
    assert not _by(result["findings"], "anonymous_access", "/api/users/me")


def test_declared_public_tiny_status_route_gets_no_node(main_run):
    result, _ = main_run
    assert not _by(result["findings"], path="/api/status")


def test_uploaded_file_open_anonymously(main_run):
    result, _ = main_run
    f = _by(result["findings"], "anonymous_access", "/uploads/invoice-1001.pdf")[0]
    assert f["route_class"] == "uploaded_content" and f["anon_content_class"] == "binary"


@pytest.mark.parametrize("path,kind,severity,signature", [
    ("/.git/HEAD", "vcs_exposure", "high", "git_head"),
    ("/.git/config", "vcs_exposure", "high", "git_config"),
    ("/.env", "env_file", "high", "env_lines"),
    ("/web.config", "config_file", "medium", "web_config"),
    ("/config.php.bak", "backup_file", "medium", "php_source"),
    ("/backup.zip", "backup_file", "medium", "zip_magic"),
    ("/actuator/env", "debug_endpoint", "high", "actuator_env"),
    ("/debug/error", "debug_page", "low", "django_debug"),
    ("/console", "debug_console", "high", "werkzeug_debugger"),
    ("/phpinfo.php", "debug_page", "medium", "phpinfo"),
])
def test_deterministic_findings(main_run, path, kind, severity, signature):
    result, _ = main_run
    f = _by(result["findings"], kind, path)[0]
    assert f["needs_agent_confirmation"] is False
    assert f["severity"] == severity and f["signature"] == signature
    assert f["confidence"] == 0.95


def test_env_value_never_reaches_the_finding(main_run):
    result, _ = main_run
    assert "LAB-NOT-A-SECRET" not in json.dumps(result)


def test_debug_page_answering_500_is_still_found(main_run):
    result, _ = main_run
    f = _by(result["findings"], "debug_page", "/debug/error")[0]
    assert f["anon_status"] == 500


def test_login_redirect_is_dropped_as_wall(main_run):
    result, _ = main_run
    assert not _by(result["findings"], path="/admin")
    assert result["summary"]["dropped"]["wall"] >= 1


def test_backup_is_read_with_head_and_range_only(main_run):
    _, hits = main_run
    zip_hits = [h for h in hits if h.path == "/backup.zip"]
    assert [h.method for h in zip_hits] == ["HEAD", "GET"]
    assert zip_hits[1].headers.get("range") == "bytes=0-1023"
    assert not [h for h in hits if h.path == "/backup.zip" and h.method == "GET" and "range" not in h.headers]


def test_state_changing_and_non_get_routes_never_requested(main_run):
    result, hits = main_run
    assert not [h for h in hits if h.path in ("/logout", "/account/reset", "/api/v2/orders/7/cancel")]
    assert {h.method for h in hits} <= {"GET", "HEAD"}
    assert result["summary"]["dropped"]["unsafe"] >= 3


def test_anonymous_requests_never_carry_credentials(main_run):
    _, hits = main_run
    authed = [h for h in hits if h.authed]
    assert authed, "the bearer profile was never used"
    assert all(h.headers.get("authorization") == "Bearer lab-token" for h in authed)
    assert all(h.method == "GET" for h in authed)
    # every logged-in request has an anonymous twin, except a logged-in control
    anon_paths = {h.path for h in hits if not h.authed}
    assert {h.path for h in authed if "/rdm-" not in h.path} <= anon_paths
    # artifacts are judged anonymously only
    assert not [h for h in authed if h.path.startswith(("/.git", "/.env", "/.svn", "/.hg", "/backup"))]


def test_no_artifact_becomes_an_endpoint(main_run):
    result, _ = main_run
    paths = {e["path"] for e in result["new_endpoints"]}
    assert paths == {"/api/admin/export", "/api/v1/orders/42"}
    assert not any(p.startswith(("/.git", "/.env", "/backup")) for p in paths)


def test_summary_counts_and_timestamps_bracket_the_requests(main_run):
    result, hits = main_run
    s = result["summary"]
    assert s["requests_sent"] == len(hits)
    assert s["candidates"] == len([f for f in result["findings"] if f["needs_agent_confirmation"]])
    assert s["routes_requested"] <= s["routes_harvested"] + s["routes_generated"]
    started = time.mktime(time.strptime(s["started_at"][:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    finished = time.mktime(time.strptime(s["finished_at"][:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    assert started - 1 <= min(h.at for h in hits) and max(h.at for h in hits) <= finished + 1
    assert s["error"] == ""


def test_payload_is_plain_json_with_no_map_values(main_run):
    """T3 (save_recon_file has no default=) and the flat-property rule."""
    result, _ = main_run
    json.dumps(result)
    for f in result["findings"]:
        for key, value in f.items():
            assert not isinstance(value, dict), key
            if isinstance(value, list):
                assert all(isinstance(v, str) for v in value), key
        assert "pii_counts" not in f and "matched_text" not in f


# ---------------------------------------------------------------------------
# Drops and edge cases (plan §14.3)
# ---------------------------------------------------------------------------

SPA = html_answer(200, b"<html><title>App</title><body><div id=root></div>" + b"<script>x</script>" * 10
                  + b"</body></html>")


def test_spa_catch_all_is_dropped():
    routes = {"/spa/*": SPA, "/": SPA}
    with FakeApp(routes) as app:
        result = _run(app, endpoints={"/spa/admin": {"methods": ["GET"], "category": "admin"}}, js=[])
    assert not result["findings"]
    assert result["summary"]["dropped"]["catch_all"] >= 1


def test_json_not_found_catch_all_is_dropped():
    missing = json_answer(200, b'{"error":"not found","code":404,"hint":"' + b"x" * 60 + b'"}')
    with FakeApp({"/api/missing/*": missing}) as app:
        result = _run(app, endpoints={"/api/missing/internal": {"methods": ["GET"], "category": "api"}}, js=[])
    assert not result["findings"] and result["summary"]["dropped"]["catch_all"] == 1


def test_redirect_to_login_everywhere_is_a_wall():
    wall = (302, {"Location": "/login"}, b"")
    with FakeApp({"/wall/*": wall}) as app:
        result = _run(app, endpoints={"/wall/internal": {"methods": ["GET"], "category": "api"}}, js=[])
    assert not result["findings"] and result["summary"]["dropped"]["wall"] == 1


def test_big_body_read_stops_at_the_cap():
    def big():
        chunk = b"<p>" + b"a" * 65530 + b"</p>"
        for _ in range(320):     # ~20 MB
            yield chunk
    routes = {"/internal/big": (200, {"Content-Type": "text/html"}, big)}
    with FakeApp(routes) as app:
        start = time.monotonic()
        result = _run(app, endpoints={"/internal/big": {"methods": ["GET"], "category": "api"}}, js=[],
                      ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False)
        assert time.monotonic() - start < 20
    f = _by(result["findings"], "anonymous_access", "/internal/big")[0]
    assert f["anon_size_bucket"] == ">100k"


def test_slow_route_times_out_without_marking_the_host_down():
    routes = {"/internal/slow": slow(4, json_answer(200, USERS)), "/internal/users/export": json_answer(200, USERS)}
    with FakeApp(routes) as app:
        result = _run(app, endpoints={"/internal/slow": {"methods": ["GET"], "category": "api"},
                                      "/internal/users/export": {"methods": ["GET"], "category": "api"}},
                      js=[], ROUTE_EXPOSURE_TIMEOUT=2, ROUTE_EXPOSURE_WORKERS=1)
    assert _by(result["findings"], "anonymous_access", "/internal/users/export")
    assert result["summary"]["hosts_skipped"] == 0


def test_redirect_is_never_followed():
    routes = {"/internal/redirect": (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b"")}
    with FakeApp(routes) as app:
        result = _run(app, endpoints={"/internal/redirect": {"methods": ["GET"], "category": "api"}}, js=[])
    assert app.paths() == ["/internal/redirect"] * len(app.hits)
    assert result["summary"]["dropped"]["denied"] == 1


def test_a_cookie_set_by_an_answer_never_rides_on_a_later_request():
    trap = html_answer(200, b"<html><title>Trap</title>" + b"t" * 100 + b"</html>", **{"Set-Cookie": "sid=trap"})
    with FakeApp({"/cookie-trap": trap, "/internal/users/export": json_answer(200, USERS)}) as app:
        _run(app, endpoints={"/cookie-trap": {"methods": ["GET"]},
                             "/internal/users/export": {"methods": ["GET"]}},
             js=[], ROUTE_EXPOSURE_WORKERS=1)
    assert app.hits and not [h for h in app.hits if "cookie" in h.headers]


def test_rate_limited_route_backs_off_and_retries_once():
    state = {"n": 0}

    def limited(_hit):
        state["n"] += 1
        if state["n"] == 1:
            return json_answer(429, b"{}", **{"Retry-After": "1"})
        return json_answer(200, USERS)
    with FakeApp({"/internal/rate": limited}) as app:
        start = time.monotonic()
        result = _run(app, endpoints={"/internal/rate": {"methods": ["GET"]}}, js=[],
                      ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False)
        assert time.monotonic() - start >= 0.9
    assert _by(result["findings"], "anonymous_access", "/internal/rate")
    assert app.paths().count("/internal/rate") == 2


def test_a_reset_connection_costs_one_route_only():
    with FakeApp({"/internal/reset": lambda _h: "RESET", "/internal/users/export": json_answer(200, USERS)}) as app:
        result = _run(app, endpoints={"/internal/reset": {"methods": ["GET"]},
                                      "/internal/users/export": {"methods": ["GET"]}}, js=[])
    assert _by(result["findings"], "anonymous_access", "/internal/users/export")
    assert result["summary"]["error"] == ""


def test_hostile_snippet_is_masked_and_bounded():
    body = (b"<html><title>x</title><body><img src=x onerror=alert(1)> "
            b"a1@lab.invalid a2@lab.invalid a3@lab.invalid 12345678901234</body></html>")
    with FakeApp({"/xss-snippet": html_answer(200, body)}) as app:
        result = _run(app, endpoints={"/xss-snippet": {"methods": ["GET"]}}, js=[])
    snippets = [f["evidence_snippet"] for f in _by(result["findings"], path="/xss-snippet")]
    assert snippets and all(len(s) <= 120 for s in snippets)
    assert all("@lab.invalid" not in s and "1234567890" not in s for s in snippets)


def test_hostile_paths_never_crash_and_never_reach_stdout():
    weird = {"/" + "a" * 2000: {"methods": ["GET"]}, "/café/internal": {"methods": ["GET"]},
             "/a/../internal": {"methods": ["GET"]}, "/internal%2Fsecret": {"methods": ["GET"]}}
    buf = io.StringIO()
    with FakeApp({}) as app, contextlib.redirect_stdout(buf):
        result = _run(app, endpoints=weird, js=[])
    assert result["summary"]["error"] == ""
    assert "caf" not in buf.getvalue() and "127.0.0.1" not in buf.getvalue()


def test_huge_spec_is_bounded_by_the_budget_floor_first():
    endpoints = {f"/api/item{i}": {"methods": ["GET"], "category": "api"} for i in range(400)}
    endpoints["/internal/users/export"] = {"methods": ["GET"], "category": "api",
                                           "openapi": {"GET": {"security": ["k"]}}}
    with FakeApp({"/internal/users/export": json_answer(200, USERS)}) as app:
        result = _run(app, endpoints=endpoints, js=[], ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST=10,
                      ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False)
        first = app.hits[0].path
    assert result["summary"]["budget_cut"] == 391
    assert result["summary"]["routes_requested"] == 10
    assert first == "/internal/users/export"


def test_outsider_named_in_js_receives_nothing():
    with FakeApp({}, host="127.0.0.2") as outsider, FakeApp({"/": SPA}) as app:
        combined = corpus(app.base, js=[outsider.base + "/widget.js", outsider.base + "/api/internal"])
        run_route_exposure_isolated(combined, settings(ROUTE_EXPOSURE_SEED_PATHS=True))
    assert outsider.hits == []
    assert app.hits


def test_roe_excluded_host_receives_nothing():
    with FakeApp(MAIN) as app:
        result = _run(app, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["127.0.0.1"],
                      ROUTE_EXPOSURE_SEED_PATHS=True)
    assert app.hits == [] and result["findings"] == []
    assert result["summary"]["out_of_scope"] > 0


def test_closed_time_window_fails_closed(monkeypatch):
    from recon.helpers import roe_scope
    monkeypatch.setattr(roe_scope, "_check_roe_time_window", lambda s, _now=None: (False, "closed"))
    with FakeApp(MAIN) as app:
        result = _run(app)
    assert app.hits == [] and result["findings"] == []
    report = cb.coverage_report()
    assert "route_exposure" in report.gaps_json()


def test_a_window_check_that_raises_is_closed(monkeypatch):
    from recon.helpers import roe_scope

    def boom(*_a, **_k):
        raise RuntimeError("tz")
    monkeypatch.setattr(roe_scope, "_check_roe_time_window", boom)
    with FakeApp(MAIN) as app:
        _run(app)
    assert app.hits == []


def test_total_failure_is_degraded_never_raised(monkeypatch):
    from recon.route_exposure import harvest

    def boom(*_a, **_k):
        raise ValueError("http://secret.example/x")
    monkeypatch.setattr(harvest, "harvest", boom)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = run_route_exposure_isolated(corpus("http://127.0.0.1:1"), settings())["route_exposure"]
    assert result["findings"] == [] and result["summary"]["error"] == "ValueError"
    assert "secret.example" not in buf.getvalue()
    assert "route_exposure" in cb.coverage_report().gaps_json()


def test_stdout_is_phase_safe_and_names_no_target():
    buf = io.StringIO()
    with FakeApp(MAIN) as app, contextlib.redirect_stdout(buf):
        _run(app, ROUTE_EXPOSURE_SEED_PATHS=True, ROUTE_EXPOSURE_VCS_FILES=True,
             ROUTE_EXPOSURE_BACKUP_FILES=True, AUTH_PROFILE=BEARER)
    out = buf.getvalue()
    assert out.strip()
    for line in out.splitlines():
        assert line.startswith("[") and "[RouteExposure]" in line, line
        assert not _DRAWER.search(line), line
        assert "127.0.0.1" not in line and "/" not in line.split("]", 2)[-1], line


def test_isolated_wrapper_does_not_mutate_and_returns_top_level_keys(monkeypatch):
    from recon.helpers.isolated_result import TopLevelKeys
    combined = corpus("http://127.0.0.1:1")
    combined["jev_shadow"] = {"page_type": {"x": 1}}
    before = json.dumps(combined, sort_keys=True)

    def fake(snapshot, _settings):
        snapshot["route_exposure"] = {"summary": {}}
        snapshot["jev_shadow"]["route_exposure_assess"] = {"decisions": []}
        snapshot["jev_shadow"]["page_type"] = {"y": 2}
        return snapshot
    monkeypatch.setattr(scanner, "run_route_exposure", fake)
    out = scanner.run_route_exposure_isolated(combined, settings())
    assert isinstance(out, TopLevelKeys)
    assert out["route_exposure"] == {"summary": {}}
    assert out["jev_shadow"] == {"route_exposure_assess": {"decisions": []}}
    assert json.dumps(combined, sort_keys=True) == before


def test_no_request_is_ever_verified(monkeypatch):
    """T40: a self-signed internal host must not read as down."""
    seen = []
    real = requests.Session.request

    def spy(self, method, url, **kw):
        seen.append(kw.get("verify"))
        return real(self, method, url, **kw)
    monkeypatch.setattr(requests.Session, "request", spy)
    with FakeApp(MAIN) as app:
        _run(app, ROUTE_EXPOSURE_VCS_FILES=True, AUTH_PROFILE=BEARER)
    assert seen and set(seen) == {False}


# ---------------------------------------------------------------------------
# Auth profile types (plan §22.2 S2-S4)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("profile,header,value", [
    (COOKIE, "cookie", "sid=lab-user-1"),
    (HEADER, "x-api-key", "lab-key"),
])
def test_other_profile_types_compare_logged_in(profile, header, value):
    with FakeApp(MAIN) as app:
        result = _run(app, AUTH_PROFILE=profile)
    assert _by(result["findings"], "sensitive_data", "/api/users/me")
    authed = [h for h in app.hits if h.headers.get(header) == value]
    assert authed
    assert not [h for h in app.hits if h not in authed and header in h.headers]


def test_without_a_profile_nothing_is_sent_logged_in():
    with FakeApp(MAIN) as app:
        result = _run(app)
    assert not [h for h in app.hits if h.authed]
    assert not _by(result["findings"], "sensitive_data", "/api/users/me")
    assert all("bodies_match" not in f and "authed_status" not in f for f in result["findings"])
    assert _by(result["findings"], "anonymous_access", "/internal/users/export")
