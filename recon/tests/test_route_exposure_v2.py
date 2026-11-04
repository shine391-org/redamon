"""Route exposure v2 against a local fake app: the catalog follow-up, the git walk,
the CORS and cache riders, cross-host, client-gated routes, siblings and framework
seeds. Each test asserts the findings AND the requests the scan built."""

from __future__ import annotations

import json
import zlib

import pytest

from recon.helpers import circuit_breaker as cb
from recon.route_exposure import prober
from recon.route_exposure.scanner import run_route_exposure_isolated
from recon.tests.route_exposure_fakeapp import (
    BEARER, FakeApp, corpus, html_answer, json_answer, settings,
)

DENY = json_answer(401, b'{"error":"authentication required"}')
USERS = json.dumps([{"id": i, "email": f"user{i}@lab.invalid"} for i in range(12)]).encode()


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()
    cb.reset_registry()


def _run(combined, **kw):
    return run_route_exposure_isolated(combined, settings(**kw))["route_exposure"]


def _keys(result):
    return {(f["path"], f["exposure_kind"]): f for f in result["findings"]}


# ---------------------------------------------------------------------------
# Route catalogs (one follow-up round)
# ---------------------------------------------------------------------------

MAPPINGS = json.dumps({"contexts": {"app": {"mappings": {"dispatcherServlets": {"d": [
    {"details": {"requestMappingConditions": {"patterns": [p]}}}
    for p in ("/api/internal/billing/reconcile", "/api/internal/billing/close", "/users/{id}")]}}}}}).encode()
CATALOG_APP = {
    "/actuator/mappings": json_answer(200, MAPPINGS),
    "/api/internal/billing/reconcile": json_answer(200, json.dumps({"batch": [{"n": i} for i in range(9)]}).encode()),
    "/api/internal/billing/close": DENY,
}


@pytest.mark.parametrize("follow", [True, False])
def test_an_open_catalog_is_followed_once(follow):
    with FakeApp(CATALOG_APP) as app:
        result = _run(corpus(app.base, js=["/actuator/mappings"]), ROUTE_EXPOSURE_FOLLOW_CATALOGS=follow)
        paths = app.paths()
    got = _keys(result)
    assert ("/actuator/mappings", "route_catalog") in got
    if follow:
        f = got[("/api/internal/billing/reconcile", "anonymous_access")]
        assert f["generated_by"] == "catalog"
        assert not any(k[0] == "/api/internal/billing/close" for k in got)
        assert result["summary"]["catalogs_followed"] == 1
        assert not any("{id}" in p for p in paths)
    else:
        assert "/api/internal/billing/reconcile" not in paths


# ---------------------------------------------------------------------------
# Git walk proof
# ---------------------------------------------------------------------------

COMMIT = "c" * 40
TREE = "d" * 40


def _git_app(obj_body):
    return {
        "/.git/HEAD": (200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n"),
        "/.git/refs/heads/main": (200, {"Content-Type": "text/plain"}, COMMIT.encode() + b"\n"),
        f"/.git/objects/{COMMIT[:2]}/{COMMIT[2:]}": (200, {"Content-Type": "application/octet-stream"}, obj_body),
    }


def test_git_walk_stores_the_proof_and_never_fetches_the_tree():
    obj = zlib.compress(b"commit 60\x00tree " + TREE.encode() + b"\nauthor lab\n\nmsg\n")
    with FakeApp(_git_app(obj)) as app:
        result = _run(corpus(app.base), ROUTE_EXPOSURE_VCS_FILES=True, ROUTE_EXPOSURE_GIT_WALK=True)
        paths = app.paths()
    head = _keys(result)[("/.git/HEAD", "vcs_exposure")]
    assert head["git_walk_proof"] == "head>ref>commit" and head["git_tree_prefix"] == TREE[:8]
    objects = [p for p in paths if p.startswith("/.git/objects/")]
    assert objects == [f"/.git/objects/{COMMIT[:2]}/{COMMIT[2:]}"]


def test_git_walk_off_sends_no_ref_or_object():
    obj = zlib.compress(b"commit 1\x00tree " + TREE.encode() + b"\n")
    with FakeApp(_git_app(obj)) as app:
        result = _run(corpus(app.base), ROUTE_EXPOSURE_VCS_FILES=True, ROUTE_EXPOSURE_GIT_WALK=False)
        paths = app.paths()
    assert "git_walk_proof" not in _keys(result)[("/.git/HEAD", "vcs_exposure")]
    assert not any(p.startswith("/.git/objects/") or p.startswith("/.git/refs/") for p in paths)


def test_a_zlib_bomb_is_bounded_and_yields_no_proof():
    comp = zlib.compressobj()
    bomb = b"".join(comp.compress(b"\0" * (1 << 20)) for _ in range(64)) + comp.flush()
    with FakeApp(_git_app(bomb)) as app:
        result = _run(corpus(app.base), ROUTE_EXPOSURE_VCS_FILES=True, ROUTE_EXPOSURE_GIT_WALK=True)
    head = _keys(result)[("/.git/HEAD", "vcs_exposure")]
    assert "git_walk_proof" not in head and result["summary"]["error"] == ""


# ---------------------------------------------------------------------------
# CORS and cache riders
# ---------------------------------------------------------------------------

def _profile(cors="reflect", cache="public, max-age=600", x_cache="MISS"):
    def handler(hit):
        if hit.headers.get("authorization") != "Bearer lab-token":
            return DENY
        headers = {"Content-Type": "application/json", "Cache-Control": cache}
        if x_cache:
            headers["X-Cache"] = x_cache
        origin = hit.headers.get("origin")
        if cors == "reflect" and origin:
            headers.update({"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"})
        elif cors == "star":
            headers["Access-Control-Allow-Origin"] = "*"
        return (200, headers, json.dumps({"email": "user1@lab.invalid", "role": "member",
                                          "permissions": ["read"], "note": "p" * 40}).encode())
    return handler


def test_riders_flag_a_credentialed_reflection_and_cacheable_logged_in_content():
    with FakeApp({"/api/profile": _profile()}) as app:
        result = _run(corpus(app.base, js=["/api/profile"]), AUTH_PROFILE=BEARER,
                      ROUTE_EXPOSURE_CORS_RIDER=True, ROUTE_EXPOSURE_CACHE_RIDER=True)
        hits = list(app.hits)
    got = _keys(result)
    cors = got[("/api/profile", "cors_misconfig")]
    assert set(cors["cors_variants"]) == {"reflected", "null", "suffix", "prefix"}
    assert cors["needs_agent_confirmation"] is True and cors["severity"] == "info"
    cache = got[("/api/profile", "auth_cacheable")]
    assert "cache-control:public" in cache["cache_signals"]
    origins = [h.headers.get("origin") for h in hits if h.headers.get("origin")]
    assert len(origins) == 4 and all(h.authed for h in hits if h.headers.get("origin"))


def test_riders_off_send_no_origin():
    with FakeApp({"/api/profile": _profile()}) as app:
        result = _run(corpus(app.base, js=["/api/profile"]), AUTH_PROFILE=BEARER)
        hits = list(app.hits)
    assert not any(k[1] in ("cors_misconfig", "auth_cacheable") for k in _keys(result))
    assert not any(h.headers.get("origin") for h in hits)


def test_a_wildcard_without_credentials_and_a_private_answer_are_not_flagged():
    with FakeApp({"/api/profile": _profile(cors="star", cache="private, max-age=0")}) as app:
        result = _run(corpus(app.base, js=["/api/profile"]), AUTH_PROFILE=BEARER,
                      ROUTE_EXPOSURE_CORS_RIDER=True, ROUTE_EXPOSURE_CACHE_RIDER=True)
    assert not any(k[1] in ("cors_misconfig", "auth_cacheable") for k in _keys(result))


def test_riders_skip_a_route_that_answers_anyone_the_same():
    public = json_answer(200, json.dumps({"items": [{"role": "a", "n": i} for i in range(9)]}).encode(),
                         **{"Access-Control-Allow-Origin": "https://evil.invalid",
                            "Access-Control-Allow-Credentials": "true"})
    with FakeApp({"/api/catalog": public}) as app:
        _run(corpus(app.base, js=["/api/catalog"]), AUTH_PROFILE=BEARER, ROUTE_EXPOSURE_CORS_RIDER=True)
        hits = list(app.hits)
    assert not any(h.headers.get("origin") for h in hits)


# ---------------------------------------------------------------------------
# Cross-host
# ---------------------------------------------------------------------------

LANDING = html_answer(200, b"<html><head><title>Lab Portal</title></head><body>" + b"hi " * 40 + b"</body></html>")


def _two_hosts(app_a, app_b):
    combined = corpus(app_a.base, js=["/internal/users/export"])
    for app in (app_a, app_b):
        combined["http_probe"]["by_url"][app.base] = {"url": app.base, "status_code": 200,
                                                      "title": "Lab Portal", "technologies": []}
    combined["resource_enum"]["by_base_url"][app_b.base] = {"endpoints": {}}
    return combined


@pytest.mark.parametrize("cross", [True, False])
def test_cross_host_tries_a_hit_path_on_a_twin_host(cross):
    with FakeApp({"/": LANDING, "/internal/users/export": json_answer(200, USERS)}) as a, \
            FakeApp({"/": LANDING, "/internal/users/export": json_answer(200, USERS)}) as b:
        result = _run(_two_hosts(a, b), ROUTE_EXPOSURE_CROSS_HOST=cross)
        b_paths = b.paths()
    twin = [f for f in result["findings"] if f["baseurl"] == b.base and f["path"] == "/internal/users/export"]
    if cross:
        assert twin and all(f["generated_by"] == "cross_host" for f in twin)
        assert result["summary"]["cross_host_routes"] >= 1
    else:
        assert not twin and "/internal/users/export" not in b_paths


# ---------------------------------------------------------------------------
# Client-gated routes, siblings, framework seeds
# ---------------------------------------------------------------------------

def test_an_api_the_router_bundle_calls_is_client_gated():
    app_routes = {"/api/admin/stats": json_answer(200, json.dumps({"users": 12, "revenue": [1, 2, 3], "x": "y" * 60}).encode()),
                  "/api/orders": json_answer(200, USERS)}
    with FakeApp(app_routes) as app:
        combined = corpus(app.base, js=["/api/admin/stats", "/api/orders"])
        combined["js_recon"]["endpoints"].append({"type": "route", "method": "GET", "path": "/admin/dashboard",
                                                  "full_url": "/admin/dashboard",
                                                  "source_js": app.base + "/static/app.js", "category": "admin"})
        result = _run(combined)
    got = _keys(result)
    assert got[("/api/admin/stats", "anonymous_access")]["route_class"] == "client_gated"
    assert got[("/api/orders", "anonymous_access")]["route_class"] != "client_gated"


def test_a_sibling_collection_is_found_and_becomes_an_endpoint():
    with FakeApp({"/api/orders/7": DENY, "/api/orders": json_answer(200, USERS)}) as app:
        result = _run(corpus(app.base, js=["/api/orders/7"]), ROUTE_EXPOSURE_SIBLINGS=True)
    got = _keys(result)
    assert got[("/api/orders", "sensitive_data")]["generated_by"] == "sibling"
    assert any(e["path"] == "/api/orders" and e["generated_by"] == "sibling" for e in result["new_endpoints"])


def test_framework_seeds_follow_technologies_and_read_the_heap_dump_with_head_only():
    heap = (200, {"Content-Type": "application/octet-stream"}, b"JAVA PROFILE 1.0.2\0" + b"\0" * 4000)
    with FakeApp({"/actuator/heapdump": heap}) as app:
        result = _run(corpus(app.base, technologies=["Spring Boot"]), ROUTE_EXPOSURE_FRAMEWORK_SEEDS=True)
        hits = list(app.hits)
    assert ("/actuator/heapdump", "debug_endpoint") in _keys(result)
    heap_hits = [h for h in hits if h.path == "/actuator/heapdump"]
    assert heap_hits and all(h.method == "HEAD" for h in heap_hits)
    assert not any(e["path"] == "/actuator/heapdump" for e in result["new_endpoints"])


def test_siblings_off_generate_no_sibling():
    with FakeApp({"/api/orders/7": DENY, "/api/orders": json_answer(200, USERS)}) as app:
        _run(corpus(app.base, js=["/api/orders/7"]), ROUTE_EXPOSURE_SIBLINGS=False)
        paths = app.paths()
    assert paths and "/api/orders" not in paths


def test_framework_seeds_off_request_no_framework_path():
    with FakeApp({}) as app:
        _run(corpus(app.base, technologies=["Spring Boot"]), ROUTE_EXPOSURE_FRAMEWORK_SEEDS=False)
        paths = app.paths()
    assert not any(p.startswith("/actuator") for p in paths)
