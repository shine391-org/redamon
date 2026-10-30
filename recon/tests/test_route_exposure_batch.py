"""Domain-batch behaviour: one Phase A per scope group, in sequence, in one process (plan §9.4)."""

from __future__ import annotations

import json

import pytest

from recon.helpers import circuit_breaker as cb
from recon.route_exposure import prober, run_route_exposure_isolated
from recon.tests.route_exposure_fakeapp import FakeApp, corpus, json_answer, settings

USERS = json.dumps([{"id": i, "email": f"u{i}@lab.invalid"} for i in range(5)]).encode()
ROUTES = {"/internal/users/export": json_answer(200, USERS)}
# Declared secured, so it is in the floor and always inside the 10-route cap.
ENDPOINTS = {"/internal/users/export": {"methods": ["GET"], "openapi": {"GET": {"security": ["k"]}}}}


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()


def test_two_groups_stay_in_their_own_hosts_with_their_own_caps():
    with FakeApp(ROUTES) as a, FakeApp(ROUTES, host="127.0.0.2") as b:
        # Both groups run under one project's settings; each group's own
        # corpus names the other group's host in its JS.
        shared = settings(TARGET_IPS=["127.0.0.1", "127.0.0.2"], ROUTE_EXPOSURE_SEED_PATHS=True,
                          ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST=10)
        group_a = corpus(a.base, endpoints=ENDPOINTS, js=[b.base + "/internal/users/export"])
        group_b = corpus(b.base, endpoints=ENDPOINTS, js=[a.base + "/internal/users/export"],
                         ip="127.0.0.2")
        pacer = prober._pacer_for(shared["ROUTE_EXPOSURE_MAX_RPS"])
        out_a = run_route_exposure_isolated(group_a, shared)["route_exposure"]
        hits_a = (len(a.hits), len(b.hits))
        clock_after_a = pacer._next
        out_b = run_route_exposure_isolated(group_b, shared)["route_exposure"]
        assert prober._pacer_for(1) is pacer, "the pacer must not reset between groups"
        assert pacer._next > clock_after_a

    assert hits_a[1] == 0, "group A requested group B's host"
    assert len(a.hits) == hits_a[0], "group B requested group A's host"
    for out in (out_a, out_b):
        assert out["summary"]["routes_requested"] == 10       # the cap applies per group
        assert out["summary"]["out_of_scope"] == 1
        assert any(f["path"] == "/internal/users/export" for f in out["findings"])
    assert {f["baseurl"] for f in out_a["findings"]} == {a.base}
    assert {f["baseurl"] for f in out_b["findings"]} == {b.base}


def test_cross_host_never_crosses_scope_groups():
    """Group A's hit path is never tried on group B's host, even with cross-host on and
    both hosts sharing a title: each group's run knows only its own hosts."""
    landing = (200, {"Content-Type": "text/html"},
               b"<html><head><title>Same</title></head><body>" + b"x " * 40 + b"</body></html>")
    with FakeApp({**ROUTES, "/": landing}) as a, FakeApp({**ROUTES, "/": landing}, host="127.0.0.2") as b:
        shared = settings(TARGET_IPS=["127.0.0.1", "127.0.0.2"], ROUTE_EXPOSURE_CROSS_HOST=True)
        group_a = corpus(a.base, endpoints=ENDPOINTS)
        group_a["http_probe"]["by_url"][a.base]["title"] = "Same"
        out_a = run_route_exposure_isolated(group_a, shared)["route_exposure"]
    assert len(b.hits) == 0
    assert out_a["summary"]["cross_host_routes"] == 0
