"""The three Jev hooks inside a real route exposure run (ACT).

The hook modules are unit-tested on their own; this drives the scanner end to end
against a loopback app, with Jev answering through a mocked agent, and locks in:
- with AI in Pipeline and the three flags on, each hook leaves its record under
  jev_shadow.<hook> in the run's output, rollout act, with no fallback;
- the hooks annotate and order, never add or drop: the findings are the same set as
  a run with the hooks off, each lead carries Jev's kind and sensitivity, the HTML
  lead its page class, and every asked route's finding its privacy reading;
- the leads are ordered most sensitive first, and a lead Jev places as a wall goes
  last however sensitive;
- Jev's privacy answer decides which routes the per-host budget requests;
- a hook that raises is reported in one log line and the scan completes unchanged.
"""
from __future__ import annotations

import contextlib
import io
import json
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.route_exposure import prober, run_route_exposure_isolated
from recon.tests.route_exposure_fakeapp import FakeApp, corpus, html_answer, json_answer, settings

USERS = json.dumps([{"id": i, "email": f"user{i}@lab.invalid"} for i in range(20)]).encode()
ROUTES = {
    "/": html_answer(200, b"<html><title>Lab</title><body>" + b"welcome " * 30 + b"</body></html>"),
    "/internal/users/export": json_answer(200, USERS),
    "/admin/overview": html_answer(200, b"<html><title>Overview</title><body>" + b"stats " * 40
                                        + b"</body></html>"),
    "/.env": (200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=LAB-NOT-A-SECRET-1\nAPP_ENV=lab\n"),
}
ENDPOINTS = {
    "/internal/users/export": {"methods": ["GET"], "category": "file_access", "sources": ["katana"]},
    "/admin/overview": {"methods": ["GET"], "category": "admin", "sources": ["katana"]},
}
HOOKS_ON = {"AI_IN_PIPELINE": True, "ROUTE_EXPOSURE_JEV_RANK": True,
            "ROUTE_EXPOSURE_JEV_WALL_CHECK": True, "ROUTE_EXPOSURE_JEV_ASSESS": True}


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()
    cb.reset_registry()


def _agent(page_class=("app", 80), sensitivity=lambda path: 85, privacy=lambda path: 0.8):
    """A mocked agent answering the three /jev routes; each answer may depend on the item."""
    def post(url, json=None, headers=None, timeout=None):
        r = mock.MagicMock(status_code=200, text="")
        if url.endswith("/jev/route-privacy-rank"):
            body = {"scores": [privacy(i["path"]) for i in json["routes"]], "model": "jev-1.13.0"}
        elif url.endswith("/jev/page-type"):
            body = {"labels": [{"page_class": page_class[0], "confidence": page_class[1]}
                               for _ in json["pages"]], "model": "jev-1.13.0"}
        elif url.endswith("/jev/route-exposure-assess"):
            body = {"labels": [{"kind": "data_export", "kind_confidence": 90,
                                "sensitivity": sensitivity(c["path"])} for c in json["candidates"]],
                    "model": "jev-1.13.0"}
        else:
            raise AssertionError(f"unexpected agent call {url}")
        r.json.return_value = body
        return r
    return post


def _run(routes=None, endpoints=None, **extra):
    with FakeApp(ROUTES if routes is None else routes) as app:
        combined = corpus(app.base, endpoints=ENDPOINTS if endpoints is None else endpoints, js=[])
        out = run_route_exposure_isolated(combined, settings(**{"ROUTE_EXPOSURE_VCS_FILES": True, **extra}))
        requested = app.paths("GET")
    prober._reset_pacer()
    return out, requested


def _shape(findings):
    keys = ("path", "exposure_kind", "route_class", "needs_agent_confirmation", "severity",
            "auth_expected_by", "generated_by", "leak_signals")
    return sorted(json.dumps({k: f.get(k) for k in keys}, sort_keys=True) for f in findings)


def _leads(out):
    return [f for f in out["route_exposure"]["findings"] if f.get("needs_agent_confirmation")]


def test_the_hooks_act_and_annotate_without_adding_or_dropping_a_finding():
    off, _ = _run()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=_agent()) as post:
        on, _ = _run(**HOOKS_ON)
    called = {c.args[0].rsplit("/", 1)[-1] for c in post.call_args_list}
    assert called == {"route-privacy-rank", "page-type", "route-exposure-assess"}
    assert "jev_shadow" not in off
    records = on["jev_shadow"]
    for hook in ("route_privacy_rank", "route_exposure_wall", "route_exposure_assess"):
        assert records[hook]["rollout"] == "act", hook
        assert records[hook]["summary"]["fallbacks"] == 0, hook
        assert records[hook]["summary"]["decisions"] > 0, hook
    assert _shape(on["route_exposure"]["findings"]) == _shape(off["route_exposure"]["findings"])
    assert on["route_exposure"]["findings"]

    leads = _leads(on)
    assert leads
    for lead in leads:
        assert (lead["route_jev_kind"], lead["route_jev_kind_confidence"], lead["route_jev_sensitivity"],
                lead["route_jev_source"]) == ("data_export", 90, 85, "jev_classifier")
    html = [f for f in leads if f["exposure_kind"] == "anonymous_access" and f["anon_content_class"] == "html"]
    assert html and all((f["anon_page_class"], f["anon_page_class_source"]) == ("app", "jev_classifier")
                        for f in html)
    assert all(f["route_jev_privacy"] == 80 for f in on["route_exposure"]["findings"]
               if f["generated_by"] == "found")
    # With the hooks off nothing carries a Jev field.
    assert not any(k.startswith(("route_jev_", "anon_page_class"))
                   for f in off["route_exposure"]["findings"] for k in f)


def test_the_leads_are_ordered_most_sensitive_first():
    def sensitivity(path):
        return 95 if path == "/admin/overview" else 30
    with mock.patch.object(jev_shadow.requests, "post", side_effect=_agent(sensitivity=sensitivity)):
        on, _ = _run(AI_IN_PIPELINE=True, ROUTE_EXPOSURE_JEV_ASSESS=True)
    order = [f["route_jev_sensitivity"] for f in _leads(on)]
    assert order == sorted(order, reverse=True) and order[0] == 95 and order[-1] == 30


def test_a_lead_jev_places_as_a_wall_goes_last_however_sensitive():
    def sensitivity(path):
        return 95 if path == "/admin/overview" else 30
    with mock.patch.object(jev_shadow.requests, "post",
                           side_effect=_agent(page_class=("login_only", 90), sensitivity=sensitivity)):
        on, _ = _run(**HOOKS_ON)
    leads = _leads(on)
    walls = [i for i, f in enumerate(leads) if f.get("anon_page_class") == "login_only"]
    assert walls and walls == list(range(len(leads) - len(walls), len(leads)))
    assert all(leads[i]["path"] == "/admin/overview" for i in walls)
    assert all(f["needs_agent_confirmation"] for f in leads)          # moved, never dropped


def test_jevs_privacy_answer_picks_what_the_budget_requests():
    endpoints = {f"/p{i:02d}": {"methods": ["GET"], "category": "other", "sources": ["katana"]}
                 for i in range(20)}
    wanted = {"/p17", "/p18", "/p19"}
    knobs = dict(ROUTE_EXPOSURE_VCS_FILES=False, ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST=10)

    _, plain = _run(routes={}, endpoints=endpoints, **knobs)
    assert not wanted & set(plain)                    # the prior order never reaches them
    with mock.patch.object(jev_shadow.requests, "post",
                           side_effect=_agent(privacy=lambda p: 0.95 if p in wanted else 0.1)):
        out, ranked = _run(routes={}, endpoints=endpoints,
                           AI_IN_PIPELINE=True, ROUTE_EXPOSURE_JEV_RANK=True, **knobs)
    assert wanted <= set(ranked)
    assert len(set(ranked)) == len(set(plain))        # same budget, other routes
    assert out["route_exposure"]["summary"]["budget_cut"] > 0


def test_with_jev_down_the_run_is_the_deterministic_one():
    off, plain = _run()
    down = mock.MagicMock(status_code=503, text="")
    down.json.return_value = {"error_type": "jev_unavailable"}
    with mock.patch.object(jev_shadow.requests, "post", return_value=down):
        on, requested = _run(**HOOKS_ON)
    def routes_only(paths):          # the catch-all control path is random per run
        return sorted(p for p in paths if "/rdm-" not in p)
    assert routes_only(requested) == routes_only(plain)
    def portless(findings):          # each FakeApp listens on its own port
        return [json.dumps({k: v for k, v in f.items() if k not in ("baseurl", "endpoint_url")},
                           sort_keys=True) for f in findings]
    assert portless(on["route_exposure"]["findings"]) == portless(off["route_exposure"]["findings"])
    assert all(on["jev_shadow"][h]["summary"]["fallbacks"] >= 1 for h in on["jev_shadow"])


@pytest.mark.parametrize("target,line", [
    ("recon.helpers.ai_planner.route_privacy_rank.run_for_routes", "Jev ranking skipped"),
    ("recon.helpers.ai_planner.route_wall_check.run_for_pages", "Jev wall check skipped"),
    ("recon.helpers.ai_planner.route_exposure_assess.run_for_candidates", "Jev assessment skipped"),
])
def test_a_hook_that_raises_is_logged_and_the_scan_completes(target, line):
    off, _ = _run()
    out = io.StringIO()
    with mock.patch(target, side_effect=RuntimeError("boom")), \
            mock.patch.object(jev_shadow.requests, "post", side_effect=_agent()), \
            contextlib.redirect_stdout(out):
        on, _ = _run(**HOOKS_ON)
    assert f"[!][RouteExposure] {line} (RuntimeError)" in out.getvalue()
    assert _shape(on["route_exposure"]["findings"]) == _shape(off["route_exposure"]["findings"])
