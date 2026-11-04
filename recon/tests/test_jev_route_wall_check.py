"""Disguised login wall and error page check on Jev (route exposure, hook B).

What it locks in:
- Kind B gating: no request unless AI_IN_PIPELINE and ROUTE_EXPOSURE_JEV_WALL_CHECK;
- it reuses page_type's request item and the agent's page-type route, and writes its
  OWN shadow key, so the page-type hook of the same run keeps its records;
- alike pages are asked once, batched, capped, and inside a time budget;
- a malformed answer or a failed batch is a fallback, never a raise, never re-asked,
  and annotates nothing;
- ACT writes Jev's page class onto each lead of an answered page (anon_page_class*),
  and records the prefilter's label ("app" when it placed nothing) beside Jev's;
- is_wall needs a wall class at confidence >= WALL_CONFIDENCE, and the wall classes
  are the ones route exposure's own prefilter drops;
- stdout carries counts only.
"""
from __future__ import annotations

from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow, page_type
from recon.helpers.ai_planner import route_wall_check as rw

ON = {"AI_IN_PIPELINE": True, "ROUTE_EXPOSURE_JEV_WALL_CHECK": True}


@pytest.fixture(autouse=True)
def _fresh_breakers():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _post(label=("login_only", 85), status=200, body=None):
    calls = []

    def post(url, json=None, headers=None, timeout=None):
        calls.append((url, json))
        if status != 200:
            return _resp(status, {"error_type": "jev_timeout"})
        if body is not None:
            return _resp(200, body)
        return _resp(200, {"labels": [{"page_class": label[0], "confidence": label[1]}
                                      for _ in json["pages"]], "model": "jev-1.13.0"})
    return calls, post


def _entry(i=0, body="Welcome to the records portal. " * 20, title="Records"):
    return {"url": f"http://app.example.test/p{i}", "host": "app.example.test", "status_code": 200,
            "content_length": len(body), "content_type": "text/html", "title": title,
            "server": "nginx", "headers": {}, "word_count": len(body.split()), "body": body + str(i)}


def _pairs(entries):
    return [({"path": f"/p{i}", "exposure_kind": "anonymous_access", "needs_agent_confirmation": True},
             entry) for i, entry in enumerate(entries)]


@pytest.mark.parametrize("settings", [{}, {"AI_IN_PIPELINE": True},
                                      {"ROUTE_EXPOSURE_JEV_WALL_CHECK": True}])
def test_nothing_is_sent_unless_both_switches_are_on(settings):
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        assert rw.run_for_pages(_pairs([_entry()]), settings, {})["asked"] == 0
    assert calls == []


def test_it_posts_page_type_items_to_the_page_type_route_under_its_own_key():
    calls, post = _post()
    recon = {"jev_shadow": {"page_type": {"records": ["kept"]}}}
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = rw.run_for_pages(_pairs([_entry(0)]), ON, recon)
    url, payload = calls[0]
    assert url.endswith("/jev/page-type")
    assert payload["pages"][0] == page_type._page(_entry(0))
    assert stats == {"pages": 1, "asked": 1, "failed_batches": 0}
    assert recon["jev_shadow"]["page_type"] == {"records": ["kept"]}
    record = recon["jev_shadow"][rw.HOOK]["records"][0]
    assert (record["item"], record["jev"], record["conf"]) == ("page_0", "login_only", 85)
    assert record["baseline"] == (page_type.prefilter(_entry(0)) or "app")


def test_pages_are_batched_and_capped():
    entries = [_entry(i) for i in range(rw.MAX_PAGES_PER_SCAN + 7)]
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = rw.run_for_pages(_pairs(entries), ON, {})
    assert all(len(p["pages"]) <= rw.BATCH_SIZE for _, p in calls)
    assert sum(len(p["pages"]) for _, p in calls) == stats["asked"] <= rw.MAX_PAGES_PER_SCAN


def test_the_time_budget_stops_further_batches():
    ticks = iter([0.0, 0.0] + [rw.TIME_BUDGET_S + 1.0] * 50)   # start, batch 1, then over
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = rw.run_for_pages(_pairs([_entry(i) for i in range(12)]), ON, {}, clock=lambda: next(ticks))
    assert len(calls) == 1 and stats["asked"] == rw.BATCH_SIZE


@pytest.mark.parametrize("body", [{"labels": []}, {"labels": [{"page_class": "gibberish", "confidence": 90}]},
                                  {"nope": 1}])
def test_a_malformed_answer_is_a_fallback(body):
    calls, post = _post(body=body)
    recon = {}
    pairs = _pairs([_entry()])
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = rw.run_for_pages(pairs, ON, recon)
    assert stats["failed_batches"] == 1 and stats["asked"] == 0
    assert recon["jev_shadow"][rw.HOOK]["summary"]["fallbacks"] == 1
    assert "anon_page_class" not in pairs[0][0]


def test_a_failed_batch_is_not_re_asked_and_never_raises():
    calls, post = _post(status=503)
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = rw.run_for_pages(_pairs([_entry(i) for i in range(2)]), ON, {})
    assert len(calls) == 1 and stats["failed_batches"] == 1


def test_stdout_never_carries_a_url_or_a_title(capsys):
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        rw.run_for_pages(_pairs([_entry(0, title="Secret Title")]), ON, {})
    out = capsys.readouterr().out
    assert "app.example.test" not in out and "Secret Title" not in out


def test_the_hook_acts():
    assert rw.ROLLOUT == jev_shadow.ACT


def test_act_writes_the_page_class_onto_every_lead_of_an_answered_page():
    same = _entry(0)
    twin = dict(same, url="http://app.example.test/other")   # same page, other route
    pairs = _pairs([same, twin])
    calls, post = _post(label=("login_only", 88))
    recon = {}
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        rw.run_for_pages(pairs, ON, recon)
    assert len(calls) == 1 and len(calls[0][1]["pages"]) == 1
    for finding, _ in pairs:
        assert (finding["anon_page_class"], finding["anon_page_class_confidence"],
                finding["anon_page_class_source"]) == ("login_only", 88, "jev_classifier")
        assert finding["needs_agent_confirmation"] is True     # annotated, never dropped
    assert recon["jev_shadow"][rw.HOOK]["rollout"] == "act"


@pytest.mark.parametrize("cls,conf,wall", [
    ("login_only", 70, True), ("error", 95, True), ("placeholder", 80, True),
    ("login_only", 69, False), ("app", 99, False), ("login_only", True, False), (None, 90, False)])
def test_is_wall_needs_a_wall_class_at_the_confidence_floor(cls, conf, wall):
    assert rw.is_wall({"anon_page_class": cls, "anon_page_class_confidence": conf}) is wall


def test_the_wall_classes_are_the_ones_the_scan_drops_itself():
    from recon.route_exposure import verdict
    assert rw.WALL_CLASSES == verdict.WALL_CLASSES


def test_the_agents_lead_query_demotes_the_same_classes_at_the_same_floor():
    """The agent cannot import recon; its query names the classes and the floor as literals."""
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "agentic" / "prompts" / "route_exposure_shared.py").read_text()
    listed = re.search(r"v\.anon_page_class IN \[([^\]]*)\]", src).group(1)
    assert set(re.findall(r"'([a-z_]+)'", listed)) == set(rw.WALL_CLASSES)
    assert f"coalesce(v.anon_page_class_confidence, 0) >= {rw.WALL_CONFIDENCE}" in src
    from recon.helpers.ai_planner import route_exposure_assess as ra
    assert f"coalesce(v.route_jev_kind_confidence, 0) >= {ra.PUBLIC_CONFIDENCE}" in src
