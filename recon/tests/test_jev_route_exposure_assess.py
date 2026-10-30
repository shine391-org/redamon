"""Route exposure lead assessment on Jev (route exposure, hook C).

What it locks in:
- Kind B gating: no request unless AI_IN_PIPELINE and ROUTE_EXPOSURE_JEV_ASSESS;
- the item is evidence only and closed: no route_class, no signature, no value; an
  unknown content class, bucket, signal, hint or generator is clamped or dropped;
- only leads (needs_agent_confirmation) are asked, batched, capped, in a time budget;
- a malformed answer or a failed batch is a fallback, never a raise, and annotates
  nothing;
- ACT writes Jev's kind and sensitivity onto the lead (route_jev_*), never touches
  route_class or any other field, and records Jev's kind beside route_class mapped
  into the same closed set;
- is_public needs public_content at confidence >= PUBLIC_CONFIDENCE;
- stdout carries counts only; the call sits in the shared entry.
"""
from __future__ import annotations

import copy
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.helpers.ai_planner import route_exposure_assess as ra

ON = {"AI_IN_PIPELINE": True, "ROUTE_EXPOSURE_JEV_ASSESS": True}


@pytest.fixture(autouse=True)
def _fresh_breakers():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _post(label=("data_export", 80, 90), status=200, body=None):
    calls = []

    def post(url, json=None, headers=None, timeout=None):
        calls.append(json)
        if status != 200:
            return _resp(status, {"error_type": "jev_timeout"})
        if body is not None:
            return _resp(200, body)
        return _resp(200, {"labels": [{"kind": label[0], "kind_confidence": label[1], "sensitivity": label[2]}
                                      for _ in json["candidates"]], "model": "jev-1.13.0"})
    return calls, post


def _finding(i=0, **over):
    f = {"baseurl": "http://app.example.test", "path": f"/internal/users/export{i}",
         "exposure_kind": "anonymous_access", "route_class": "data_export",
         "needs_agent_confirmation": True, "anon_status": 200, "authed_status": 200,
         "anon_content_class": "json", "anon_size_bucket": "1-10k", "bodies_match": True,
         "leak_signals": ["pii_others"], "auth_expected_by": ["path_word"], "generated_by": "found",
         "signature": "users_export", "snippet": "keys: users[].email"}
    f.update(over)
    return f


def _pairs(findings):
    return [(f, ra.item_for(f, ["users[].email", "users[].role"], 50)) for f in findings]


@pytest.mark.parametrize("settings", [{}, {"AI_IN_PIPELINE": True},
                                      {"ROUTE_EXPOSURE_JEV_ASSESS": True}])
def test_nothing_is_sent_unless_both_switches_are_on(settings):
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        assert ra.run_for_candidates(_pairs([_finding()]), settings, {})["asked"] == 0
    assert calls == []


def test_the_item_is_evidence_only():
    item = ra.item_for(_finding(), ["users[].email"], 50)
    assert set(item) == {"path", "method", "anon_status", "authed_status", "content_class", "size_bucket",
                         "bodies_match", "key_paths", "max_array_len", "det_signals", "auth_expected_by",
                         "generated_by"}
    assert "data_export" not in str(item) and "users_export" not in str(item)


def test_the_item_clamps_every_closed_field_and_bounds_the_rest():
    odd = _finding(anon_status=True, authed_status=5000, anon_content_class="pdf", anon_size_bucket="huge",
                   bodies_match="yes", leak_signals=["pii", "ssn"], auth_expected_by=["path_word", "vibes"],
                   generated_by="guess", path="/" + "p" * 500)
    item = ra.item_for(odd, ["k" * 200] * 100, -3)
    assert item["anon_status"] == 0 and item["authed_status"] is None
    assert (item["content_class"], item["size_bucket"], item["bodies_match"]) == ("other", "<1k", None)
    assert item["det_signals"] == ["pii"] and item["auth_expected_by"] == ["path_word"]
    assert item["generated_by"] == "found" and len(item["path"]) == ra.MAX_PATH_CHARS
    assert len(item["key_paths"]) == ra.MAX_KEY_PATHS and all(len(k) == ra.MAX_KEY_CHARS for k in item["key_paths"])
    assert item["max_array_len"] == 0


def test_only_leads_are_asked_batched_and_capped():
    findings = [_finding(i) for i in range(ra.MAX_CANDIDATES_PER_SCAN + 5)]
    findings.append(_finding(999, needs_agent_confirmation=False))
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post), \
            mock.patch.object(ra, "TIME_BUDGET_S", 10 ** 6):
        stats = ra.run_for_candidates(_pairs(findings), ON, {})
    assert stats["candidates"] == ra.MAX_CANDIDATES_PER_SCAN + 5
    assert stats["asked"] == ra.MAX_CANDIDATES_PER_SCAN and stats["not_asked"] == 5
    assert all(len(c["candidates"]) <= ra.BATCH_SIZE for c in calls)
    assert all("export999" not in c["path"] for call in calls for c in call["candidates"])


def test_the_time_budget_counts_what_is_left_unasked():
    ticks = iter([0.0, 0.0] + [ra.TIME_BUDGET_S + 1.0] * 50)
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = ra.run_for_candidates(_pairs([_finding(i) for i in range(10)]), ON, {},
                                      clock=lambda: next(ticks))
    assert len(calls) == 1 and stats["asked"] == ra.BATCH_SIZE and stats["not_asked"] == 10 - ra.BATCH_SIZE


@pytest.mark.parametrize("body", [
    {"labels": []},
    {"labels": [{"kind": "client_gated", "kind_confidence": 80, "sensitivity": 80}]},   # not in KINDS
    {"labels": [{"kind": "data_export", "kind_confidence": 101, "sensitivity": 80}]},
    {"labels": [{"kind": "data_export", "kind_confidence": 80, "sensitivity": True}]},
    {"labels": ["data_export"]},
])
def test_a_malformed_answer_is_a_fallback(body):
    calls, post = _post(body=body)
    recon = {}
    finding = _finding()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        stats = ra.run_for_candidates(_pairs([finding]), ON, recon)
    assert stats["failed_batches"] == 1 and stats["asked"] == 0
    assert recon["jev_shadow"][ra.HOOK]["summary"]["fallbacks"] == 1
    assert not any(k.startswith("route_jev_") for k in finding)


def test_a_failed_call_never_raises():
    calls, post = _post(status=503)
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        assert ra.run_for_candidates(_pairs([_finding()]), ON, {})["failed_batches"] == 1


def test_the_hook_acts():
    assert ra.ROLLOUT == jev_shadow.ACT


@pytest.mark.parametrize("route_class,baseline", [
    ("data_export", "data_export"), ("client_gated", "admin_function"), ("unknown", "public_content")])
def test_act_annotates_the_lead_only_and_records_the_mapped_baseline(route_class, baseline):
    finding = _finding(route_class=route_class)
    before = copy.deepcopy(finding)
    calls, post = _post(label=("public_content", 70, 10))
    recon = {}
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        ra.run_for_candidates(_pairs([finding]), ON, recon)
    added = {k: v for k, v in finding.items() if k not in before}
    assert added == {"route_jev_kind": "public_content", "route_jev_kind_confidence": 70,
                     "route_jev_sensitivity": 10, "route_jev_source": "jev_classifier"}
    assert {k: finding[k] for k in before} == before        # route_class and the rest untouched
    assert recon["jev_shadow"][ra.HOOK]["rollout"] == "act"
    record = recon["jev_shadow"][ra.HOOK]["records"][0]
    assert (record["jev"], record["baseline"], record["sensitivity"]) == ("public_content", baseline, 10)


@pytest.mark.parametrize("kind,conf,public", [
    ("public_content", 70, True), ("public_content", 69, False), ("data_export", 99, False),
    ("public_content", True, False), (None, 90, False)])
def test_is_public_needs_public_content_at_the_confidence_floor(kind, conf, public):
    assert ra.is_public({"route_jev_kind": kind, "route_jev_kind_confidence": conf}) is public


def test_every_route_class_verdict_returns_has_a_baseline_in_the_closed_kinds():
    """A route_class missing from the map would record as public_content and read as
    a disagreement Jev never made."""
    import ast
    from recon.route_exposure import verdict
    tree = ast.parse(Path(verdict.__file__).read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "route_class")
    returned = {n.value.value for n in ast.walk(fn)
                if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)}
    assert returned and returned <= set(ra._BASELINE), returned - set(ra._BASELINE)
    assert set(ra._BASELINE.values()) <= set(ra.KINDS)


def test_stdout_never_carries_a_path(capsys):
    calls, post = _post()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=post):
        ra.run_for_candidates(_pairs([_finding(path="/very-secret-path")]), ON, {})
    assert "/very-secret-path" not in capsys.readouterr().out


def test_the_hooks_sit_in_the_shared_entry():
    src = (Path(__file__).resolve().parents[1] / "route_exposure" / "scanner.py").read_text()
    assert "route_exposure_assess.run_for_candidates(" in src
    assert "route_wall_check.run_for_pages(" in src
    assert "_jev_second_opinions(observations, findings, settings, combined_result)" in src
