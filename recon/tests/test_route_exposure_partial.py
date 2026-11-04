"""Partial-recon entry for the route exposure scan (plan §12.1).

Patches the graph builder, settings and Neo4j client; the scan itself runs for
real against a loopback app, so a typed URL is requested only when it reached
the run's scope (T41: `_scope_partial_urls`' hosts land in `subdomains`).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

import recon.partial_recon_modules.route_exposure_scanning as mod
from recon.helpers import circuit_breaker as cb
from recon.route_exposure import prober
from recon.tests.route_exposure_fakeapp import FakeApp, json_answer

USERS = json.dumps([{"id": i, "email": f"u{i}@lab.invalid"} for i in range(4)]).encode()
SETTINGS = {"IP_MODE": True, "TARGET_IPS": ["127.0.0.1"], "ROUTE_EXPOSURE_MAX_RPS": 50,
            "ROUTE_EXPOSURE_SEED_PATHS": False, "ROUTE_EXPOSURE_VCS_FILES": False,
            "ROUTE_EXPOSURE_BACKUP_FILES": False, "ROUTE_EXPOSURE_VERSION_VARIANTS": False}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    cb.reset_registry()
    prober._reset_pacer()
    monkeypatch.setenv("USER_ID", "user1")
    monkeypatch.setenv("PROJECT_ID", "proj1")
    yield
    prober._reset_pacer()


def _graph_data(base=None):
    data = mod._empty_recon_data(["ip-targets.proj1"], SETTINGS)
    if base:
        data["http_probe"]["by_url"][base] = {"url": base, "host": "127.0.0.1", "status_code": 200}
        data["resource_enum"]["by_base_url"][base] = {"endpoints": {
            "/internal/users/export": {"methods": ["GET"], "category": "api"}}}
    return data


def _run(config, graph_data=None, settings=None):
    client = MagicMock()
    client.update_graph_from_route_exposure.return_value = {"errors": []}
    neo4j_cls = MagicMock()
    neo4j_cls.return_value.__enter__ = MagicMock(return_value=client)
    neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)
    fake_graph_db = MagicMock(Neo4jClient=neo4j_cls)
    builder = MagicMock(return_value=graph_data if graph_data is not None else _graph_data())
    with patch.dict("sys.modules", {"graph_db": fake_graph_db}), \
         patch.object(mod, "scope_roots", return_value=["ip-targets.proj1"]), \
         patch.object(mod, "partial_settings", return_value=dict(settings or SETTINGS)), \
         patch.object(mod, "_graph_subdomains", return_value=[]), \
         patch.object(mod, "_build_route_exposure_data_from_graph", builder):
        mod.run_route_exposure_partial(config)
    return client, builder


def test_graph_targets_are_scanned_and_written_with_the_toggle_forced_on():
    with FakeApp({"/internal/users/export": json_answer(200, USERS)}) as app:
        client, builder = _run({"include_graph_targets": True}, graph_data=_graph_data(app.base))
    assert builder.called
    recon_data, uid, pid = client.update_graph_from_route_exposure.call_args[0]
    assert (uid, pid) == ("user1", "proj1")
    kinds = {(f["path"], f["exposure_kind"]) for f in recon_data["route_exposure"]["findings"]}
    assert ("/internal/users/export", "anonymous_access") in kinds
    assert "127.0.0.1" in recon_data["subdomains"]
    assert app.paths("GET")


def test_typed_urls_without_graph_targets_reach_the_scope():
    with FakeApp({"/internal/users/export": json_answer(200, USERS)}) as app:
        client, builder = _run({"include_graph_targets": False,
                                "user_targets": {"urls": [app.base + "/internal/users/export"]}})
    assert not builder.called
    recon_data = client.update_graph_from_route_exposure.call_args[0][0]
    assert recon_data["subdomains"] == ["127.0.0.1"]
    assert any(f["path"] == "/internal/users/export" for f in recon_data["route_exposure"]["findings"])
    assert "/internal/users/export" in app.paths()
    client.create_user_input_node.assert_called_once()
    data = client.create_user_input_node.call_args.kwargs["user_input_data"]
    assert data["tool_id"] == "RouteExposure"
    # The UserInput PRODUCED the run's findings, or the partial run deletes it as
    # an orphan (_cleanup_orphan_user_inputs).
    ui_id, linked, uid, pid = client.link_route_exposure_user_input.call_args[0]
    assert (ui_id, uid, pid) == (data["id"], "user1", "proj1")
    assert ("/internal/users/export", "anonymous_access") in {(f["path"], f["exposure_kind"]) for f in linked}


def test_only_findings_on_a_typed_base_url_are_linked():
    client = MagicMock()
    findings = [{"baseurl": "http://127.0.0.1:8080", "path": "/a", "exposure_kind": "env_file"},
                {"baseurl": "http://127.0.0.1", "path": "/b", "exposure_kind": "env_file"}]
    mod._link_user_urls(client, ["http://127.0.0.1:8080/x"], None, ["ip-targets.p"], "u", "p", findings)
    linked = client.link_route_exposure_user_input.call_args[0][1]
    assert [f["path"] for f in linked] == ["/a"]


def test_a_typed_url_attached_to_a_base_url_makes_no_user_input():
    with FakeApp({}) as app:
        client, _ = _run({"include_graph_targets": False,
                          "user_targets": {"urls": [app.base + "/x"], "url_attach_to": app.base}})
    assert not client.create_user_input_node.called


def test_an_out_of_scope_graph_url_is_dropped():
    with FakeApp({}, host="127.0.0.2") as outsider:
        client, _ = _run({"include_graph_targets": True}, graph_data=_graph_data(outsider.base))
    assert outsider.hits == []
    assert not client.update_graph_from_route_exposure.called   # nothing left to scan


def test_bails_with_no_targets():
    client, _ = _run({"include_graph_targets": False})
    assert not client.update_graph_from_route_exposure.called


def _jev_agent(url, json=None, headers=None, timeout=None):
    r = MagicMock(status_code=200, text="")
    if url.endswith("/jev/route-privacy-rank"):
        r.json.return_value = {"scores": [0.9] * len(json["routes"]), "model": "jev-1.13.0"}
    elif url.endswith("/jev/page-type"):
        r.json.return_value = {"labels": [{"page_class": "app", "confidence": 80} for _ in json["pages"]],
                               "model": "jev-1.13.0"}
    elif url.endswith("/jev/route-exposure-assess"):
        r.json.return_value = {"labels": [{"kind": "data_export", "kind_confidence": 90, "sensitivity": 88}
                                          for _ in json["candidates"]], "model": "jev-1.13.0"}
    else:
        raise AssertionError(f"unexpected agent call {url}")
    return r


def test_the_jev_hooks_act_on_the_partial_path_and_reach_the_graph_writer():
    """A partial run shares run_route_exposure, so Jev's answers land on the findings
    the writer persists, exactly as in the full pipeline."""
    from recon.helpers.ai_planner import jev_shadow
    jev_on = dict(SETTINGS, AI_IN_PIPELINE=True, ROUTE_EXPOSURE_JEV_RANK=True,
                  ROUTE_EXPOSURE_JEV_WALL_CHECK=True, ROUTE_EXPOSURE_JEV_ASSESS=True)
    with FakeApp({"/internal/users/export": json_answer(200, USERS)}) as app, \
            patch.object(jev_shadow.requests, "post", side_effect=_jev_agent) as post:
        client, _ = _run({"include_graph_targets": True}, graph_data=_graph_data(app.base),
                         settings=jev_on)
    called = {c.args[0].rsplit("/", 1)[-1] for c in post.call_args_list}
    assert {"route-privacy-rank", "route-exposure-assess"} <= called
    findings = client.update_graph_from_route_exposure.call_args[0][0]["route_exposure"]["findings"]
    lead = next(f for f in findings if f["path"] == "/internal/users/export" and f["needs_agent_confirmation"])
    assert (lead["route_jev_kind"], lead["route_jev_sensitivity"], lead["route_jev_source"]) == \
        ("data_export", 88, "jev_classifier")
    assert lead["route_jev_privacy"] == 90


def test_settings_overrides_apply():
    with FakeApp({"/internal/users/export": json_answer(200, USERS)}) as app:
        client, _ = _run({"include_graph_targets": True,
                          "settings_overrides": {"ROUTE_EXPOSURE_PII_DETECTION": False}},
                         graph_data=_graph_data(app.base))
    findings = client.update_graph_from_route_exposure.call_args[0][0]["route_exposure"]["findings"]
    assert findings and all(f["pii_types"] == [] for f in findings)


def test_a_graph_subdomain_lookup_failure_is_not_fatal(monkeypatch):
    fake = MagicMock()
    fake.Neo4jClient.side_effect = RuntimeError("down")
    with patch.dict("sys.modules", {"graph_db": fake}):
        assert mod._graph_subdomains(["x.test"], "u", "p", None) == []


def test_a_user_input_failure_is_reported_not_raised():
    client = MagicMock()
    client.create_user_input_node.side_effect = RuntimeError("neo4j")
    mod._link_user_urls(client, ["http://127.0.0.1/x"], None, ["ip-targets.p"], "u", "p")


def test_the_partial_entry_is_dispatched():
    from pathlib import Path
    src = (Path(mod.__file__).parents[1] / "partial_recon.py").read_text()
    assert 'elif tool_id == "RouteExposure":' in src
    assert "run_route_exposure_partial(config)" in src
