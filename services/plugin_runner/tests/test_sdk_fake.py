"""FakeSdk, the double plugins test against: the shared contract cases (so a plugin that
passes on the fake sends what the Gateway expects and reads what it answers), then the
fake's own behaviour."""

import asyncio

import pytest

from redamon_plugin_sdk import Context, PluginError
from redamon_plugin_sdk.client import check_where
from redamon_plugin_sdk.testing import FakeSdk, ScriptedLlm, make_context
from tests.support import context_kwargs, load_contract_cases, resolve_call

FAKE_CASES = [c for c in load_contract_cases() if "fake" in c]


def _fake_for(case: dict) -> FakeSdk:
    setup = dict(case["fake"].get("setup") or {})
    ctx = context_kwargs(case)
    sdk = FakeSdk(
        project_id=ctx["project_id"],
        session_id=ctx["session_id"],
        job_id=ctx["job_id"],
        transcript=setup.get("transcript"),
        llm=ScriptedLlm(setup.get("llm") or []),
        registry=setup.get("registry"),
        permissions=setup.get("permissions"),
    )
    for skill in setup.get("userSkills") or []:
        sdk.add_user_skill(skill["id"], skill["name"], skill["content"],
                           used_in_session=skill.get("usedInSession", True), owner=skill.get("owner"),
                           description=skill.get("description"), version=skill.get("version"))
    return sdk


@pytest.mark.parametrize("case", FAKE_CASES, ids=[c["name"] for c in FAKE_CASES])
def test_contract_case_on_the_fake(case):
    sdk = _fake_for(case)
    for call in case["fake"].get("given", []):
        asyncio.run(resolve_call(sdk, call))
    expect = case["fake"].get("expect", case["expect"])
    if "error" in expect:
        with pytest.raises(PluginError) as caught:
            asyncio.run(resolve_call(sdk, case["call"]))
        assert caught.value.code == expect["error"]["code"]
        if "message" in expect["error"]:
            assert caught.value.message == expect["error"]["message"]
    elif "keys" in expect:
        got = asyncio.run(resolve_call(sdk, case["call"]))
        assert [item["key"] for item in got["items"]] == expect["keys"]
        assert got["next"] == expect["next"]
    else:
        assert asyncio.run(resolve_call(sdk, case["call"])) == expect["return"]


def test_every_sdk_call_has_a_fake_case():
    names = {c["call"]["method"] for c in FAKE_CASES}
    assert names >= {
        "session.read", "llm.invoke", "data.get", "data.put", "data.query", "data.count",
        "data.delete", "override.get", "override.propose", "override.withdraw", "jobs.progress",
    }


def test_scripted_llm_records_prompts_and_options():
    llm = ScriptedLlm(["first", "second"])
    sdk = FakeSdk(llm=llm)
    msgs = [{"role": "user", "content": "hi"}]
    assert asyncio.run(sdk.llm.invoke(msgs, max_tokens=50))["content"] == "first"
    assert asyncio.run(sdk.llm.invoke(msgs, temperature=0.1))["content"] == "second"
    assert llm.prompts == [msgs, msgs]
    assert [c["max_tokens"] for c in llm.calls] == [50, None]
    assert [c["temperature"] for c in llm.calls] == [None, 0.1]


def test_scripted_llm_can_return_an_error_and_runs_dry_loudly():
    llm = ScriptedLlm([PluginError("model_required", "Choose a model.")])
    sdk = FakeSdk(llm=llm)
    with pytest.raises(PluginError) as caught:
        asyncio.run(sdk.llm.invoke([{"role": "user", "content": "hi"}]))
    assert caught.value.code == "model_required"
    with pytest.raises(PluginError) as caught:
        asyncio.run(sdk.llm.invoke([{"role": "user", "content": "hi"}]))
    assert caught.value.code == "llm_script_exhausted"


def test_scripted_llm_needs_the_permission():
    sdk = FakeSdk(llm=ScriptedLlm(["x"]), permissions=["session:read"])
    with pytest.raises(PluginError) as caught:
        asyncio.run(sdk.llm.invoke([{"role": "user", "content": "hi"}]))
    assert caught.value.code == "permission_denied"


def test_data_expires_by_the_injected_clock():
    now = [1000.0]
    sdk = FakeSdk(clock=lambda: now[0])
    asyncio.run(sdk.data.put("cache", "k", 1, ttl_seconds=60))
    assert asyncio.run(sdk.data.get("cache", "k")) == 1
    now[0] += 61
    assert asyncio.run(sdk.data.get("cache", "k")) is None
    assert asyncio.run(sdk.data.query("cache")) == {"items": [], "next": None}
    assert asyncio.run(sdk.data.count("cache")) == 0


def test_data_owners_are_separate():
    sdk = FakeSdk(project_id="project-1")
    asyncio.run(sdk.data.put("notes", "k", "mine"))
    asyncio.run(sdk.data.put("notes", "k", "ours", owner="project"))
    assert asyncio.run(sdk.data.get("notes", "k")) == "mine"
    assert asyncio.run(sdk.data.get("notes", "k", owner="project")) == "ours"


def test_data_values_are_copied_like_json():
    sdk = FakeSdk()
    value = {"list": [1, 2]}
    asyncio.run(sdk.data.put("notes", "k", value))
    value["list"].append(3)
    assert asyncio.run(sdk.data.get("notes", "k")) == {"list": [1, 2]}


def test_proposals_are_visible_to_the_test_and_in_pending_count():
    registry = {"path_traversal": {"displayName": "Path Traversal",
                                   "parts": {"payload_reference": {"text": "factory"}}}}
    sdk = FakeSdk(registry=registry)
    out = asyncio.run(sdk.override.propose("skill.text", "path_traversal",
                                           {"payload_reference": "better"}, note="why"))
    assert out["changeSetId"] == sdk.proposals[0]["changeSetId"]
    assert sdk.proposals[0]["parts"] == {"payload_reference": "better"}
    assert sdk.proposals[0]["status"] == "proposed"
    got = asyncio.run(sdk.override.get("skill.text", "path_traversal"))
    assert got["pendingCount"] == 1 and got["active"] is None
    asyncio.run(sdk.override.withdraw(out["changeSetId"]))
    assert sdk.proposals[0]["status"] == "withdrawn"
    assert asyncio.run(sdk.override.get("skill.text", "path_traversal"))["pendingCount"] == 0


def test_an_active_version_is_reported_by_override_get():
    registry = {"path_traversal": {"displayName": "Path Traversal",
                                   "parts": {"payload_reference": {"text": "factory"}}}}
    sdk = FakeSdk(registry=registry)
    sdk.set_active("path_traversal", revision=3, parts={"payload_reference": "v3 text"})
    got = asyncio.run(sdk.override.get("skill.text", "path_traversal"))
    assert got["active"]["revision"] == 3
    assert got["active"]["parts"] == {"payload_reference": "v3 text"}
    out = asyncio.run(sdk.override.propose("skill.text", "path_traversal",
                                           {"payload_reference": "v4 text"}, note="n"))
    assert out["fromRevision"] == 3


def test_override_get_reports_each_part_kind_and_placeholders():
    registry = {"path_traversal": {"parts": {
        "tools": {"text": "Scan with {timeout} s.", "kind": "template", "placeholders": ["timeout"]},
        "payload_reference": {"text": "Use ../ sequences."}}}}
    got = asyncio.run(FakeSdk(registry=registry).override.get("skill.text", "path_traversal"))
    kinds = {p["partId"]: (p["kind"], p["placeholders"]) for p in got["parts"]}
    assert kinds == {"tools": ("template", ["timeout"]), "payload_reference": ("plain", [])}


def test_project_scope_needs_a_project():
    registry = {"path_traversal": {"parts": {"payload_reference": {"text": "factory"}}}}
    sdk = FakeSdk(registry=registry)
    with pytest.raises(PluginError) as caught:
        asyncio.run(sdk.override.propose("skill.text", "path_traversal",
                                         {"payload_reference": "x"}, note="n", scope="project"))
    assert caught.value.code == "invalid_proposal"


def test_progress_is_recorded_in_order():
    sdk = FakeSdk(job_id="job-1")
    asyncio.run(sdk.jobs.progress("one"))
    asyncio.run(sdk.jobs.progress("two", {"Stage": "2 of 3"}))
    assert sdk.progress == [{"message": "one", "fields": None},
                            {"message": "two", "fields": {"Stage": "2 of 3"}}]


def test_make_context_builds_a_context_around_a_fake():
    ctx = make_context(project_id="project-1", session_id="session-1", job_id="job-1")
    assert isinstance(ctx, Context)
    assert isinstance(ctx.sdk, FakeSdk)
    assert (ctx.plugin_id, ctx.user_id, ctx.project_id, ctx.session_id, ctx.job_id) == (
        "test-plugin", "user-1", "project-1", "session-1", "job-1")
    assert ctx.sdk.project_id == "project-1" and ctx.sdk.job_id == "job-1"


# --- TD-28: paging, where, order, count ------------------------------------------------


def _keys(page):
    return [item["key"] for item in page["items"]]


def test_query_pages_through_every_row_exactly_once_with_writes_between_pages():
    sdk = FakeSdk()
    for i in range(120):
        asyncio.run(sdk.data.put("rows", f"k{i:03d}", i))
    seen, pages, cursor = [], 0, None
    while True:
        page = asyncio.run(sdk.data.query("rows", limit=50, cursor=cursor))
        pages += 1
        seen += _keys(page)
        asyncio.run(sdk.data.put("rows", f"late{pages}", "written between pages"))
        cursor = page["next"]
        if cursor is None:
            break
        assert isinstance(cursor, str)
    originals = [k for k in seen if k.startswith("k")]
    assert sorted(originals) == [f"k{i:03d}" for i in range(120)]
    assert len(originals) == len(set(originals)) == 120
    assert pages == 3


def test_query_orders():
    now = [1000.0]
    sdk = FakeSdk(clock=lambda: now[0])
    for key in ("b", "a", "c"):
        now[0] += 1
        asyncio.run(sdk.data.put("rows", key, key))
    assert _keys(asyncio.run(sdk.data.query("rows"))) == ["c", "a", "b"]
    assert _keys(asyncio.run(sdk.data.query("rows", order="updated"))) == ["b", "a", "c"]
    assert _keys(asyncio.run(sdk.data.query("rows", order="key"))) == ["a", "b", "c"]
    assert _keys(asyncio.run(sdk.data.query("rows", order="-key"))) == ["c", "b", "a"]


def test_query_orders_page_by_key_too():
    sdk = FakeSdk()
    for i in range(7):
        asyncio.run(sdk.data.put("rows", f"k{i}", i))
    first = asyncio.run(sdk.data.query("rows", order="key", limit=3))
    second = asyncio.run(sdk.data.query("rows", order="key", limit=3, cursor=first["next"]))
    third = asyncio.run(sdk.data.query("rows", order="key", limit=3, cursor=second["next"]))
    assert _keys(first) + _keys(second) + _keys(third) == [f"k{i}" for i in range(7)]
    assert third["next"] is None


def _where_rows():
    sdk = FakeSdk()
    rows = {
        "open-int": {"status": "open", "n": 1, "flag": True, "gone": None},
        "closed-float": {"status": "closed", "n": 1.0, "flag": False},
        "bool-one": {"status": "open", "n": True},
        "text-one": {"status": "open", "n": "1"},
        "not-an-object": "open",
        "list-value": ["open"],
    }
    for key, value in rows.items():
        asyncio.run(sdk.data.put("rows", key, value))
    return sdk


def _where(sdk, **where):
    return sorted(_keys(asyncio.run(sdk.data.query("rows", where=where))))


def test_where_follows_jsonb_equality():
    sdk = _where_rows()
    assert _where(sdk, status="open") == ["bool-one", "open-int", "text-one"]
    assert _where(sdk, n=1) == ["closed-float", "open-int"]          # 1 == 1.0
    assert _where(sdk, n=1.0) == ["closed-float", "open-int"]
    assert _where(sdk, n=True) == ["bool-one"]                       # a bool is not a number
    assert _where(sdk, flag=False) == ["closed-float"]
    assert _where(sdk, n="1") == ["text-one"]
    assert _where(sdk, gone=None) == ["open-int"]                    # null matches a JSON null
    assert _where(sdk, missing=None) == []                           # a missing field never matches
    assert _where(sdk, status="open", n=1) == ["open-int"]           # fields are ANDed


def test_where_is_anded_with_prefix_and_counted():
    sdk = _where_rows()
    assert sorted(_keys(asyncio.run(sdk.data.query("rows", prefix="open", where={"status": "open"})))) == ["open-int"]
    assert asyncio.run(sdk.data.count("rows")) == 6
    assert asyncio.run(sdk.data.count("rows", where={"status": "open"})) == 3
    assert asyncio.run(sdk.data.count("rows", prefix="open", where={"status": "open"})) == 1


def test_a_cursor_only_fits_the_query_that_made_it():
    sdk = FakeSdk()
    for i in range(5):
        asyncio.run(sdk.data.put("rows", f"k{i}", {"even": i % 2 == 0}))
    cursor = asyncio.run(sdk.data.query("rows", limit=2))["next"]
    for kwargs in ({"where": {"even": True}}, {"order": "key"}, {"prefix": "k1"}):
        with pytest.raises(PluginError) as caught:
            asyncio.run(sdk.data.query("rows", limit=2, cursor=cursor, **kwargs))
        assert caught.value.code == "invalid_cursor", kwargs
    with pytest.raises(PluginError) as caught:
        asyncio.run(sdk.data.query("other", limit=2, cursor=cursor))
    assert caught.value.code == "invalid_cursor"
    with pytest.raises(PluginError) as caught:
        asyncio.run(sdk.data.query("rows", cursor="not a cursor"))
    assert caught.value.code == "invalid_cursor"


def test_where_values_are_checked_before_sending():
    sdk = FakeSdk()
    for where in ({"long": "x" * 513}, {"nan": float("nan")}, {"inf": float("inf")}, {1: "x"}):
        with pytest.raises(PluginError) as caught:
            asyncio.run(sdk.data.query("rows", where=where))
        assert caught.value.code == "invalid_query", where
    assert asyncio.run(sdk.data.query("rows", where={"ok": "x" * 512}))["items"] == []


def test_the_echo_fixture_pages_its_list():
    import importlib.util
    from tests.support import ECHO_ROOT
    spec = importlib.util.spec_from_file_location("echo_items", ECHO_ROOT / "engine" / "items.py")
    items = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(items)
    ctx = make_context()
    empty = asyncio.run(items.list_items(ctx, {}))
    assert empty["next"] is None and len(empty["items"]) == 1
    for k in ("a", "b", "c"):
        asyncio.run(ctx.sdk.data.put("items", k, k.upper()))
    first = asyncio.run(items.list_items(ctx, {"limit": 2}))
    second = asyncio.run(items.list_items(ctx, {"limit": 2, "cursor": first["next"]}))
    assert [i["title"] for i in first["items"] + second["items"]] == ["c", "b", "a"]
    assert first["next"] and second["next"] is None


# --- the fake measures and refuses as the Gateway does (phase 03 review) ------------------

def _refused(coro) -> str:
    with pytest.raises(PluginError) as caught:
        asyncio.run(coro)
    return caught.value.code


def _put(sdk, key, value) -> dict:
    """The Gateway's answer, which data.put does not return to the plugin."""
    return asyncio.run(sdk.gateway.post("data/put", {"owner": "user", "collection": "rows", "key": key, "value": value}))


def test_a_value_is_measured_as_compact_utf8_json_like_the_gateway():
    sdk = FakeSdk()
    # 800,001 bytes compact; with Python's default ", " separators it would be 1.2 MB.
    assert _put(sdk, "zeros", [0] * 400_000)["sizeBytes"] == 800_001
    # Two UTF-8 bytes each, never a six-byte \u escape.
    assert _put(sdk, "accents", "é" * 400_000)["sizeBytes"] == 800_002


def test_a_key_is_measured_in_utf16_units_like_the_gateway():
    sdk = FakeSdk()
    assert _put(sdk, "😀" * 256, 1)["sizeBytes"] == 1
    assert _refused(sdk.data.put("rows", "😀" * 257, 1)) == "invalid_key"


@pytest.mark.parametrize("key,value,code", [
    ("a\x00b", 1, "invalid_key"),
    ("k", {"text": "a\x00b"}, "invalid_value"),
    ("k", {"a\x00": 1}, "invalid_value"),
])
def test_nul_is_refused_as_postgres_refuses_it(key, value, code):
    assert _refused(FakeSdk().data.put("rows", key, value)) == code


@pytest.mark.parametrize("name", ["rows\n", "ok"])
def test_a_trailing_newline_is_not_a_valid_name(name):
    sdk = FakeSdk()
    if name == "ok":
        assert asyncio.run(sdk.data.query(name, where={"field": 1}))["items"] == []
        return
    assert _refused(sdk.data.put(name, "k", 1)) == "invalid_collection"
    assert _refused(sdk.data.query("rows", where={name: 1})) == "invalid_query"


@pytest.mark.parametrize("prefix", [5, ["a"], "x" * 513, "a\x00"])
def test_a_prefix_that_is_not_short_text_is_refused(prefix):
    sdk = FakeSdk()
    sdk.gateway.rows.clear()
    assert _refused(sdk.gateway.post("data/query", {"owner": "user", "collection": "rows", "prefix": prefix})) == "invalid_query"


def test_a_huge_integer_in_where_is_refused_not_an_overflow():
    with pytest.raises(PluginError) as caught:
        check_where({"n": 10 ** 400})
    assert caught.value.code == "invalid_query"
    check_where({"n": 10 ** 300})


SKILL = {"path_traversal": {"displayName": "Path Traversal", "skillMaxChars": 30,
                            "parts": {"a": {"text": "aaaaaaaaaa", "maxChars": 40},
                                      "b": {"text": "bbbbbbbbbb", "maxChars": 40}}}}


def test_a_proposal_is_checked_over_the_factory_text_not_the_active_version():
    # TD-19: parts not sent are factory text in the proposed version.
    sdk = FakeSdk(registry=SKILL)
    sdk.set_active("path_traversal", revision=2, parts={"b": "B" * 20})
    # 15 + 10 factory = 25 <= 30, although 15 + the active 20 would be 35.
    out = asyncio.run(sdk.override.propose("skill.text", "path_traversal", {"a": "A" * 15}, note="n"))
    assert out["fromRevision"] == 2
    # 25 + 10 factory = 35 > 30, although 25 + nothing changed elsewhere looked small.
    assert _refused(sdk.override.propose("skill.text", "path_traversal", {"a": "A" * 25}, note="n")) == "invalid_proposal"


def test_parts_equal_to_their_factory_text_are_dropped_and_none_left_is_refused():
    sdk = FakeSdk(registry=SKILL)
    asyncio.run(sdk.override.propose("skill.text", "path_traversal", {"a": "A", "b": "bbbbbbbbbb"}, note="n"))
    assert sdk.proposals[0]["parts"] == {"a": "A"}
    assert _refused(sdk.override.propose("skill.text", "path_traversal", {"b": "bbbbbbbbbb"}, note="n")) == "invalid_proposal"


def test_a_proposal_built_on_a_factory_text_that_has_changed_is_refused():
    sdk = FakeSdk(registry=SKILL)
    got = asyncio.run(sdk.override.get("skill.text", "path_traversal"))
    sdk.gateway.registry["path_traversal"]["parts"]["a"]["text"] = "a fixed upstream"
    assert _refused(sdk.override.propose("skill.text", "path_traversal", {"b": "B"}, note="n", based_on=got)) == "factory_changed"
    assert sdk.proposals == []


def test_from_revision_is_the_version_of_its_own_scope_that_get_showed():
    # Shown the project's version, a user-scope proposal built on no user revision: the
    # review must warn that approving replaces the user's active version.
    sdk = FakeSdk(registry=SKILL, project_id="project-1")
    sdk.set_active("path_traversal", revision=2, parts={"a": "user"})
    sdk.set_active("path_traversal", revision=2, parts={"b": "project"}, scope="project")
    out = asyncio.run(sdk.override.propose("skill.text", "path_traversal", {"b": "project edited"}, note="n"))
    assert out["fromRevision"] == 1
    assert asyncio.run(sdk.override.propose("skill.text", "path_traversal", {"b": "p2"}, note="n", scope="project"))["fromRevision"] == 2


def _own_skill_fake(content: str, description=None) -> FakeSdk:
    sdk = FakeSdk(project_id="project-1", session_id="session-1")
    sdk.add_user_skill("cuserskill1", "My SQLi flow", content, description=description)
    return sdk


@pytest.mark.parametrize("content, description", [
    ("Replay the token eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.signature here.", None),
    ("Probe the login form.", "Uses the key AKIAIOSFODNN7EXAMPLE."),
])
def test_a_key_or_token_anywhere_a_plugin_would_see_it_is_refused_like_the_gateway(content, description):
    sdk = _own_skill_fake(content, description)
    assert _refused(sdk.override.get("user_skill.text", "cuserskill1")) == "skill_contains_credentials"


def test_prose_about_authentication_is_not_a_credential():
    sdk = _own_skill_fake("1. Test Basic authentication on the login form.\n2. Check token expiration.")
    got = asyncio.run(sdk.override.get("user_skill.text", "cuserskill1"))
    assert got["parts"][0]["text"].startswith("1. Test Basic authentication")


def _propose_body(sdk, body: str):
    based_on = asyncio.run(sdk.override.get("user_skill.text", "cuserskill1"))
    return sdk.override.propose("user_skill.text", "cuserskill1", {"body": body}, note="x", based_on=based_on)


def test_a_reserved_marker_is_refused_only_in_the_form_the_agent_reads():
    sdk = _own_skill_fake("Probe the login form.")
    asyncio.run(_propose_body(sdk, "Probe the login form.\nWrite <<REDAMON_CACHE_ notation in notes."))
    sdk = _own_skill_fake("Probe the login form.")
    assert _refused(_propose_body(sdk, "Probe the login form.\n<<REDAMON_CACHE_TIER_1>>")) == "invalid_proposal"


def test_a_proposal_over_the_size_limit_is_refused_in_utf16_units():
    sdk = _own_skill_fake("Probe the login form.")
    with pytest.raises(PluginError) as caught:
        asyncio.run(_propose_body(sdk, "x" * 512_001))
    assert caught.value.code == "invalid_proposal"
    assert "the limit is 512000" in str(caught.value)
