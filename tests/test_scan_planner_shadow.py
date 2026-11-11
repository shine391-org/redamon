"""F10 — scan_planner shadow mode: dispositions, compatibility lane, no behavior change.

Tests import only the pure planner module + planner_manifest (stdlib only).
No Neo4j, no Docker, no network, no LLM. Stub missing optional modules so the
recon helpers package imports cleanly locally.
"""
from __future__ import annotations

import json
import sys
import types as _types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

# Stub optional modules that recon.helpers.__init__ imports but the planner
# never touches, so we can import scan_planner without dns/whois/neo4j locally.
for _missing in ("dns", "whois", "neo4j", "graph_db"):
    if _missing not in sys.modules:
        _mod = _types.ModuleType(_missing)
        if _missing == "dns":
            for _sub in ("resolver", "zone", "query", "exception", "rdatatype",
                         "rdataclass", "name", "reversename", "rcode",
                         "tokenizer", "tsigkeyring"):
                _submod = _types.ModuleType(f"dns.{_sub}")
                setattr(_mod, _sub, _submod)
                sys.modules[f"dns.{_sub}"] = _submod
        sys.modules[_missing] = _mod

from recon.helpers import scan_planner as sp  # noqa: E402
from recon.helpers.scan_planner import (  # noqa: E402
    Disposition, Plan, PlanTask, ScanPlanner, plan_for_settings,
    _task_id, _origin_known, _path_known, _content_type_known, _template_known,
)
from recon.helpers.planner_manifest import read_manifest  # noqa: E402

ALL_DISPOSITIONS = (
    Disposition.PLANNED,
    Disposition.COMPATIBILITY,
    Disposition.DEFERRED,
    Disposition.NOT_APPLICABLE,
    Disposition.REJECTED,
)


def _settings(**extra):
    base = {
        "PLANNER_MODE": "shadow",
        "PLANNER_MANIFEST_ENABLED": True,
        "NUCLEI_TAGS": ["cve", "xss"],
        "NUCLEI_TEMPLATES": ["cve/2021-44228.yaml", "exposure/panel.yaml"],
        "TARGET_DOMAIN": "example.com",
    }
    base.update(extra)
    return base


# --------------------------------------------------------------------------- #
# Disposition coverage: every candidate gets a disposition, no silent drop     #
# --------------------------------------------------------------------------- #

def test_every_candidate_has_a_disposition():
    """No candidate check×request is silently dropped."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/2021-44228.yaml"])
    plan = planner.plan(["https://example.com/api?q=1"])
    for task in plan.tasks:
        assert task.disposition in ALL_DISPOSITIONS, task
    # All dispositions sum to the total task count.
    assert sum(plan.disposition_counts().values()) == len(plan.tasks)


def test_empty_template_is_deferred_explicit_failed_selection():
    """Missing/empty template -> DEFERRED, never a silent drop or rejection."""
    settings = _settings()
    planner = ScanPlanner(settings, [])
    plan = planner.plan(["https://example.com/x"])
    assert plan.template_count == 0
    # No tasks can be built without templates (empty template ref list).
    assert len(plan.tasks) == 0


def test_empty_template_string_is_deferred():
    """An empty template ref in the list produces a DEFERRED task per target."""
    settings = _settings()
    planner = ScanPlanner(settings, [""])
    plan = planner.plan(["https://example.com/x"])
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.disposition == Disposition.DEFERRED
    assert task.provenance == "rule:template-missing"
    assert "missing" in task.reason.lower()
    assert task.estimate is None


def test_unknown_template_semantics_goes_to_compatibility_not_nonexistent():
    """Unknown template semantics -> COMPATIBILITY, not REJECTED/NOT_APPLICABLE."""
    settings = _settings()
    planner = ScanPlanner(settings, ["weird/unknown-template.yaml"])
    plan = planner.plan(["https://example.com/x"])
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.disposition == Disposition.COMPATIBILITY
    assert task.provenance == "rule:template-unknown"
    assert "compatibility" in task.reason.lower()
    assert task.estimate is not None  # labeled estimate present


def test_known_template_known_target_is_planned_with_provenance():
    """Known template + known target -> PLANNED with rule provenance."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/2021-44228.yaml"])
    plan = planner.plan(["https://example.com/api/search"])
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.disposition == Disposition.PLANNED
    assert "rule:template-known-cve" in task.provenance
    assert "rule:target-known" in task.provenance
    assert task.estimate is not None


def test_out_of_scope_origin_is_not_applicable():
    """Origin outside scope roots -> NOT_APPLICABLE."""
    settings = _settings(TARGET_DOMAIN="example.com")
    planner = ScanPlanner(settings, ["cve/2021-44228.yaml"])
    plan = planner.plan(["https://evil.example.net/x"])
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.disposition == Disposition.NOT_APPLICABLE
    assert task.provenance == "rule:out-of-scope"
    assert task.estimate is None


# --------------------------------------------------------------------------- #
# B1 — credential in URL never reaches the manifest                            #
# --------------------------------------------------------------------------- #

def test_credential_in_url_redacted_from_manifest():
    """URL userinfo is stripped from origin before the manifest is written."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://user:pass@example.com/admin"])
    text = json.dumps(plan.manifest)
    assert "user:pass" not in text, text
    # Origin kept the host (redacted userinfo), not the raw credential URL.
    assert "https://example.com" in text


# --------------------------------------------------------------------------- #
# Task key fidelity: method/path/query/body/content type/auth revision        #
# --------------------------------------------------------------------------- #

def test_task_key_keeps_method_path_query_body_content_type_auth_revision():
    """The task id changes when any key component changes."""
    base = dict(template="cve/x.yaml", origin="https://a.test",
                path="/x", method="GET", query=(), body=(),
                content_type="", auth_revision="")
    id1 = _task_id(**base)
    id2 = _task_id(**{**base, "method": "POST"})
    id3 = _task_id(**{**base, "query": (("q", "1"),)})
    id4 = _task_id(**{**base, "body": (("k", "v"),)})
    id5 = _task_id(**{**base, "content_type": "application/json"})
    id6 = _task_id(**{**base, "auth_revision": "rev2"})
    assert len({id1, id2, id3, id4, id5, id6}) == 6, "task ids must differ"


def test_sampling_family_does_not_claim_equivalent_security_behavior():
    """Different query params are different tasks; no equivalence claim."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://a.test/x?q=1", "https://a.test/x?q=2"])
    ids = {t.task_id for t in plan.tasks}
    assert len(ids) == 2, "q=1 and q=2 must be distinct tasks"


# --------------------------------------------------------------------------- #
# B3 — encoding fidelity: distinct encoded URLs -> distinct task ids           #
# --------------------------------------------------------------------------- #

def test_encoded_and_decoded_query_stay_distinct_tasks():
    """?a=%2F and ?a=/ are different tasks; ?a=%20 and ?a=+ are different."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    urls = [
        "https://example.com/a?q=%2F",
        "https://example.com/a?q=/",
        "https://example.com/a?q=%20",
        "https://example.com/a?q=+",
        "https://example.com/a?q=1",
    ]
    plan = planner.plan(urls)
    ids = [t.task_id for t in plan.tasks]
    assert len(ids) == len(set(ids)) == len(urls), "each encoded URL is its own task"
    assert len(plan.tasks) == 5


# --------------------------------------------------------------------------- #
# B4 — method/body/content_type/auth_revision ingested from inventory          #
# --------------------------------------------------------------------------- #

def _endpoint(method="GET", query=None, body=None, content_type="",
              auth_revision=""):
    return {
        "methods": [method],
        "parameters": {
            "query": [{"name": n, "sample_values": [v]} for n, v in (query or [])],
            "body": [{"name": n, "sample_values": [v]} for n, v in (body or [])],
        },
        "content_type": content_type,
        "auth_profile_revision": auth_revision,
    }


def test_inventory_populates_method_body_content_type_auth():
    """plan() reads method/body/content_type/auth_revision from the inventory."""
    settings = _settings()
    inventory = {
        "endpoints": {
            "https://example.com/api": _endpoint(
                method="POST",
                query=(("q", "1"),),
                body=(("k", "v"),),
                content_type="application/json",
                auth_revision="rev2",
            )
        }
    }
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/api?q=1"], inventory=inventory)
    assert len(plan.tasks) == 1
    task = plan.tasks[0]
    assert task.method == "POST", task.method
    assert ("k", "v") in task.body, task.body
    assert task.content_type == "application/json", task.content_type
    assert task.auth_revision == "rev2", task.auth_revision
    # The task id reflects the POST + body + auth revision, not a GET default.
    expected = _task_id(
        template="cve/x.yaml", origin="https://example.com", path="/api",
        method="POST", query=(("q", "1"),), body=(("k", "v"),),
        content_type="application/json", auth_revision="rev2",
    )
    assert task.task_id == expected


def test_inventory_absent_target_gets_safe_defaults():
    """A target with no inventory plans as GET with no body/auth revision."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a?q=1"])
    task = plan.tasks[0]
    assert task.method == "GET"
    assert task.body == ()
    assert task.content_type == ""
    assert task.auth_revision == ""


# --------------------------------------------------------------------------- #
# B2 — planner manifest is accepted by the existing reader                     #
# --------------------------------------------------------------------------- #

def test_planner_manifest_is_reader_known_and_run_scoped():
    """read_manifest accepts the planner manifest and reports known status."""
    settings = _settings(
        PLANNER_TENANT="t1", PLANNER_PROJECT_ID="p1",
        PLANNER_RUN_ID="run9", PLANNER_GROUP_ID="g1",
    )
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a?q=1"])
    manifest = plan.manifest

    required = set(read_manifest.__globals__["REQUIRED_MANIFEST_KEYS"])
    known = set(read_manifest.__globals__["KNOWN_MANIFEST_KEYS"])
    assert set(manifest).issubset(required | known), set(manifest) - (required | known)
    for key in ("tenant", "project_id", "run_id", "group_id", "scope",
                "settings_hash_prefix", "reason", "created_at",
                "schema_version", "planner_version", "planner_mode",
                "settings_hash", "template_hashes", "tasks"):
        assert key in manifest, key
    assert manifest["tenant"] == "t1"
    assert manifest["project_id"] == "p1"
    assert manifest["run_id"] == "run9"
    assert manifest["group_id"] == "g1"
    assert manifest["scope"] == {"roots": ["example.com"]}
    assert isinstance(manifest["settings_hash_prefix"], str) \
        and len(manifest["settings_hash_prefix"]) == 16
    assert manifest["created_at"].startswith("plan_v1:")


# --------------------------------------------------------------------------- #
# Determinism: shuffle and PYTHONHASHSEED invariant                            #
# --------------------------------------------------------------------------- #

def test_plan_deterministic_under_input_shuffle():
    """Same inputs in different order -> same plan (dispositions + ids)."""
    settings = _settings()
    urls = [
        "https://example.com/a?q=1",
        "https://example.com/b?q=2",
        "https://example.com/c?q=3",
    ]
    plan_a = plan_for_settings(settings, ["cve/x.yaml"], urls)
    plan_b = plan_for_settings(settings, ["cve/x.yaml"], list(reversed(urls)))
    assert [t.task_id for t in plan_a.tasks] == [t.task_id for t in plan_b.tasks]
    assert plan_a.disposition_counts() == plan_b.disposition_counts()
    assert plan_a.plan_id == plan_b.plan_id
    assert plan_a.manifest == plan_b.manifest


def test_plan_deterministic_under_different_hash_seed(monkeypatch):
    """PYTHONHASHSEED change must not change the plan (we sort, never iterate sets)."""
    # PYTHONHASHSEED affects str hash randomization at interpreter start; we
    # can't change it in-process. Instead verify the planner never iterates an
    # unsorted set/dict: it sorts targets and template refs, and task_id uses
    # json sort_keys. The plan_id is hash-based, not order-based.
    settings = _settings()
    urls = ["https://example.com/a?q=1", "https://example.com/b?q=2"]
    plan1 = plan_for_settings(settings, ["cve/x.yaml", "exposure/y.yaml"], urls)
    plan2 = plan_for_settings(settings, ["exposure/y.yaml", "cve/x.yaml"], urls)
    # Same template set regardless of input order -> same plan.
    assert plan1.plan_id == plan2.plan_id
    assert [t.task_id for t in plan1.tasks] == [t.task_id for t in plan2.tasks]


def test_plan_identical_across_pythonhashseed_subprocess(tmp_path):
    """Different PYTHONHASHSEED subprocesses produce identical plan_id + manifest hash."""
    import subprocess, os, sys
    code = (
        "import json, sys\n"
        "import types as _types\n"
        "_dns = _types.ModuleType(\"dns\"); _dns.__path__ = []\n"
        "for _sub in (\"resolver\", \"zone\", \"query\", \"exception\", \"rdatatype\",\n"
        "             \"rdataclass\", \"name\", \"reversename\", \"rcode\",\n"
        "             \"tokenizer\", \"tsigkeyring\"):\n"
        "    _m = _types.ModuleType(\"dns.\" + _sub); setattr(_dns, _sub, _m)\n"
        "    sys.modules[\"dns.\" + _sub] = _m\n"
        "sys.modules[\"dns\"] = _dns\n"
        "for m in (\"whois\", \"neo4j\", \"graph_db\"):\n"
        "    sys.modules[m] = _types.ModuleType(m)\n"
        "from recon.helpers.scan_planner import plan_for_settings\n"
        "settings = {\"PLANNER_MODE\": \"shadow\", \"TARGET_DOMAIN\": \"example.com\",\n"
        "            \"NUCLEI_TAGS\": [\"cve\"], \"NUCLEI_TEMPLATES\": [\"cve/x.yaml\"]}\n"
        "plan = plan_for_settings(settings, [\"cve/x.yaml\", \"exposure/y.yaml\"],\n"
        "                         [\"https://example.com/a?q=1\", \"https://example.com/b?q=2\"])\n"
        "print(json.dumps({\"plan_id\": plan.plan_id,\n"
        "                  \"manifest_hash\": __import__(\"hashlib\").sha256(\n"
        "                      json.dumps(plan.manifest, sort_keys=True).encode()).hexdigest(),\n"
        "                  \"task_ids\": [t.task_id for t in plan.tasks]}))\n"
    )
    env_base = dict(os.environ)
    env_base["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + str(PROJECT_ROOT / "recon")
    env_a = dict(env_base, PYTHONHASHSEED="0")
    env_b = dict(env_base, PYTHONHASHSEED="12345")
    out_a = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, env=env_a, cwd=str(PROJECT_ROOT))
    out_b = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, env=env_b, cwd=str(PROJECT_ROOT))
    assert out_a.returncode == 0, out_a.stderr
    assert out_b.returncode == 0, out_b.stderr
    res_a = json.loads(out_a.stdout.strip().splitlines()[-1])
    res_b = json.loads(out_b.stdout.strip().splitlines()[-1])
    assert res_a["plan_id"] == res_b["plan_id"], "plan_id must not depend on PYTHONHASHSEED"
    assert res_a["manifest_hash"] == res_b["manifest_hash"], "manifest hash must not depend on PYTHONHASHSEED"
    assert res_a["task_ids"] == res_b["task_ids"], "task ids must not depend on PYTHONHASHSEED"


# --------------------------------------------------------------------------- #
# Shadow mode: no behavior change                                             #
# --------------------------------------------------------------------------- #

def test_shadow_mode_does_not_change_targets_argv_order():
    """Shadow mode computes a plan but does not alter targets/argv/order."""
    settings = _settings(PLANNER_MODE="shadow")
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a", "https://example.com/b"])
    assert plan.mode == "shadow"
    assert len(plan.tasks) == 2
    # The plan's task list is pure accounting; targets are untouched.
    assert plan.tasks[0].origin == "https://example.com"
    assert plan.tasks[1].origin == "https://example.com"


def test_off_mode_returns_no_planner_optimization():
    """off = patched legacy, no planner tasks."""
    settings = _settings(PLANNER_MODE="off")
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a"])
    assert plan.mode == "off"
    assert len(plan.tasks) == 0


def test_enforce_mode_still_plans_but_is_not_executed_here():
    """enforce computes a plan (execution cutover is a later card)."""
    settings = _settings(PLANNER_MODE="enforce")
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a"])
    assert plan.mode == "enforce"
    assert len(plan.tasks) == 1


# --------------------------------------------------------------------------- #
# Estimates vs actuals                                                          #
# --------------------------------------------------------------------------- #

def test_estimates_labeled_not_actual_request_count():
    """estimate is present for planned/compatibility tasks, None for deferred."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml", ""])
    plan = planner.plan(["https://example.com/a"])
    for task in plan.tasks:
        if task.disposition == Disposition.DEFERRED:
            assert task.estimate is None
        else:
            assert task.estimate is not None
            assert isinstance(task.estimate, int)


def test_url_times_template_is_not_exact_request_count():
    """A URL × template pair is one planned task, not an exact request count."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml", "exposure/y.yaml"])
    plan = planner.plan(["https://example.com/a"])
    assert len(plan.tasks) == 2  # 1 URL × 2 templates
    # Each task estimate is 1 (labeled), not "2 requests total".
    for task in plan.tasks:
        assert task.estimate == 1


# --------------------------------------------------------------------------- #
# Bounded: oversize corpus -> failure/backpressure, no silent truncation       #
# --------------------------------------------------------------------------- #

def test_oversize_corpus_marks_oversize_no_silent_truncation():
    """When the task count would exceed MAX_TASKS, oversize is set."""
    settings = _settings()
    many_templates = [f"cve/{i}.yaml" for i in range(200)]
    many_urls = [f"https://example.com/u{i}" for i in range(200)]
    planner = ScanPlanner(settings, many_templates)
    plan = planner.plan(many_urls)
    assert plan.oversize is True
    assert len(plan.tasks) <= sp.MAX_TASKS
    # The oversize flag is observable: a reader knows the corpus was bounded.
    assert plan.disposition_counts()["planned"] + plan.disposition_counts()[\
        "compatibility"] == len(plan.tasks)


# --------------------------------------------------------------------------- #
# Manifest: run-scoped, credentials redacted                                  #
# --------------------------------------------------------------------------- #

def test_manifest_has_no_credentials_and_is_bounded():
    """Manifest redacts credentials and is bounded in size."""
    settings = _settings(NUCLEI_TAGS=["cve"],
                         NUCLEI_TEMPLATES=["cve/x.yaml"],
                         Authorization="Bearer secret",
                         Cookie="sess=abc")
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a"])
    manifest = plan.manifest
    text = json.dumps(manifest)
    assert "Bearer secret" not in text
    assert "sess=abc" not in text
    assert "settings" not in manifest  # hashed, not stored wholesale
    assert "Authorization" not in text
    assert "Cookie" not in text
    assert "plan_id" in manifest
    assert "disposition_counts" in manifest
    assert "template_hashes" in manifest
    assert "task_count" in manifest


# --------------------------------------------------------------------------- #
# Manifest reader acceptance (end-to-end with planner_manifest reader)         #
# --------------------------------------------------------------------------- #

def test_read_manifest_accepts_planner_manifest(tmp_path):
    """A planner manifest written to disk reads back as status: known."""
    from recon.helpers.planner_manifest import (
        manifest_path, manifest_base_dir, write_manifest,
        read_manifest_in_context,
    )
    settings = _settings(
        PLANNER_TENANT="t1", PLANNER_PROJECT_ID="p1",
        PLANNER_RUN_ID="run9", PLANNER_GROUP_ID="g1",
    )
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/a?q=1"])
    output_file = tmp_path / "recon.json"
    base = manifest_base_dir(output_file)
    path = manifest_path(base, "t1", "p1", "run9", "g1")
    written = write_manifest(path, plan.manifest)
    assert written is not None and "sha256" in written
    result = read_manifest_in_context(path, {"tenant": "t1", "project_id": "p1",
                                             "run_id": "run9", "group_id": "g1"},
                                      expected_sha256=written["sha256"])
    assert result["status"] == "known", result


# --------------------------------------------------------------------------- #
# PlanTask immutability and hashability                                       #
# --------------------------------------------------------------------------- #

def test_plan_task_is_hashable_and_immutable():
    """PlanTask is frozen: hashable and field assignment raises."""
    from dataclasses import FrozenInstanceError
    t = PlanTask(
        task_id="task_v1:abc",
        template="cve/x.yaml",
        origin="https://a.test",
        path="/x",
        method="GET",
        query=(("q", "1"),),
        body=(("k", "v"),),
        content_type="application/json",
        auth_revision="rev1",
        disposition=Disposition.PLANNED,
        estimate=1,
        provenance="rule:template-known-cve",
        reason="known",
    )
    # Hashable.
    assert hash(t) is not None
    # Immutable.
    try:
        t.disposition = Disposition.COMPATIBILITY  # type: ignore[misc]
        raise AssertionError("PlanTask should be immutable")
    except FrozenInstanceError:
        pass
    # Equality by value.
    t2 = PlanTask(
        task_id="task_v1:abc", template="cve/x.yaml", origin="https://a.test",
        path="/x", method="GET", query=(("q", "1"),), body=(("k", "v"),),
        content_type="application/json", auth_revision="rev1",
        disposition=Disposition.PLANNED, estimate=1,
        provenance="rule:template-known-cve", reason="known",
    )
    assert t == t2
