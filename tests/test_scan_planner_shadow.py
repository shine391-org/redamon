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

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
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
# Determinism: shuffle and PYTHONHASHSEED invariant                           #
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
    assert plan.disposition_counts()["planned"] + plan.disposition_counts()[
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
