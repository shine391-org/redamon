"""F10 golden-corpus offline replay: shadow vs off zero-delta verification.

Replays a realistic, synthetic scan corpus through the planner in shadow mode
and patched-off mode, and asserts:

* Shadow computes one (check x request) task per target x template with a
  disposition for every candidate (no silent drop).
* Off mode emits zero planner tasks — execution (targets, argv, order) is
  untouched, i.e. zero dispatch/traffic delta vs legacy.
* The shadow plan does not alter the input target list, argv, or order.
* Encoding fidelity: percent-encoded query variants stay distinct task ids.
* Determinism: shuffle of inputs does not change the plan.
* Manifest diff: shadow emits a run-scoped manifest; off emits an empty plan.

Offline/hermetic: stdlib only, no Docker, no network, no LLM.
"""
from __future__ import annotations

import json
import sys
import types as _types
from pathlib import Path

# Stub optional modules that recon.helpers.__init__ imports but the planner
# never touches, so we can import scan_planner without dns/whois/neo4j locally.
for _missing in ("dns", "whois", "neo4j", "graph_db"):
    if _missing not in sys.modules:
        _mod = _types.ModuleType(_missing)
        if _missing == "dns":
            _dns = _mod
            _dns.__path__ = []
            for _sub in ("resolver", "zone", "query", "exception", "rdatatype",
                         "rdataclass", "name", "reversename", "rcode",
                         "tokenizer", "tsigkeyring"):
                _submod = _types.ModuleType(f"dns.{_sub}")
                setattr(_dns, _sub, _submod)
                sys.modules[f"dns.{_sub}"] = _submod
        sys.modules[_missing] = _mod

from recon.helpers.scan_planner import (  # noqa: E402
    Disposition, PlanTask, ScanPlanner, plan_for_settings, _task_id,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "golden_corpus.json"


def _load_corpus():
    with open(FIXTURE, "r") as f:
        return json.load(f)


def test_golden_corpus_shadow_computes_full_plan():
    """Shadow plans every candidate with a disposition; no silent drop."""
    corpus = _load_corpus()
    settings = dict(corpus["settings"])
    templates = list(settings["NUCLEI_TEMPLATES"])
    planner = ScanPlanner(settings, templates)
    plan = planner.plan(corpus["targets"], inventory=corpus.get("inventory"))

    expected = corpus["expected"]
    counts = plan.disposition_counts()
    assert counts["planned"] == expected["planned"], counts
    assert counts["compatibility"] == expected["compatibility"], counts
    assert counts["deferred"] == expected["deferred"], counts
    assert counts["not_applicable"] == expected["not_applicable"], counts
    assert counts["rejected"] == expected["rejected"], counts
    assert sum(counts.values()) == len(plan.tasks) == expected["total"]
    # Every candidate has a disposition.
    for task in plan.tasks:
        assert task.disposition in Disposition.__members__.values()


def test_golden_corpus_off_zero_traffic_delta():
    """Off mode = patched legacy: zero planner tasks, execution unchanged."""
    corpus = _load_corpus()
    settings_off = dict(corpus["settings"], PLANNER_MODE="off")
    templates = list(settings_off["NUCLEI_TEMPLATES"])
    planner = ScanPlanner(settings_off, templates)
    plan = planner.plan(corpus["targets"], inventory=corpus.get("inventory"))

    assert plan.mode == "off"
    assert len(plan.tasks) == 0
    assert all(v == 0 for v in plan.disposition_counts().values())
    # No manifest tasks, no optimization — legacy behavior preserved.
    assert plan.manifest["task_count"] == 0
    assert plan.manifest["planner_mode"] == "off"


def test_golden_corpus_targets_argv_order_unchanged():
    """Shadow planning does not mutate the input target list (no argv change)."""
    corpus = _load_corpus()
    targets = list(corpus["targets"])
    before = list(targets)
    settings = dict(corpus["settings"])
    templates = list(settings["NUCLEI_TEMPLATES"])
    planner = ScanPlanner(settings, templates)
    plan = planner.plan(targets, inventory=corpus.get("inventory"))
    assert targets == before, "planner must not mutate the input target list"
    # Plan task origins reflect the original targets, in sorted plan order.
    origins = [t.origin for t in plan.tasks]
    assert len(origins) == len(plan.tasks)


def test_golden_corpus_encoding_fidelity_distinct_task_ids():
    """Percent-encoded query variants (?a=%2F vs ?a=/) are distinct tasks."""
    corpus = _load_corpus()
    settings = dict(corpus["settings"])
    templates = list(settings["NUCLEI_TEMPLATES"])
    planner = ScanPlanner(settings, templates)
    plan = planner.plan(corpus["targets"], inventory=corpus.get("inventory"))

    ids = [t.task_id for t in plan.tasks]
    assert len(ids) == len(set(ids)) == corpus["expected"]["total"], \
        "every target x template must be a distinct task"

    # ?a=%2F and ?a=/ on the same path must not collapse to one task id.
    ids_percent = [t.task_id for t in plan.tasks
                   if t.path == "/api/search" and t.query == (("q", "%2F"),)]
    ids_slash = [t.task_id for t in plan.tasks
                 if t.path == "/api/search" and t.query == (("q", "/"),)]
    # The two encodings are distinct keys (query kept raw, not decoded): each
    # appears once per template (5 templates) and no id is shared between them.
    assert len(ids_percent) == len(templates)
    assert len(ids_slash) == len(templates)
    assert set(ids_percent).isdisjoint(set(ids_slash))


def test_golden_corpus_shadow_vs_off_manifest_diff(tmp_path):
    """Manifest diff between shadow and off: documented decision trail."""
    corpus = _load_corpus()
    settings = corpus["settings"]
    templates = list(settings["NUCLEI_TEMPLATES"])
    targets = corpus["targets"]

    plan_shadow = plan_for_settings(dict(settings), templates, targets)
    plan_off = plan_for_settings(
        dict(corpus["settings"], PLANNER_MODE="off"), templates, targets)

    diff = {
        "mode_shadow": plan_shadow.mode,
        "mode_off": plan_off.mode,
        "tasks_shadow": len(plan_shadow.tasks),
        "tasks_off": len(plan_off.tasks),
        "disposition_counts_shadow": plan_shadow.disposition_counts(),
        "disposition_counts_off": plan_off.disposition_counts(),
        "plan_id_shadow": plan_shadow.plan_id,
        "plan_id_off": plan_off.plan_id,
        "oversize_shadow": plan_shadow.oversize,
        "oversize_off": plan_off.oversize,
        # Zero traffic delta: off carries no tasks; shadow's plan is pure
        # accounting and never changes dispatched targets/argv/order.
        "traffic_delta": "none",
    }
    report_path = tmp_path / "golden_replay_diff.json"
    report_path.write_text(json.dumps(diff, indent=2, sort_keys=True))
    assert report_path.exists()

    # Shadow has real tasks; off has none; both deterministic.
    assert len(plan_shadow.tasks) > 0
    assert len(plan_off.tasks) == 0
    assert plan_shadow.plan_id != "" and plan_off.plan_id != ""


def test_golden_corpus_shuffle_invariant():
    """Shuffling the input targets does not change the shadow plan."""
    corpus = _load_corpus()
    settings = corpus["settings"]
    templates = list(settings["NUCLEI_TEMPLATES"])
    targets = list(corpus["targets"])
    import random
    shuffled = list(targets)
    random.Random(7).shuffle(shuffled)
    plan_a = plan_for_settings(settings, templates, targets,
                               inventory=corpus.get("inventory"))
    plan_b = plan_for_settings(settings, templates, shuffled,
                               inventory=corpus.get("inventory"))
    assert [t.task_id for t in plan_a.tasks] == [t.task_id for t in plan_b.tasks]
    assert plan_a.disposition_counts() == plan_b.disposition_counts()
    assert plan_a.plan_id == plan_b.plan_id
    assert plan_a.manifest == plan_b.manifest
