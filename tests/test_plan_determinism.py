"""F10 — plan determinism: fixed source/settings/template hash/seed produce the
same plan regardless of input shuffle and PYTHONHASHSEED.

Imports only the pure planner module (stdlib only).
"""
from __future__ import annotations

import sys
import types as _types
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

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

from recon.helpers.scan_planner import (  # noqa: E402
    Disposition, PlanTask, ScanPlanner, plan_for_settings,
)


def _settings(**extra):
    base = {
        "PLANNER_MODE": "shadow",
        "PLANNER_MANIFEST_ENABLED": True,
        "NUCLEI_TAGS": ["cve", "xss"],
        "NUCLEI_TEMPLATES": ["cve/2021-44228.yaml", "exposure/panel.yaml"],
        "TARGET_DOMAIN": "example.com",
        "NUCLEI_RATE_LIMIT": 100,
    }
    base.update(extra)
    return base


# --------------------------------------------------------------------------- #
# Determinism: same inputs -> same plan                                       #
# --------------------------------------------------------------------------- #

def test_same_inputs_same_plan():
    """Identical inputs produce byte-identical plans."""
    settings = _settings()
    urls = [
        "https://example.com/a?q=1",
        "https://example.com/b?q=2",
        "https://example.com/c?q=3",
    ]
    p1 = plan_for_settings(settings, ["cve/x.yaml"], urls)
    p2 = plan_for_settings(settings, ["cve/x.yaml"], urls)
    assert p1.plan_id == p2.plan_id
    assert [t.task_id for t in p1.tasks] == [t.task_id for t in p2.tasks]
    assert p1.disposition_counts() == p2.disposition_counts()
    assert p1.manifest == p2.manifest


def test_input_shuffle_invariant():
    """Shuffling the input URL list does not change the plan."""
    settings = _settings()
    urls = [
        "https://example.com/z",
        "https://example.com/a",
        "https://example.com/m",
    ]
    import random
    # Deterministic shuffle seed for the test itself.
    shuffled = list(urls)
    random.Random(42).shuffle(shuffled)
    p_original = plan_for_settings(settings, ["cve/x.yaml"], urls)
    p_shuffled = plan_for_settings(settings, ["cve/x.yaml"], shuffled)
    assert [t.task_id for t in p_original.tasks] == [t.task_id for t in p_shuffled.tasks]
    assert p_original.disposition_counts() == p_shuffled.disposition_counts()
    assert p_original.plan_id == p_shuffled.plan_id


def test_template_order_invariant():
    """Template ref list order does not change the plan."""
    settings = _settings()
    urls = ["https://example.com/a"]
    t_a = ["cve/x.yaml", "exposure/y.yaml"]
    t_b = ["exposure/y.yaml", "cve/x.yaml"]
    p_a = plan_for_settings(settings, t_a, urls)
    p_b = plan_for_settings(settings, t_b, urls)
    assert p_a.plan_id == p_b.plan_id
    assert [t.task_id for t in p_a.tasks] == [t.task_id for t in p_b.tasks]


def test_settings_hash_in_plan_id():
    """Changing a setting changes the plan_id (settings hash is part of the plan)."""
    settings_a = _settings(NUCLEI_RATE_LIMIT=100)
    settings_b = _settings(NUCLEI_RATE_LIMIT=200)
    p_a = plan_for_settings(settings_a, ["cve/x.yaml"], ["https://example.com/a"])
    p_b = plan_for_settings(settings_b, ["cve/x.yaml"], ["https://example.com/a"])
    assert p_a.plan_id != p_b.plan_id


def test_seed_in_plan_id():
    """A different planning seed changes the plan_id."""
    p_a = plan_for_settings(_settings(), ["cve/x.yaml"], ["https://example.com/a"],
                            seed="alpha")
    p_b = plan_for_settings(_settings(), ["cve/x.yaml"], ["https://example.com/a"],
                            seed="beta")
    assert p_a.plan_id != p_b.plan_id


# --------------------------------------------------------------------------- #
# PYTHONHASHSEED invariance (structural)                                      #
# --------------------------------------------------------------------------- #

def test_planner_never_iterates_unsorted_sets():
    """Structural check: the planner sorts all inputs; no set/dict order dependence."""
    settings = _settings()
    # Build a planner with templates in non-sorted order; the planner must sort them.
    planner = ScanPlanner(settings, ["zebra.yaml", "alpha.yaml", "mid.yaml"])
    # Internal template_refs must be sorted.
    assert planner.template_refs == ["alpha.yaml", "mid.yaml", "zebra.yaml"]
    # Plan targets are sorted internally too.
    plan = planner.plan(["https://example.com/c", "https://example.com/a",
                         "https://example.com/b"])
    origins = [t.origin for t in plan.tasks]
    assert origins == sorted(origins)


# --------------------------------------------------------------------------- #
# Fixed source/settings/template hash/seed                                    #
# --------------------------------------------------------------------------- #

def test_plan_reflects_source_settings_template_seed():
    """The plan is bound to source/settings/template hash/seed."""
    settings = _settings()
    base_urls = ["https://example.com/a"]
    base_templates = ["cve/x.yaml"]

    p1 = plan_for_settings(settings, base_templates, base_urls)

    # Different settings -> different plan.
    p2 = plan_for_settings({**settings, "TARGET_DOMAIN": "other.com"},
                           base_templates, base_urls)
    assert p1.plan_id != p2.plan_id

    # Different templates -> different plan.
    p3 = plan_for_settings(settings, ["cve/y.yaml"], base_urls)
    assert p1.plan_id != p3.plan_id

    # Different seed -> different plan.
    p4 = plan_for_settings(settings, base_templates, base_urls, seed="s1")
    p5 = plan_for_settings(settings, base_templates, base_urls, seed="s2")
    assert p4.plan_id != p5.plan_id


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
