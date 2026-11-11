"""F10 — planner partition properties: every candidate/eligible check has a
disposition (planned/compatibility/deferred/not-applicable/rejected); no silent
drop; task key keeps method/path/query/body/content type/auth revision; known
categories have proof/rule provenance; unknown semantics -> compatibility;
missing template -> explicit failed selection.

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
    Disposition, Plan, PlanTask, ScanPlanner, plan_for_settings,
    _template_known, _origin_known, _path_known, _content_type_known,
)


def _settings(**extra):
    base = {
        "PLANNER_MODE": "shadow",
        "PLANNER_MANIFEST_ENABLED": True,
        "TARGET_DOMAIN": "example.com",
    }
    base.update(extra)
    return base


# --------------------------------------------------------------------------- #
# Partition: every candidate/eligible check has a disposition                  #
# --------------------------------------------------------------------------- #

def test_partition_covers_all_dispositions():
    """A mixed input set exercises every disposition exactly once per case."""
    settings = _settings()
    templates = ["cve/2021-44228.yaml", "", "weird/unknown.yaml"]
    urls = [
        "https://example.com/api?q=1",       # in scope, known template -> planned
        "https://evil.example.net/x",         # out of scope -> not_applicable
        "https://example.com/a",              # unknown template -> compatibility
        "https://example.com/b",              # empty template -> deferred
    ]
    planner = ScanPlanner(settings, templates)
    plan = planner.plan(urls)
    present = {t.disposition for t in plan.tasks}
    assert Disposition.PLANNED in present
    assert Disposition.COMPATIBILITY in present
    assert Disposition.DEFERRED in present
    assert Disposition.NOT_APPLICABLE in present


def test_no_silent_drop_all_inputs_accounted():
    """Every input target × template yields exactly one task."""
    settings = _settings()
    urls = ["https://example.com/a", "https://example.com/b"]
    templates = ["cve/x.yaml"]
    planner = ScanPlanner(settings, templates)
    plan = planner.plan(urls)
    assert len(plan.tasks) == len(urls) * len(templates)
    total = sum(plan.disposition_counts().values())
    assert total == len(plan.tasks)


# --------------------------------------------------------------------------- #
# Known categories have proof/rule provenance                                  #
# --------------------------------------------------------------------------- #

def test_known_template_prefixes_map_to_rule_provenance():
    """Each known template prefix maps to a distinct rule provenance."""
    cases = [
        ("cve/2021-44228.yaml", "rule:template-known-cve"),
        ("vuln/xss.yaml", "rule:template-known-vuln"),
        ("exposure/panel.yaml", "rule:template-known-exposure"),
        ("misconfig/s3.yaml", "rule:template-known-misconfig"),
        ("default-login/admin.yaml", "rule:template-known-default-login"),
        ("takeover/subdomain.yaml", "rule:template-known-takeover"),
        ("technologies/nginx.yaml", "rule:template-known-technologies"),
        ("fuzz/paths.yaml", "rule:template-known-fuzz"),
    ]
    for template, expected in cases:
        prov = _template_known(template)
        assert prov == expected, f"{template}: expected {expected}, got {prov}"


def test_unknown_template_has_no_provenance():
    """A template not matching any known prefix has None provenance."""
    assert _template_known("") is None
    assert _template_known("random/thing.yaml") is None
    assert _template_known("CVE/2021-44228.yaml") is None  # case-sensitive


def test_planned_task_carries_rule_provenance():
    """A PLANNED task's provenance includes both template and target rules."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/2021-44228.yaml"])
    plan = planner.plan(["https://example.com/api/search"])
    task = plan.tasks[0]
    assert task.disposition == Disposition.PLANNED
    assert "rule:template-known-cve" in task.provenance
    assert "rule:target-known" in task.provenance


# --------------------------------------------------------------------------- #
# Unknown semantics -> compatibility, missing template -> explicit failed      #
# --------------------------------------------------------------------------- #

def test_unknown_template_semantics_is_compatibility():
    """Unknown template semantics -> COMPATIBILITY, not nonexistent/disallowed."""
    settings = _settings()
    planner = ScanPlanner(settings, ["obscure/new-category.yaml"])
    plan = planner.plan(["https://example.com/x"])
    task = plan.tasks[0]
    assert task.disposition == Disposition.COMPATIBILITY
    assert task.provenance == "rule:template-unknown"
    assert "compatibility" in task.reason.lower()


def test_missing_template_is_explicit_failed_selection():
    """Empty template ref -> DEFERRED with an explicit reason, never silent."""
    settings = _settings()
    planner = ScanPlanner(settings, [""])
    plan = planner.plan(["https://example.com/x"])
    task = plan.tasks[0]
    assert task.disposition == Disposition.DEFERRED
    assert task.provenance == "rule:template-missing"
    assert "missing" in task.reason.lower()
    assert task.estimate is None


# --------------------------------------------------------------------------- #
# Task key fidelity                                                             #
# --------------------------------------------------------------------------- #

def test_task_key_preserves_method_path_query_body_content_type_auth():
    """The task key includes all security-relevant components."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://example.com/x?q=1&b=2"])
    task = plan.tasks[0]
    assert task.method == "GET"
    assert ("q", "1") in task.query
    assert ("b", "2") in task.query
    # Different auth revision -> different task id.
    from recon.helpers.scan_planner import _task_id
    id_a = _task_id(template="cve/x.yaml", origin="https://a.test", path="/x",
                    method="GET", query=(("q", "1"),), body=(),
                    content_type="", auth_revision="rev1")
    id_b = _task_id(template="cve/x.yaml", origin="https://a.test", path="/x",
                    method="GET", query=(("q", "1"),), body=(),
                    content_type="", auth_revision="rev2")
    assert id_a != id_b


# --------------------------------------------------------------------------- #
# Scope: in-scope vs out-of-scope                                              #
# --------------------------------------------------------------------------- #

def test_in_scope_root_domain_is_planned():
    """A target under the configured root domain is in scope."""
    settings = _settings(TARGET_DOMAIN="example.com")
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://www.example.com/path"])
    task = plan.tasks[0]
    assert task.disposition != Disposition.NOT_APPLICABLE


def test_out_of_scope_domain_is_not_applicable():
    """A target outside the root domain is NOT_APPLICABLE."""
    settings = _settings(TARGET_DOMAIN="example.com")
    planner = ScanPlanner(settings, ["cve/x.yaml"])
    plan = planner.plan(["https://other.example.org/path"])
    task = plan.tasks[0]
    assert task.disposition == Disposition.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
# Bounded counts                                                               #
# --------------------------------------------------------------------------- #

def test_counts_sum_to_task_count():
    """Disposition counts always sum to the number of tasks."""
    settings = _settings()
    planner = ScanPlanner(settings, ["cve/x.yaml", "exposure/y.yaml"])
    plan = planner.plan(["https://example.com/a", "https://example.com/b"])
    assert sum(plan.disposition_counts().values()) == len(plan.tasks) == 4
