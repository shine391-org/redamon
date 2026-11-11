"""F10 planner smoke tests — runs without pytest (plain Python)."""
import sys, types, json
from pathlib import Path
from dataclasses import FrozenInstanceError

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

for _missing in ("dns", "whois", "neo4j", "graph_db"):
    if _missing not in sys.modules:
        _mod = types.ModuleType(_missing)
        if _missing == "dns":
            for _sub in ("resolver", "zone", "query", "exception", "rdatatype",
                         "rdataclass", "name", "reversename", "rcode",
                         "tokenizer", "tsigkeyring"):
                _submod = types.ModuleType(f"dns.{_sub}")
                setattr(_mod, _sub, _submod)
                sys.modules[f"dns.{_sub}"] = _submod
        sys.modules[_missing] = _mod

from recon.helpers.scan_planner import (  # noqa: E402
    Disposition, Plan, PlanTask, ScanPlanner, plan_for_settings,
    _task_id, _origin_known, _path_known, _content_type_known, _template_known,
    MAX_TASKS,
)

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print(f"FAIL: {msg}")
    else:
        print(f"PASS: {msg}")


def _settings(**extra):
    base = {"PLANNER_MODE": "shadow", "PLANNER_MANIFEST_ENABLED": True,
            "NUCLEI_TAGS": ["cve"], "NUCLEI_TEMPLATES": ["cve/x.yaml"],
            "TARGET_DOMAIN": "example.com"}
    base.update(extra)
    return base


# 1. every candidate has a disposition
settings = _settings()
planner = ScanPlanner(settings, ["cve/x.yaml"])
plan = planner.plan(["https://example.com/a"])
check(len(plan.tasks) == 1, "one task for one target")
check(plan.tasks[0].disposition in (Disposition.PLANNED, Disposition.COMPATIBILITY,
                                    Disposition.DEFERRED, Disposition.NOT_APPLICABLE,
                                    Disposition.REJECTED),
      "task has a valid disposition")

# 2. empty template -> deferred
planner = ScanPlanner(settings, [""])
plan = planner.plan(["https://example.com/x"])
check(plan.tasks[0].disposition == Disposition.DEFERRED, "empty template -> deferred")
check(plan.tasks[0].provenance == "rule:template-missing",
      "deferred provenance is template-missing")
check(plan.tasks[0].estimate is None, "deferred estimate is None")

# 3. unknown template -> compatibility
planner = ScanPlanner(settings, ["weird/unknown.yaml"])
plan = planner.plan(["https://example.com/x"])
check(plan.tasks[0].disposition == Disposition.COMPATIBILITY,
      "unknown template -> compatibility")
check(plan.tasks[0].provenance == "rule:template-unknown",
      "compatibility provenance is template-unknown")

# 4. known template + known target -> planned
planner = ScanPlanner(settings, ["cve/2021-44228.yaml"])
plan = planner.plan(["https://example.com/api/search"])
check(plan.tasks[0].disposition == Disposition.PLANNED,
      "known template + known target -> planned")
check("rule:template-known-cve" in plan.tasks[0].provenance,
      "planned task carries template provenance")
check("rule:target-known" in plan.tasks[0].provenance,
      "planned task carries target provenance")

# 5. out of scope -> not_applicable
settings2 = dict(settings, TARGET_DOMAIN="example.com")
planner = ScanPlanner(settings2, ["cve/x.yaml"])
plan = planner.plan(["https://evil.example.net/x"])
check(plan.tasks[0].disposition == Disposition.NOT_APPLICABLE,
      "out of scope -> not_applicable")

# 6. task key fidelity
base = dict(template="cve/x.yaml", origin="https://a.test", path="/x",
            method="GET", query=(), body=(), content_type="", auth_revision="")
ids = set()
ids.add(_task_id(**base))
ids.add(_task_id(**{**base, "method": "POST"}))
ids.add(_task_id(**{**base, "query": (("q", "1"),)}))
ids.add(_task_id(**{**base, "body": (("k", "v"),)}))
ids.add(_task_id(**{**base, "content_type": "application/json"}))
ids.add(_task_id(**{**base, "auth_revision": "rev2"}))
check(len(ids) == 6, "task key changes with any component")

# 7. determinism under shuffle
urls = ["https://example.com/a?q=1", "https://example.com/b?q=2",
        "https://example.com/c?q=3"]
p1 = plan_for_settings(settings, ["cve/x.yaml"], urls)
p2 = plan_for_settings(settings, ["cve/x.yaml"], list(reversed(urls)))
check([t.task_id for t in p1.tasks] == [t.task_id for t in p2.tasks],
      "shuffle invariant task ids")
check(p1.plan_id == p2.plan_id, "shuffle invariant plan_id")
check(p1.disposition_counts() == p2.disposition_counts(), "shuffle invariant counts")

# 8. off mode -> no tasks
settings_off = dict(settings, PLANNER_MODE="off")
planner = ScanPlanner(settings_off, ["cve/x.yaml"])
plan = planner.plan(["https://example.com/a"])
check(plan.mode == "off", "off mode recorded")
check(len(plan.tasks) == 0, "off mode -> no tasks")

# 9. estimates labeled
planner = ScanPlanner(settings, ["cve/x.yaml", ""])
plan = planner.plan(["https://example.com/a"])
ok = True
for task in plan.tasks:
    if task.disposition == Disposition.DEFERRED:
        if task.estimate is not None:
            ok = False
    else:
        if task.estimate is None:
            ok = False
check(ok, "estimates labeled: None for deferred, int for others")

# 10. oversize bounded
many_templates = [f"cve/{i}.yaml" for i in range(200)]
many_urls = [f"https://example.com/u{i}" for i in range(200)]
planner = ScanPlanner(settings, many_templates)
plan = planner.plan(many_urls)
check(plan.oversize is True, "oversize flag set")
check(len(plan.tasks) <= MAX_TASKS, "task count bounded by MAX_TASKS")

# 11. manifest no credentials
settings_with_creds = dict(settings, Authorization="Bearer secret", Cookie="sess=abc")
planner = ScanPlanner(settings_with_creds, ["cve/x.yaml"])
plan = planner.plan(["https://example.com/a"])
text = json.dumps(plan.manifest)
check("Bearer secret" not in text, "manifest redacts Authorization")
check("sess=abc" not in text, "manifest redacts Cookie")
check("settings" not in plan.manifest, "settings hashed not stored")
check("plan_id" in plan.manifest, "plan has plan_id")
check("disposition_counts" in plan.manifest, "manifest has disposition_counts")

# 12. seed changes plan_id
p_a = plan_for_settings(settings, ["cve/x.yaml"], ["https://example.com/a"], seed="a")
p_b = plan_for_settings(settings, ["cve/x.yaml"], ["https://example.com/a"], seed="b")
check(p_a.plan_id != p_b.plan_id, "seed changes plan_id")

# 13. PlanTask immutability
t = PlanTask(task_id="x", template="t", origin="o", path="/p", method="GET")
try:
    t.disposition = Disposition.COMPATIBILITY  # type: ignore[misc]
    check(False, "PlanTask immutable")
except FrozenInstanceError:
    check(True, "PlanTask immutable")

# 14. disposition counts sum to task count
planner = ScanPlanner(settings, ["cve/x.yaml", "exposure/y.yaml"])
plan = planner.plan(["https://example.com/a", "https://example.com/b"])
check(sum(plan.disposition_counts().values()) == len(plan.tasks) == 4,
      "counts sum to task count")

# 15. known template prefixes map to rule provenance
cases = [("cve/2021-44228.yaml", "rule:template-known-cve"),
         ("vuln/xss.yaml", "rule:template-known-vuln"),
         ("exposure/panel.yaml", "rule:template-known-exposure")]
for template, expected in cases:
    check(_template_known(template) == expected,
          f"template {template} -> {expected}")

# 16. unknown template has no provenance
check(_template_known("") is None, "empty template no provenance")
check(_template_known("random/thing.yaml") is None, "unknown template no provenance")

print()
if failures:
    print(f"{len(failures)} FAILURES:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("ALL SMOKE TESTS PASSED")
