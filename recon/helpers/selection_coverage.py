"""Selection coverage: what a tool run was asked to check, and what it proved.

A run that selects a subset of targets or templates cannot prove a finding
outside that subset was re-checked, so the prune must keep it. The plan is
persisted into the recon artifact BEFORE the tool launches, so a cancellation
or a crash still leaves the accounting; a run whose plan is missing reads as
unknown coverage, never as clean.

The plan is deliberately conservative. It records the selection and its
outcome; it never emits a per-path or per-template verdict, and it never
concludes "clean" from a process exit code. A later card may replace the
host-level protection with precise routing; this one must not invent it.

"Exhaustive" means the run's effective selection is exactly its configured
baseline. The operator's saved tags/templates/severity ARE the baseline: if
they counted as a selection, every default run would be selective and the
Nuclei prune would never run again. A reduction from that baseline (AI tag
pruning, a partial run's explicit limits, a deferred task) is a cut.
"""
from __future__ import annotations

import copy
import json
import threading
import uuid
from typing import Any, Iterable, Optional

from recon.helpers.circuit_breaker import host_key
from recon.helpers.coverage_stamps import run_started_at

#: The top-level recon-artifact key the plan lives under. It must survive the
#: isolated deep copy, the TopLevelKeys whitelist, the fan-in, the file save,
#: the Domain-batch merge, the graph writer and the API coverage reader.
KEY = "selection_coverage"
SCHEMA_VERSION = 1

#: The one lock every writer of the canonical recon artifact takes. The
#: isolated vuln_scan wrapper persists its selection plan from a fan-out
#: thread while the main thread keeps saving the merged result; a plan write
#: that bypassed this lock could interleave with a save into a corrupt file,
#: or clobber a tool whose results merged a moment earlier.
ARTIFACT_SAVE_LOCK = threading.Lock()

#: Plan statuses, worst-first, for merging several groups' plans.
STATUS_ORDER = ("failed", "partial", "planned", "complete")

#: Outcome counters summed when two groups' plans merge. A Domain batch runs
#: one plan per group; the canonical artifact must describe the whole batch,
#: not whichever group merged first.
OUTCOME_FIELDS = ("completed", "partial", "failed", "deferred", "unknown")


def new_plan_id() -> str:
    return uuid.uuid4().hex


def target_hosts(targets: Iterable[str]) -> list:
    """``host:port`` keys for the target URLs, sorted, empties dropped.

    The same shape the coverage record's ``skipped_hosts`` and the prune's
    ``keep_hostnames`` use, so a plan can be handed to the prune unchanged.
    """
    out = set()
    for url in targets or ():
        key = host_key(url)
        if key:
            out.add(key)
    return sorted(out)


def build_plan(*, module: str, targets: Iterable[str] = (), templates: Optional[dict] = None,
               exhaustive: bool = False, reason: str = "", scope: str = "full",
               plan_id: Optional[str] = None, extra: Optional[dict] = None) -> dict:
    """One run's selection plan.

    ``targets`` are the exact inputs asked for; ``templates`` is the effective
    selection; ``exhaustive`` says the selection covers everything the run's
    configuration could have asked for.
    """
    targets = list(targets or ())
    plan = {
        "schema_version": SCHEMA_VERSION,
        "module": str(module or "recon"),
        "plan_id": plan_id or new_plan_id(),
        "at": run_started_at(),
        "status": "planned",
        "scope": str(scope or "full"),
        "exhaustive": bool(exhaustive),
        "targets": {"count": len(targets), "hosts": target_hosts(targets)},
        "templates": copy.deepcopy(templates or {}),
        "outcomes": {field: 0 for field in OUTCOME_FIELDS},
        "reason": reason or None,
    }
    if extra:
        plan.update(copy.deepcopy(extra))
    return plan


def record_outcome(plan: dict, status: str, *, completed: int = 0, partial: int = 0,
                   failed: int = 0, deferred: int = 0, unknown: int = 0) -> dict:
    """Return a copy of ``plan`` with its outcome recorded. Never raises."""
    try:
        out = copy.deepcopy(plan)
        out["status"] = str(status or "complete")
        for field, value in (("completed", completed), ("partial", partial),
                             ("failed", failed), ("deferred", deferred),
                             ("unknown", unknown)):
            out["outcomes"][field] = int(out["outcomes"].get(field) or 0) + int(value or 0)
        return out
    except Exception:  # noqa: BLE001 - a plan is never worth failing a scan over
        return plan


def is_exhaustive(plan) -> bool:
    return bool(isinstance(plan, dict) and plan.get("exhaustive"))


def plan_hosts(plan) -> list:
    """The ``host:port`` keys a selective plan applies to, sorted."""
    if not isinstance(plan, dict):
        return []
    return sorted((plan.get("targets") or {}).get("hosts") or [])


def plan_ids(plan) -> list:
    """Every plan id a (possibly merged) plan carries, in order."""
    if not isinstance(plan, dict):
        return []
    ids = []
    for value in [plan.get("plan_id")] + list(plan.get("plan_ids") or []):
        if isinstance(value, str) and value and value not in ids:
            ids.append(value)
    return ids


def _worst(status: str) -> int:
    try:
        return STATUS_ORDER.index(status)
    except ValueError:
        return len(STATUS_ORDER)


def merge_plans(plans: Iterable[dict]) -> Optional[dict]:
    """Merge several groups' plans into one canonical plan.

    Counts are SUMMED (two groups that covered 5 and 3 targets covered 8, not
    5), the host list and every template list are UNIONED (never concatenated
    twice), ``at`` is the earliest, ``exhaustive`` holds only when every plan
    was exhaustive, and the status is the worst. The id list keeps every id so
    a reader can tell a merged batch from one group's plan.
    """
    plans = [p for p in plans or () if isinstance(p, dict)]
    if not plans:
        return None
    out = copy.deepcopy(plans[0])
    out["plan_id"] = None
    ids: list = []
    for plan in plans:
        for pid in plan_ids(plan):
            if pid not in ids:
                ids.append(pid)
    out["plan_ids"] = ids
    out["targets"] = out.get("targets") or {}
    out["targets"]["count"] = sum(int((p.get("targets") or {}).get("count") or 0) for p in plans)
    hosts: set = set()
    for plan in plans:
        hosts.update(plan_hosts(plan))
    out["targets"]["hosts"] = sorted(hosts)

    templates = out.setdefault("templates", {})
    for plan in plans:
        for key, value in (plan.get("templates") or {}).items():
            if isinstance(value, list):
                merged = list(templates.get(key) or [])
                for item in value:
                    if item not in merged:
                        merged.append(item)
                templates[key] = merged
            elif value not in (None, "", [], {}):
                templates.setdefault(key, value)

    outcomes = out.setdefault("outcomes", {})
    for field in OUTCOME_FIELDS:
        outcomes[field] = sum(int((p.get("outcomes") or {}).get(field) or 0) for p in plans)

    out["exhaustive"] = all(is_exhaustive(p) for p in plans)
    out["scope"] = "partial" if any(p.get("scope") == "partial" for p in plans) else "full"
    out["status"] = min(((p.get("status") or "complete") for p in plans), key=_worst)
    out["at"] = min([p.get("at") or "" for p in plans]) or None
    reasons = []
    for plan in plans:
        reason = plan.get("reason")
        if isinstance(reason, str) and reason and reason not in reasons:
            reasons.append(reason)
    out["reason"] = "; ".join(reasons) or None
    return out


def summarize(plans: Iterable[dict]) -> dict:
    """The bounded block the coverage record carries for the API reader.

    Never a URL, a template body or a credential: counts, ids, sources and
    reasons only, so the block can be shown without leaking target data.
    """
    plans = [p for p in plans or () if isinstance(p, dict)]
    if not plans:
        return {"recorded": False}
    sources = sorted({str(p.get("module") or "recon") for p in plans})
    return {
        "recorded": True,
        "exhaustive": all(is_exhaustive(p) for p in plans),
        "scope": "partial" if any(p.get("scope") == "partial" for p in plans) else "full",
        "status": min(((p.get("status") or "complete") for p in plans), key=_worst),
        "plan_ids": [pid for p in plans for pid in plan_ids(p)],
        "sources": sources,
        "hosts_count": len({h for p in plans for h in plan_hosts(p)}),
        "targets_count": sum(int((p.get("targets") or {}).get("count") or 0) for p in plans),
        "reasons": sorted({p["reason"] for p in plans if isinstance(p.get("reason"), str)}),
    }


# ---------------------------------------------------------------------------
# The bounded block the coverage record and the graph writer carry for the API
# coverage reader. One shape, so a reader can merge the per-run record with the
# per-group plan write without guessing which writer produced which field.
# ---------------------------------------------------------------------------

def selection_block(plan, *, selection_unknown: bool = False) -> dict:
    """The bounded block for one recorded selection plan.

    ``recorded``: a plan exists. ``selection_unknown``: a selection cut had no
    plan id, so the run cannot say what it selected (the prune fails closed).
    ``plan_ids``: every plan id behind the block. ``exhaustive``: the run cut
    nothing - a recorded plan that was itself exhaustive, and no unknown cut.
    Never a URL, a template body or a credential.
    """
    plan = plan if isinstance(plan, dict) else {}
    ids = plan_ids(plan)
    return {
        "recorded": bool(plan) or bool(ids),
        "selection_unknown": bool(selection_unknown),
        "plan_ids": ids,
        "exhaustive": (not selection_unknown) and is_exhaustive(plan),
    }


def parse_selection_block(raw) -> Optional[dict]:
    """Parse a stored selection block (JSON string or dict); None when malformed.

    Lenient about extra keys, strict about the ones the reader relies on: an
    unparseable value is dropped rather than trusted, because an imported graph
    bundle is untrusted input.
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            return None
    if not isinstance(raw, dict):
        return None
    raw_ids = raw.get("plan_ids")
    if raw_ids is None:
        raw_ids = []
    if not isinstance(raw_ids, list):
        return None
    ids = [p for p in raw_ids if isinstance(p, str) and p]
    return {
        "recorded": bool(raw.get("recorded")),
        "selection_unknown": bool(raw.get("selection_unknown")),
        "plan_ids": ids,
        "exhaustive": bool(raw.get("exhaustive")),
    }


def merge_selection_blocks(old, new) -> Optional[dict]:
    """Merge two selection blocks (a run's groups, or the record and the plan).

    ``recorded`` and ``selection_unknown`` are OR-ed (either writer saw it),
    ``plan_ids`` are unioned without duplication, and ``exhaustive`` holds only
    when both sides cut nothing - one selective group makes the whole run
    selective. Returns None only when neither side parses.
    """
    old_b = parse_selection_block(old)
    new_b = parse_selection_block(new)
    if old_b is None:
        return new_b
    if new_b is None:
        return old_b
    ids = list(old_b["plan_ids"])
    for pid in new_b["plan_ids"]:
        if pid not in ids:
            ids.append(pid)
    return {
        "recorded": old_b["recorded"] or new_b["recorded"],
        "selection_unknown": old_b["selection_unknown"] or new_b["selection_unknown"],
        "plan_ids": ids,
        "exhaustive": old_b["exhaustive"] and new_b["exhaustive"],
    }


def persist_plan(output_file, plan) -> bool:
    """Merge ``plan`` into the canonical artifact at ``output_file``.

    The isolated vuln_scan wrapper calls this BEFORE its Nuclei pass launches,
    from a fan-out thread. The read-modify-write is under ``ARTIFACT_SAVE_LOCK``,
    the same lock ``save_recon_file`` holds, so it can neither interleave with
    the main thread's saves nor clobber a tool whose results merged a moment
    earlier; a plan is never worth failing a scan over, so a write failure
    returns False and the prune then fails closed on the missing manifest.
    """
    if not isinstance(plan, dict) or not plan:
        return False
    try:
        with ARTIFACT_SAVE_LOCK:
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
            except Exception:  # noqa: BLE001 - absent or unreadable: start fresh
                data = {}
            if not isinstance(data, dict):
                data = {}
            data[KEY] = plan
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
        return True
    except Exception:  # noqa: BLE001 - the prune fails closed without the plan
        return False
