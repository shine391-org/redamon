"""FFuf origin-ownership planner (F11).

The FFuf caller used to build ONE global base-path set from every origin in the
run and then fuzzed EVERY target under EVERY base path -- a cross-product. With
origin A showing ``/api`` and origin B showing ``/console``, the run produced
``A/console/FUZZ`` and ``B/api/FUZZ``: workload no observation justified, under
an app prefix that origin never showed.

This module plans per origin instead:

* a base path is fuzzed under an origin only when that origin's OWN inventory
  showed it (``owned``);
* a base path seen on another origin is a cross-origin HYPOTHESIS, recorded
  with its reason and a labeled cost, and fuzzed only when the caller
  explicitly opts in (``cross_origin=True``, default False -- no default
  workload expansion);
* the extensions list is per origin, so an AI pick made for one target is not
  replayed against every other target.

The planner is gated by the shared planner controls (``PLANNER_MODE``):

* ``off``     -> ``None``. The caller keeps the legacy global-union behaviour
                exactly. This is the rollback.
* ``shadow``  -> a plan is computed and recorded, and the caller still executes
                the legacy path: zero behaviour change, no new traffic and no
                new LLM probes.
* ``enforce`` -> the caller executes the ownership plan.

Determinism: origins and base paths are sorted, the cap pick is seeded from the
plan inputs, and ``select_base_paths`` stays the single seam a ranker hooks.
The manifest carries no credentials and no raw headers: origins are keyed with
userinfo stripped and only paths/counts are recorded.
"""
from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from recon.helpers.planner_manifest import (
    MODE_OFF,
    MODE_ENFORCE,
    resolve_mode,
    _redact,
)
from recon.helpers.resource_enum.ffuf_helpers import (
    base_paths_of,
    directory_target,
    origin_key,
    select_base_paths,
)

#: Bound on recorded cross-origin hypotheses per plan. Overflow is counted, so
#: the truncation is observable rather than silent.
MAX_CROSS_ORIGIN = 200
#: Bound on target plans recorded per run (a target URL is one plan entry).
MAX_TARGETS = 4096
#: Labeled estimate for one fuzz task. Never reported as an actual request
#: count: one task is one ffuf invocation over a wordlist, not one request.
TASK_ESTIMATE = 1
#: Provenance recorded for an owned base path.
PROV_OWNED = "rule:origin-owned"
#: Provenance recorded for a cross-origin task executed under the opt-in.
PROV_CROSS_ORIGIN = "rule:cross-origin-opt-in"


@dataclass(frozen=True)
class CrossOriginHypothesis:
    """A base path one origin showed that another origin did not.

    ``estimate`` is a LABELED estimate of the requests this task would cause;
    it is never an actual request count.
    """

    base_path: str
    target_origin: str
    source_origins: Tuple[str, ...]
    reason: str
    estimate: int = TASK_ESTIMATE


@dataclass(frozen=True)
class TargetFuzzPlan:
    """The planned FFuf tasks for one caller target URL."""

    target: str
    origin: str
    root_task: str
    owned_base_paths: Tuple[str, ...]
    owned_tasks: Tuple[str, ...]
    cross_origin_base_paths: Tuple[str, ...]
    cross_origin_tasks: Tuple[str, ...]
    extensions: Tuple[str, ...]
    extensions_source: str
    provenance: str
    reason: str


@dataclass
class FFufOwnershipPlan:
    """A deterministic per-origin FFuf plan for one run."""

    mode: str
    execute: bool
    cap: int
    cap_scope: str
    cross_origin_enabled: bool
    targets: List[TargetFuzzPlan] = field(default_factory=list)
    cross_origin: Dict[str, List[CrossOriginHypothesis]] = field(default_factory=dict)
    counts: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False
    seed: str = ""
    manifest: Dict[str, Any] = field(default_factory=dict)

    def origin_base_paths(self) -> Dict[str, List[str]]:
        """The per-origin base-path map the executor consumes.

        Cross-origin base paths are folded in only when the opt-in was given,
        so by default the map is exactly the owned set and nothing expands.
        """
        out: Dict[str, List[str]] = {}
        for plan in self.targets:
            bucket = out.setdefault(plan.origin, [])
            for path in plan.owned_base_paths:
                if path not in bucket:
                    bucket.append(path)
            if self.cross_origin_enabled:
                for path in plan.cross_origin_base_paths:
                    if path not in bucket:
                        bucket.append(path)
        return out

    def all_tasks(self) -> List[str]:
        """Every planned task URL, root + owned + opted-in cross-origin."""
        tasks: List[str] = []
        for plan in self.targets:
            tasks.append(plan.root_task)
            tasks.extend(plan.owned_tasks)
            if self.cross_origin_enabled:
                tasks.extend(plan.cross_origin_tasks)
        return list(dict.fromkeys(tasks))


def _cap_from_settings(settings: Mapping[str, Any]) -> int:
    """The saved prefix cap, read but never silently changed (F11 DoD)."""
    raw = settings.get("FFUF_SMART_FUZZ_MAX_BASE_PATHS", 20)
    try:
        cap = int(raw)
    except (TypeError, ValueError):
        cap = 20
    return cap if cap > 0 else 0


def _plan_seed(targets: Sequence[str], observed: Mapping[str, set], *,
               cap: int, smart: bool, cross_origin: bool) -> str:
    """Seed the cap pick from the plan inputs, so the plan is reproducible."""
    payload = {
        "targets": sorted(targets),
        "observed": {o: sorted(p) for o, p in sorted(observed.items())},
        "cap": cap,
        "smart": smart,
        "cross_origin": cross_origin,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]


def _normalize_inventory(by_base_url: Any) -> Dict[str, set]:
    """`{origin: set(base paths)}` from the canonical resource_enum shape.

    Accepts the full pipeline's ``organized_data['by_base_url']`` and the
    partial caller's per-origin path map alike, so both plan from the same
    canonical inventory. Endpoints with no usable path contribute nothing; the
    caller keeps every raw observation regardless.
    """
    observed: Dict[str, set] = {}
    if not isinstance(by_base_url, Mapping):
        return observed
    for base_url, data in by_base_url.items():
        origin = origin_key(base_url) if isinstance(base_url, str) else ""
        if not origin:
            continue
        paths = set()
        if isinstance(data, Mapping):
            endpoints = data.get("endpoints")
            if isinstance(endpoints, Mapping):
                for path in endpoints:
                    if isinstance(path, str) and path:
                        paths |= base_paths_of(path)
            elif isinstance(data.get("paths"), (list, tuple, set)):
                # Partial caller shape: {origin: {"paths": [...]}}
                for path in data["paths"]:
                    if isinstance(path, str) and path:
                        paths |= base_paths_of(path)
        observed.setdefault(origin, set()).update(paths)
    return observed


def plan_ffuf_ownership(
    *,
    target_urls: Iterable[str],
    by_base_url: Any,
    settings: Mapping[str, Any],
    extensions: Optional[Sequence[str]] = None,
    extensions_by_origin: Optional[Mapping[str, Sequence[str]]] = None,
    ranker=None,
    cross_origin: bool = False,
) -> Optional[FFufOwnershipPlan]:
    """Plan FFuf per origin. ``None`` when the planner is off (legacy runs).

    ``extensions`` is the operator's global list (static config). 
    ``extensions_by_origin`` is the per-origin AI pick; when present it wins
    per origin, so one target's pick is never replayed against another origin.
    ``cross_origin`` is the explicit opt-in for the cross-origin lane; it is
    False by default, so nothing expands without a deliberate choice.
    """
    mode = resolve_mode(settings)
    if mode == MODE_OFF:
        return None

    targets = sorted({u for u in (target_urls or []) if isinstance(u, str) and u})
    observed = _normalize_inventory(by_base_url)
    cap = _cap_from_settings(settings)
    smart = bool(settings.get("FFUF_SMART_FUZZ", True))
    seed = _plan_seed(targets, observed, cap=cap, smart=smart,
                      cross_origin=cross_origin)
    rng = random.Random(seed)

    counts = {
        "targets": 0,
        "root_tasks": 0,
        "owned_tasks": 0,
        "cross_origin_tasks": 0,
        "cross_origin_hypotheses": 0,
        "truncated_hypotheses": 0,
        "owned_paths_capped": 0,
    }
    plan = FFufOwnershipPlan(
        mode=mode,
        execute=(mode == MODE_ENFORCE),
        cap=cap,
        cap_scope="per_origin",
        cross_origin_enabled=bool(cross_origin),
        seed=seed,
    )

    for url in targets:
        if len(plan.targets) >= MAX_TARGETS:
            plan.truncated = True
            break
        origin = origin_key(url)
        if not origin:
            # Not an http(s) target: admission owns the refusal; the planner
            # records nothing rather than inventing an origin for it.
            continue

        root_task = directory_target(url)
        owned = sorted(observed.get(origin, set())) if smart else []
        if smart and cap > 0 and len(owned) > cap:
            owned = sorted(select_base_paths(set(owned), cap, rng=rng,
                                             ranker=ranker))
            counts["owned_paths_capped"] += 1
        owned_tasks = tuple(directory_target(url, p) for p in owned)

        # Cross-origin lane: a base path THIS origin did not show, but another
        # one did. Recorded always; executed only under the explicit opt-in.
        other: Dict[str, set] = {}
        for other_origin, paths in observed.items():
            if other_origin != origin:
                other[other_origin] = paths
        cross_paths = sorted(set().union(*other.values()) - set(owned)) if other else []
        hypotheses: List[CrossOriginHypothesis] = []
        cross_tasks: List[str] = []
        for path in cross_paths:
            if len(hypotheses) >= MAX_CROSS_ORIGIN:
                plan.truncated = True
                counts["truncated_hypotheses"] += 1
                continue
            sources = tuple(sorted(o for o, paths in other.items() if path in paths))
            hypotheses.append(CrossOriginHypothesis(
                base_path=path,
                target_origin=origin,
                source_origins=sources,
                reason=("base path observed on another origin, not owned by this "
                        "origin; cross-origin fuzz is an explicit opt-in"),
            ))
            if cross_origin:
                cross_paths.append(path)
                cross_tasks.append(directory_target(url, path))
        if hypotheses:
            plan.cross_origin[origin] = hypotheses
            counts["cross_origin_hypotheses"] += len(hypotheses)
            counts["cross_origin_tasks"] += len(cross_tasks)

        if extensions_by_origin is not None:
            origin_exts = tuple(extensions_by_origin.get(origin, ()) or ())
            extensions_source = "per_origin"
        else:
            origin_exts = tuple(extensions or ())
            extensions_source = "global"

        plan.targets.append(TargetFuzzPlan(
            target=url,
            origin=origin,
            root_task=root_task,
            owned_base_paths=tuple(owned),
            owned_tasks=owned_tasks,
            cross_origin_base_paths=tuple(cross_paths),
            cross_origin_tasks=tuple(cross_tasks),
            extensions=origin_exts,
            extensions_source=extensions_source,
            provenance=PROV_CROSS_ORIGIN if cross_tasks else PROV_OWNED,
            reason=("per-origin ownership plan"
                    + ("; cross-origin lane enabled" if cross_tasks else "")),
        ))
        counts["targets"] += 1
        counts["root_tasks"] += 1
        counts["owned_tasks"] += len(owned_tasks)

    plan.counts = counts
    plan.manifest = _build_manifest(plan, observed)
    return plan


def _build_manifest(plan: FFufOwnershipPlan,
                    observed: Mapping[str, set]) -> Dict[str, Any]:
    """Run-scoped, credential-free manifest content for the ownership plan."""
    return _redact({
        "schema_version": 1,
        "planner_version": 1,
        "consumer": "ffuf_ownership",
        "mode": plan.mode,
        "execute": plan.execute,
        "cap": plan.cap,
        "cap_scope": plan.cap_scope,
        "cross_origin_enabled": plan.cross_origin_enabled,
        "seed": plan.seed,
        "counts": dict(plan.counts),
        "truncated": plan.truncated,
        "observed_origins": sorted(observed),
        "targets": [
            {
                "target": p.target,
                "origin": p.origin,
                "root_task": p.root_task,
                "owned_base_paths": list(p.owned_base_paths),
                "owned_tasks": list(p.owned_tasks),
                "cross_origin_tasks": list(p.cross_origin_tasks),
                "extensions": list(p.extensions),
                "extensions_source": p.extensions_source,
                "provenance": p.provenance,
            }
            for p in plan.targets
        ],
        "cross_origin": {
            origin: [
                {
                    "base_path": h.base_path,
                    "source_origins": list(h.source_origins),
                    "reason": h.reason,
                    "estimate": h.estimate,
                }
                for h in hyps
            ]
            for origin, hyps in sorted(plan.cross_origin.items())
        },
    })


def planner_honoured(settings: Mapping[str, Any]) -> bool:
    """Whether the FFuf ownership planner is honoured for this run.

    Shared by both call sites so the full pipeline and partial recon make the
    SAME decision from the SAME settings -- they cannot drift apart.
    """
    return resolve_mode(settings) != MODE_OFF
