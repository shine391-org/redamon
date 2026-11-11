"""
Scan planner: deterministic per (check × request) planning with a compatibility lane.

Sits between target/template construction and ``build_nuclei_command``. The
planner never edits ``build_target_urls`` (the shared builder) and never changes
dispatched target files, argv, or order.

In ``shadow`` mode the plan is computed and written into the run-scoped manifest,
but execution uses the legacy path unchanged — no target files, argv, or order
changes. ``off`` means no planner at all (patched legacy behavior).

Unknown template semantics go to the compatibility lane (legacy behavior), never
to "nonexistent/disallowed". A missing template is an explicit failed selection
(DEFERRED), never a silent drop.

Every candidate check×request gets a disposition:

* ``planned``      - known origin/app/path/input category with proof/rule provenance
* ``compatibility`` - unknown template semantics -> run legacy behavior
* ``deferred``      - missing template -> explicit failed selection
* ``not_applicable`` - out of scope / excluded by RoE
* ``rejected``      - policy conflict

Determinism: fixed source/settings/template hash/seed produce the same plan
regardless of input shuffle and PYTHONHASHSEED.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional

from recon.helpers.planner_manifest import (
    MODE_OFF, MODE_SHADOW, MODE_ENFORCE, resolve_mode,
    template_hashes_from_settings, scope_roots_from_settings,
)

#: Bound on tasks per plan, mirrored from planner_manifest so the manifest
#: writer and the planner agree on the collection ceiling.
MAX_TASKS = 64

#: Bound on template references hashed into the plan provenance.
MAX_TEMPLATE_REFS = 200

#: Bound on origin/path string length kept in a plan task.
MAX_TASK_STRING = 512


class Disposition(str, Enum):
    """Disposition of one planned (check × request) unit."""

    PLANNED = "planned"
    COMPATIBILITY = "compatibility"
    DEFERRED = "deferred"
    NOT_APPLICABLE = "not_applicable"
    REJECTED = "rejected"


ALL_DISPOSITIONS = (
    Disposition.PLANNED,
    Disposition.COMPATIBILITY,
    Disposition.DEFERRED,
    Disposition.NOT_APPLICABLE,
    Disposition.REJECTED,
)


#: Proof/rule references for known template categories. A template ref whose
#: leading segment matches one of these prefixes is treated as having known
#: semantics; anything else is unknown -> compatibility lane.
TEMPLATE_RULES: tuple[tuple[str, str], ...] = (
    ("cve/", "rule:template-known-cve"),
    ("vuln/", "rule:template-known-vuln"),
    ("exposure/", "rule:template-known-exposure"),
    ("misconfig/", "rule:template-known-misconfig"),
    ("default-login/", "rule:template-known-default-login"),
    ("takeover/", "rule:template-known-takeover"),
    ("technologies/", "rule:template-known-technologies"),
    ("dtap/", "rule:template-known-dtap"),
    ("fuzz/", "rule:template-known-fuzz"),
)

#: Origin rules: an origin is "known" when it parses as http(s), has a real
#: hostname (not a mock IP placeholder), and is not obviously out of scope.
KNOWN_ORIGIN_SCHEMES = ("http", "https")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clip(text: str, limit: int = MAX_TASK_STRING) -> str:
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _is_mock_ip_hostname(hostname: str) -> bool:
    """True when hostname is a dashed-IP placeholder (``192-88-99-10`` style).

    These exist so the graph can label the host; they are NOT resolvable and
    must never be planned as scan targets.
    """
    if not hostname or "." in hostname:
        return False
    candidate = hostname.strip().lower()
    import ipaddress
    try:
        if all(c in "0123456789-" for c in candidate) and "-" in candidate:
            ipaddress.ip_address(candidate.replace("-", "."))
            return True
        if all(c in "0123456789abcdef-" for c in candidate) and "-" in candidate:
            ipaddress.ip_address(candidate.replace("-", ":"))
            return True
    except ValueError:
        return False
    return False


def _origin_known(origin: str) -> bool:
    """An origin is known when it is a real http(s) URL with a resolvable host."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(origin)
    except (ValueError, TypeError):
        return False
    if parts.scheme not in KNOWN_ORIGIN_SCHEMES:
        return False
    if not parts.hostname:
        return False
    if _is_mock_ip_hostname(parts.hostname):
        return False
    return True


def _path_known(path: str) -> bool:
    """A path is known when it is a relative path without unresolved template vars."""
    if not isinstance(path, str) or not path:
        return False
    if not path.startswith("/") or path.startswith("//"):
        return False
    if "{" in path or "}" in path:
        return False
    return True


def _content_type_known(content_type: str) -> bool:
    """A content type is known when it is a simple media type string."""
    if not isinstance(content_type, str) or not content_type:
        return True  # absent content type is acceptable (GET with no body)
    ct = content_type.lower().split(";")[0].strip()
    return ct in ("", "application/x-www-form-urlencoded",
                  "application/json", "text/plain", "multipart/form-data",
                  "application/octet-stream")


def _template_known(template: str) -> Optional[str]:
    """Return the provenance rule for a known template, or None when unknown."""
    if not isinstance(template, str) or not template:
        return None
    for prefix, provenance in TEMPLATE_RULES:
        if template.startswith(prefix):
            return provenance
    return None


def _task_id(template: str, origin: str, path: str, method: str,
             query: tuple, body: tuple, content_type: str,
             auth_revision: str) -> str:
    """Deterministic task id: sha256 over the full task key.

    The key keeps method/path/query/body/content type/auth revision, so two
    requests that differ in any of these are different tasks. Sampling family
    does not imply equivalent security behavior.
    """
    payload = {
        "template": template,
        "origin": origin,
        "path": path,
        "method": method,
        "query": list(query),
        "body": list(body),
        "content_type": content_type,
        "auth_revision": auth_revision,
    }
    return "task_v1:" + _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")))


@dataclass(frozen=True)
class PlanTask:
    """One planned (check × request) unit.

    ``estimate`` is a labeled estimate of the number of requests this task
    would cause; it is never reported as an actual request count. URL × template
    is not an exact request count.
    """
    task_id: str
    template: str
    origin: str
    path: str
    method: str
    query: tuple[tuple[str, str], ...] = ()
    body: tuple[tuple[str, str], ...] = ()
    content_type: str = ""
    auth_revision: str = ""
    disposition: Disposition = Disposition.COMPATIBILITY
    estimate: Optional[int] = None
    provenance: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        # Normalize tuples so the frozen dataclass is hashable and comparable.
        object.__setattr__(self, "query", tuple(self.query))
        object.__setattr__(self, "body", tuple(self.body))


@dataclass
class Plan:
    """A deterministic plan for one run.

    ``counts`` maps disposition name -> task count. ``oversize`` is set when the
    input corpus exceeded a bound (backpressure observable, never silent
    truncation). ``manifest`` is the run-scoped manifest content (credentials
    redacted, settings hashed).
    """
    plan_id: str
    mode: str
    tasks: list[PlanTask] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    oversize: bool = False
    input_count: int = 0
    template_count: int = 0
    manifest: dict = field(default_factory=dict)

    def disposition_counts(self) -> dict[str, int]:
        return {d.value: self.counts.get(d.value, 0) for d in ALL_DISPOSITIONS}

    def tasks_by_disposition(self, disposition: Disposition) -> list[PlanTask]:
        return [t for t in self.tasks if t.disposition == disposition]


class ScanPlanner:
    """Deterministic planner for (check × request) units.

    ``settings`` is the run's settings dict (used for mode, template refs, and
    scope roots). ``template_refs`` are the configured template/tag references
    the planner classifies. ``seed`` is an optional planning seed (hashed into
    the plan id for reproducibility).
    """

    def __init__(self, settings: dict[str, Any], template_refs: Iterable[str],
                 seed: Optional[str] = None) -> None:
        self.settings = settings or {}
        # Dedupe and sort template refs for determinism (input shuffle invariant).
        # Keep empty strings (they become DEFERRED tasks), drop None only.
        self.template_refs = sorted(
            {str(t) for t in (template_refs or []) if t is not None})
        self.seed = seed or ""
        self.mode = resolve_mode(self.settings)
        # Planning context hash: settings hash + template refs hash + seed.
        ctx = {
            "settings_hash": hashlib.sha256(
                json.dumps(self.settings, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "template_refs": self.template_refs,
            "seed": self.seed,
        }
        self.plan_id = "plan_v1:" + _sha256(json.dumps(ctx, sort_keys=True))

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def plan(self, target_urls: Iterable[str],
             inventory: Optional[dict[str, Any]] = None) -> Plan:
        """Build a deterministic plan for the given target URLs.

        Each target × template combination becomes one PlanTask with a
        disposition. The plan never changes targets, argv, or execution order.
        """
        # Sort inputs for determinism: shuffle of the input list must not
        # change the plan, and PYTHONHASHSEED must not affect set/dict order.
        targets = sorted({str(u) for u in (target_urls or []) if isinstance(u, str) and u})
        input_count = len(targets)
        template_count = len(self.template_refs)

        # Off mode = patched legacy: no planner tasks, no optimization.
        if self.mode == MODE_OFF:
            return Plan(
                plan_id=self.plan_id,
                mode=self.mode,
                tasks=[],
                counts={d.value: 0 for d in ALL_DISPOSITIONS},
                oversize=False,
                input_count=input_count,
                template_count=template_count,
                manifest=self._build_manifest([], {d.value: 0 for d in ALL_DISPOSITIONS},
                                              False, input_count, template_count),
            )

        # Oversize detection: observable backpressure, never silent truncation.
        oversize = False
        if input_count > MAX_TASKS or template_count > MAX_TEMPLATE_REFS:
            oversize = True

        tasks: list[PlanTask] = []
        counts = {d.value: 0 for d in ALL_DISPOSITIONS}

        # Scope roots for not_applicable decisions.
        roots = scope_roots_from_settings(self.settings)

        for target in targets:
            if len(tasks) >= MAX_TASKS:
                # Bounded: stop adding tasks, mark oversize so a reader sees the
                # corpus was not fully planned (backpressure, not truncation).
                oversize = True
                break
            origin, path, method, query, body, content_type, auth_revision = \
                self._decompose_target(target)
            in_scope = self._origin_in_scope(origin, roots)

            for template in self.template_refs:
                if len(tasks) >= MAX_TASKS:
                    oversize = True
                    break
                task = self._classify_task(
                    template=template, origin=origin, path=path, method=method,
                    query=query, body=body, content_type=content_type,
                    auth_revision=auth_revision, in_scope=in_scope,
                )
                tasks.append(task)
                counts[task.disposition.value] += 1

        plan = Plan(
            plan_id=self.plan_id,
            mode=self.mode,
            tasks=tasks,
            counts=counts,
            oversize=oversize,
            input_count=input_count,
            template_count=template_count,
            manifest=self._build_manifest(tasks, counts, oversize, input_count,
                                          template_count),
        )
        return plan

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #

    def _decompose_target(self, target: str) -> tuple[str, str, str, tuple, tuple, str, str]:
        """Split a target URL into its plan key components.

        Query and body are preserved as (name, value) tuples with the encoding
        the URL carried. Method defaults to GET. Content type defaults to "".
        Auth revision is "" (the caller supplies it from its own profile).
        """
        from urllib.parse import urlsplit, parse_qsl
        try:
            parts = urlsplit(target)
        except (ValueError, TypeError):
            return ("", "", "GET", (), (), "", "")
        origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""
        path = parts.path or "/"
        query = tuple((name, value) for name, value in
                      parse_qsl(parts.query, keep_blank_values=True))
        return (origin, path, "GET", query, (), "", "")

    def _origin_in_scope(self, origin: str, roots: list[str]) -> bool:
        """Whether the origin is within the configured scope roots."""
        if not origin:
            return False
        from urllib.parse import urlsplit
        try:
            host = urlsplit(origin).hostname or ""
        except (ValueError, TypeError):
            return False
        if not host:
            return False
        host = host.lower()
        if not roots:
            return True  # no roots configured -> accept anything (legacy default)
        for root in roots:
            root_host = root.lower()
            if root_host.startswith("http"):
                try:
                    from urllib.parse import urlsplit as _us
                    root_host = (_us(root_host).hostname or "").lower()
                except (ValueError, TypeError):
                    pass
            if host == root_host or host.endswith("." + root_host):
                return True
        return False

    def _classify_task(self, *, template: str, origin: str, path: str,
                       method: str, query: tuple, body: tuple,
                       content_type: str, auth_revision: str,
                       in_scope: bool) -> PlanTask:
        """Classify one (template × target) into a disposition.

        Precedence:
          1. Missing/empty template -> DEFERRED (explicit failed selection)
          2. Out of scope -> NOT_APPLICABLE
          3. Unknown template semantics -> COMPATIBILITY (legacy behavior)
          4. Known template but unknown target aspect -> COMPATIBILITY
          5. Known template + known target -> PLANNED with provenance
        """
        provenance = ""
        reason = ""

        # 1. Missing template -> explicit failed selection, never silent drop.
        template_prov = _template_known(template)
        if not template:
            disposition = Disposition.DEFERRED
            reason = "template ref is empty or missing"
            provenance = "rule:template-missing"
            estimate = None
        # 2. Out of scope -> not applicable.
        elif not in_scope:
            disposition = Disposition.NOT_APPLICABLE
            reason = "origin outside configured scope roots"
            provenance = "rule:out-of-scope"
            estimate = None
        # 3. Unknown template semantics -> compatibility lane (legacy behavior).
        elif template_prov is None:
            disposition = Disposition.COMPATIBILITY
            reason = "template semantics unknown -> compatibility lane (run legacy behavior)"
            provenance = "rule:template-unknown"
            estimate = 1  # one request per template, labeled estimate
        # 4. Known template; classify target aspects.
        else:
            provenance = template_prov
            origin_ok = _origin_known(origin)
            path_ok = _path_known(path)
            ct_ok = _content_type_known(content_type)
            if origin_ok and path_ok and ct_ok:
                disposition = Disposition.PLANNED
                reason = "known template + known target category"
                provenance = f"{template_prov};rule:target-known"
                estimate = 1
            else:
                disposition = Disposition.COMPATIBILITY
                missing = []
                if not origin_ok:
                    missing.append("origin")
                if not path_ok:
                    missing.append("path")
                if not ct_ok:
                    missing.append("content-type")
                reason = "unknown target aspect(s): " + ", ".join(missing) + " -> compatibility"
                provenance = f"{template_prov};rule:target-unknown"
                estimate = 1

        task_id = _task_id(template, origin, path, method, query, body,
                           content_type, auth_revision)
        return PlanTask(
            task_id=task_id,
            template=_clip(template),
            origin=_clip(origin),
            path=_clip(path),
            method=method,
            query=query,
            body=body,
            content_type=_clip(content_type),
            auth_revision=_clip(auth_revision),
            disposition=disposition,
            estimate=estimate,
            provenance=provenance,
            reason=reason,
        )

    # ------------------------------------------------------------------ #
    # Manifest construction
    # ------------------------------------------------------------------ #

    def _build_manifest(self, tasks: list[PlanTask], counts: dict[str, int],
                        oversize: bool, input_count: int, template_count: int) -> dict:
        """Build the run-scoped manifest content (credentials redacted)."""
        task_summaries = []
        for task in tasks:
            task_summaries.append({
                "task_id": task.task_id,
                "template": task.template,
                "origin": task.origin,
                "path": task.path,
                "method": task.method,
                "disposition": task.disposition.value,
                "estimate": task.estimate,
                "provenance": task.provenance,
                "reason": task.reason,
            })

        return {
            "schema_version": 1,
            "planner_version": 1,
            "plan_id": self.plan_id,
            "planner_mode": self.mode,
            "settings_hash": hashlib.sha256(
                json.dumps(self.settings, sort_keys=True).encode()).hexdigest(),
            "template_hashes": template_hashes_from_settings(self.settings),
            "input_count": input_count,
            "template_count": template_count,
            "task_count": len(tasks),
            "oversize": oversize,
            "disposition_counts": counts,
            "tasks": task_summaries,
            #: Content-bound stamp (not wall-clock): identical inputs must
            #: produce identical manifests so plans are reproducible under
            #: input shuffle and PYTHONHASHSEED changes.
            "created_at": "plan_v1:" + _sha256(
                json.dumps(
                    {"plan_id": self.plan_id,
                     "task_ids": [t.task_id for t in tasks]},
                    sort_keys=True, separators=(",", ":")
                )),
        }


def plan_for_settings(settings: dict[str, Any], template_refs: Iterable[str],
                      target_urls: Iterable[str],
                      seed: Optional[str] = None) -> Plan:
    """Convenience: build a Plan from settings + templates + targets."""
    planner = ScanPlanner(settings, template_refs, seed=seed)
    return planner.plan(target_urls)
