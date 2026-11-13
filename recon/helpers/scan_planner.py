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
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit
from recon.helpers.settings_fingerprint import settings_fingerprint

from recon.helpers.planner_manifest import (
    MODE_OFF, MODE_SHADOW, MODE_ENFORCE, resolve_mode,
    template_hashes_from_settings, scope_roots_from_settings,
    _strip_userinfo, _redact, MANIFEST_MAX_TASKS,
)
from recon.helpers.template_classification import (
    TemplateCategory,
    TemplateClassificationRegistry,
    ClassifiedTemplate,
    get_registry,
    classify_template,
    analyze_template_capability,
    RequestCapability,
    validate_auth_batch_safety,
)

#: Bound on tasks per plan — imported from planner_manifest (MANIFEST_MAX_TASKS)
#: so the manifest writer and the planner share one ceiling; no hand-mirrored
#: constant that can drift.
MAX_TASKS = MANIFEST_MAX_TASKS

#: Bound on template references hashed into the plan provenance.
MAX_TEMPLATE_REFS = 200

#: Bound on origin/path string length kept in a plan task. Truncation is
#: observable (marker appended), never silent.
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

#: Task-key components populated from the caller's inventory, not hardcoded.
#: Query/body/method/auth/slash/encoding keep fidelity; family grouping does not
#: prove equivalent security behavior.
TASK_KEY_FIELDS = ("template", "origin", "path", "method", "query",
                   "body", "content_type", "auth_revision")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clip(text: str, limit: int = MAX_TASK_STRING) -> str:
    """Truncate to ``limit`` with an explicit marker; never silent truncation."""
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


def _get_template_registry() -> TemplateClassificationRegistry:
    """Get the template classification registry (lazy-loaded)."""
    global _TEMPLATE_REGISTRY
    if _TEMPLATE_REGISTRY is None:
        _TEMPLATE_REGISTRY = get_registry()
    return _TEMPLATE_REGISTRY


# Module-level registry cache
_TEMPLATE_REGISTRY: Optional[TemplateClassificationRegistry] = None


def _template_known(template: str) -> Optional[str]:
    """Return the provenance rule for a known template, or None when unknown.

    TEMPLATE_RULES wins: the planner's provenance contract is the
    ``rule:template-known-*`` set, and a registry ``rule:<category>`` string
    would just duplicate the ``category:<value>`` segment the task provenance
    already carries. The registry classifies what TEMPLATE_RULES does not
    cover: the rest of the official template tree, plus bare NUCLEI_TAGS.
    """
    if not isinstance(template, str) or not template:
        return None

    for prefix, provenance in TEMPLATE_RULES:
        if template.startswith(prefix):
            return provenance

    registry = _get_template_registry()

    # Full template paths (like 'ssl/...') outside the TEMPLATE_RULES prefixes
    classified = registry.classify(template)
    if classified.is_known():
        return classified.provenance

    # For bare tag names (no '/'), try tag-based classification
    # NUCLEI_TAGS are tag names like 'cve', 'xss', 'ssl', not template paths
    if "/" not in template:
        tag_category = registry._classify_by_tags((template,))
        if tag_category != TemplateCategory.UNKNOWN:
            return f"rule:tag-known-{tag_category.value}"

    return None


def _raw_query_pairs(query_string: str) -> tuple[tuple[str, str], ...]:
    """Parse a raw query string into (name, value) pairs WITHOUT percent-decoding.

    ``?a=%2F`` and ``?a=/`` stay distinct because the value keeps the encoding
    the URL carried; sampling family does not prove equivalent security behavior.
    Empty names/values are kept (keep_blank_values semantics).
    """
    pairs: list[tuple[str, str]] = []
    if not query_string:
        return ()
    for chunk in query_string.split("&"):
        if "=" in chunk:
            name, value = chunk.split("=", 1)
        else:
            name, value = chunk, ""
        pairs.append((name, value))
    return tuple(pairs)


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
    template_category: str = ""  # TemplateCategory value
    requires_body_support: bool = False  # Whether template needs body/multipart transport
    is_multi_request: bool = False  # Whether template executes multiple requests

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


def _endpoint_for(origin: str, path: str,
                  inventory: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Look up the caller's endpoint record for one (origin, path).

    Accepts either shape the inventory can carry:

    * ``inventory["endpoints"][f"{origin}{path}"]`` — flat keyed by origin+path
    * ``inventory["by_base_url"][origin]["endpoints"][path]`` — resource_enum shape

    Returns {} when nothing is recorded for this origin/path, so a target with
    no inventory still plans with safe defaults (GET, no body, no auth).
    """
    if not inventory or not isinstance(inventory, dict):
        return {}
    flat = inventory.get("endpoints")
    if isinstance(flat, dict):
        ep = flat.get(f"{origin}{path}")
        if isinstance(ep, dict):
            return ep
    by_base = inventory.get("by_base_url")
    if isinstance(by_base, dict):
        base = by_base.get(origin)
        if isinstance(base, dict):
            endpoints = base.get("endpoints")
            if isinstance(endpoints, dict):
                ep = endpoints.get(path)
                if isinstance(ep, dict):
                    return ep
    return {}


def _endpoint_methods(endpoint: dict[str, Any]) -> list[str]:
    methods = endpoint.get("methods")
    if isinstance(methods, list):
        return [str(m).upper() for m in methods if isinstance(m, str)]
    single = endpoint.get("method")
    if isinstance(single, str) and single:
        return [single.upper()]
    return []


def _endpoint_query(endpoint: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    params = endpoint.get("parameters")
    if not isinstance(params, dict):
        return ()
    query = params.get("query")
    if isinstance(query, list):
        pairs = []
        for param in query:
            if not isinstance(param, dict):
                continue
            name = param.get("name")
            if not name:
                continue
            samples = param.get("sample_values") or []
            value = samples[0] if samples else ""
            pairs.append((str(name), str(value)))
        return tuple(pairs)
    return ()


def _endpoint_body(endpoint: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    params = endpoint.get("parameters")
    if not isinstance(params, dict):
        return ()
    body = params.get("body")
    if isinstance(body, list):
        pairs = []
        for param in body:
            if not isinstance(param, dict):
                continue
            name = param.get("name")
            if not name:
                continue
            samples = param.get("sample_values") or []
            value = samples[0] if samples else ""
            pairs.append((str(name), str(value)))
        return tuple(pairs)
    return ()


def _endpoint_content_type(endpoint: dict[str, Any]) -> str:
    ct = endpoint.get("content_type")
    if isinstance(ct, str) and ct:
        return ct
    return ""


def _endpoint_auth_revision(endpoint: dict[str, Any]) -> str:
    rev = endpoint.get("auth_profile_revision")
    if isinstance(rev, str) and rev:
        return rev
    return ""


def _origin_in_scope(origin: str, settings: dict[str, Any]) -> bool:
    """Whether the origin is within the configured scope.

    Reuses the project's own scope controls (``host_in_scope`` from the auth
    profile, which handles exact hosts, ``*.suffix`` wildcards and CIDRs, plus
    RoE exclusions) rather than reimplementing a matcher that can drift from
    the auth profile's scope. A bare root domain (e.g. ``example.com`` from
    ``TARGET_DOMAIN``) also admits its subdomains, matching
    ``default_scope_hosts``'s ``*.<scanRoot>`` enumerate behavior. With no
    roots configured at all, nothing is in scope -- default-deny, not
    default-allow.
    """
    if not origin:
        return False
    try:
        host = urlsplit(origin).hostname or ""
    except (ValueError, TypeError):
        return False
    if not host:
        return False

    # RoE exclusions win first: an excluded host is never in scope.
    roe_excluded = settings.get("ROE_EXCLUDED_HOSTS") or []
    if settings.get("ROE_ENABLED") and roe_excluded:
        from recon.helpers.roe_scope import _is_roe_excluded
        if _is_roe_excluded(host, list(roe_excluded)):
            return False

    roots = scope_roots_from_settings(settings)
    if not roots:
        return False  # no roots configured -> nothing is in scope (default-deny)

    try:
        from recon.helpers.auth_profile import host_in_scope
    except Exception:  # auth_profile unavailable -> fall back to suffix match
        host_l = host.lower()
        for root in roots:
            root_host = root.lower()
            if root_host.startswith("http"):
                try:
                    root_host = (urlsplit(root_host).hostname or "").lower()
                except (ValueError, TypeError):
                    pass
            if host_l == root_host or host_l.endswith("." + root_host):
                return True
        return False

    host_l = host.lower()
    for root in roots:
        root_l = root.lower()
        # Canonical control: exact host, *.suffix wildcard, or CIDR.
        if host_in_scope(host_l, [root_l]):
            return True
        # A bare root domain (no wildcard, no CIDR) admits its subdomains,
        # matching default_scope_hosts' "*.<scanRoot>" enumerate behavior.
        if "/" not in root_l and not root_l.startswith("*."):
            if host_l == root_l or host_l.endswith("." + root_l):
                return True
    return False


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
            "settings_hash": settings_fingerprint(self.settings, compact=True),
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

        ``inventory`` is the caller's honest accounting of what each target
        looks like (methods, parameters, content type, auth revision). It is
        never assumed complete: a target absent from the inventory plans with
        safe defaults (GET, no body, no auth revision).
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

        for target in targets:
            if len(tasks) >= MAX_TASKS:
                oversize = True
                break
            origin, path, method, query, body, content_type, auth_revision = \
                self._decompose_target(target, inventory)
            in_scope = (_origin_in_scope(origin, self.settings)
                        if scope_roots_from_settings(self.settings) else None)

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
    # Target decomposition
    # ------------------------------------------------------------------ #

    def _decompose_target(self, target: str,
                          inventory: Optional[dict[str, Any]]) \
            -> tuple[str, str, str, tuple, tuple, str, str]:
        """Split a target URL into its plan key components.

        Query and body are preserved as (name, value) tuples with the encoding
        the URL carried — query values are NOT percent-decoded, so ``?a=%2F``
        and ``?a=/`` stay distinct task keys.

        Origin has URL userinfo stripped (``https://user:pass@host/`` ->
        ``https://host/``) so credentials never enter a task key or manifest.

        Method/body/content_type/auth_revision default to GET/()/"/"", then are
        overridden from the caller's inventory for this (origin, path) when the
        caller recorded them (e.g. a POST endpoint discovered by resource_enum).
        """
        try:
            parts = urlsplit(target)
        except (ValueError, TypeError):
            return ("", "", "GET", (), (), "", "")

        origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""
        # Strip URL userinfo so it never lands in a task key or the manifest.
        origin = _strip_userinfo(origin)
        path = parts.path or "/"
        # Keep the raw query string (percent encoding preserved) as (name, value)
        # pairs; do NOT decode %2F -> / etc.
        query = _raw_query_pairs(parts.query)

        # Defaults; the caller's inventory may override them per (origin, path).
        method = "GET"
        body = ()
        content_type = ""
        auth_revision = ""
        endpoint = _endpoint_for(origin, path, inventory)
        if endpoint:
            methods = _endpoint_methods(endpoint)
            if methods:
                method = methods[0]
            body = _endpoint_body(endpoint)
            content_type = _endpoint_content_type(endpoint)
            auth_revision = _endpoint_auth_revision(endpoint)

        return (origin, path, method, query, body, content_type, auth_revision)

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #

    def _classify_task(self, *, template: str, origin: str, path: str,
                       method: str, query: tuple, body: tuple,
                       content_type: str, auth_revision: str,
                       in_scope: Optional[bool]) -> PlanTask:
        """Classify one (template × target) into a disposition.

        Precedence:
          1. Missing/empty template -> DEFERRED (explicit failed selection)
          2. Out of scope -> NOT_APPLICABLE
          3. Unknown template semantics -> COMPATIBILITY (legacy behavior)
          4. Known template but unknown target aspect -> COMPATIBILITY
          5. Known template + known target -> PLANNED with provenance

        Uses TemplateClassificationRegistry for semantic routing:
        - origin_safe: runs on origin only (no path needed)
        - app_prefix: runs on known app paths
        - endpoint: runs on parameterized endpoints
        - body_multipart: requires body-capable transport
        - multi_request: multi-step flows
        - raw_http: raw HTTP requests
        - unknown: compatibility lane
        """
        provenance = ""
        reason = ""
        template_category = TemplateCategory.UNKNOWN
        capability = None

        # 1. Missing template -> explicit failed selection, never silent drop.
        template_prov = _template_known(template)
        if not template:
            disposition = Disposition.DEFERRED
            reason = "template ref is empty or missing"
            provenance = "rule:template-missing"
            estimate = None
        # 2. Out of scope -> not applicable.
        elif in_scope is False:
            disposition = Disposition.NOT_APPLICABLE
            reason = "origin outside configured scope roots"
            provenance = "rule:out-of-scope"
            estimate = None
        elif in_scope is None:
            disposition = Disposition.COMPATIBILITY
            reason = "scope evidence unavailable -> compatibility (not a scope authorization)"
            provenance = "rule:scope-unknown"
            estimate = None
        # 3. Unknown template semantics -> compatibility lane (legacy behavior).
        elif template_prov is None:
            disposition = Disposition.COMPATIBILITY
            reason = "template semantics unknown -> compatibility lane (run legacy behavior)"
            provenance = "rule:template-unknown"
            estimate = 1  # one request per template, labeled estimate
        # 4. Known template; classify target aspects with semantic routing.
        else:
            provenance = template_prov
            
            # Get template classification for semantic routing
            registry = _get_template_registry()
            classified = registry.classify(template)
            
            # For bare tag names (no '/'), use tag-based classification
            # NUCLEI_TAGS are tag names like 'cve', 'xss', 'ssl', not template paths
            if classified.category == TemplateCategory.UNKNOWN and "/" not in template:
                tag_category = registry._classify_by_tags((template,))
                if tag_category != TemplateCategory.UNKNOWN:
                    # Create a synthetic classified object with the tag category
                    classified = type(classified)(
                        template_id=template,
                        category=tag_category,
                        provenance=f"rule:tag-known-{tag_category.value}",
                        confidence=0.5,
                        meta=None,
                    )
            
            template_category = classified.category
            capability = analyze_template_capability(template)
            
            origin_ok = _origin_known(origin)
            path_ok = _path_known(path)
            ct_ok = _content_type_known(content_type)
            
            # Semantic routing rules:
            # - origin_safe: only needs origin_ok
            # - app_prefix: needs origin_ok + path matches known prefix
            # - endpoint: needs origin_ok + path_ok + ct_ok
            # - body_multipart/multi_request/raw_http: needs full target known
            # - unknown: compatibility
            
            target_known = False
            if template_category == TemplateCategory.ORIGIN_SAFE:
                target_known = origin_ok
            elif template_category == TemplateCategory.APP_PREFIX:
                target_known = origin_ok and path_ok
            elif template_category in (TemplateCategory.ENDPOINT, TemplateCategory.BODY_MULTIPART):
                target_known = origin_ok and path_ok and ct_ok
            elif template_category in (TemplateCategory.MULTI_REQUEST, TemplateCategory.RAW_HTTP):
                target_known = origin_ok and path_ok and ct_ok
            else:  # UNKNOWN
                target_known = False
            
            if target_known:
                disposition = Disposition.PLANNED
                reason = f"known template ({template_category.value}) + known target category"
                provenance = f"{template_prov};rule:target-known;category:{template_category.value}"
                estimate = 1
            else:
                disposition = Disposition.COMPATIBILITY
                missing = []
                if not origin_ok:
                    missing.append("origin")
                if template_category != TemplateCategory.ORIGIN_SAFE and not path_ok:
                    missing.append("path")
                if template_category in (TemplateCategory.ENDPOINT, TemplateCategory.BODY_MULTIPART, TemplateCategory.MULTI_REQUEST, TemplateCategory.RAW_HTTP) and not ct_ok:
                    missing.append("content-type")
                reason = f"unknown target aspect(s) for {template_category.value}: " + ", ".join(missing) + " -> compatibility"
                provenance = f"{template_prov};rule:target-unknown;category:{template_category.value}"
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
            template_category=template_category.value,
            requires_body_support=capability.has_body if capability else False,
            is_multi_request=capability.is_multi_request if capability else False,
        )

    # ------------------------------------------------------------------ #
    # Manifest construction — run-scoped, reader-compatible, credentials redacted
    # ------------------------------------------------------------------ #

    def _build_manifest(self, tasks: list[PlanTask], counts: dict[str, int],
                        oversize: bool, input_count: int, template_count: int) -> dict:
        """Build the run-scoped manifest content (credentials redacted).

        Emits every key the G2 manifest reader requires
        (``REQUIRED_MANIFEST_KEYS`` plus ``KNOWN_MANIFEST_KEYS``) so the
        existing ``read_manifest`` / ``read_manifest_in_context`` accept it as
        ``status: known``. Job context (tenant/project/run/group) comes from
        the caller's settings, never fabricated.
        """
        ctx = {
            "tenant": str(self.settings.get("PLANNER_TENANT") or
                          self.settings.get("TENANT") or ""),
            "project_id": str(self.settings.get("PLANNER_PROJECT_ID") or
                              self.settings.get("PROJECT_ID") or ""),
            "run_id": str(self.settings.get("PLANNER_RUN_ID") or
                          self.settings.get("RUN_ID") or ""),
            "group_id": str(self.settings.get("PLANNER_GROUP_ID") or
                            self.settings.get("GROUP_ID") or ""),
        }

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
                "template_category": task.template_category,
                "requires_body_support": task.requires_body_support,
                "is_multi_request": task.is_multi_request,
            })

        #: Content-bound stamp so two runs of the same inputs produce an
        #: identical manifest (determinism across shuffle and PYTHONHASHSEED).
        #: plan_id is the run identity; created_at mirrors it rather than using
        #: wall-clock, which would break manifest equality between identical runs.
        created_at = "plan_v1:" + _sha256(
            json.dumps(
                {"plan_id": self.plan_id,
                 "task_ids": [t.task_id for t in tasks]},
                sort_keys=True, separators=(",", ":")),
        )

        settings_hash = settings_fingerprint(self.settings)
        return _redact({
            "schema_version": 1,
            "planner_version": 1,
            "planner_mode": self.mode,
            "plan_id": self.plan_id,
            "tenant": ctx["tenant"],
            "project_id": ctx["project_id"],
            "run_id": ctx["run_id"],
            "group_id": ctx["group_id"],
            "scope": {"roots": scope_roots_from_settings(self.settings)},
            "settings_hash": settings_hash,
            "settings_hash_prefix": settings_hash[:16],
            "template_hashes": template_hashes_from_settings(self.settings),
            "input_count": input_count,
            "template_count": template_count,
            "task_count": len(tasks),
            "oversize": oversize,
            "disposition_counts": counts,
            "tasks": task_summaries,
            "reason": "",
            #: ISO-8601 UTC wall-clock stamp of manifest build time. Content-bound
            #: identity comes from plan_id; created_at records when this run's
            #: manifest was written, so two runs of the same inputs get different
            #: created_at but identical plan_id (determinism is about plan_id,
            #: not wall-clock).
            "created_at": created_at,
        })


def plan_for_settings(settings: dict[str, Any], template_refs: Iterable[str],
                      target_urls: Iterable[str],
                      seed: Optional[str] = None,
                      inventory: Optional[dict[str, Any]] = None) -> Plan:
    """Convenience: build a Plan from settings + templates + targets.

    ``inventory`` is the caller's honest per-endpoint accounting, forwarded to
    ``ScanPlanner.plan`` so method/body/content_type/auth_revision are
    populated from real observations rather than hardcoded GET defaults.
    """
    planner = ScanPlanner(settings, template_refs, seed=seed)
    return planner.plan(target_urls, inventory=inventory)
