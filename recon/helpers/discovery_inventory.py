"""Typed discovery inventory: versioned observations, producer evidence, consumer disposition.

A recon run discovers the same path many times, from tools that ran at different
moments and with different authority. ``by_base_url`` keeps one node per
``(base, path)`` and the graph keeps one per ``(base, path, method)``, so every
merge after the first is a lossy fold: the second tool's status, its source, its
sample query and its auth context are dropped. Downstream consumers then read a
flat URL union (``build_target_urls``) or ``discovered_urls`` and cannot say why a
URL is present, or why a source they expected is absent.

This module is the evidence layer that survives those folds. It is deliberately
separate from discovery itself:

* it never decides what is discovered. A tool's raw output still flows into
  ``by_base_url`` / ``discovered_urls`` exactly as before; this only records what
  each producer saw, with a reference to the raw record.
* it never decides what is requested. Consumers keep their own admission rules;
  this records, per consumer, which sources their real input contained and which
  it did not, and says why.
* it is pure: no I/O, no settings writes, no network, no graph writes. Callers
  hand it data and persist the returned dict.

Identity is the exact observed tuple. A trailing slash, a different case, a
different percent-encoding or a different method is a DIFFERENT observation and
is never coalesced: equivalence between two spellings is a behaviour claim, and
no producer here has proven one. ``family_key`` exists only as a derived,
clearly-labelled grouping for rollups; it is never used to drop or merge
observations.

Unknown stays unknown. A producer that reported no status yields
``status_code = None`` and a validation status that says so; nothing here
fabricates 200. A declared-only OpenAPI path is recorded as declared, never as
observed or executable.

Retention is bounded and the bound is observable: a producer past
``MAX_OBSERVATIONS_PER_SOURCE`` stops gaining observations and records
``truncated = {limit, dropped, reason}``. The bound limits the EVIDENCE copy,
never the discovery path, so a truncated inventory costs evidence, not coverage.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

#: The top-level recon-artifact key. Additive: removing the call site restores
#: the previous artifact byte-for-byte apart from this key.
KEY = "discovery_inventory"
SCHEMA_VERSION = 1

#: Version of the context-aware observation identity. A reader comparing
#: identities across two artifacts must not silently mix two versions, so the
#: version is part of the identity string and of the hashed material.
OBSERVATION_ID_VERSION = 1
REJECTED_ID_VERSION = 1

#: Per-producer cap on the retained INPUT ledger. The ledger accounts for every
#: input a producer received; past the cap the total keeps growing and the
#: surplus is counted, so backpressure is observable rather than silent.
MAX_INPUT_LEDGER_PER_SOURCE = 1000

#: Dispositions that imply the observation was merged into ``by_base_url``.
#: An observation carrying one of these that the structure lacks is a real
#: identity mismatch. The remaining dispositions are evidence the structure is
#: not expected to carry: js_recon candidates, declared-only templates, spec
#: documents, and rows the caller's own merge skipped.
MERGED_DISPOSITIONS = frozenset({
    "merged_new", "overlap_existing",
    "param_new_endpoint", "param_enrich_existing",
    "declared_only_new", "declared_observed_overlap",
})

#: Producer tools that write observations. A tool not listed here cannot be
#: blamed for an absence: an unlisted producer is an unknown producer.
PRODUCERS = (
    "katana", "hakrawler", "gau", "urlscan", "paramspider", "jsluice",
    "ffuf", "zap_ajax_spider", "arjun", "kiterunner", "openapi", "js_recon",
)

#: Validation states, worst-first for rollups. ``observed`` is the producer's own
#: measurement; ``declared`` is a specification's claim; the JS states are
#: js_recon's. ``unknown`` and ``unvalidated`` are not dead and not verified.
VALIDATION_STATUSES = (
    "observed", "declared", "hittable", "not_hittable", "catch_all",
    "unknown", "unvalidated",
)

#: Consumers whose input is derived from the inventory's producers. Each one
#: reads a different structure, so each gets its own adapter.
CONSUMERS = ("nuclei_detection", "nuclei_dast", "arjun_full", "arjun_partial",
             "js_recon", "partial_crawl")

#: Per-producer observation cap. Evidence-only: the discovery path is uncapped.
MAX_OBSERVATIONS_PER_SOURCE = 50000

#: Per-observation bounds. A single observation is a small record; a producer
#: that emits more than this is truncated here, not stored unbounded.
MAX_PARAMS_PER_OBSERVATION = 200
MAX_SAMPLE_VALUES = 5
MAX_STRING = 512
#: Bound on a raw-evidence list (execution states, parse states, reasons).
MAX_RAW_LIST = 16

#: Scalar evidence fields kept per observation, with their bounds. Anything else
#: a producer emits is dropped: the raw record stays in the producer's own
#: artifact, referenced by ``raw_ref``.
EVIDENCE_FIELDS = {
    "status_code": int,
    "length": int,
    "words": int,
    "lines": int,
    "duration_ms": int,
    "content_type": str,
    "redirect_location": str,
    "input_fuzz": str,
    "urls_found": int,
    "error": str,
}


def _clip(text, limit: int = MAX_STRING) -> str:
    """A short bounded string; target-derived text is data, never instructions."""
    if not isinstance(text, str):
        return ""
    return text[:limit]


def _sha(raw: Any) -> str:
    """Content reference for a raw producer record. The record itself is not copied."""
    try:
        blob = json.dumps(raw, sort_keys=True, ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        blob = repr(raw)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


def _producer(inventory: dict, source: str) -> dict:
    """The per-producer block, including its input ledger.

    One shape, built in one place: ``add_observation``, ``reject``,
    ``reject_input`` and ``record_raw_evidence`` all used to repeat it, and a
    new accounting field added to one of them would have silently differed from
    the others.
    """
    return inventory["producers"].setdefault(source, {
        "observations": [], "observations_total": 0, "truncated": None,
        "rejected": {}, "raw_evidence": {},
        "input_ledger": {"total": 0, "entries": [], "truncated": None},
    })


def observation_id(obs: dict) -> str:
    """Versioned, context-aware identity of one observation.

    Distinct from ``raw_ref`` on purpose. ``raw_ref`` is a hash of the raw
    producer record, so the SAME record observed under two request contexts
    (another auth profile, another method, another parameter schema) collapses
    to one identity and the second context is lost. This identity is built from
    the request context instead: producer, origin, path, method, the parameter
    schema with its encoding marker, and the auth profile reference/revision.

    Raw values are never hashed. Query samples, bodies and headers can carry a
    credential, so they stay in the raw record (hashed as ``raw_ref``, never
    copied) and only their NAMES, positions, types and encoding markers enter
    the identity.
    """
    params = []
    for param in obs.get("parameters") or []:
        if not isinstance(param, dict):
            continue
        params.append({
            "name": param.get("name"),
            "position": param.get("position"),
            "type": param.get("type"),
            "encoding": param.get("sample_values_encoding"),
        })
    parts = {
        "v": OBSERVATION_ID_VERSION,
        "source": obs.get("source", ""),
        "origin": obs.get("origin", ""),
        "path": obs.get("path", ""),
        "method": obs.get("method", ""),
        "parameters": params,
        "auth_ref": obs.get("auth_profile_ref", ""),
        "auth_revision": obs.get("auth_profile_revision", ""),
    }
    blob = json.dumps(parts, sort_keys=True, ensure_ascii=True, default=str)
    return "obs_v1:" + hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


def rejected_identity(source: str, ref: str, reason: str) -> str:
    """Stable identity for one rejected input.

    Built from the producer, the input's stable reference and the reason - never
    from the input's own value, which is the thing that made it malformed and
    may be a credential.
    """
    parts = {"v": REJECTED_ID_VERSION, "source": source, "ref": ref, "reason": reason}
    blob = json.dumps(parts, sort_keys=True, ensure_ascii=True)
    return "rej_v1:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def safe_input_ref(source: str, index: int) -> str:
    """A stable, safe reference for one input position.

    Positional, so it carries no target text at all: a producer that received a
    malformed URL still accounts for it without echoing the value into the
    artifact.
    """
    return f"{source}:input:{int(index)}"


def _ledger_add(producer: dict, entry: dict) -> None:
    """Append one input to the producer's ledger, bounding it explicitly."""
    ledger = producer.setdefault("input_ledger",
                                 {"total": 0, "entries": [], "truncated": None})
    ledger["total"] += 1
    if len(ledger["entries"]) < MAX_INPUT_LEDGER_PER_SOURCE:
        ledger["entries"].append(entry)
        return
    truncated = ledger.get("truncated")
    if truncated is None:
        truncated = ledger["truncated"] = {
            "limit": MAX_INPUT_LEDGER_PER_SOURCE, "dropped": 0,
            "reason": "input_ledger_cap_evidence_only",
        }
    truncated["dropped"] += 1


def ledger_identities(inventory: dict) -> Dict[str, set]:
    """Every identity the producers' input ledgers assert, by disposition.

    ``retained`` are observation identities the producer says it kept;
    ``rejected`` are the identities of inputs it refused. A reconciliation that
    only compares counts cannot tell these two sets apart from the observations
    that actually survived, which is the gap this exposes.
    """
    retained: set = set()
    rejected: set = set()
    for data in (inventory.get("producers") or {}).values():
        for entry in ((data or {}).get("input_ledger") or {}).get("entries") or []:
            if not isinstance(entry, dict):
                continue
            identity = entry.get("identity")
            if not identity:
                continue
            if entry.get("disposition") == "rejected":
                rejected.add(identity)
            else:
                retained.add(identity)
    return {"retained": retained, "rejected": rejected}


def origin_of(url: str) -> str:
    """``scheme://host[:port]`` for an HTTP(S) URL, else ``""``.

    Exact spelling is kept (no case folding, no default-port removal): two
    origins that differ are two observations until a consumer proves otherwise.
    """
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def path_of(url: str) -> str:
    """The path exactly as observed, ``/`` when empty. Never normalized."""
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return ""
    return parts.path or "/"


def method_of(method: Any) -> str:
    """Upper-cased method, or ``GET`` when the producer named none.

    A missing method is a real gap in the producer's record; the default is the
    historical one every merge already assumes, and ``validation.status`` says
    whether the producer measured anything at all.
    """
    text = str(method or "GET").strip().upper()
    return text[:16] if text else "GET"


def family_key(origin: str, path: str, method: str) -> str:
    """A DERIVED grouping label for rollups only.

    Never use this to merge, drop or deduplicate observations. It exists so a
    reader can ask "how many distinct spellings did this family produce?" and
    the answer is evidence of unproved equivalence, not a licence to collapse.
    """
    return f"{origin}|{method}|{path}"


def new_inventory() -> dict:
    """An empty inventory with the rollups every merged result carries."""
    return {
        "schema_version": SCHEMA_VERSION,
        "producers": {},
        "origins": {},
        "consumers": {},
        "reconciliation": {
            "summary_total_endpoints": None,
            "inventory_distinct_endpoints": None,
            "summary_total_parameters": None,
            "inventory_distinct_parameters": None,
            "observed_distinct_endpoints": None,
            "observed_identities": 0,
            "ledger_identities": 0,
            "unaccounted_identities": [],
            "identity_match": None,
            "match": None,
            "mismatches": [],
            "overlap_note": (
                "Per-source counts are NOT disjoint: one endpoint observed by "
                "three tools is counted once by each source and once in "
                "distinct_endpoints. Never sum by_source."
            ),
        },
        "truncated": {},
    }


def _param_schema(param: Any, position: str) -> Optional[dict]:
    """One parameter's schema (name/type/position/required) plus bounded samples.

    Sample values are kept only with their producer's encoding marker, so a
    consumer never mistakes a serialized example for a decoded observation.
    """
    if not isinstance(param, dict):
        return None
    name = param.get("name")
    if not isinstance(name, str) or not name:
        return None
    entry = {
        "name": _clip(name, 128),
        "position": position,
        "type": _clip(str(param.get("type") or "string"), 32),
    }  # type: Dict[str, Any]
    if param.get("required") is not None:
        entry["required"] = bool(param.get("required"))
    samples = param.get("sample_values")
    if isinstance(samples, (list, tuple)) and samples:
        kept = []
        for value in samples[:MAX_SAMPLE_VALUES]:
            if value is None:
                kept.append(None)
            else:
                kept.append(_clip(str(value), 128))
        entry["sample_values"] = kept
        encoding = param.get("sample_values_encoding")
        # An unmarked legacy sample has mixed producer encodings: keep the
        # values, but never let a reader assume they were decoded.
        entry["sample_values_encoding"] = (
            encoding if encoding in ("percent-encoded", "decoded-observation")
            else "unknown"
        )
    return entry


def observation(
    *,
    source: str,
    raw: Any,
    origin: str,
    path: str,
    method: Any = "GET",
    query: Iterable = (),
    body: Iterable = (),
    auth_profile_ref: str = "",
    auth_profile_revision: str = "",
    validation: Optional[dict] = None,
    disposition: str = "",
    evidence: Optional[dict] = None,
    raw_locator: str = "",
) -> dict:
    """One versioned observation. ``raw`` is hashed, never stored.

    ``auth_profile_revision`` is the profile's own revision marker (a version or
    timestamp the caller already holds), never a header value: two observations
    under the same profile NAME but different revisions are different contexts.
    """
    if source not in PRODUCERS:
        raise ValueError(f"unknown discovery producer {source!r}")
    method = method_of(method)
    entry: Dict[str, Any] = {
        "raw_ref": _sha(raw),
        "source": source,
        "origin": origin,
        "path": _clip(path, MAX_STRING),
        "method": method,
    }
    if raw_locator:
        entry["raw_locator"] = _clip(raw_locator, 256)
    params: List[dict] = []
    for position, bucket in (("query", query), ("body", body)):
        for param in bucket or ():
            schema = _param_schema(param, position)
            if schema is not None:
                params.append(schema)
            if len(params) >= MAX_PARAMS_PER_OBSERVATION:
                break
        if len(params) >= MAX_PARAMS_PER_OBSERVATION:
            break
    if params:
        entry["parameters"] = params
    if auth_profile_ref:
        # A reference only: profile id/name, never a header value or credential.
        entry["auth_profile_ref"] = _clip(str(auth_profile_ref), 128)
    if auth_profile_revision:
        entry["auth_profile_revision"] = _clip(str(auth_profile_revision), 64)
    state = {"status": "unknown"}
    if isinstance(validation, dict):
        status = validation.get("status")
        state["status"] = status if status in VALIDATION_STATUSES else "unknown"
        for field in ("status_code", "error"):
            value = validation.get(field)
            if value is not None:
                state[field] = value if field == "status_code" else _clip(str(value), 128)
    entry["validation"] = state
    if disposition:
        entry["disposition"] = _clip(disposition, 128)
    kept_evidence = {}
    for field, kind in EVIDENCE_FIELDS.items():
        value = (evidence or {}).get(field)
        if value is None or isinstance(value, bool):
            continue
        try:
            kept_evidence[field] = kind(value)
        except (TypeError, ValueError):
            continue
    if kept_evidence:
        entry["evidence"] = kept_evidence
    entry["observation_id"] = observation_id(entry)
    return entry


def add_observation(inventory: dict, obs: dict, ref: Optional[str] = None) -> dict:
    """Append one observation, bounding the producer's retention explicitly.

    Every append is also an input the producer received, so the input ledger
    records it with a stable reference whether or not the observation cap keeps
    it: a dropped observation is backpressure the artifact must show, not a
    silent absence.
    """
    if not isinstance(obs, dict) or not obs.get("raw_ref"):
        return inventory
    source = obs.get("source", "")
    producer = _producer(inventory, source)
    producer["observations_total"] += 1
    _ledger_add(producer, {
        "ref": _clip(str(ref or f"{source}:observation:{obs.get('observation_id')}"), 256),
        "identity": obs.get("observation_id") or "",
        "disposition": "retained",
    })
    limit = MAX_OBSERVATIONS_PER_SOURCE
    if len(producer["observations"]) >= limit:
        # Bounded retention, observable: the count of what was not copied.
        truncated = producer["truncated"]
        if truncated is None:
            truncated = producer["truncated"] = {
                "limit": limit, "dropped": 0,
                "reason": "observation_cap_evidence_only",
            }
        truncated["dropped"] += 1
        inventory.setdefault("truncated", {})[source] = {
            "limit": limit, "dropped": truncated["dropped"],
            "reason": "observation_cap_evidence_only",
        }
    else:
        producer["observations"].append(obs)

    origin = obs.get("origin", "")
    if origin:
        bucket = inventory["origins"].setdefault(origin, {
            "observations": 0, "distinct_endpoints": 0, "distinct_parameters": 0,
            "by_source": {}, "by_disposition": {}, "by_validation": {},
            "family_keys": {},
        })
        bucket["observations"] += 1
        bucket["by_source"][source] = bucket["by_source"].get(source, 0) + 1
        disposition = obs.get("disposition", "")
        if disposition:
            bucket["by_disposition"][disposition] = \
                bucket["by_disposition"].get(disposition, 0) + 1
        status = (obs.get("validation") or {}).get("status", "unknown")
        bucket["by_validation"][status] = bucket["by_validation"].get(status, 0) + 1
        # Family keys are a rollup label only; a family with more than one
        # distinct spelling is itself evidence of unproved equivalence.
        key = family_key(origin, obs.get("path", ""), obs.get("method", ""))
        bucket["family_keys"][key] = bucket["family_keys"].get(key, 0) + 1
    return inventory


def reject(inventory: dict, source: str, reason: str, count: int = 1) -> dict:
    """Record inputs a producer refused, so an absence is never silent.

    Aggregate form: the caller counted a group of inputs it did not retain and
    names the reason. Per-input accounting is ``reject_input``.
    """
    producer = _producer(inventory, source)
    bucket = producer["rejected"]
    bucket[reason] = bucket.get(reason, 0) + int(count or 0)
    return inventory


def reject_input(inventory: dict, source: str, reason: str, ref: str) -> dict:
    """Account for ONE malformed/rejected input by stable safe identity.

    The reference is positional (``safe_input_ref``) or supplied by the adapter;
    the input's own value is never hashed or stored, because a malformed value is
    exactly where a credential would be echoed into the artifact.
    """
    producer = _producer(inventory, source)
    bucket = producer["rejected"]
    bucket[reason] = bucket.get(reason, 0) + 1
    safe_ref = _clip(str(ref), 256)
    _ledger_add(producer, {
        "ref": safe_ref,
        "identity": rejected_identity(source, safe_ref, reason),
        "disposition": "rejected",
        "reason": _clip(reason, 128),
    })
    return inventory


def record_raw_evidence(inventory: dict, source: str, record: dict) -> dict:
    """Persist a producer's raw metadata summary BEFORE its temp files are removed.

    ``record`` must contain no response body and no header value: this lives in
    the recon artifact, which is not a secrets store.
    """
    producer = _producer(inventory, source)
    cleaned = {}
    for key, value in (record or {}).items():
        if value is None:
            continue
        if isinstance(value, str):
            cleaned[key] = _clip(value, MAX_STRING)
        elif isinstance(value, (bool, int, float)):
            cleaned[key] = value
        elif isinstance(value, (list, tuple)):
            # A bounded list of scalars (execution states, reasons). Anything
            # nested or longer is dropped: this is a summary, not a raw dump.
            kept = []
            for item in value[:MAX_RAW_LIST]:
                if isinstance(item, (str, bool, int, float)):
                    kept.append(_clip(str(item), 128) if isinstance(item, str) else item)
                else:
                    kept.append(None)
            cleaned[key] = kept
    producer["raw_evidence"].update(cleaned)
    return inventory


def record_consumer(inventory: dict, consumer: str, *, admitted=None,
                    not_admitted=None, notes=None, sources=None) -> dict:
    """What one consumer's real input contained, and what it did not.

    ``admitted`` counts what reached the consumer; ``not_admitted`` maps a
    producer (or a reason) to a count, so a source the consumer never saw is
    named rather than missing. ``sources`` is the consumer's own per-source
    accounting, when its input is a structure that still carries one.
    """
    if consumer not in CONSUMERS:
        raise ValueError(f"unknown discovery consumer {consumer!r}")
    entry = inventory["consumers"].setdefault(consumer, {
        "admitted": 0, "not_admitted": {}, "sources": {}, "notes": [],
    })
    if isinstance(admitted, int):
        entry["admitted"] = max(entry["admitted"], admitted)
    for key, value in (not_admitted or {}).items():
        if isinstance(value, int):
            entry["not_admitted"][key] = entry["not_admitted"].get(key, 0) + value
        else:
            entry["not_admitted"][key] = value
    for key, value in (sources or {}).items():
        entry["sources"][key] = value
    for note in notes or ():
        if note and note not in entry["notes"]:
            entry["notes"].append(_clip(str(note), MAX_STRING))
    return inventory


def recompute_counts(by_base_url: dict) -> dict:
    """Recompute every base and global summary from the actual members.

    The mergers maintain counters incrementally, and two of them drift: FFuf
    never updates ``total_parameters``, and an Arjun-created base starts its
    summary at zero. A drifted counter is a statement about the run that the
    artifact does not support, so the summary is rebuilt from what is really
    there rather than trusted.
    """
    total_endpoints = total_parameters = 0
    methods: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    for base, base_data in (by_base_url or {}).items():
        if not isinstance(base_data, dict):
            continue
        endpoints = base_data.get("endpoints") or {}
        base_methods: Dict[str, int] = {}
        base_categories: Dict[str, int] = {}
        base_params = 0
        for endpoint in endpoints.values():
            if not isinstance(endpoint, dict):
                continue
            params = endpoint.setdefault("parameters", {})
            counts = {position: len(params.setdefault(position, []) or [])
                      for position in ("query", "body", "path")}
            counts["total"] = sum(counts.values())
            endpoint["parameter_count"] = counts
            base_params += counts["total"]
            for method in dict.fromkeys(endpoint.get("methods") or []):
                base_methods[method] = base_methods.get(method, 0) + 1
            category = endpoint.get("category", "other")
            base_categories[category] = base_categories.get(category, 0) + 1
        summary = base_data.setdefault("summary", {})
        summary["total_endpoints"] = len(endpoints)
        summary["total_parameters"] = base_params
        summary["methods"] = base_methods
        summary["categories"] = base_categories
        total_endpoints += len(endpoints)
        total_parameters += base_params
        for method, count in base_methods.items():
            methods[method] = methods.get(method, 0) + count
        for category, count in base_categories.items():
            categories[category] = categories.get(category, 0) + count
    return {
        "total_base_urls": len(by_base_url or {}),
        "total_endpoints": total_endpoints,
        "total_parameters": total_parameters,
        "methods": methods,
        "categories": categories,
    }


def reconcile(inventory: dict, by_base_url: dict, summary: Optional[dict] = None) -> dict:
    """Reconcile the inventory against the run's own summary, BY IDENTITY.

    Equality of counts is NOT the test and never was sufficient: a synthetic
    input ``/lost`` and a structural output ``/different`` with matching totals
    reconcile clean under a counter comparison. Three things are checked here:

    1. every summary counter can be recomputed from the structure;
    2. every identity the producers' INPUT LEDGERS assert as retained is an
       observation that actually survived (the cap or a merge dropped none
       silently), and every retained observation was an input (none is phantom);
    3. every observation whose disposition says it was merged into
       ``by_base_url`` is present in the structure, so an observation lost
       between the producer and the merge is named by identity.
    """
    distinct = set()
    parameters = 0
    structure_keys = set()
    for base, base_data in (by_base_url or {}).items():
        if not isinstance(base_data, dict):
            continue
        origin = base_data.get("base_url") or origin_of(base)
        for path, endpoint in (base_data.get("endpoints") or {}).items():
            structure_keys.add((origin, path))
            if not isinstance(endpoint, dict):
                continue
            for method in dict.fromkeys(endpoint.get("methods") or ["GET"]):
                distinct.add((origin, path, method))
            params = endpoint.get("parameters") or {}
            parameters += sum(len(params.get(position) or [])
                              for position in ("query", "body", "path"))
    recomputed = recompute_counts(by_base_url)
    mismatches = []
    for key in ("total_endpoints", "total_parameters", "total_base_urls"):
        if summary is not None:
            claimed = summary.get(key)
            actual = recomputed.get(key)
            if claimed is not None and claimed != actual:
                mismatches.append({
                    "field": key, "claimed": claimed, "recomputed": actual,
                    "reason": "summary_counter_drift",
                })

    # (2) ledger identities against the observations that survived.
    observed_identities = set()
    observed_endpoints = set()
    ledger = ledger_identities(inventory)
    ledger_truncated = []
    for source, data in (inventory.get("producers") or {}).items():
        data = data or {}
        for obs in data.get("observations") or []:
            if not isinstance(obs, dict):
                continue
            identity = obs.get("observation_id")
            if identity:
                observed_identities.add(identity)
            observed_endpoints.add((obs.get("origin", ""), obs.get("path", ""),
                                    obs.get("method", "")))
        trunc = (data.get("input_ledger") or {}).get("truncated")
        if isinstance(trunc, dict) and trunc.get("dropped"):
            ledger_truncated.append({
                "source": source, "limit": trunc.get("limit"),
                "dropped": trunc.get("dropped"), "reason": trunc.get("reason"),
            })
    unaccounted = sorted(ledger["retained"] - observed_identities)
    phantom = sorted(observed_identities - ledger["retained"] - ledger["rejected"])
    for identity in unaccounted:
        mismatches.append({
            "field": "input_ledger", "identity": identity,
            "reason": "ledger_retained_but_observation_absent",
        })
    for identity in phantom:
        mismatches.append({
            "field": "observation_id", "identity": identity,
            "reason": "observation_without_input_ledger_entry",
        })

    # (3) a merged observation the structure lacks is a lost identity.
    for source, data in (inventory.get("producers") or {}).items():
        for obs in (data or {}).get("observations") or []:
            if not isinstance(obs, dict):
                continue
            if obs.get("disposition") not in MERGED_DISPOSITIONS:
                continue
            key = (obs.get("origin", ""), obs.get("path", ""))
            if key not in structure_keys:
                mismatches.append({
                    "field": "observation_not_in_structure",
                    "identity": obs.get("observation_id"),
                    "source": source,
                    "origin": obs.get("origin"),
                    "path": obs.get("path"),
                    "method": obs.get("method"),
                    "disposition": obs.get("disposition"),
                    "reason": "merged_disposition_but_absent_from_by_base_url",
                })

    inventory["reconciliation"].update({
        "summary_total_endpoints": (summary or {}).get("total_endpoints"),
        "inventory_distinct_endpoints": len(distinct),
        "summary_total_parameters": (summary or {}).get("total_parameters"),
        "inventory_distinct_parameters": parameters,
        "observed_distinct_endpoints": len(observed_endpoints),
        "observed_identities": len(observed_identities),
        "ledger_identities": len(ledger["retained"] | ledger["rejected"]),
        "unaccounted_identities": unaccounted,
        "identity_match": not unaccounted and not phantom,
        "match": not mismatches,
        "mismatches": mismatches,
        "ledger_truncated": ledger_truncated,
    })
    return inventory


def serialize(inventory: dict) -> str:
    """Stable, ASCII-only, separator-free JSON for byte-comparable roundtrips."""
    return json.dumps(inventory, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), default=str)


def deserialize(text: str) -> dict:
    """Read back a serialized inventory, refusing anything not shaped like one."""
    data = json.loads(text)
    if not isinstance(data, dict) or "producers" not in data or "origins" not in data:
        raise ValueError("not a discovery inventory")
    return data


def _merge_ledger(a: dict, b: dict) -> dict:
    """Fold two groups' input ledgers, keeping the cap observable.

    The ledger is the INPUT side of the accounting, so both groups' entries are
    kept; only the retained list is capped, and the surplus is counted.
    """
    merged = {"total": 0, "entries": [], "truncated": None}
    dropped = 0
    for source in (a, b):
        ledger = source.get("input_ledger") or {}
        merged["total"] += int(ledger.get("total") or 0)
        for entry in ledger.get("entries") or []:
            if len(merged["entries"]) < MAX_INPUT_LEDGER_PER_SOURCE:
                merged["entries"].append(entry)
            else:
                dropped += 1
        trunc = ledger.get("truncated")
        if isinstance(trunc, dict) and trunc.get("dropped"):
            dropped += int(trunc.get("dropped") or 0)
            merged["truncated"] = {
                "limit": MAX_INPUT_LEDGER_PER_SOURCE, "dropped": dropped,
                "reason": "input_ledger_cap_evidence_only",
            }
    if dropped and merged["truncated"] is None:
        merged["truncated"] = {
            "limit": MAX_INPUT_LEDGER_PER_SOURCE, "dropped": dropped,
            "reason": "input_ledger_cap_evidence_only",
        }
    return merged


def merge_inventories(older: Optional[dict], newer: Optional[dict]) -> dict:
    """Fold two groups' inventories without losing either one's evidence.

    Observations are deduplicated by ``(observation_id, raw_ref)``. The
    identity is the request CONTEXT; the raw_ref is the raw RECORD. Two groups
    that observed the same record under the same context are one observation.
    The same record under a different auth profile, method or parameter schema
    is a DIFFERENT observation and both survive: the old raw_ref-only key
    coalesced them and lost the second context.
    """
    if not isinstance(older, dict):
        return newer if isinstance(newer, dict) else new_inventory()
    if not isinstance(newer, dict):
        return older
    merged = new_inventory()
    merged["schema_version"] = max(int(older.get("schema_version", 1)),
                                  int(newer.get("schema_version", 1)))
    seen_sources = set()
    for source in list(older.get("producers") or {}) + list(newer.get("producers") or {}):
        if source in seen_sources:
            continue
        seen_sources.add(source)
        a = (older.get("producers") or {}).get(source) or {}
        b = (newer.get("producers") or {}).get(source) or {}
        observations = []
        seen = set()
        dropped = 0
        for obs in list(a.get("observations") or []) + list(b.get("observations") or []):
            if not isinstance(obs, dict):
                continue
            key = (obs.get("observation_id") or "", obs.get("raw_ref") or "")
            if key in seen:
                dropped += 1
                continue
            seen.add(key)
            observations.append(obs)
        producer = {
            "observations": observations,
            "observations_total": sum(int(x.get("observations_total") or 0)
                                      for x in (a, b)),
            "truncated": None,
            "rejected": {},
            "raw_evidence": {**(a.get("raw_evidence") or {}), **(b.get("raw_evidence") or {})},
            "input_ledger": _merge_ledger(a, b),
        }
        if dropped:
            producer["truncated"] = {
                "limit": MAX_OBSERVATIONS_PER_SOURCE, "dropped": dropped,
                "reason": "duplicate_observation_identity_across_groups",
            }
        for key in set(a.get("rejected") or {}) | set(b.get("rejected") or {}):
            producer["rejected"][key] = ((a.get("rejected") or {}).get(key, 0)
                                         + (b.get("rejected") or {}).get(key, 0))
        merged["producers"][source] = producer
    for origin in set(older.get("origins") or {}) | set(newer.get("origins") or {}):
        a = (older.get("origins") or {}).get(origin) or {}
        b = (newer.get("origins") or {}).get(origin) or {}
        bucket = {
            "observations": int(a.get("observations") or 0) + int(b.get("observations") or 0),
            "distinct_endpoints": None,
            "distinct_parameters": None,
            "by_source": {}, "by_disposition": {}, "by_validation": {},
            "family_keys": {},
        }
        for field in ("by_source", "by_disposition", "by_validation", "family_keys"):
            for key in set(a.get(field) or {}) | set(b.get(field) or {}):
                bucket[field][key] = ((a.get(field) or {}).get(key, 0)
                                      + (b.get(field) or {}).get(key, 0))
        merged["origins"][origin] = bucket
    for consumer in set(older.get("consumers") or {}) | set(newer.get("consumers") or {}):
        a = (older.get("consumers") or {}).get(consumer) or {}
        b = (newer.get("consumers") or {}).get(consumer) or {}
        entry = {"admitted": max(int(a.get("admitted") or 0), int(b.get("admitted") or 0)),
                 "not_admitted": {}, "sources": {}, "notes": []}
        for key in set(a.get("not_admitted") or {}) | set(b.get("not_admitted") or {}):
            av, bv = (a.get("not_admitted") or {}).get(key), (b.get("not_admitted") or {}).get(key)
            entry["not_admitted"][key] = (av if isinstance(av, int) else 0) + \
                                         (bv if isinstance(bv, int) else 0)
        entry["sources"] = {**(a.get("sources") or {}), **(b.get("sources") or {})}
        entry["notes"] = list(dict.fromkeys((a.get("notes") or []) + (b.get("notes") or [])))
        merged["consumers"][consumer] = entry
    # The reconciliation block is recomputed by the caller against the merged
    # by_base_url; keeping one group's numbers would be the first-group-wins bug.
    merged["reconciliation"] = dict(new_inventory()["reconciliation"])
    merged["truncated"] = {**(older.get("truncated") or {}), **(newer.get("truncated") or {})}
    return merged


def summary_of(inventory: dict) -> dict:
    """The small, safe-to-print accounting: counts only, no target text."""
    producers = {}
    for source, data in (inventory.get("producers") or {}).items():
        producers[source] = {
            "observations": len(data.get("observations") or []),
            "observations_total": int(data.get("observations_total") or 0),
            "truncated": data.get("truncated"),
            "rejected": dict(data.get("rejected") or {}),
        }
    return {
        "schema_version": inventory.get("schema_version"),
        "producers": producers,
        "origins": len(inventory.get("origins") or {}),
        "consumers": {name: {"admitted": data.get("admitted"),
                             "not_admitted": dict(data.get("not_admitted") or {})}
                      for name, data in (inventory.get("consumers") or {}).items()},
        "reconciliation": dict(inventory.get("reconciliation") or {}),
        "truncated": dict(inventory.get("truncated") or {}),
    }


# ---------------------------------------------------------------------------
# Persisted-artifact reader
# ---------------------------------------------------------------------------

#: Top-level inventory fields a reader may project.
SELECTED_FIELDS = ("schema_version", "producers", "origins", "consumers",
                   "reconciliation", "truncated", "inputs")

#: Per-observation fields a reader may project. ``evidence`` and ``raw_locator``
#: are excluded: the first is producer response metadata that belongs to the
#: artifact, the second is a producer-local pointer that means nothing outside
#: the run that produced it.
SELECTED_OBSERVATION_FIELDS = (
    "observation_id", "raw_ref", "source", "origin", "path", "method",
    "auth_profile_ref", "auth_profile_revision", "disposition", "parameters",
    "validation",
)


def select_persisted_fields(inventory: dict) -> dict:
    """The inventory's selected fields, with each observation projected.

    A reader that returns the whole artifact would carry response metadata and
    producer-local locators into an API response that never asked for them.
    """
    if not isinstance(inventory, dict):
        return {}
    out = {key: inventory.get(key) for key in SELECTED_FIELDS if key in inventory}
    producers = {}
    for source, data in (inventory.get("producers") or {}).items():
        if not isinstance(data, dict):
            continue
        entry = {
            "observations": [
                {k: obs.get(k) for k in SELECTED_OBSERVATION_FIELDS if k in obs}
                for obs in (data.get("observations") or []) if isinstance(obs, dict)
            ],
            "observations_total": int(data.get("observations_total") or 0),
            "truncated": data.get("truncated"),
            "rejected": dict(data.get("rejected") or {}),
        }
        ledger = data.get("input_ledger")
        if isinstance(ledger, dict):
            entry["input_ledger"] = {
                "total": int(ledger.get("total") or 0),
                "entries": list(ledger.get("entries") or []),
                "truncated": ledger.get("truncated"),
            }
        producers[source] = entry
    out["producers"] = producers
    return out


def read_persisted_inventory(artifact: Any) -> dict:
    """Read the discovery inventory a recon artifact persisted.

    Honors only what is persisted. An absent key, a non-dict value, an
    unsupported schema version or a malformed producer block returns
    ``status: "unknown"`` with a reason, never an empty inventory that a caller
    would read as "scanned and clean".
    """
    if not isinstance(artifact, dict):
        return {"status": "unknown", "reason": "artifact_not_an_object"}
    inventory = artifact.get(KEY)
    if inventory is None:
        return {"status": "unknown", "reason": "inventory_not_persisted"}
    if not isinstance(inventory, dict):
        return {"status": "unknown", "reason": "inventory_not_an_object"}
    version = inventory.get("schema_version")
    if version != SCHEMA_VERSION:
        return {"status": "unknown", "reason": "unsupported_schema_version",
                "schema_version": version}
    if not isinstance(inventory.get("producers"), dict):
        return {"status": "unknown", "reason": "producers_not_an_object"}
    return {"status": "known", "schema_version": version,
            "inventory": select_persisted_fields(inventory)}
