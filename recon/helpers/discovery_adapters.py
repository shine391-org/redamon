"""Producer and consumer adapters for the discovery inventory.

Two directions, one rule: an adapter never changes what a tool discovered or
what a consumer requested. It records what happened, with a reason, so a later
reader can tell "this source was not accepted" from "this source never ran".

Producer adapters take a tool's real output plus the ``(origin, path)`` keys
that were already present when the tool merged, and write one observation per
raw record. The raw record itself is hashed into ``raw_ref``; only bounded
metadata crosses into the artifact.

Consumer adapters take the structure the consumer actually reads and record
which producers that structure contained and which it did not. The gaps they
name are real and pre-existing (``discovered_urls`` is built before the late
merges; Arjun runs before GAU/Kiterunner/OpenAPI). Naming them is this card's
job; closing them is a pipeline-ordering decision that belongs elsewhere.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from recon.helpers import discovery_inventory as di

#: Why a producer's record did not become an observation. Kept as data, never
#: as a judgement about the target.
REASON_BY_DISPOSITION = {
    "merged_new": "observed by this producer; no earlier producer had it",
    "overlap_existing": "observed by this producer; an earlier producer already had it",
    "declared_only_new": "declared by an API specification; no tool observed it",
    "declared_observed_overlap": "declared by a specification and already observed by a tool",
    "declared_only_template": "a specification path template filled with an encoded example; not an observation",
    "spec_document_observed": "the specification document itself was fetched",
    "param_new_endpoint": "Arjun found parameters on a path no earlier producer had",
    "param_enrich_existing": "Arjun found parameters on a path an earlier producer had",
    "validated_hittable": "js_recon's own probe accepted the response and the catch-all control disagreed",
    "retained_not_hittable": "js_recon's own probe got an unaccepted status; retained, not deleted",
    "retained_catch_all": "the host answers a made-up path the same way; retained as catch_all_like",
    "retained_unknown": "js_recon's probe timed out or hit a transport error; unknown is not dead",
    "retained_unvalidated": "js_recon did not probe this endpoint",
    "not_merged": "the producer observed it, but this run's own merge did not add it to by_base_url (blacklisted, unverified, out of scope, or a base not live in this scan)",
}


def keys_of(by_base_url: dict) -> Set[Tuple[str, str]]:
    """``(origin, path)`` for every endpoint currently merged."""
    keys: Set[Tuple[str, str]] = set()
    for base, base_data in (by_base_url or {}).items():
        if not isinstance(base_data, dict):
            continue
        origin = di.origin_of(base)
        for path in (base_data.get("endpoints") or {}):
            if isinstance(path, str):
                keys.add((origin, path))
    return keys


def observe_crawl(inventory: dict, *, source: str, urls: Iterable[str],
                  auth_ref: str = "", disposition: str = "merged_new",
                  existing_keys: Optional[Set[Tuple[str, str]]] = None,
                  merged_keys: Optional[Set[Tuple[str, str]]] = None,
                  auth_revision: str = "") -> dict:
    """One observation per URL a crawler reported (katana/hakrawler/GAU/...).

    A crawler's URL is an observation of a request it made, so its validation
    status is ``observed``; the status code is the crawler's own, when it kept
    one, and ``None`` otherwise — never a fabricated 200.

    ``merged_keys`` is the ``(origin, path)`` set the caller's merge actually
    produced. A URL the merge skipped (blacklisted, unverified, out of scope, a
    base not live in this scan) is still an observation, but its disposition is
    ``not_merged`` rather than a first sighting the structure does not contain.
    Every input, including a non-string or empty one, is accounted for: a
    malformed URL becomes a rejected ledger entry with a stable positional ref.
    """
    for index, url in enumerate(urls or ()):
        ref = di.safe_input_ref(source, index)
        if not isinstance(url, str) or not url:
            di.reject_input(inventory, source, "non_string_or_empty_url", ref)
            continue
        origin, path = di.origin_of(url), di.path_of(url)
        if not origin:
            di.reject_input(inventory, source, "non_http_url", ref)
            continue
        query = []
        try:
            raw_query = urlsplit(url).query
        except (ValueError, TypeError):
            raw_query = ""
        if raw_query:
            # The crawler observed these names; their values are its request's,
            # kept with the encoding the URL carried.
            from urllib.parse import parse_qsl
            for name, value in parse_qsl(raw_query, keep_blank_values=True)[:di.MAX_PARAMS_PER_OBSERVATION]:
                query.append({"name": name, "type": "string", "position": "query",
                              "sample_values": [value] if value else [],
                              "sample_values_encoding": "decoded-observation"})
        if merged_keys is not None and (origin, path) not in merged_keys:
            this_disposition = "not_merged"
        elif existing_keys is not None:
            this_disposition = ("overlap_existing" if (origin, path) in existing_keys
                                else "merged_new")
        else:
            this_disposition = disposition
        di.add_observation(inventory, di.observation(
            source=source, raw={"url": url}, origin=origin, path=path, method="GET",
            query=query, auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
            validation={"status": "observed"}, disposition=this_disposition,
            raw_locator=f"{source}:{origin}{path}",
        ), ref=ref)
    return inventory


def observe_ffuf(inventory: dict, *, results: Sequence[dict], existing_keys: Set[Tuple[str, str]],
                 auth_ref: str = "", merged_keys: Optional[Set[Tuple[str, str]]] = None,
                 auth_revision: str = "") -> dict:
    """One observation per FFuf result, including overlaps the merge folds away.

    FFuf reports only responses that matched its filters, so every result is an
    observation. The status is FFuf's own; a result without one is ``unknown``,
    not 200. A non-dict result is a rejected input, not a silent skip.
    """
    for index, result in enumerate(results or ()):
        ref = di.safe_input_ref("ffuf", index)
        if not isinstance(result, dict):
            di.reject_input(inventory, "ffuf", "malformed_result", ref)
            continue
        url = result.get("url", "")
        origin, path = di.origin_of(url), di.path_of(url)
        if not origin:
            di.reject_input(inventory, "ffuf", "non_http_url", ref)
            continue
        status = result.get("status")
        validation: Dict[str, Any] = {
            "status": "observed" if isinstance(status, int) else "unknown"}
        if isinstance(status, int):
            validation["status_code"] = status
        if merged_keys is not None and (origin, path) not in merged_keys:
            disposition = "not_merged"
        else:
            disposition = "overlap_existing" if (origin, path) in existing_keys else "merged_new"
        di.add_observation(inventory, di.observation(
            source="ffuf", raw=result, origin=origin, path=path, method="GET",
            auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
            validation=validation, disposition=disposition,
            raw_locator=f"ffuf:{index}",
            evidence={
                "status_code": status if isinstance(status, int) else None,
                "length": result.get("length") if isinstance(result.get("length"), int) else None,
                "words": result.get("words") if isinstance(result.get("words"), int) else None,
                "lines": result.get("lines") if isinstance(result.get("lines"), int) else None,
                "content_type": result.get("content_type") or "",
                "redirect_location": result.get("redirect_location") or "",
                "input_fuzz": result.get("input_fuzz") or "",
            },
        ), ref=ref)
    return inventory


def observe_arjun(inventory: dict, *, results: Sequence[dict], existing_keys: Set[Tuple[str, str]],
                  auth_ref: str = "", merged_keys: Optional[Set[Tuple[str, str]]] = None,
                  auth_revision: str = "") -> dict:
    """One observation per Arjun result: a parameter discovery on a real URL.

    Arjun's execution status is its own and is carried verbatim. ``partial``
    means the process was killed or exited nonzero, so the parameter list is
    incomplete — that is ``unknown`` evidence, not a complete observation.
    """
    for index, result in enumerate(results or ()):
        ref = di.safe_input_ref("arjun", index)
        if not isinstance(result, dict):
            di.reject_input(inventory, "arjun", "malformed_result", ref)
            continue
        url = result.get("url", "")
        origin, path = di.origin_of(url), di.path_of(url)
        params = [p for p in (result.get("params") or []) if isinstance(p, str) and p]
        mode = str(result.get("method") or "GET").upper()
        if not origin or not params:
            reason = "no_parameters" if origin else "non_http_url"
            di.reject_input(inventory, "arjun", reason, ref)
            continue
        position = "body" if mode in ("POST", "JSON", "XML") else "query"
        execution = str(result.get("execution_status") or "unknown")
        validation = {"status": "observed" if execution == "complete" else "unknown"}
        if execution != "complete":
            validation["error"] = "execution_incomplete"
        if merged_keys is not None and (origin, path) not in merged_keys:
            disposition = "not_merged"
        else:
            disposition = "param_enrich_existing" if (origin, path) in existing_keys else "param_new_endpoint"
        di.add_observation(inventory, di.observation(
            source="arjun", raw=result, origin=origin, path=path, method=mode,
            body=[{"name": name, "type": "string", "position": "body"} for name in params]
            if position == "body" else [],
            query=[{"name": name, "type": "string", "position": "query"} for name in params]
            if position == "query" else [],
            auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
            validation=validation, disposition=disposition,
            raw_locator=f"arjun:{index}",
            evidence={"error": execution},
        ), ref=ref)
    return inventory


def observe_kiterunner(inventory: dict, *, results: Sequence[dict],
                       existing_keys: Set[Tuple[str, str]], auth_ref: str = "",
                       merged_keys: Optional[Set[Tuple[str, str]]] = None,
                       auth_revision: str = "") -> dict:
    """One observation per Kiterunner endpoint, with its detected methods."""
    for index, result in enumerate(results or ()):
        ref = di.safe_input_ref("kiterunner", index)
        if not isinstance(result, dict):
            di.reject_input(inventory, "kiterunner", "malformed_result", ref)
            continue
        url, path = result.get("url", ""), result.get("path", "")
        origin = di.origin_of(url)
        if not origin or not path:
            di.reject_input(inventory, "kiterunner", "missing_url_or_path", ref)
            continue
        status = result.get("status")
        validation: Dict[str, Any] = {
            "status": "observed" if isinstance(status, int) else "unknown"}
        if isinstance(status, int):
            validation["status_code"] = status
        if merged_keys is not None and (origin, path) not in merged_keys:
            disposition = "not_merged"
        else:
            disposition = "overlap_existing" if (origin, path) in existing_keys else "merged_new"
        di.add_observation(inventory, di.observation(
            source="kiterunner", raw=result, origin=origin, path=path,
            method=result.get("method") or "GET", auth_profile_ref=auth_ref,
            auth_profile_revision=auth_revision,
            validation=validation, disposition=disposition,
            raw_locator=f"kiterunner:{index}",
            evidence={"status_code": status if isinstance(status, int) else None},
        ), ref=ref)
    return inventory


def observe_openapi(inventory: dict, *, payload: dict, existing_keys: Set[Tuple[str, str]],
                    auth_ref: str = "", merged_keys: Optional[Set[Tuple[str, str]]] = None,
                    auth_revision: str = "") -> dict:
    """Declared operations and fetched specification documents.

    A declaration is NOT an observation of the concrete path. The template is
    recorded beside the filled path so a reader can tell an example URL that
    was requested from one that was only ever written down.
    """
    from recon.helpers.resource_enum.openapi_helpers import concrete_path

    for index, operation in enumerate((payload or {}).get("operations") or []):
        ref = di.safe_input_ref("openapi", index)
        if not isinstance(operation, dict):
            di.reject_input(inventory, "openapi", "malformed_operation", ref)
            continue
        try:
            base, template = operation["baseurl"], operation["path"]
        except (KeyError, TypeError):
            di.reject_input(inventory, "openapi", "malformed_operation", ref)
            continue
        origin = di.origin_of(base)
        if not origin or not isinstance(template, str) or not template:
            di.reject_input(inventory, "openapi", "malformed_operation", ref)
            continue
        spec = operation.get("operation") if isinstance(operation.get("operation"), dict) else {}
        declared = [p for p in spec.get("parameters") or [] if isinstance(p, dict)]
        path_params = {p.get("name"): p for p in declared if p.get("in") == "path"}
        try:
            path = concrete_path(template, path_params)
        except Exception:  # noqa: BLE001 - a malformed template is a rejected declaration
            di.reject_input(inventory, "openapi", "unfillable_template", ref)
            continue
        method = str(operation.get("method") or "GET").upper()
        query = [{"name": p.get("name"), "type": "string", "position": "query",
                  "sample_values": [], "sample_values_encoding": "percent-encoded"}
                 for p in declared if p.get("in") == "query" and p.get("name")]
        overlap = (origin, path) in existing_keys
        di.add_observation(inventory, di.observation(
            source="openapi", raw=operation, origin=origin, path=path, method=method,
            query=query, auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
            validation={"status": "observed" if overlap else "declared"},
            disposition="declared_observed_overlap" if overlap else "declared_only_new",
            raw_locator=f"openapi:operation:{index}",
            evidence={"input_fuzz": template if path != template else ""},
        ), ref=ref)
        if path != template:
            # The template is the declaration; the filled path is an example.
            # Both are kept, and neither is presented as requested.
            di.add_observation(inventory, di.observation(
                source="openapi", raw={"template": template, "baseurl": base},
                origin=origin, path=template, method=method, query=query,
                auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
                validation={"status": "declared"},
                disposition="declared_only_template",
                raw_locator=f"openapi:template:{index}",
            ), ref=f"{ref}:template")

    for index, document in enumerate((payload or {}).get("documents") or []):
        ref = di.safe_input_ref("openapi:document", index)
        if not isinstance(document, dict):
            di.reject_input(inventory, "openapi", "malformed_document", ref)
            continue
        try:
            parts = urlsplit(document["url"])
            origin, path = di.origin_of(document["url"]), (parts.path or "/")
        except (KeyError, TypeError, ValueError):
            di.reject_input(inventory, "openapi", "malformed_document", ref)
            continue
        if not origin:
            di.reject_input(inventory, "openapi", "malformed_document", ref)
            continue
        di.add_observation(inventory, di.observation(
            source="openapi", raw=document, origin=origin, path=path, method="GET",
            auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
            validation={"status": "observed"}, disposition="spec_document_observed",
            raw_locator=f"openapi:document:{index}",
            evidence={"input_fuzz": str(document.get("version") or "")},
        ), ref=ref)
    return inventory


def observe_js_endpoints(inventory: dict, *, endpoints: Sequence[dict],
                         auth_ref: str = "", auth_revision: str = "") -> dict:
    """One observation per js_recon candidate, with its validation state.

    js_recon retains candidates whose probe failed or never ran. Those are
    evidence with a state, not deletions, so each gets the state it earned and
    no state is upgraded to "verified". A non-dict candidate, or one with no
    path, is a rejected input with a stable ref rather than a silent skip.
    """
    for index, endpoint in enumerate(endpoints or ()):
        ref = di.safe_input_ref("js_recon", index)
        if not isinstance(endpoint, dict):
            di.reject_input(inventory, "js_recon", "malformed_endpoint", ref)
            continue
        base = endpoint.get("base_url") or ""
        origin = di.origin_of(base)
        path = endpoint.get("path") or ""
        if not path:
            di.reject_input(inventory, "js_recon", "missing_path", ref)
            continue
        if not origin:
            # An uploaded relative path has no host; it is still an observation.
            di.add_observation(inventory, di.observation(
                source="js_recon", raw=endpoint, origin="", path=path,
                method=endpoint.get("method") or "GET",
                auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
                validation=_js_validation(endpoint),
                disposition=_js_disposition(endpoint),
                raw_locator=f"js_recon:{index}",
                evidence={"error": endpoint.get("validation_error") or ""},
            ), ref=ref)
            continue
        status = endpoint.get("status_code")
        di.add_observation(inventory, di.observation(
            source="js_recon", raw=endpoint, origin=origin, path=path,
            method=endpoint.get("method") or "GET",
            auth_profile_ref=auth_ref, auth_profile_revision=auth_revision,
            validation=_js_validation(endpoint),
            disposition=_js_disposition(endpoint),
            raw_locator=f"js_recon:{index}",
            evidence={"status_code": status if isinstance(status, int) else None,
                      "error": endpoint.get("validation_error") or ""},
        ), ref=ref)
    return inventory


def _js_validation(endpoint: dict) -> dict:
    """The endpoint's own validation state, verbatim; never promoted."""
    status = endpoint.get("validation_status")
    state: Dict[str, Any] = {
        "status": status if status in di.VALIDATION_STATUSES else "unknown"}
    code = endpoint.get("status_code")
    if isinstance(code, int):
        state["status_code"] = code
    return state


def _js_disposition(endpoint: dict) -> str:
    return {
        "hittable": "validated_hittable",
        "not_hittable": "retained_not_hittable",
        "catch_all": "retained_catch_all",
        "unknown": "retained_unknown",
        "unvalidated": "retained_unvalidated",
    }.get(str(endpoint.get("validation_status") or ""), "retained_unknown")


def record_input_facts(inventory: dict, *, discovered_url_sources: Dict[str, int],
                       discovered_urls_total: int, by_base_url_sources: Sequence[str],
                       by_base_url_endpoints: int,
                       arjun: Optional[dict] = None,
                       arjun_late: Optional[dict] = None,
                       js_recon: Optional[dict] = None) -> dict:
    """The composition of the structures consumers read, before any finalization.

    Stored rather than recomputed later so the consumer adapters reason about
    the same lists the pipeline actually built.
    """
    inventory["inputs"] = {
        "discovered_url_sources": dict(discovered_url_sources or {}),
        "discovered_urls_total": int(discovered_urls_total or 0),
        "by_base_url_sources": list(by_base_url_sources or []),
        "by_base_url_endpoints": int(by_base_url_endpoints or 0),
        "arjun": dict(arjun or {}),
        "arjun_late": dict(arjun_late or {}),
        "js_recon": dict(js_recon or {}),
    }
    return inventory


def consumer_nuclei_detection(inventory: dict, *, target_count: int,
                              admission: Optional[dict], declared: Optional[dict]) -> dict:
    """Nuclei's detection pass reads ``build_target_urls(...)``.

    That is the union of resource_enum's by_base_url, httpx's live URLs and
    uncovered-host fallbacks — NOT ``discovered_urls``. The admission report is
    the builder's own, so what it refused is named here rather than inferred.
    """
    not_admitted: Dict[str, Any] = {}
    notes = [
        "Nuclei detection reads build_target_urls(): resource_enum by_base_url "
        "+ httpx live URLs + uncovered-host fallbacks. It does not read "
        "discovered_urls, so an archive-only URL absent from by_base_url is not "
        "a detection target.",
    ]
    for key in ("resource_enum_path", "resource_enum_endpoint", "resource_enum_base",
                "httpx_or_supplied", "fallback_hostname", "fallback_ip", "final_union"):
        block = (admission or {}).get(key)
        if isinstance(block, dict) and block.get("rejected"):
            for reason, count in block["rejected"].items():
                not_admitted[reason] = not_admitted.get(reason, 0) + int(count or 0)
    for key in ("skipped_mock_hostname",):
        count = (admission or {}).get(key)
        if isinstance(count, int) and count:
            not_admitted[key] = not_admitted.get(key, 0) + count
    declared = declared or {}
    for key, reason in (
        ("declared_only_cap_dropped", "declared_only_cap_500"),
        ("declared_only_non_get_head", "declared_only_non_get_head"),
        ("templated_paths_skipped", "path_still_a_template"),
    ):
        count = declared.get(key)
        if isinstance(count, int) and count:
            not_admitted[reason] = not_admitted.get(reason, 0) + count
    sources = {
        "resource_enum_base": (admission or {}).get("resource_enum_base", 0),
        "resource_enum_endpoint": (admission or {}).get("resource_enum_endpoint", 0),
        "httpx": (admission or {}).get("httpx", 0),
        "fallback_subdomain": (admission or {}).get("fallback_subdomain", 0),
        "fallback_ip": (admission or {}).get("fallback_ip", 0),
    }
    if declared.get("sources_present"):
        sources["by_base_url_sources"] = list(declared["sources_present"])
    return di.record_consumer(inventory, "nuclei_detection", admitted=int(target_count or 0),
                              not_admitted=not_admitted, notes=notes, sources=sources)


def consumer_nuclei_dast(inventory: dict, *, dast_count: int,
                         discovered_url_sources: Optional[dict],
                         sources_absent: Sequence[str], note: str = "") -> dict:
    """Nuclei's DAST pass reads ``resource_enum.discovered_urls`` with ``?``/``=``.

    Kiterunner and OpenAPI endpoints are merged into ``by_base_url`` but never
    added to ``discovered_urls``, so DAST cannot see them by construction. That
    is recorded here, not repaired: closing it is a pipeline-ordering decision.
    """
    not_admitted = {}
    for source in sources_absent or ():
        not_admitted[source] = {
            "count": int((discovered_url_sources or {}).get(source) or 0),
            "reason": "not_in_discovered_urls",
        }
    notes = [note] if note else []
    notes.append(
        "DAST reads resource_enum.discovered_urls filtered to URLs carrying a "
        "query value. Sources absent from that list are named in not_admitted; "
        "they are absent by construction, not by a scanner failure."
    )
    return di.record_consumer(inventory, "nuclei_dast", admitted=int(dast_count or 0),
                              not_admitted=not_admitted, notes=notes,
                              sources=dict(discovered_url_sources or {}))


def consumer_arjun(inventory: dict, *, targets: int, unexecuted: int,
                   sources_present: Sequence[str], sources_absent: Sequence[str]) -> dict:
    """Arjun's input is ``by_base_url`` as it stood when Arjun ran.

    The late producers (GAU, ParamSpider, Kiterunner, URLScan, OpenAPI) merge
    after Arjun, so their endpoints are not in its input. Recorded, not moved.
    """
    not_admitted = {source: {"count": 0, "reason": "not_yet_merged"} for source in sources_absent}
    if unexecuted:
        not_admitted["unexecuted_by_cap"] = {
            "count": int(unexecuted), "reason": "arjun_max_endpoints"}
    notes = [
        "Arjun reads by_base_url at its own point in the merge order. Producers "
        "that merge later are named in not_admitted with reason not_yet_merged.",
    ]
    return di.record_consumer(inventory, "arjun_full", admitted=int(targets or 0),
                              not_admitted=not_admitted, notes=notes,
                              sources={"present": list(sources_present or [])})


def consumer_js_recon(inventory: dict, *, input_count: int,
                      sources_present: Sequence[str], sources_absent: Sequence[str]) -> dict:
    """js_recon reads ``discovered_urls`` plus the crawls' JS file URLs."""
    not_admitted = {source: {"count": 0, "reason": "not_in_discovered_urls"}
                    for source in sources_absent}
    notes = [
        "js_recon reads resource_enum.discovered_urls and the crawls' js_urls. "
        "Sources absent from those lists are named in not_admitted.",
    ]
    return di.record_consumer(inventory, "js_recon", admitted=int(input_count or 0),
                              not_admitted=not_admitted, notes=notes,
                              sources={"present": list(sources_present or [])})


def finalize_inventory(recon_data: dict) -> dict:
    """Add every consumer disposition that can be derived from the artifact, then reconcile.

    Idempotent: a run that never built an inventory gets an empty one with an
    explicit ``not_built`` note rather than a fabricated accounting.
    """
    inventory = recon_data.get(di.KEY)
    if not isinstance(inventory, dict) or not inventory.get("producers"):
        inventory = di.new_inventory()
        inventory["reconciliation"]["mismatches"].append({
            "field": "inventory", "claimed": None, "recomputed": None,
            "reason": "not_built_by_resource_enum",
        })
        inventory["reconciliation"]["match"] = False
    resource_enum = recon_data.get("resource_enum") or {}
    by_base_url = resource_enum.get("by_base_url") or {}
    summary = resource_enum.get("summary") or {}
    inputs = inventory.get("inputs") or {}
    discovered_url_sources = inputs.get("discovered_url_sources") or {}
    absent_from_discovered = sorted(
        source for source in di.PRODUCERS
        if source not in ("arjun", "js_recon") and not discovered_url_sources.get(source)
    )

    vuln_scan = recon_data.get("vuln_scan") or {}
    metadata = vuln_scan.get("scan_metadata") or {}
    consumer_nuclei_detection(
        inventory,
        target_count=int(metadata.get("total_urls_scanned") or 0),
        admission=metadata.get("target_admission"),
        declared=metadata.get("declared_only"),
    )
    consumer_nuclei_dast(
        inventory,
        dast_count=int(metadata.get("dast_urls_discovered") or 0),
        discovered_url_sources=discovered_url_sources,
        sources_absent=absent_from_discovered,
        note="dast_urls_discovered is the consumer's own count; 0 means the "
             "consumer ran on nothing, which is not the same as no parameters existing.",
    )
    arjun = inputs.get("arjun") or {}
    if arjun:
        consumer_arjun(inventory, targets=int(arjun.get("targets") or 0),
                       unexecuted=int(arjun.get("unexecuted") or 0),
                       sources_present=arjun.get("sources_present") or [],
                       sources_absent=arjun.get("sources_absent") or [])
    js = inputs.get("js_recon") or {}
    if js:
        consumer_js_recon(inventory, input_count=int(js.get("input_count") or 0),
                          sources_present=js.get("sources_present") or [],
                          sources_absent=js.get("sources_absent") or [])

    di.reconcile(inventory, by_base_url, summary)
    recon_data[di.KEY] = inventory
    return inventory


def build_partial_inventory(*, source: str, observations: Sequence[dict],
                            rejected: Optional[dict] = None,
                            by_base_url: Optional[dict] = None,
                            summary: Optional[dict] = None,
                            raw_evidence: Optional[dict] = None) -> dict:
    """An inventory for a partial run, which has no resource_enum phase.

    A partial run's own tool is its only producer, so the inventory is honest
    about being narrower than a full run rather than implying parity.
    """
    inventory = di.new_inventory()
    for obs in observations or ():
        di.add_observation(inventory, obs)
    for reason, count in (rejected or {}).items():
        di.reject(inventory, source, reason, count)
    if raw_evidence:
        di.record_raw_evidence(inventory, source, raw_evidence)
    inventory["inputs"] = {
        "discovered_url_sources": {source: len(observations or [])},
        "discovered_urls_total": len(observations or []),
        "by_base_url_sources": [source],
        "by_base_url_endpoints": len((by_base_url or {}).get("endpoints") or {}),
        "arjun": {}, "js_recon": {},
        "partial_run": True,
    }
    inventory["consumers"] = {}
    di.reconcile(inventory, by_base_url or {}, summary or {})
    return inventory
