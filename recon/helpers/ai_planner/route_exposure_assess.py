"""
Route exposure lead assessment on TypeSafe Jev (route exposure, hook C)
======================================================================
Each route exposure lead (needs_agent_confirmation) carries a deterministic
route_class. This hook asks Jev two typed questions about each lead's evidence:
which kind of route it is (a choice over a closed set that adds `public_content`)
and how sensitive what it returns is (a noul).

Jev gets evidence only, never the verdict: the path, the statuses, the content
class and size bucket, whether the bodies matched, the masked key names, the
largest array, and the closed hint and signal labels. No route_class and no
signature, so its kind is a second opinion, not the classifier read back. No value
crosses: key names only, masked like the stored snippet.

ROLLOUT is ACT: each answered lead gets `route_jev_kind`,
`route_jev_kind_confidence`, `route_jev_sensitivity` and `route_jev_source`, which
the graph writer persists. The leads are ordered by that sensitivity, most
sensitive first, and a lead Jev reads as public content (`is_public`: confidence
>= PUBLIC_CONFIDENCE) is put last; the agent's lead query orders the same way. It
never drops a lead and never rewrites route_class: a lead Jev could not answer
keeps no annotation and follows the answered ones, so with Jev off, out of credit
or down the leads are exactly the deterministic ones. Every decision is also
recorded next to route_class mapped into the same closed set, in
`jev_shadow.route_exposure_assess`. Rich items blur when several share one state
(jev-1.13.0), so the agent asks one request per lead; recon sends BATCH_SIZE per
call. Log lines carry counts and indexes only.
"""

import os
import time
from typing import List, Optional, Tuple

from recon.helpers.ai_planner.jev_shadow import ACT, ShadowRecorder, jev_model, jev_post

ROLLOUT = ACT

HOOK = "route_exposure_assess"
_TAG = "RouteExposure-Jev"

MAX_CANDIDATES_PER_SCAN = 200
BATCH_SIZE = 4
TIME_BUDGET_S = 60
TIMEOUT = 30

#: Literals: test_jev_item_contract holds them equal to the agent's request model.
KINDS = ("internal_api", "debug_management", "admin_function", "data_export", "old_version",
         "uploaded_content", "public_content")
CONTENT_CLASSES = ("json", "html", "text", "xml", "binary", "other")
SIZE_BUCKETS = ("<1k", "1-10k", "10-100k", ">100k")
DET_SIGNALS = ("pii", "pii_others", "sensitive_fields", "secret")
AUTH_HINTS = ("openapi", "openapi_tag", "declared_only", "seen_denied", "path_word", "host_word",
              "siblings_locked", "version_locked", "vary_auth")
GENERATORS = ("found", "seed", "vcs", "backup", "version", "sibling", "framework", "catalog",
              "cross_host")

MAX_PATH_CHARS = 200
MAX_KEY_PATHS = 60
MAX_KEY_CHARS = 80

#: Below this a public_content answer annotates the lead but does not move it.
PUBLIC_CONFIDENCE = 70

#: route_class -> the closed kind, for the decision record's baseline only.
_BASELINE = {"internal_api": "internal_api", "debug_management": "debug_management",
             "admin_function": "admin_function", "data_export": "data_export",
             "old_version": "old_version", "uploaded_content": "uploaded_content",
             "client_gated": "admin_function", "unknown": "public_content"}


def _status(value) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 999 else None


def item_for(finding: dict, key_paths: List[str], max_array_len: int) -> dict:
    """The request item for one lead: evidence only, bounded, every closed field clamped."""
    def closed(values, allowed):
        return [v for v in (values or []) if v in allowed]

    authed = _status(finding.get("authed_status"))
    item = {
        "path": str(finding.get("path") or "/")[:MAX_PATH_CHARS] or "/",
        "method": "GET",
        "anon_status": _status(finding.get("anon_status")) or 0,
        "authed_status": authed,
        "content_class": finding.get("anon_content_class") if finding.get("anon_content_class") in CONTENT_CLASSES else "other",
        "size_bucket": finding.get("anon_size_bucket") if finding.get("anon_size_bucket") in SIZE_BUCKETS else "<1k",
        "bodies_match": finding.get("bodies_match") if isinstance(finding.get("bodies_match"), bool) else None,
        "key_paths": [str(k)[:MAX_KEY_CHARS] for k in (key_paths or [])][:MAX_KEY_PATHS],
        "max_array_len": max(0, int(max_array_len or 0)),
        "det_signals": closed(finding.get("leak_signals"), DET_SIGNALS),
        "auth_expected_by": closed(finding.get("auth_expected_by"), AUTH_HINTS),
        "generated_by": finding.get("generated_by") if finding.get("generated_by") in GENERATORS else "found",
    }
    return item


def _validate(data, n: int) -> Optional[List[Tuple[str, int, int]]]:
    if not isinstance(data, dict) or not isinstance(data.get("labels"), list) or len(data["labels"]) != n:
        return None
    out = []
    for label in data["labels"]:
        if not isinstance(label, dict):
            return None
        kind, conf, sens = label.get("kind"), label.get("kind_confidence"), label.get("sensitivity")
        if not isinstance(kind, str) or kind not in KINDS:
            return None
        for value in (conf, sens):
            if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 100:
                return None
        out.append((kind, conf, sens))
    return out


def jev_assess_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get("AI_IN_PIPELINE") and settings.get("ROUTE_EXPOSURE_JEV_ASSESS"))


def is_public(finding: dict) -> bool:
    """Jev read the lead as public content, confidently enough to put it last."""
    conf = finding.get("route_jev_kind_confidence")
    return (finding.get("route_jev_kind") == "public_content" and isinstance(conf, int)
            and not isinstance(conf, bool) and conf >= PUBLIC_CONFIDENCE)


def run_for_candidates(pairs: List[Tuple[dict, dict]], settings: dict, recon_data: Optional[dict],
                       clock=time.monotonic) -> dict:
    """`pairs` is (finding, request item) per lead. Under ACT each answered finding
    gets Jev's kind and sensitivity. Never raises; returns count stats."""
    stats = {"candidates": 0, "asked": 0, "failed_batches": 0, "not_asked": 0}
    if not pairs or not jev_assess_enabled(settings):
        return stats
    recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
    try:
        pairs = [p for p in pairs if isinstance(p[0], dict) and p[0].get("needs_agent_confirmation")]
        stats["candidates"] = len(pairs)
        if len(pairs) > MAX_CANDIDATES_PER_SCAN:
            stats["not_asked"] = len(pairs) - MAX_CANDIDATES_PER_SCAN
            pairs = pairs[:MAX_CANDIDATES_PER_SCAN]
        print(f"[*][{_TAG}] {stats['candidates']} leads, {len(pairs)} to ask")
        started = clock()
        for start in range(0, len(pairs), BATCH_SIZE):
            if clock() - started > TIME_BUDGET_S:
                stats["not_asked"] += len(pairs) - start
                print(f"[!][{_TAG}] Time budget of {TIME_BUDGET_S}s reached - "
                      f"{len(pairs) - start} leads left unasked")
                break
            batch = pairs[start:start + BATCH_SIZE]
            data = jev_post("route-exposure-assess",
                            {"candidates": [item for _, item in batch],
                             "user_id": os.environ.get("USER_ID", ""),
                             "project_id": os.environ.get("PROJECT_ID", "")},
                            _TAG, TIMEOUT)
            labels = _validate(data, len(batch)) if data is not None else None
            if labels is None:
                if data is not None:
                    print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
                stats["failed_batches"] += 1
                recorder.fallback()
                continue
            recorder.model = jev_model(data)
            stats["asked"] += len(batch)
            for offset, ((finding, _), (kind, conf, sens)) in enumerate(zip(batch, labels)):
                baseline = _BASELINE.get(str(finding.get("route_class")), "public_content")
                recorder.decision(f"lead_{start + offset}", kind, conf, baseline, sensitivity=sens,
                                  exposure_kind=finding.get("exposure_kind"), path=finding.get("path"))
                if ROLLOUT == ACT:
                    finding["route_jev_kind"] = kind
                    finding["route_jev_kind_confidence"] = conf
                    finding["route_jev_sensitivity"] = sens
                    finding["route_jev_source"] = "jev_classifier"
        print(f"[+][{_TAG}] {stats['asked']} leads assessed, {stats['failed_batches']} batches fell back")
    except Exception as e:  # noqa: BLE001 - an assessment is never worth breaking the scan
        print(f"[!][{_TAG}] Pass failed ({type(e).__name__}) - the leads stand as found.")
        recorder.fallback()
    finally:
        recorder.finish(recon_data)
    return stats
