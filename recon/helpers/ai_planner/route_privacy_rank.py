"""
Route privacy ranking on TypeSafe Jev (route exposure, hook A)
=============================================================
The route exposure scan spends a request budget per host, floor first, then by a
deterministic prior score (OpenAPI security, path words, generator). This hook
asks Jev one noul per route: is it meant only for logged-in, internal or
administrative callers?

ROLLOUT is ACT: each answered route gets `jev_rank` (the noul), which fills the
budget after the floor (ranking._order_key): the routes Jev reads as private are
requested first, the ones it did not answer follow by prior score. It never drops
a floor route and never invents one, and with Jev off, out of credit or down the
order is exactly the deterministic one. The answer also lands on each finding as
`route_jev_privacy` (0-100), which the graph writer persists. Every decision is
recorded next to the prior score's own verdict (score >= 5 is "private") in the
recon JSON `jev_shadow.route_privacy_rank`.

Items are tiny (a path, a method, a closed category and four flags), so one
request carries many; the path is target text and is only ever state data on the
agent side, named by index. Log lines carry counts only.

Kind B (no LLM twin), gated by AI_IN_PIPELINE and ROUTE_EXPOSURE_JEV_RANK at the
call site inside run_route_exposure, so a partial run inherits it.
"""

import os
from typing import List, Optional

from recon.helpers.ai_planner.jev_shadow import ACT, ShadowRecorder, jev_model, jev_post

ROLLOUT = ACT

HOOK = "route_privacy_rank"
_TAG = "RoutePrivacy-Jev"

#: Routes asked about per scan (and per request): the highest prior scores first.
MAX_ROUTES_PER_SCAN = 400
MAX_PATH_CHARS = 200
TIMEOUT = 30

#: Literals, not frozensets: the agent's contract test reads them from this file and
#: holds them equal to its request model. The union of classify_endpoint's and
#: js_recon's categories; anything else is sent as "other".
ROUTE_CATEGORIES = ("admin", "admin_debug", "api", "api_documentation", "authentication", "dynamic",
                    "endpoint", "file_access", "file_upload", "search", "upload", "other")
METHODS = ("GET", "HEAD")

#: The deterministic floor: a route scoring this much always gets a request.
_PRIVATE_SCORE = 5


def _item(route) -> dict:
    category = str(getattr(route, "category", "") or "other")
    method = str(getattr(route, "method", "GET") or "GET").upper()
    return {
        "path": str(route.path or "/")[:MAX_PATH_CHARS] or "/",
        "method": method if method in METHODS else "GET",
        "category": category if category in ROUTE_CATEGORIES else "other",
        "openapi_secured": bool(getattr(route, "openapi_security", None)),
        "declared_only": bool(getattr(route, "declared_only", False)),
        "js_only": bool(getattr(route, "js_only", False)),
        "host_internal": "host_word" in (getattr(route, "hints", None) or []),
    }


def cache_key(item: dict) -> tuple:
    return (item["method"], item["path"], item["category"], item["openapi_secured"],
            item["declared_only"], item["js_only"], item["host_internal"])


def _validate(data, n: int) -> Optional[List[float]]:
    if not isinstance(data, dict) or not isinstance(data.get("scores"), list) or len(data["scores"]) != n:
        return None
    out = []
    for score in data["scores"]:
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1:
            return None
        out.append(float(score))
    return out


def jev_route_rank_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get("AI_IN_PIPELINE") and settings.get("ROUTE_EXPOSURE_JEV_RANK"))


def run_for_routes(routes: list, settings: dict, recon_data: Optional[dict]) -> Optional[List[float]]:
    """Ask Jev about the routes (highest prior score first, capped). The routes must
    already carry their prior score. Under ACT each answered route gets `jev_rank`;
    returns the noul per asked route, or None. Never raises."""
    if not routes or not jev_route_rank_enabled(settings):
        return None
    recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
    try:
        order = sorted(range(len(routes)), key=lambda i: (-int(getattr(routes[i], "score", 0) or 0), i))
        asked = order[:MAX_ROUTES_PER_SCAN]
        unique: dict = {}
        for i in asked:
            unique.setdefault(cache_key(_item(routes[i])), []).append(i)
        keys = list(unique)
        items = [_item(routes[unique[k][0]]) for k in keys]
        print(f"[*][{_TAG}] {len(routes)} routes, {len(items)} distinct asked")
        data = jev_post("route-privacy-rank", {"routes": items,
                                               "user_id": os.environ.get("USER_ID", ""),
                                               "project_id": os.environ.get("PROJECT_ID", "")},
                        _TAG, TIMEOUT)
        scores = _validate(data, len(items)) if data is not None else None
        if scores is None:
            if data is not None:
                print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
            recorder.fallback()
            return None
        recorder.model = jev_model(data)
        per_route: List[Optional[float]] = [None] * len(routes)
        for k, score in zip(keys, scores):
            for i in unique[k]:
                per_route[i] = score
                prior = int(getattr(routes[i], "score", 0) or 0)
                recorder.decision(f"route_{i}", "private" if score >= 0.5 else "public",
                                  round(score * 100), "private" if prior >= _PRIVATE_SCORE else "public",
                                  prior_score=prior, path=routes[i].path)
                if ROLLOUT == ACT:
                    routes[i].jev_rank = score
        print(f"[+][{_TAG}] {len(scores)} distinct routes ranked")
        return [s for s in per_route if s is not None]
    except Exception as e:  # noqa: BLE001 - a ranking is never worth breaking the scan
        print(f"[!][{_TAG}] Pass failed ({type(e).__name__}) - the deterministic order stands.")
        recorder.fallback()
        return None
    finally:
        recorder.finish(recon_data)
