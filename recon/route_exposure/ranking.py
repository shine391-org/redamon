"""S3: a deterministic prior score per route, and the request budget.

The score's reasons double as ``auth_expected_hints``: a route OpenAPI declares
secured, or that a discovery tool already saw denied, is a route whose
anonymous 2xx means something. The budget keeps the floor (score >= 5 and every
version-control/env seed), then fills each host by Jev's privacy answer when the
route_privacy_rank hook gave one and by score otherwise, round-robin across hosts
so the first host never spends the whole budget.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from recon.route_exposure import seeds
from recon.route_exposure.harvest import Route

FLOOR_SCORE = 5
_PRIVATE_TAGS = frozenset({"internal", "admin", "private"})

try:
    from recon.main_recon_modules.vhost_sni_enum import INTERNAL_KEYWORDS
except Exception:  # pragma: no cover - spawned-container import shim
    INTERNAL_KEYWORDS = frozenset({"admin", "internal", "intranet", "private", "staging", "dev"})


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def score(route: Route) -> int:
    """Sum the signal weights (plan §5.3); record each hint on the route."""
    total, hints = 0, []

    def hint(label: str) -> None:
        if label and label not in hints:
            hints.append(label)

    if route.openapi_security:
        total += 5
        hint("openapi")
    if any(t.lower() in _PRIVATE_TAGS for t in route.openapi_tags):
        total += 3
        hint("openapi_tag")
    if route.declared_only:
        total += 2
        hint("declared_only")
    if route.discovery_status in (401, 403):
        total += 3
        hint("seen_denied")
    if route.category in ("admin", "admin_debug"):
        total += 3
        hint("path_word")
    words = {t for seg in route.path.split("/") for t in seeds.tokens(seg)}
    if words & seeds.STRONG_PATH_WORDS:
        total += 2
        hint("path_word")
    host = _host(route.baseurl)
    if host and not _is_ip(host) and set(seeds.tokens(host.split(".")[0])) & set(INTERNAL_KEYWORDS):
        total += 1
        hint("host_word")
    if route.js_only:
        total += 1
    if route.generated_by == "vcs":
        total += 5
    elif route.generated_by == "version":
        total += 2
    elif route.generated_by == "sibling":
        total += 1
    route.score = total
    route.hints = hints
    route.floor = total >= FLOOR_SCORE or route.generated_by == "vcs"
    return total


def _order_key(route: Route):
    """Floor first, by prior score and path only: the per-host cap can cut the floor
    itself, and which floor routes survive it must never depend on Jev. After the
    floor, Jev's privacy answer (route_privacy_rank) fills the budget: answered routes
    by that answer, then the unanswered ones by prior score, so with no answer the
    order is the deterministic one."""
    if route.floor:
        return (False, -route.score, False, 0.0, 0, route.path)
    jev = route.jev_rank
    return (True, 0, jev is None, -(jev or 0.0), -route.score, route.path)


def select(routes: list, *, per_host: int, total: int) -> tuple[list, int]:
    """(the routes to request, how many the budget cut).

    The floor goes first on every host and counts inside the caps; across
    hosts the picks interleave, hostnames before bare IPs.
    """
    for route in routes:
        score(route)
    by_host: dict = {}
    for route in routes:
        by_host.setdefault(_host(route.baseurl), []).append(route)
    queues = {}
    for host, items in by_host.items():
        queues[host] = sorted(items, key=_order_key)[:max(0, per_host)]
    hosts = sorted(queues, key=lambda h: (_is_ip(h), h))
    chosen: list = []
    for floor_pass in (True, False):
        depth = {h: 0 for h in hosts}
        progressed = True
        while progressed and len(chosen) < total:
            progressed = False
            for host in hosts:
                queue = queues[host]
                while depth[host] < len(queue) and queue[depth[host]].floor != floor_pass:
                    depth[host] += 1
                if depth[host] < len(queue):
                    chosen.append(queue[depth[host]])
                    depth[host] += 1
                    progressed = True
                    if len(chosen) >= total:
                        break
    return chosen, len(routes) - len(chosen)
