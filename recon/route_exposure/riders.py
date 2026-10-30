"""S4 riders (v2): CORS and cache checks on a personalised, sensitive logged-in route.

Each runs only where the logged-in answer was 2xx and personalised (the anonymous
answer was denied, or the bodies differ) and a leak signal fired - decided by the
caller. Each request goes through the pacer. Neither rider plants anything: the CORS
rider only reads the response's CORS headers, and the cache rider only reads headers
and the cache oracle. Proving a poisoned fetch is the agent's job.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from recon.cache_scan import oracle
from recon.route_exposure import prober as prober_mod

#: Origin variants sent one per request (plan §5.7). At most 4.
_ATTACKER_ORIGIN = "https://evil.invalid"


def _registrable(host: str) -> str:
    """A best-effort registrable domain for the prefix variant; a bare IP or a
    single-label host is returned unchanged (the prefix variant is then harmless)."""
    labels = (host or "").split(".")
    if len(labels) >= 2 and not labels[-1].isdigit():
        return ".".join(labels[-2:])
    return host


def cors_variants(host: str) -> list:
    """(label, Origin) pairs: a foreign origin, null, a suffix match and a prefix match."""
    return [
        ("reflected", _ATTACKER_ORIGIN),
        ("null", "null"),
        ("suffix", f"https://{host}.evil.invalid"),
        ("prefix", f"https://evil{_registrable(host)}"),
    ]


def cors_rider(probe, route, enabled: bool = True) -> dict:
    """``{"cors_variants": [...]}`` when a sent Origin (or null) is echoed in
    ``Access-Control-Allow-Origin`` with ``Access-Control-Allow-Credentials: true``,
    else ``{}``. The logged-in request carries the session; only its CORS headers are read."""
    if not enabled:
        return {}
    auth = probe.auth_headers(route.url)
    if not auth:
        return {}
    host = urlsplit(route.url).hostname or ""
    matched: list = []
    for label, origin in cors_variants(host):
        answer = probe.send("GET", route.url, auth=auth, headers={"Origin": origin})
        if answer is None or not answer.ok:
            continue
        acao = answer.header("access-control-allow-origin").strip()
        acac = answer.header("access-control-allow-credentials").strip().lower() == "true"
        if acac and (acao == origin or (origin == "null" and acao == "null")):
            matched.append(label)
    return {"cors_variants": matched} if matched else {}


def cache_rider(authed, enabled: bool = True) -> dict:
    """``{"cache_signals": [...]}`` when the logged-in answer is cacheable to an
    anonymous visitor and a cache layer is present, else ``{}``. Reads headers only."""
    if not enabled or authed is None or not authed.ok:
        return {}
    cache_control = authed.header("cache-control").lower()
    vary = authed.header("vary").lower()
    if "cookie" in vary or "authorization" in vary:
        return {}
    signals: list = []
    if "public" in cache_control:
        signals.append("cache-control:public")
    if "s-maxage" in cache_control:
        signals.append("s-maxage")
    if (oracle._positive_max_age(cache_control) and "private" not in cache_control
            and "no-store" not in cache_control and "s-maxage" not in cache_control):
        signals.append("max-age")
    if not signals:
        return {}
    # A cache layer must actually be in front: a cacheable header alone is intent.
    state = oracle.response_cache_state(authed)
    if state == "unknown":
        return {}
    signals.append(f"cache:{state}")
    return {"cache_signals": signals}
