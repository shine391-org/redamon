"""Route exposure scan: request what recon found, plus what it generates, anonymously.

GROUP 6 Phase A (concurrent with nuclei, cache poisoning, GraphQL). For every
route it sends one anonymous GET (HEAD and a 1 KB Range read for backups), one
control request on a 2xx, and one logged-in GET where the project's AuthProfile
covers the host, then writes two kinds of :Vulnerability: candidates for the
agent to confirm (needs_agent_confirmation) and findings a signature proves.
GET and HEAD only; a state-changing path is never requested; PII is stored as
types and one count, never a value.

Logs are counts only: the orchestrator reads the drawer's phase out of stdout,
and a URL, host or exception text could move it.
"""

from __future__ import annotations

import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from recon.helpers.isolated_result import TopLevelKeys
from recon.route_exposure import catalogs, generators, harvest, normalizers, prober, ranking, seeds, verdict

SOURCE = "route_exposure"
ROUTE_EXPOSURE_JEV_HOOKS = ("route_privacy_rank", "route_exposure_wall", "route_exposure_assess")

#: Registry bounds (recon_settings/registry.yaml) and defaults. fetch_project_settings
#: does not clamp, so a stale or hand-edited row is clamped here.
BOUNDS = {
    "ROUTE_EXPOSURE_MAX_RPS": (1, 50, 5),
    "ROUTE_EXPOSURE_WORKERS": (1, 16, 4),
    "ROUTE_EXPOSURE_TIMEOUT": (2, 60, 10),
    "ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST": (10, 5000, 300),
    "ROUTE_EXPOSURE_MAX_ROUTES_TOTAL": (50, 50000, 3000),
}
#: Generator and analysis switches. All default on except cross_host.
SWITCHES = {
    "seed_paths": "ROUTE_EXPOSURE_SEED_PATHS",
    "vcs_files": "ROUTE_EXPOSURE_VCS_FILES",
    "backup_files": "ROUTE_EXPOSURE_BACKUP_FILES",
    "version_variants": "ROUTE_EXPOSURE_VERSION_VARIANTS",
    "compare_logged_in": "ROUTE_EXPOSURE_COMPARE_LOGGED_IN",
    "pii_detection": "ROUTE_EXPOSURE_PII_DETECTION",
    # v2
    "siblings": "ROUTE_EXPOSURE_SIBLINGS",
    "framework_seeds": "ROUTE_EXPOSURE_FRAMEWORK_SEEDS",
    "follow_catalogs": "ROUTE_EXPOSURE_FOLLOW_CATALOGS",
    "git_walk": "ROUTE_EXPOSURE_GIT_WALK",
    "cross_host": "ROUTE_EXPOSURE_CROSS_HOST",
    "cors_rider": "ROUTE_EXPOSURE_CORS_RIDER",
    "cache_rider": "ROUTE_EXPOSURE_CACHE_RIDER",
}
#: Defaults for the switches when a settings dict omits them (cross_host is off).
_SWITCH_DEFAULT = {"cross_host": False}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _clamp(value, low, high, default):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN
        return default
    return max(low, min(high, number))


def config(settings: dict) -> dict:
    """The run's knobs, every numeric clamped to its registry bounds."""
    cfg = {name: bool(settings.get(key, _SWITCH_DEFAULT.get(name, True))) for name, key in SWITCHES.items()}
    rps = _clamp(settings.get("ROUTE_EXPOSURE_MAX_RPS"), *BOUNDS["ROUTE_EXPOSURE_MAX_RPS"])
    ceiling = settings.get("ROE_GLOBAL_MAX_RPS") if settings.get("ROE_ENABLED") else 0
    if isinstance(ceiling, (int, float)) and not isinstance(ceiling, bool) and ceiling > 0:
        # The bounds' floor of 1 rps must never lift a slower engagement ceiling.
        rps = min(rps, float(ceiling))
    cfg["rps"] = rps
    cfg["workers"] = int(_clamp(settings.get("ROUTE_EXPOSURE_WORKERS"), *BOUNDS["ROUTE_EXPOSURE_WORKERS"]))
    cfg["timeout"] = _clamp(settings.get("ROUTE_EXPOSURE_TIMEOUT"), *BOUNDS["ROUTE_EXPOSURE_TIMEOUT"])
    cfg["per_host"] = int(_clamp(settings.get("ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST"),
                                 *BOUNDS["ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST"]))
    cfg["total"] = int(_clamp(settings.get("ROUTE_EXPOSURE_MAX_ROUTES_TOTAL"),
                              *BOUNDS["ROUTE_EXPOSURE_MAX_ROUTES_TOTAL"]))
    return cfg


def _roe_excluded(settings: dict) -> list:
    if not settings.get("ROE_ENABLED"):
        return []
    return [h for h in settings.get("ROE_EXCLUDED_HOSTS") or [] if isinstance(h, str) and h.strip()]


def build_guard(combined_result: dict, settings: dict):
    """One guard per run, for every request and every control (plan T39).

    The run's own hosts (operator targets, the target list, the hosts
    http_probe reached) follow the pipeline's address rule: private addresses
    are scanned, metadata and never-scannable ones are not. A host seen only in
    a bundle must first be in the probe scope (a strict subdomain of a root in
    a full-discovery run), then pass the attacker-influenced URL rule, which
    refuses every private address. Answers are cached per host.
    """
    from recon.helpers.openapi.discovery import operator_targets
    from recon.helpers.roe_scope import _is_roe_excluded
    from recon.main_recon_modules.ip_filter import is_address_safe_to_scan, is_url_safe_to_probe
    from recon.main_recon_modules.js_recon import _endpoint_probe_scope, _host_of, _in_probe_scope

    by_url = (combined_result.get("http_probe") or {}).get("by_url") or {}
    reached = [{"url": str(e.get("url") or u)} for u, e in by_url.items() if isinstance(e, dict)]
    scope = _endpoint_probe_scope(combined_result, reached, settings)
    op_hosts, op_nets = operator_targets(settings)
    excluded = _roe_excluded(settings)
    cache: dict = {}
    lock = threading.Lock()

    def guard(url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if not _in_probe_scope(url, scope):
            return False
        host = _host_of(url)
        if excluded and _is_roe_excluded(host, excluded):
            return False
        with lock:
            if host in cache:
                return cache[host]
        if host in scope.hosts:
            allowed = is_address_safe_to_scan(host, op_hosts, op_nets)
        else:
            allowed = is_url_safe_to_probe(url)
        with lock:
            cache[host] = allowed
        return allowed

    return guard


def _window_open(settings: dict) -> bool:
    try:
        from recon.helpers import roe_scope
        allowed, _ = roe_scope._check_roe_time_window(settings)
        return bool(allowed)
    except Exception:  # noqa: BLE001 - a window that cannot be checked is closed
        return False


def _note_degraded(reason: str) -> None:
    try:
        from recon.helpers import circuit_breaker
        circuit_breaker.note_degraded(SOURCE, sources=(SOURCE,), reason=reason)
    except Exception:  # noqa: BLE001
        pass


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _observe_all(routes: list, probe: prober.Prober, cfg: dict) -> list:
    def one(route):
        try:
            return verdict.observe(route, probe, cfg)
        except Exception:  # noqa: BLE001 - one route's fault costs that route
            return verdict.Observation(route=route)

    if cfg["workers"] <= 1 or len(routes) <= 1:
        return [one(r) for r in routes]
    with ThreadPoolExecutor(max_workers=cfg["workers"], thread_name_prefix="route-exposure") as pool:
        return list(pool.map(one, routes))


def _catalog_routes(observations: list, corpus, cfg: dict) -> tuple:
    """Routes an open catalog lists (plan §5.2), one follow-up round only: what the
    round's own probes find is never followed again. ``(routes, catalogs_followed)``."""
    if not cfg.get("follow_catalogs"):
        return [], 0
    made: list = []
    per_host: dict = {}
    followed = 0
    for obs in observations:
        is_catalog = (obs.signature or {}).get("kind") == "route_catalog" or obs.api_spec
        if not is_catalog or obs.anon is None:
            continue
        paths = catalogs.parse(obs.anon.content, obs.anon.header("content-type"))
        if paths:
            followed += 1
        base = obs.route.baseurl
        for path in paths:
            if per_host.get(base, 0) >= seeds.CAP_CATALOG_ROUTES:
                break
            route = generators.make_route(base, path, "catalog")
            if corpus.add(route):
                made.append(route)
                per_host[base] = per_host.get(base, 0) + 1
    return made, followed


def _titles(combined_result: dict) -> dict:
    """{base URL: page title} of each host's root page, from http_probe."""
    out: dict = {}
    by_url = (combined_result.get("http_probe") or {}).get("by_url") or {}
    for url, entry in by_url.items():
        if not isinstance(entry, dict):
            continue
        full = str(entry.get("url") or url)
        if (urlsplit(full).path or "/") in ("", "/") and entry.get("title"):
            out.setdefault(harvest.base_of(full), str(entry["title"]).strip())
    return out


def _cross_host_routes(observations: list, corpus, combined_result: dict, cfg: dict, guard) -> list:
    """Paths that hit on one host, tried on the run's other hosts that share its
    page title or technology set (plan §5.2). Each keeps its source route's request
    shape, so an archive is still read with HEAD and Range only. Off by default."""
    if not cfg.get("cross_host"):
        return []
    shape = {(o.route.baseurl, o.route.path): o.route.request for o in observations}
    hit: dict = {}
    for finding in verdict.assess(observations, cfg)["findings"]:
        hit.setdefault(finding["baseurl"], set()).add(finding["path"])
    titles = _titles(combined_result)
    made: list = []
    for base_a in sorted(hit):
        for base_b in corpus.bases:
            if base_b == base_a:
                continue
            same_title = titles.get(base_a) and titles.get(base_a) == titles.get(base_b)
            same_tech = corpus.technologies.get(base_a) and \
                corpus.technologies.get(base_a) == corpus.technologies.get(base_b)
            if not (same_title or same_tech):
                continue
            for path in sorted(hit[base_a]):
                if len(made) >= seeds.CAP_CROSS_HOST:
                    return made
                route = generators.make_route(base_b, path, "cross_host",
                                              request=shape.get((base_a, path), "get"))
                if guard(route.url) and corpus.add(route):
                    made.append(route)
    return made


def _jev_rank(routes: list, settings: dict, combined_result: dict) -> None:
    """Hook A: Jev's privacy reading of each route, set as `jev_rank`, which fills the
    budget after the floor. Runs before ranking.select; the routes carry their prior
    score already."""
    try:
        from recon.helpers.ai_planner import route_privacy_rank
        route_privacy_rank.run_for_routes(routes, settings, combined_result)
    except Exception as e:  # noqa: BLE001 - a hook never breaks the scan
        print(f"[!][RouteExposure] Jev ranking skipped ({type(e).__name__})")


def _order_leads(findings: list) -> None:
    """The leads, in their own slots, ordered as the agent's lead query reads them:
    Jev's answered ones most sensitive first, the unanswered after, and the ones Jev
    placed as a wall or as public content last. A signature finding keeps its slot;
    with no Jev annotation the order is unchanged. Re-orders only; never drops."""
    from recon.helpers.ai_planner import route_exposure_assess, route_wall_check

    def key(finding: dict) -> tuple:
        demoted = route_wall_check.is_wall(finding) or route_exposure_assess.is_public(finding)
        sensitivity = finding.get("route_jev_sensitivity")
        if isinstance(sensitivity, int) and not isinstance(sensitivity, bool):
            return (demoted, 0, -sensitivity)
        return (demoted, 1, 0)

    slots = [i for i, f in enumerate(findings) if f.get("needs_agent_confirmation")]
    for i, finding in zip(slots, sorted((findings[i] for i in slots), key=key)):
        findings[i] = finding


def _jev_second_opinions(observations: list, findings: list, settings: dict, combined_result: dict) -> None:
    """Hooks B and C: Jev's page class of each HTML lead and its kind and sensitivity,
    written onto the leads (the graph writer persists them), then the leads ordered by
    them. No lead is dropped and no route_class rewritten."""
    from recon.helpers.ai_planner import route_exposure_assess, route_wall_check

    by_key = {(o.route.baseurl, o.route.path): o for o in observations}
    try:
        if route_wall_check.jev_wall_check_enabled(settings):
            pairs = []
            for f in findings:
                obs = by_key.get((f["baseurl"], f["path"]))
                if (f["exposure_kind"] == "anonymous_access" and f.get("anon_content_class") == "html"
                        and obs is not None and obs.anon is not None):
                    pairs.append((f, verdict.page_entry(obs.anon, obs.route.url)))
            route_wall_check.run_for_pages(pairs, settings, combined_result)
    except Exception as e:  # noqa: BLE001
        print(f"[!][RouteExposure] Jev wall check skipped ({type(e).__name__})")
    try:
        if route_exposure_assess.jev_assess_enabled(settings):
            pairs = []
            for f in findings:
                if not f.get("needs_agent_confirmation"):
                    continue
                obs = by_key.get((f["baseurl"], f["path"]))
                anon_sig = obs.anon_signals if obs is not None else None
                auth_sig = obs.authed_signals if obs is not None else None
                keys = (anon_sig.key_paths if anon_sig is not None and anon_sig.key_paths
                        else (auth_sig.key_paths if auth_sig is not None else []))
                longest = max(anon_sig.max_array_len if anon_sig is not None else 0,
                              auth_sig.max_array_len if auth_sig is not None else 0)
                pairs.append((f, route_exposure_assess.item_for(f, keys, longest)))
            route_exposure_assess.run_for_candidates(pairs, settings, combined_result)
    except Exception as e:  # noqa: BLE001
        print(f"[!][RouteExposure] Jev assessment skipped ({type(e).__name__})")
    try:
        _order_leads(findings)
    except Exception as e:  # noqa: BLE001 - an order is never worth breaking the scan
        print(f"[!][RouteExposure] Jev lead order skipped ({type(e).__name__})")


def _run(combined_result: dict, settings: dict, started: str) -> dict:
    from recon.helpers import circuit_breaker as cb

    cfg = config(settings)
    scope = cb.scope((), label="RouteExposure", unit="host(s)")
    # Client-side router routes are harvested so a page hidden only by the browser,
    # and the APIs it calls, are requested like any other route (plan §5.2).
    corpus = harvest.harvest(combined_result, routers=True)
    harvested = len(corpus.routes)
    generated = generators.generate(corpus, cfg)
    guard = build_guard(combined_result, settings)
    routes = [r for r in corpus.routes.values() if guard(r.url)]
    out_of_scope = len(corpus.routes) - len(routes)
    for route in routes:
        ranking.score(route)
    _jev_rank(routes, settings, combined_result)
    selected, cut = ranking.select(routes, per_host=cfg["per_host"], total=cfg["total"])
    hosts = len({_host(r.baseurl) for r in routes})
    print(f"[*][RouteExposure] {len(routes)} route(s) on {hosts} host(s): {len(selected)} requested, "
          f"{cut} cut by the budget")
    probe = prober.Prober(settings, guard=guard, timeout=cfg["timeout"], rps=cfg["rps"],
                          breaker_scope=scope, roe_excluded=_roe_excluded(settings))
    observations = _observe_all(selected, probe, cfg)
    # One follow-up round: the routes open catalogs list, and the paths that hit tried
    # on the sibling hosts. Never recursive.
    catalog_routes, catalogs_followed = _catalog_routes(observations, corpus, cfg)
    cross_routes = _cross_host_routes(observations, corpus, combined_result, cfg, guard)
    follow_up = [r for r in catalog_routes + cross_routes if guard(r.url)]
    for route in follow_up:
        ranking.score(route)
    if follow_up:
        observations += _observe_all(follow_up, probe, cfg)
    assessed = verdict.assess(observations, cfg)
    findings = assessed["findings"]
    _jev_second_opinions(observations, findings, settings, combined_result)

    dropped = dict(assessed["dropped"], unsafe=corpus.unsafe)
    summary = {
        "routes_harvested": harvested, "routes_generated": len(generated) + len(follow_up),
        "routes_requested": len(selected) + len(follow_up), "budget_cut": cut, "hosts": hosts,
        "out_of_scope": out_of_scope, "dropped": dropped,
        "logged_in_compared": assessed["logged_in_compared"], "requests_sent": probe.sent,
        "catalogs_followed": catalogs_followed, "cross_host_routes": len(cross_routes),
        "started_at": started, "finished_at": _now(),
    }
    result = normalizers.build_result(findings, endpoint_status=assessed["endpoint_status"],
                                      new_endpoints=assessed["new_endpoints"], summary=summary)
    scope.finish("route_exposure", host_source=SOURCE, payload=result, log=False)
    skipped = len(scope.hosts())
    result["summary"]["hosts_skipped"] = skipped
    # The breaker's own host list stays in the recon JSON, never in stdout.
    print(f"[*][RouteExposure] {probe.sent} request(s) sent ({probe.control_requests} control, "
          f"{probe.sent_with_auth} logged in)")
    if skipped:
        print(f"[!][RouteExposure] {skipped} host(s) skipped as unreachable")
    s = result["summary"]
    if findings:
        print(f"[+][RouteExposure] {s['candidates']} lead(s) for the agent, "
              f"{s['findings']} signature finding(s)")
    else:
        print("[-][RouteExposure] no exposed route found")
    return result


def run_route_exposure(combined_result: dict, settings: dict) -> dict:
    """Mutate combined_result["route_exposure"] in place and return combined_result.

    Shared entry of the full pipeline AND partial recon. Never raises.
    """
    settings = settings or {}
    if not settings.get("ROUTE_EXPOSURE_ENABLED", False):
        print("[-][RouteExposure] disabled")
        return combined_result
    started = _now()
    if not _window_open(settings):
        # Fail closed, and keep last run's findings: nothing was re-checked.
        _note_degraded("RoE time window")
        print("[!][RouteExposure] outside the RoE time window: nothing requested")
        combined_result["route_exposure"] = normalizers.build_result(
            [], summary={"started_at": started, "finished_at": _now()})
        return combined_result
    try:
        combined_result["route_exposure"] = _run(combined_result, settings, started)
    except Exception as e:  # noqa: BLE001
        # Empty and marked degraded: the prune must keep last run's findings
        # instead of deleting them as "gone". Type only: a message can quote a URL.
        _note_degraded("the route exposure scan failed")
        print(f"[!][RouteExposure] Error ({type(e).__name__}) - no results this run")
        combined_result["route_exposure"] = normalizers.build_result(
            [], summary={"started_at": started, "finished_at": _now()}, error=type(e).__name__)
    return combined_result


def run_route_exposure_isolated(combined_result: dict, settings: dict) -> TopLevelKeys:
    """Thread-safe: deep-copies first, returns this tool's payload plus its own Jev
    decision records (merged per hook by _merge_isolated_result)."""
    snapshot = copy.deepcopy(combined_result)
    run_route_exposure(snapshot, settings)
    out = TopLevelKeys(route_exposure=snapshot.get("route_exposure", {}))
    shadow = {h: rec for h, rec in (snapshot.get("jev_shadow") or {}).items()
              if h in ROUTE_EXPOSURE_JEV_HOOKS}
    if shadow:
        out["jev_shadow"] = shadow
    return out
