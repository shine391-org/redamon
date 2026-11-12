"""Shared full/partial Arjun contract; no project-setting writes or new budgets."""
import re
from urllib.parse import urlsplit

from recon.helpers.openapi.scope import _normalize_scope_host

# Missing-key fallbacks are deliberately conservative (the historical full caller).
# Normal get_settings()/partial_settings() already supplies registry defaults,
# including MAX_ENDPOINTS=50000. Do not raise a saved cap to repair a fallback.
FALLBACKS = {
    'ARJUN_METHODS': ['GET'], 'ARJUN_THREADS': 2, 'ARJUN_TIMEOUT': 15,
    'ARJUN_SCAN_TIMEOUT': 600, 'ARJUN_CHUNK_SIZE': 500,
    'ARJUN_MAX_ENDPOINTS': 50, 'ARJUN_RATE_LIMIT': 0,
    'ARJUN_STABLE': False, 'ARJUN_PASSIVE': False,
    'ARJUN_DISABLE_REDIRECTS': False, 'ARJUN_CUSTOM_HEADERS': [],
}


def arjun_settings(settings):
    res = {key: settings.get(key, list(value) if isinstance(value, list) else value)
           for key, value in FALLBACKS.items()}
    if 'ARJUN_LATE_SOURCES' in settings:
        res['ARJUN_LATE_SOURCES'] = bool(settings['ARJUN_LATE_SOURCES'])
    return res


def arjun_url_host(url):
    """Strict HTTP authority, canonical exact host; never suffix-widen scope."""
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url) or '\\' in url:
        return ''
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or parsed.username is not None or parsed.password is not None:
            return ''
        # Accessing .port validates numeric/range and bracketed IPv6 syntax.
        parsed.port
        return _normalize_scope_host(parsed.hostname)
    except (ValueError, TypeError):
        return ''


def select_arjun_targets(urls, maximum):
    """
    Select targets for Arjun respecting API/dynamic priority with fair origin scheduling.
    When urls exceed maximum, distributes fairly across origins rather than starving
    origins that appear later in the list.
    """
    urls = list(dict.fromkeys(urls))
    if len(urls) <= maximum:
        return urls, []

    # Group by origin (scheme + netloc)
    by_origin = {}
    for u in urls:
        parsed = urlsplit(u)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        by_origin.setdefault(origin, []).append(u)

    def _priority_bucket(u):
        u_lower = u.lower()
        if any(p in u_lower for p in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/']):
            return 0
        if any(u_lower.endswith(e) for e in ['.php', '.asp', '.aspx', '.jsp']):
            return 1
        return 2

    for org in by_origin:
        by_origin[org].sort(key=_priority_bucket)

    selected = []
    unselected = []
    origin_lists = [list(by_origin[org]) for org in sorted(by_origin.keys())]

    while len(selected) < maximum and any(origin_lists):
        for o_list in origin_lists:
            if o_list:
                selected.append(o_list.pop(0))
                if len(selected) == maximum:
                    break

    for o_list in origin_lists:
        unselected.extend(o_list)

    return selected, unselected


_UNINSTANTIATED_TEMPLATE_PATTERN = re.compile(r'\{[a-zA-Z0-9_]+\}')


def classify_late_source_endpoint(base_url, path, endpoint_data, allowed_hosts=None):
    """
    Classify an endpoint appearing from late sources (GAU, OpenAPI, ParamSpider, Kiterunner, URLScan).

    Returns:
        dict:
            eligible: bool
            defer_reason: str or None
            methods: list of HTTP methods to probe (retained from endpoint)
            has_known_schema: bool
            sources: list of sources
    """
    full_url = base_url.rstrip('/') + path
    host = arjun_url_host(full_url)
    sources = endpoint_data.get('sources') or []
    methods = endpoint_data.get('methods') or []

    # Scope check
    if not host:
        return {
            'eligible': False,
            'defer_reason': 'invalid_authority',
            'methods': ['GET'],
            'has_known_schema': False,
            'sources': sources,
        }
    if allowed_hosts is not None:
        normalized_allowed = {_normalize_scope_host(h) for h in allowed_hosts} - {''}
        if host not in normalized_allowed:
            return {
                'eligible': False,
                'defer_reason': 'out_of_scope',
                'methods': ['GET'],
                'has_known_schema': False,
                'sources': sources,
            }

    # Declared-only check (OpenAPI templates that were never instantiated/observed on wire)
    is_declared_only = (
        endpoint_data.get('declared_only', False)
        or (sources == ['openapi'])
        or bool(_UNINSTANTIATED_TEMPLATE_PATTERN.search(path))
    )
    observed_sources = {'katana', 'hakrawler', 'gau', 'paramspider', 'kiterunner', 'urlscan', 'ffuf', 'zap_ajax'}
    has_observed_source = bool(set(sources) & observed_sources)
    if is_declared_only and not has_observed_source:
        return {
            'eligible': False,
            'defer_reason': 'declared_only_uninstantiated',
            'methods': methods or ['GET'],
            'has_known_schema': bool(endpoint_data.get('parameters')),
            'sources': sources,
        }

    # Dead / unverified check
    if endpoint_data.get('dead', False) or endpoint_data.get('status_code') in (404, 410):
        return {
            'eligible': False,
            'defer_reason': 'dead_endpoint',
            'methods': methods or ['GET'],
            'has_known_schema': bool(endpoint_data.get('parameters')),
            'sources': sources,
        }

    if endpoint_data.get('unverified_archive', False):
        return {
            'eligible': False,
            'defer_reason': 'unverified_archive',
            'methods': methods or ['GET'],
            'has_known_schema': bool(endpoint_data.get('parameters')),
            'sources': sources,
        }

    # Retain methods - do not blind GET-only if POST is known
    supported_methods = ('GET', 'POST', 'JSON', 'XML')
    retained_methods = [m for m in methods if m.upper() in supported_methods]
    if not retained_methods:
        retained_methods = ['GET']

    # Known schema evidence reuse
    has_known_schema = bool(endpoint_data.get('parameters'))

    return {
        'eligible': True,
        'defer_reason': None,
        'methods': retained_methods,
        'has_known_schema': has_known_schema,
        'sources': sources,
    }


def plan_arjun_late_sources(by_base_url, already_targeted_urls, allowed_hosts=None, remaining_budget=None):
    """
    Plan Arjun enrichment for endpoints appearing after early crawl.

    Returns:
        Tuple of (admitted_tasks, deferred_endpoints, late_summary)
    """
    already_set = set(already_targeted_urls)
    candidate_tasks = []
    deferred_endpoints = []

    for base_url, base_data in by_base_url.items():
        endpoints = base_data.get('endpoints') or {}
        for path, ep_data in endpoints.items():
            full_url = base_url.rstrip('/') + path
            if full_url in already_set:
                continue

            classification = classify_late_source_endpoint(base_url, path, ep_data, allowed_hosts=allowed_hosts)
            if classification['eligible']:
                candidate_tasks.append({
                    'url': full_url,
                    'base_url': base_url,
                    'path': path,
                    'methods': classification['methods'],
                    'has_known_schema': classification['has_known_schema'],
                    'sources': classification['sources'],
                })
            else:
                deferred_endpoints.append({
                    'url': full_url,
                    'base_url': base_url,
                    'path': path,
                    'reason': classification['defer_reason'],
                    'sources': classification['sources'],
                })

    # Apply remaining budget with fair origin scheduling
    admitted_tasks = []
    if remaining_budget is not None and remaining_budget <= 0:
        for t in candidate_tasks:
            deferred_endpoints.append({
                'url': t['url'],
                'base_url': t['base_url'],
                'path': t['path'],
                'reason': 'budget_cap_exceeded',
                'sources': t['sources'],
            })
    elif remaining_budget is not None and len(candidate_tasks) > remaining_budget:
        candidate_urls = [t['url'] for t in candidate_tasks]
        selected_urls, unselected_urls = select_arjun_targets(candidate_urls, remaining_budget)
        selected_set = set(selected_urls)
        for t in candidate_tasks:
            if t['url'] in selected_set:
                admitted_tasks.append(t)
            else:
                deferred_endpoints.append({
                    'url': t['url'],
                    'base_url': t['base_url'],
                    'path': t['path'],
                    'reason': 'budget_cap_exceeded',
                    'sources': t['sources'],
                })
    else:
        admitted_tasks = candidate_tasks

    reason_counts = {}
    for d in deferred_endpoints:
        r = d.get('reason', 'unknown')
        reason_counts[r] = reason_counts.get(r, 0) + 1

    late_summary = {
        'total_late_endpoints': len(candidate_tasks) + len(deferred_endpoints),
        'admitted_count': len(admitted_tasks),
        'deferred_count': len(deferred_endpoints),
        'deferred_reasons': reason_counts,
    }

    return admitted_tasks, deferred_endpoints, late_summary


def record_arjun_selection(meta, unexecuted):
    meta['unexecuted_urls'] = list(unexecuted)
    if unexecuted:
        meta['status'] = 'partial'
    if meta.get('status') not in (None, 'complete'):
        from recon.helpers import circuit_breaker as cb
        cb.note_degraded('resource_enum', entries=[{
            'source': 'arjun', 'reason': 'Arjun selected-input execution incomplete',
            'skipped': len(unexecuted) or 1,
        }])


def reconcile_arjun_schema(by_base_url):
    """Count actual bucket members, not parameter-map keys or stale counters."""
    total_endpoints = total_parameters = 0
    for base in by_base_url.values():
        summary = {'total_endpoints': 0, 'total_parameters': 0, 'methods': {}, 'categories': {}}
        for endpoint in base.get('endpoints', {}).values():
            params = endpoint.setdefault('parameters', {})
            counts = {position: len(params.setdefault(position, [])) for position in ('query', 'body', 'path')}
            counts['total'] = sum(counts.values())
            endpoint['parameter_count'] = counts
            summary['total_endpoints'] += 1
            summary['total_parameters'] += counts['total']
            for method in set(endpoint.get('methods', [])):
                summary['methods'][method] = summary['methods'].get(method, 0) + 1
            category = endpoint.get('category', 'other')
            summary['categories'][category] = summary['categories'].get(category, 0) + 1
        base['summary'] = {**base.get('summary', {}), **summary}
        total_endpoints += summary['total_endpoints']
        total_parameters += summary['total_parameters']
    return {'total_endpoints': total_endpoints, 'total_parameters': total_parameters,
            'total_base_urls': len(by_base_url)}