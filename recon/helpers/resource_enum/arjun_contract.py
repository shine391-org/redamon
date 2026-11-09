"""Shared full/partial Arjun contract; no project-setting writes or new budgets."""
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
    return {key: settings.get(key, list(value) if isinstance(value, list) else value)
            for key, value in FALLBACKS.items()}


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
    """Retain the existing API/dynamic priority only when the saved cap binds."""
    urls = list(dict.fromkeys(urls))
    if len(urls) <= maximum:
        return urls, []
    api = [u for u in urls if any(p in u.lower() for p in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/'])]
    dynamic = [u for u in urls if u not in api and any(u.lower().endswith(e) for e in ['.php', '.asp', '.aspx', '.jsp'])]
    other = [u for u in urls if u not in api and u not in dynamic]
    ordered = api + dynamic + other
    return ordered[:maximum], ordered[maximum:]


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
