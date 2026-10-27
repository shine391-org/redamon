"""
RedAmon - Rules of Engagement scope helpers
============================================
Excluded-host matching and the time window for the RoE governor. Extracted
from ``recon.main`` so active scanners (e.g. origin_discovery, AI Surface Recon)
can enforce them without importing ``recon.main``, which would re-run the
pipeline's top level as a second module. ``recon.main`` re-exports these names,
so ``from main import _is_roe_excluded`` still resolves.

It imports no other recon module: the auth profile and the OpenAPI scope build
on its normalizers.
"""

import ipaddress
from urllib.parse import urlsplit


def _is_roe_excluded(host: str, excluded_list: list) -> bool:
    """True when ``host`` matches an RoE exclusion.

    An exclusion is an exact host or IP; a domain, which also excludes its
    subdomains; ``*.domain``, which excludes its subdomains only; or a CIDR.
    Case, port, scheme, path and a trailing dot are ignored on both sides, and
    an IPv6 address matches in any spelling. A bare string suffix is never an
    IP rule: ``0.5`` does not exclude ``10.0.0.5``.
    """
    host = _normalize_host(host)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for value in excluded_list:
        entry = _normalize_scope_entry(value)
        if not entry:
            continue
        if entry.startswith('*.'):
            if host.endswith(entry[1:]):
                return True
        elif '/' in entry or address is not None:
            try:
                if address is not None and address in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
        elif host == entry or host.endswith('.' + entry):
            return True
    return False


def _normalize_host(host) -> str:
    """Lower-cased hostname/IP with any scheme, path, port and trailing dot removed."""
    if not isinstance(host, str):
        return ''
    host = host.strip()
    if '://' in host:
        host = urlsplit(host).hostname or ''
    elif host.startswith('['):
        host = host[1:].split(']', 1)[0]
    elif host.count(':') == 1:
        host = host.split(':', 1)[0]
    return host.strip().rstrip('.').lower()


def _normalize_scope_entry(entry) -> str:
    if not isinstance(entry, str):
        return ''
    entry = entry.strip()
    if entry.startswith('*.'):
        return '*.' + _normalize_host(entry[2:])
    if '/' in entry and '://' not in entry:
        return entry.lower()
    return _normalize_host(entry)


def _filter_roe_excluded(hosts: list, settings: dict, label: str = "host") -> list:
    """Filter a list of hosts/IPs against ROE_EXCLUDED_HOSTS. Returns the filtered list."""
    roe_excluded = settings.get('ROE_EXCLUDED_HOSTS', [])
    if not settings.get('ROE_ENABLED', False) or not roe_excluded:
        return hosts
    before_count = len(hosts)
    filtered = [h for h in hosts if not _is_roe_excluded(h, roe_excluded)]
    removed = before_count - len(filtered)
    if removed:
        print(f"[RoE] Excluded {removed} {label}(s) per Rules of Engagement")
    return filtered


def _check_roe_time_window(settings: dict, _now=None) -> tuple[bool, str]:
    """Check if current time is within the RoE-allowed window.

    Returns (allowed, reason_message). Always returns (True, "") if
    RoE or its time window is disabled. Pass _now for testing.
    """
    if not settings.get('ROE_ENABLED') or not settings.get('ROE_TIME_WINDOW_ENABLED'):
        return True, ""

    from datetime import datetime as _dt
    import zoneinfo as _zi

    tz_name = settings.get('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
    try:
        tz = _zi.ZoneInfo(tz_name)
    except Exception:
        print(f"[RoE] Unknown timezone '{tz_name}', falling back to UTC")
        tz = _zi.ZoneInfo('UTC')

    now = _now or _dt.now(tz)

    # Check day of week
    allowed_days = [d.lower() for d in settings.get('ROE_TIME_WINDOW_DAYS', [])]
    current_day = now.strftime('%A').lower()
    if current_day not in allowed_days:
        return False, f"Current day ({current_day}) is not in allowed days: {', '.join(allowed_days)} ({tz_name})"

    # Check time range
    start = settings.get('ROE_TIME_WINDOW_START_TIME', '09:00')
    end = settings.get('ROE_TIME_WINDOW_END_TIME', '18:00')
    current_time = now.strftime('%H:%M')
    if current_time < start or current_time >= end:
        return False, f"Current time ({current_time} {tz_name}) is outside allowed window ({start}\u2013{end})"

    return True, ""
