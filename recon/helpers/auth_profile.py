"""
RedAmon - Project AuthProfile header builder
=============================================
Turns the project's single AuthProfile (manual entry or a recorded browser
session) into HTTP headers for every recon tool and the agent.

Two controls live here and nowhere else, so every consumer gets them:

* Sanitizing. A recorded value is target-controlled (the target sets the
  Set-Cookie) and ends up in each tool's ``-H``. Values carrying CR/LF split the
  request (header injection / smuggling), and hakrawler (``;;``) and arjun
  (``\\n``) pack every header, including the internal ``X-Redamon-Ctx`` tag, into
  one joined argument, so those delimiters could split or spoof the tag. A bad
  value is rejected outright rather than stripped: a stripped cookie is a
  different, silently broken cookie.
* Scope. Auth lines are produced only for in-scope hosts, so a crawl that
  wanders to a CDN or a third party never carries the session with it.
"""

import base64
import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Tuple

from .roe_scope import _is_roe_excluded, _normalize_host, _normalize_scope_entry

AUTH_TYPES = frozenset({'bearer', 'cookie', 'header', 'basic', 'apikey'})
_DEFAULT_HEADER_NAMES = {'header': 'X-Auth-Token', 'apikey': 'X-API-Key'}

MAX_HEADER_NAME_LEN = 256
MAX_HEADER_VALUE_LEN = 8192

# RFC 9110 field-name token.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Every C0 control except TAB (legal inside a field value), plus DEL.
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x08\x0a-\x1f\x7f]')
_TOOL_JOIN_DELIMITERS = (';;',)
# Set only by the capture-proxy routing branch; a profile must never spoof it.
_RESERVED_HEADER_NAMES = frozenset({'x-redamon-ctx'})


def mask_auth_value(auth_value: str, auth_type: str = '') -> str:
    """Mask an authentication value for safe logging."""
    if not auth_value:
        return ''
    if auth_type == 'basic' and ':' in auth_value:
        username, _ = auth_value.split(':', 1)
        return f"{username}:***"
    if len(auth_value) > 10:
        return f"{auth_value[:4]}...{auth_value[-4:]}"
    if len(auth_value) > 4:
        return f"{auth_value[:2]}***"
    return "***"


def sanitize_header_name(name) -> Optional[str]:
    """Return the trimmed header name, or None if it is unsafe to send."""
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or len(name) > MAX_HEADER_NAME_LEN:
        return None
    if not _HEADER_NAME_RE.match(name):
        return None
    if name.lower() in _RESERVED_HEADER_NAMES:
        return None
    return name


def sanitize_header_value(value) -> Optional[str]:
    """Return the trimmed header value, or None if it is unsafe to send."""
    if not isinstance(value, str):
        return None
    if _CONTROL_CHARS_RE.search(value):
        return None
    if any(delim in value for delim in _TOOL_JOIN_DELIMITERS):
        return None
    value = value.strip()
    if not value or len(value) > MAX_HEADER_VALUE_LEN:
        return None
    return value


def _log(log_prefix: Optional[str], message: str) -> None:
    if log_prefix is not None:
        print(message.replace('{prefix}', log_prefix))


def _primary_header(auth_type: str, raw_value: str, header_name,
                    log_prefix: Optional[str]) -> Optional[tuple]:
    value = sanitize_header_value(raw_value)
    if value is None:
        _log(log_prefix, f"[!]{{prefix}} Rejected {auth_type} auth value: control "
                         f"characters, ';;' or longer than {MAX_HEADER_VALUE_LEN} chars")
        return None

    if auth_type == 'bearer':
        # A recorded Authorization header already carries the scheme.
        token = value if value.lower().startswith('bearer ') else f'Bearer {value}'
        return 'Authorization', token
    if auth_type == 'cookie':
        return 'Cookie', value
    if auth_type == 'basic':
        if ':' not in value:
            _log(log_prefix, "[!]{prefix} Basic auth value should be in format 'username:password'")
            return None
        return 'Authorization', 'Basic ' + base64.b64encode(value.encode()).decode()

    # header / apikey: an empty name falls back to the conventional one, but an
    # invalid one is refused rather than silently renamed.
    requested = header_name.strip() if isinstance(header_name, str) else ''
    name = sanitize_header_name(requested or _DEFAULT_HEADER_NAMES[auth_type])
    if name is None:
        _log(log_prefix, f"[!]{{prefix}} Rejected auth header name {requested[:40]!r}")
        return None
    return name, value


def build_auth_headers(profile: Optional[dict], log_prefix: Optional[str] = '[Auth]') -> Dict[str, str]:
    """Build the headers an AuthProfile contributes to a request.

    ``profile`` uses the ProjectAuthProfile field names (``authType``,
    ``authValue``, ``authHeaderName``, ``extraHeaders``). The primary auth header
    wins over an extra header of the same name. ``log_prefix=None`` is silent,
    for per-request callers.
    """
    profile = profile or {}
    headers: Dict[str, str] = {}

    auth_type = str(profile.get('authType') or '').strip().lower()
    raw_value = profile.get('authValue') or ''
    if auth_type in AUTH_TYPES and raw_value:
        primary = _primary_header(auth_type, raw_value, profile.get('authHeaderName'), log_prefix)
        if primary:
            name, value = primary
            headers[name] = value
            _log(log_prefix, f"[*]{{prefix}} Using {auth_type} authentication: "
                             f"{name} = {mask_auth_value(raw_value, auth_type)}")
    elif auth_type not in ('', 'none') and raw_value:
        _log(log_prefix, f"[!]{{prefix}} Unknown auth type: {auth_type[:40]}")

    extras = profile.get('extraHeaders') or {}
    if isinstance(extras, dict):
        taken = {n.lower() for n in headers}
        for raw_name, raw_extra in extras.items():
            name = sanitize_header_name(raw_name)
            value = sanitize_header_value(raw_extra)
            if name is None or value is None:
                _log(log_prefix, f"[!]{{prefix}} Rejected extra header {str(raw_name)[:40]!r}")
                continue
            if name.lower() in taken:
                continue
            headers[name] = value
            taken.add(name.lower())

    return headers


def _dedupe(entries: Iterable[str]) -> List[str]:
    seen: Dict[str, None] = {}
    for e in entries:
        if e:
            seen.setdefault(e, None)
    return list(seen)


def default_scope_hosts(settings: dict, extra_hosts: Iterable[str] = ()) -> List[str]:
    """Where the project's session may go (§4.6), minus RoE exclusions.

    Per scope group: an ENUMERATE group gets ``*.<scan root>`` (its strict
    subdomains, which are its attack surface: a scope covering only the root
    would silently degrade every authenticated scan once discovery found
    anything); an EXACT group gets exactly its listed hosts; either gets its
    scan root only when the root is a target. The same rule as the webapp's
    authScopePatterns and the agent's auth_scope_patterns.

    Residual risk, accepted deliberately: a discovered subdomain CNAME'd to a
    third party is in an ENUMERATE group's scope. An operator who cannot accept
    that narrows it with explicit ``scopeHosts`` on the profile.
    """
    hosts: List[str] = []
    if settings.get('IP_MODE'):
        hosts.extend(settings.get('TARGET_IPS') or [])
    else:
        from recon.helpers.batch_groups import settings_scope_groups
        for group in settings_scope_groups(settings):
            root = group['scanRoot']
            if group['mode'] == 'enumerate':
                hosts.append(f"*.{root}")
            else:
                hosts.extend(group.get('exactHosts') or [])
            if group.get('includeRoot'):
                hosts.append(root)
    hosts.extend(extra_hosts or ())

    scope = _dedupe(_normalize_scope_entry(h) for h in hosts)
    return _roe_filtered(scope, settings)


def _roe_filtered(scope: List[str], settings: dict) -> List[str]:
    if settings.get('ROE_ENABLED') and settings.get('ROE_EXCLUDED_HOSTS'):
        scope = [h for h in scope if not _is_roe_excluded(h, settings['ROE_EXCLUDED_HOSTS'])]
    return scope


def _ip_net(entry: str):
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _under(host: str, root: str) -> bool:
    return host.endswith('.' + root)


def _meet(a: str, b: str) -> Optional[str]:
    """The intersection of two scope entries, when it is one entry. ``*.x`` is
    the strict subdomains of x, so ``*.example.com`` and ``www.example.com``
    meet at the host, and ``*.example.com`` never admits ``example.com``.
    Mirrors agentic/scope_groups.py:_meet."""
    na, nb = _ip_net(a), _ip_net(b)
    if na is not None or nb is not None:
        if na is None or nb is None or na.version != nb.version:
            return None
        if na.subnet_of(nb):
            return a
        return b if nb.subnet_of(na) else None
    wa, wb = a.startswith('*.'), b.startswith('*.')
    ra, rb = (a[2:] if wa else a), (b[2:] if wb else b)
    if wa and wb:
        if ra == rb or _under(ra, rb):
            return a
        return b if _under(rb, ra) else None
    if wa:
        return b if _under(rb, ra) else None
    if wb:
        return a if _under(ra, rb) else None
    return a if a == b else None


def intersect_explicit_scope(explicit: Iterable[str], default: List[str]) -> List[str]:
    """An explicit ``scopeHosts`` only NARROWS the project's scope (D-22): the
    hosts both admit. ``*.a.example.com`` survives under ``*.example.com``; an
    explicit ``*.example.com`` on a project listing only ``www.example.com``
    leaves ``www.example.com``; a host survives only if the project admits it."""
    kept: List[str] = []
    for raw in explicit or ():
        e = _normalize_scope_entry(raw)
        if not e:
            continue
        for d in default:
            m = _meet(e, d) if d else None
            if m:
                kept.append(m)
    return _dedupe(kept)


def resolve_scope_hosts(profile: Optional[dict], settings: Optional[dict] = None,
                        extra_hosts: Iterable[str] = ()) -> List[str]:
    """The project default, narrowed by the profile's explicit ``scopeHosts``
    when set (the intersection, never a replacement), less RoE exclusions.

    An explicit entry used to REPLACE the default, so ``*.example.com`` on a
    project scoped to ``www.example.com`` sent the session to every subdomain.
    """
    settings = settings or {}
    default = default_scope_hosts(settings, extra_hosts)
    explicit = (profile or {}).get('scopeHosts') or []
    if not explicit:
        return default
    return _roe_filtered(intersect_explicit_scope(explicit, default), settings)


def host_in_scope(host, scope_hosts: Iterable[str]) -> bool:
    """Exact host, ``*.suffix`` (subdomains only, not the apex) or CIDR match."""
    h = _normalize_host(host)
    if not h:
        return False
    for entry in scope_hosts:
        if not entry:
            continue
        if entry.startswith('*.'):
            if h.endswith(entry[1:]):
                return True
        elif '/' in entry:
            try:
                if ipaddress.ip_address(h) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        elif h == entry:
            return True
    return False


def recon_enabled(profile: Optional[dict]) -> bool:
    """Whether the recon consumer gate is on (default on when absent)."""
    return bool(profile) and profile.get('reconEnabled', True) is not False


def profile_from_settings(settings: Optional[dict]) -> Optional[dict]:
    """The AuthProfile row out of a recon settings dict, or None when unusable."""
    profile = (settings or {}).get('AUTH_PROFILE')
    if not isinstance(profile, dict):
        return None
    # Independent recon consumer gate (default on). Off => recon runs anonymous.
    if not recon_enabled(profile):
        return None
    if str(profile.get('authType') or 'none').lower() == 'none':
        # An extras-only profile is still usable.
        if not (isinstance(profile.get('extraHeaders'), dict) and profile['extraHeaders']):
            return None
    return profile


def engagement_identity_header(settings: Optional[dict]) -> Optional[str]:
    """The validated ``engagementIdentityHeader`` line ("Name: value"), or None.

    One place, so every HTTP tool path gets the same answer: this is a
    mandatory-attribution header, not a credential, so it is attached
    unconditionally (no scope gate — an identity header only makes sense on
    traffic the operator wants attributed, and scope-gating it would drop it on
    exactly the out-of-scope hosts where attribution matters most). It rides
    the tool's own ``-H`` set, so it is sent identically on the direct path and
    through the capture proxy, and survives the proxy's fail-open fallback.

    Validated on write by the webapp (checkHeader) and re-validated here:
    the value crosses a DB boundary and a scan that silently sent a forged or
    split header would be worse than one that sent none. Host / Authorization /
    Cookie / Proxy-* are refused — an identity header that changes where the
    request goes or what it carries is not an identity header.
    """
    raw = (settings or {}).get('ENGAGEMENT_IDENTITY_HEADER')
    if not isinstance(raw, str) or not raw.strip():
        return None
    if _CONTROL_CHARS_RE.search(raw) or any(d in raw for d in _TOOL_JOIN_DELIMITERS):
        return None
    line = raw.strip()
    if len(line) > MAX_HEADER_VALUE_LEN + MAX_HEADER_NAME_LEN:
        return None
    if line.count(':') < 1:
        return None
    name, value = line.split(':', 1)
    name = sanitize_header_name(name)
    value = sanitize_header_value(value)
    if (not name or not value or name.lower() in _IDENTITY_FORBIDDEN_NAMES
            or name.lower().startswith('proxy-')):
        return None
    return f"{name}: {value}"


# Mirrors the webapp's checkHeader FORBIDDEN_HEADERS: names that change where
# the request goes or what it carries, plus the proxy-* family.
_IDENTITY_FORBIDDEN_NAMES = frozenset({
    'host', 'authorization', 'cookie', 'proxy-authorization',
    'x-redamon-ctx', 'content-length', 'transfer-encoding', 'connection',
})


def append_engagement_identity(headers: Optional[Iterable[str]],
                                settings: Optional[dict]) -> List[str]:
    """``headers`` plus the engagement identity line, deduplicated.

    The identity header is appended once, after any auth-session lines: if the
    operator (or a tool profile) already sends the same header name, THEIR line
    wins and ours is dropped — never sent twice, which some servers treat as a
    malformed request. Returns a new list; the input is not mutated.
    """
    out = [h for h in (headers or []) if h]
    line = engagement_identity_header(settings)
    if line:
        name = line.split(':', 1)[0].strip().lower()
        if not any(h.split(':', 1)[0].strip().lower() == name for h in out):
            out.append(line)
    return out


def merge_auth_headers(custom_headers: Optional[Iterable[str]], settings: Optional[dict],
                       hosts: Iterable[str]) -> List[str]:
    """Prepend the profile's in-scope auth lines to a tool's ``custom_headers``.

    ``hosts`` is the set the command will hit (the crawl's ``allowed_hosts`` or a
    single target). Most recon tools send ONE ``-H`` set for a whole targets file,
    so the session is attached only when EVERY host is in scope; a single
    out-of-scope host means no auth at all (fail closed), never a cross-origin
    leak. Auth lines go FIRST so a tool that packs headers into one delimited
    argument (hakrawler ``;;``, arjun ``\\n``) keeps them ahead of, and separate
    from, the ``X-Redamon-Ctx`` tag it appends last.
    """
    base = [h for h in (custom_headers or []) if h]
    profile = profile_from_settings(settings)
    hosts = [h for h in (hosts or []) if h]
    if not profile or not hosts:
        return base

    # Scope is the profile's explicit hosts or the project target hosts — never
    # the command's own hosts, or every host would trivially match itself.
    scope = resolve_scope_hosts(profile, settings or {})
    roe_on = bool((settings or {}).get('ROE_ENABLED') and (settings or {}).get('ROE_EXCLUDED_HOSTS'))
    for host in hosts:
        # Every drop is logged: an unattached session is otherwise invisible, and
        # "the scan silently ran logged-out" is the worst failure this code has.
        if not host_in_scope(host, scope):
            print(f"[!][Auth] Session NOT attached: host '{host}' is outside the auth "
                  f"scope {scope}. Add it to the project's Authenticated Session "
                  f"scope hosts to scan this host authenticated.")
            return base
        if roe_on and _is_roe_excluded(_normalize_host(host), settings['ROE_EXCLUDED_HOSTS']):
            print(f"[!][Auth] Session NOT attached: host '{host}' is RoE-excluded.")
            return base

    auth_lines = [f"{name}: {value}" for name, value in build_auth_headers(profile, log_prefix=None).items()]
    if auth_lines:
        print(f"[*][Auth] Session attached ({profile.get('authType')}) to "
              f"{len(hosts)} in-scope host(s).")
        # Drop any operator-supplied custom header the profile already sets, so
        # the profile is authoritative and the same header is not sent twice.
        profile_names = {line.split(':', 1)[0].strip().lower() for line in auth_lines}
        base = [h for h in base if h.split(':', 1)[0].strip().lower() not in profile_names]
    return auth_lines + base


def merge_auth_headers_ex(custom_headers: Optional[Iterable[str]], settings: Optional[dict],
                          hosts: Iterable[str]) -> Tuple[List[str], bool]:
    """``merge_auth_headers`` plus whether a session was actually attached.

    Callers need the flag to tighten a tool's own cross-host behaviour (httpx and
    nuclei re-send ``-H`` headers on a redirect to ANY host, so an authenticated
    run must confine them to the scope-checked host). Counting the returned lines
    cannot answer it: the merge also drops base headers the profile overrides, so
    attaching auth can leave the list the same length.
    """
    base = [h for h in (custom_headers or []) if h]
    merged = merge_auth_headers(custom_headers, settings, hosts)
    return merged, merged != base


def auth_header_lines(profile: Optional[dict], target_host, settings: Optional[dict] = None,
                      scope_hosts: Optional[Iterable[str]] = None) -> List[str]:
    """``["Name: value", ...]`` for ``target_host``, or ``[]`` when it is out of scope.

    RoE exclusions apply even to an explicitly scoped host. Fails closed: no
    resolvable scope means no auth anywhere.
    """
    settings = settings or {}
    # Recon consumer gate (default on). ai_surface_recon / graphql call this
    # directly, so honor it here too. GraphQL passes its own typed triple (no
    # reconEnabled key) -> default on, unchanged.
    if not recon_enabled(profile):
        return []
    scope = list(scope_hosts) if scope_hosts is not None else resolve_scope_hosts(profile, settings)
    if not host_in_scope(target_host, scope):
        return []
    if settings.get('ROE_ENABLED') and settings.get('ROE_EXCLUDED_HOSTS'):
        if _is_roe_excluded(_normalize_host(target_host), settings['ROE_EXCLUDED_HOSTS']):
            return []
    return [f"{name}: {value}" for name, value in build_auth_headers(profile, log_prefix=None).items()]
