"""Static data of the route exposure scan: what it generates and what it never requests.

Every list here is data, not logic. The seed paths are the union of the lists
recon already keeps for admin and debug surfaces (js_recon's admin/debug paths,
classify_endpoint's and ffuf's admin indicators) plus the internal prefixes an
unauthenticated internal API usually hides under.
"""

from __future__ import annotations

import re

try:
    from recon.helpers.js_recon.endpoints import _ADMIN_DEBUG_PATHS, _AUTH_PATHS
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.js_recon.endpoints import _ADMIN_DEBUG_PATHS, _AUTH_PATHS

# classify_endpoint's admin patterns and ffuf's admin indicators, as paths.
_CLASSIFY_ADMIN = ("/admin", "/dashboard", "/panel", "/manage", "/control", "/backend",
                   "/cms", "/wp-admin", "/administrator")
_FFUF_ADMIN = ("/admin", "/dashboard", "/manager", "/cpanel", "/wp-admin", "/console",
               "/panel", "/control", "/backend")
INTERNAL_PREFIXES = ("/internal", "/api/internal", "/private", "/_internal", "/system",
                     "/api/system", "/admin/api", "/api/admin", "/v1/admin")

# An internal API is rarely its bare prefix: the leaves an admin or internal
# router exposes most often are requested under the prefixes that carry them,
# the two commonest first.
ADMIN_LEAF_PREFIXES = ("/api/admin", "/internal")
LATE_LEAF_PREFIXES = ("/api/internal", "/admin/api")
ADMIN_LEAVES = ("users", "export", "roles", "audit", "logs", "stats")

# Requested again under each API prefix the harvest saw (/api, /api/v1, /v2 ...).
API_PREFIX_SEEDS = ("/admin", "/internal", "/private", "/debug")

#: Well-known debug pages js_recon's list names without their file name.
_DEBUG_FILES = ("/phpinfo.php",)


def _paths(*groups) -> tuple:
    return tuple(dict.fromkeys(p.rstrip("/") or "/" for group in groups for p in group))


SEED_PATHS = _paths(
    INTERNAL_PREFIXES,
    [f"{p}/{leaf}" for p in ADMIN_LEAF_PREFIXES for leaf in ADMIN_LEAVES],
    _ADMIN_DEBUG_PATHS, _DEBUG_FILES, _CLASSIFY_ADMIN, _FFUF_ADMIN,
)
#: Requested after SEED_PATHS and the API-prefix seeds, when the per-host cap
#: still has room.
LATE_SEED_PATHS = tuple(p for p in _paths(
    [f"{p}/{leaf}" for p in LATE_LEAF_PREFIXES for leaf in ADMIN_LEAVES]) if p not in SEED_PATHS)

#: Requested at each base URL and under each discovered top-level directory.
VCS_FILES = ("/.git/HEAD", "/.git/config", "/.svn/entries", "/.svn/wc.db", "/.hg/requires",
             "/.env", "/.env.local", "/.env.production", "/.env.bak", "/web.config")
VCS_DIRS = ("/.git/", "/.svn/", "/.hg/")

#: Appended to a harvested file (`.swp` is the editor's `.<name>.swp` beside it).
BACKUP_SUFFIXES = (".bak", "~", ".old", ".orig", ".save", ".swp", ".dist")
BACKUP_ROOT_FILES = ("/backup.zip", "/backup.tar.gz", "/site.zip", "/db.sql", "/dump.sql",
                     "/database.sql")

#: Per-host caps of each generator (plan §5.2).
CAP_SEED = 60
CAP_VCS = 30
CAP_BACKUP = 40
CAP_VERSION_PER_ROUTE = 3
# v2 caps.
CAP_SIBLING_PER_ROUTE = 6
CAP_SIBLING_PER_HOST = 100
CAP_FRAMEWORK = 30
CAP_CROSS_HOST = 50
CAP_CATALOG_ROUTES = 500

#: v2 sibling generators appended to a harvested API route. The collection and the
#: list/all/export leaves are the siblings most likely to answer where one item does.
SIBLING_LEAF_SUFFIXES = ("/export", "/all", "/list")
#: Inserted right after the API prefix (/api/<x> -> /api/admin/<x>, /api/internal/<x>).
SIBLING_INSERT_SEGMENTS = ("admin", "internal")
#: Prefixed to a harvested route (/x -> /internal/x, /private/x).
SIBLING_PREFIXES = ("/internal", "/private")

#: v2 framework seeds, keyed by a lowercase technology token the host fingerprint
#: carries. The heap dump is HEAD-only (a GET streams 50 MB); `generators` marks it.
FRAMEWORK_SEEDS = {
    "spring": ("/actuator", "/actuator/env", "/actuator/mappings", "/actuator/configprops",
               "/actuator/heapdump"),
    "django": ("/admin/",),
    "laravel": ("/telescope", "/horizon", "/_ignition/health-check"),
    "rails": ("/rails/info/routes",),
    "go": ("/debug/pprof/", "/debug/vars"),
    "asp.net": ("/elmah.axd", "/trace.axd"),
    "dotnet": ("/elmah.axd", "/trace.axd"),
    "php": ("/phpinfo.php", "/info.php"),
    "apache": ("/server-status",),
}
#: Framework paths read with HEAD only (never a full GET): large or streaming bodies.
FRAMEWORK_HEAD_ONLY = frozenset({"/actuator/heapdump"})

#: Never requested, and never generated a backup variant for: public assets.
STATIC_EXTENSIONS = frozenset({
    ".css", ".js", ".mjs", ".cjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".avif", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".wav", ".ogg",
})

#: Matched as whole tokens of a path segment, so `sendgrid` or `payload` stay
#: requestable while `/account/reset` and `/orders/42/cancel` never are.
STATE_CHANGING_TOKENS = frozenset(
    "logout signout delete remove destroy reset unsubscribe cancel revoke disable "
    "deactivate purge flush shutdown restart reboot kill drop truncate wipe approve "
    "transfer send invite pay checkout".split()
)

AUTH_PATHS = tuple(_AUTH_PATHS)

#: Segment words that say a route is meant for privileged callers (+2 each, once).
STRONG_PATH_WORDS = frozenset(
    "internal private admin actuator debug management manage system config export "
    "backup dump metrics".split()
)

#: Segment words of user-uploaded files: a file there is somebody's document.
UPLOAD_DIR_WORDS = frozenset("uploads upload attachments attachment files documents docs "
                             "media invoices invoice private".split())

_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])")


def tokens(text: str) -> list:
    """Lower-cased words of a path segment or key, split on separators and camelCase."""
    return [t.lower() for t in _SPLIT_RE.split(text or "") if t]
