"""S2: routes the scan generates next to the ones recon found.

Each generator has its own setting and its own per-host cap, and marks what it
made with ``generated_by``. A generated route that recon already found is not
added again: the found one keeps its sources and hints.
"""

from __future__ import annotations

import re
from collections import Counter

from recon.route_exposure import seeds
from recon.route_exposure.harvest import Corpus, Route, has_extension

try:
    from recon.helpers.resource_enum.classification import classify_endpoint
except ImportError:  # pragma: no cover - spawned-container import shim
    from helpers.resource_enum.classification import classify_endpoint

_VERSION_SEGMENT = re.compile(r"/v(\d{1,2})(?=/)", re.I)
#: A trailing segment that identifies one item (numeric, UUID or long hex): dropping
#: it gives the collection route.
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{4,}|[0-9a-f]{12,})$")

#: Only a server-side source or configuration file is worth a backup guess; a
#: backup of a public page shows what the page already shows.
BACKUP_SOURCE_EXTENSIONS = frozenset({
    ".php", ".php5", ".phtml", ".inc", ".asp", ".aspx", ".ashx", ".asmx", ".jsp", ".jspx",
    ".do", ".action", ".cfm", ".pl", ".cgi", ".py", ".rb", ".config", ".conf", ".cfg",
    ".ini", ".yml", ".yaml", ".json", ".xml", ".properties", ".sql", ".env", ".txt",
})

#: Top-level directories that never hold a nested application's checkout.
_NOT_APP_DIRS = frozenset({"api", "static", "assets", "css", "js", "img", "images", "fonts",
                           "media", "public", "dist", "build", "vendor", "node_modules"})


def _category(path: str) -> str:
    return classify_endpoint(path.lower(), ["GET"], {})


def _route(base: str, path: str, generated_by: str, *, variant_of: str = "",
           request: str = "get") -> Route:
    return Route(baseurl=base, path=path, category=_category(path), sources=("route_exposure",),
                 generated_by=generated_by, variant_of=variant_of, request=request)


def make_route(base: str, path: str, generated_by: str, *, variant_of: str = "",
               request: str = "get") -> Route:
    """A generated route, for the scanner's probe-time generators (catalog, cross-host)."""
    return _route(base, path, generated_by, variant_of=variant_of, request=request)


def seed_paths(api_prefixes) -> list:
    """The seed list at the root, then under every API prefix the harvest saw."""
    under_prefixes = [f"{p.rstrip('/')}{s}" for p in sorted(api_prefixes or ())
                      for s in seeds.API_PREFIX_SEEDS]
    return list(dict.fromkeys([*seeds.SEED_PATHS, *under_prefixes, *seeds.LATE_SEED_PATHS]))


def _top_dirs(found: list) -> list:
    counts = Counter()
    for route in found:
        parts = [p for p in route.path.split("/") if p]
        if len(parts) >= 2 and parts[0].lower() not in _NOT_APP_DIRS and not parts[0].startswith("."):
            counts[parts[0]] += 1
    return [d for d, _ in counts.most_common()]


def vcs_paths(found: list) -> list:
    out = list(seeds.VCS_FILES)
    for directory in _top_dirs(found):
        out.extend(f"/{directory}{p}" for p in seeds.VCS_FILES)
    return out


def backup_paths(found: list) -> list:
    """(path, the file it is a backup of) pairs; root archives back up nothing."""
    out = [(p, "") for p in seeds.BACKUP_ROOT_FILES]
    for route in found:
        ext = has_extension(route.path)
        if ext not in BACKUP_SOURCE_EXTENSIONS:
            continue
        head, _, name = route.path.rpartition("/")
        for suffix in seeds.BACKUP_SUFFIXES:
            if suffix == ".swp":
                out.append((f"{head}/.{name}.swp", route.path))
            else:
                out.append((f"{route.path}{suffix}", route.path))
    return list(dict.fromkeys(out))


def version_variants(path: str) -> list:
    """`/api/v3/x` -> `/api/v2/x`, `/api/v1/x`, `/api/x` (at most 3)."""
    match = _VERSION_SEGMENT.search(path)
    if not match:
        return []
    current = int(match.group(1))
    head, tail = path[:match.start()], path[match.end():]
    out = [f"{head}/v{n}{tail}" for n in range(current - 1, 0, -1)]
    out.append(f"{head}{tail}" or "/")
    return out[:seeds.CAP_VERSION_PER_ROUTE]


def _is_api_route(route: Route) -> bool:
    """An API route (plan §5.2: siblings come from API routes only): an /api or a
    version segment, or classified api. A page or a JS-named path is not one."""
    segs = [s.lower() for s in route.path.split("/") if s]
    return "api" in segs or route.category == "api" or bool(_VERSION_SEGMENT.search(route.path))


def siblings(path: str) -> list:
    """Sibling routes of an API path (plan §5.2): the collection (a trailing id dropped),
    its /export, /all and /list leaves, admin/internal inserted after an /api prefix, and
    an /internal or /private prefix. The source path itself is never returned."""
    trimmed = (path or "/").rstrip("/") or "/"
    segs = [s for s in trimmed.split("/") if s]
    out: list = []
    if len(segs) >= 2 and _ID_SEGMENT.match(segs[-1]):
        collection = "/" + "/".join(segs[:-1])
        out.append(collection)
        leaf_base = collection
    else:
        leaf_base = trimmed
    out.extend(leaf_base.rstrip("/") + suffix for suffix in seeds.SIBLING_LEAF_SUFFIXES)
    if segs and segs[0] == "api":
        rest = "/".join(segs[1:])
        out.extend(f"/api/{seg}" + (f"/{rest}" if rest else "") for seg in seeds.SIBLING_INSERT_SEGMENTS)
    out.extend(prefix + trimmed for prefix in seeds.SIBLING_PREFIXES)
    return [p for p in dict.fromkeys(out) if p and p != trimmed]


def framework_paths(technologies) -> list:
    """(path, head_only) pairs for the frameworks named in a host's technology set."""
    toks: set = set()
    for tech in technologies or ():
        toks.update(seeds.tokens(tech))
    out: list = []
    for key, paths in seeds.FRAMEWORK_SEEDS.items():
        parts = key.split(".")
        if key in toks or key.replace(".", "") in toks or (len(parts) > 1 and all(p in toks for p in parts)):
            out.extend((p, p in seeds.FRAMEWORK_HEAD_ONLY) for p in paths)
    return list(dict.fromkeys(out))


def generate(corpus: Corpus, cfg: dict) -> list:
    """The generated routes (v1 generators), each host capped per generator."""
    known = set(corpus.routes)
    made: list = []

    def add(route: Route) -> bool:
        if route.key in known:
            return False
        known.add(route.key)
        if corpus.add(route):
            made.append(route)
            return True
        return False

    by_base: dict = {}
    for route in corpus.routes.values():
        by_base.setdefault(route.baseurl, []).append(route)
    for base in corpus.bases:
        found = [r for r in by_base.get(base, []) if r.generated_by == "found"]
        if cfg.get("seed_paths"):
            _capped(add, base, seed_paths(corpus.api_prefixes.get(base)), "seed", seeds.CAP_SEED)
        if cfg.get("vcs_files"):
            _capped(add, base, vcs_paths(found), "vcs", seeds.CAP_VCS)
        if cfg.get("backup_files"):
            _capped(add, base, backup_paths(found), "backup", seeds.CAP_BACKUP, request="backup")
    if cfg.get("version_variants"):
        for route in list(by_base.values()):
            for found in route:
                if found.generated_by != "found":
                    continue
                for path in version_variants(found.path):
                    add(_route(found.baseurl, path, "version", variant_of=found.path))
    if cfg.get("siblings"):
        for base in corpus.bases:
            taken = 0
            for found in [r for r in by_base.get(base, []) if r.generated_by == "found" and _is_api_route(r)]:
                per_route = 0
                for path in siblings(found.path):
                    if taken >= seeds.CAP_SIBLING_PER_HOST or per_route >= seeds.CAP_SIBLING_PER_ROUTE:
                        break
                    if add(_route(base, path, "sibling", variant_of=found.path)):
                        taken += 1
                        per_route += 1
    if cfg.get("framework_seeds"):
        for base in corpus.bases:
            taken = 0
            for path, head_only in framework_paths(corpus.technologies.get(base)):
                if taken >= seeds.CAP_FRAMEWORK:
                    break
                if add(_route(base, path, "framework", request="head" if head_only else "get")):
                    taken += 1
    return made


def _capped(add, base: str, paths: list, generated_by: str, cap: int, *, request: str = "get") -> None:
    taken = 0
    for item in paths:
        if taken >= cap:
            return
        path, variant_of = item if isinstance(item, tuple) else (item, "")
        if add(_route(base, path, generated_by, variant_of=variant_of, request=request)):
            taken += 1
