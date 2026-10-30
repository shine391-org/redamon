"""S4 follow-up (v2): read the routes an open catalog lists.

When a probe finds an open route catalog - a Spring ``/actuator/mappings``
document, an anonymously served OpenAPI / Swagger spec, or a Rails
``/rails/info/routes`` page - this parses the routes it names so the scan can
request them once more (one round only, in the scanner). Concrete paths only, so
a templated route (``/users/{id}``) is skipped like the harvest skips it. Every
parser is best-effort and never raises.
"""

from __future__ import annotations

import json
import re
from typing import Optional

#: A path segment that is a parameter placeholder, so the route is not concrete.
_TEMPLATE = re.compile(r"[{:*]|\(\.")
_RAILS_PATH = re.compile(r'(/[A-Za-z0-9._~/-]*)')


def _concrete(path: str) -> Optional[str]:
    """A normalised concrete path, or None for a templated or junk one."""
    if not path or not path.startswith("/"):
        return None
    path = path.split("?", 1)[0].split("#", 1)[0]
    if _TEMPLATE.search(path):
        return None
    cleaned = re.sub(r"/+", "/", path).rstrip("/") or "/"
    return cleaned if len(cleaned) <= 256 else None


def _from_actuator_mappings(doc: dict) -> list:
    out: list = []
    contexts = doc.get("contexts")
    if not isinstance(contexts, dict):
        return out
    for ctx in contexts.values():
        mappings = (ctx or {}).get("mappings") if isinstance(ctx, dict) else None
        servlets = (mappings or {}).get("dispatcherServlets") if isinstance(mappings, dict) else None
        if not isinstance(servlets, dict):
            continue
        for handlers in servlets.values():
            for handler in handlers if isinstance(handlers, list) else []:
                details = (handler or {}).get("details") if isinstance(handler, dict) else None
                conds = (details or {}).get("requestMappingConditions") if isinstance(details, dict) else None
                patterns = (conds or {}).get("patterns") if isinstance(conds, dict) else None
                for pat in patterns if isinstance(patterns, list) else []:
                    out.append(str(pat))
    return out


def _from_openapi(doc: dict) -> list:
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    base = ""
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base = str(servers[0].get("url") or "")
        base = re.sub(r"^https?://[^/]+", "", base).rstrip("/")
    elif isinstance(doc.get("basePath"), str):
        base = doc["basePath"].rstrip("/")
    return [base + str(p) for p in paths]


def _from_rails(body: str) -> list:
    out: list = []
    for line in body.splitlines():
        if "/" not in line:
            continue
        for match in _RAILS_PATH.findall(line):
            # The static head of a Rails URI pattern: stop at the first parameter.
            head = re.split(r"[:*(]", match)[0]
            if head and head != "/":
                out.append(head)
    return out


def parse(body: bytes, content_type: str) -> list:
    """The concrete, deduplicated paths an open catalog lists. Never raises."""
    text = (body or b"")[:1024 * 1024].decode("utf-8", "replace")
    found: list = []
    doc = None
    if "json" in (content_type or "").lower() or text.lstrip()[:1] in "{[":
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            doc = None
    if isinstance(doc, dict):
        if "contexts" in doc:
            found += _from_actuator_mappings(doc)
        if "paths" in doc:
            found += _from_openapi(doc)
    if not found and "rails" in (content_type or "").lower() or ("/rails/info" in text):
        found += _from_rails(text)
    out: list = []
    for path in found:
        concrete = _concrete(path)
        if concrete and concrete not in out:
            out.append(concrete)
    return out
