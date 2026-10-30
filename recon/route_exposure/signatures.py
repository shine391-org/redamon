"""Deterministic signatures: an answer that proves the exposure by its own content.

``match`` returns the most specific signature an answer carries, or None. A
signature's evidence is a fixed description of what matched, never body text:
the body of a `.env` or a `web.config` is the secret.
"""

from __future__ import annotations

import json
import re
from typing import Optional

# kind -> (vulnerability_type, default severity), plan §6.3
KINDS = {
    "vcs_exposure": ("exposed_version_control", "high"),
    "env_file": ("exposed_env_file", "high"),
    "config_file": ("exposed_config_file", "medium"),
    "backup_file": ("exposed_backup_file", "medium"),
    "debug_console": ("exposed_debug_console", "high"),
    "debug_endpoint": ("exposed_debug_endpoint", "medium"),
    "debug_page": ("debug_error_page", "low"),
    "route_catalog": ("exposed_route_catalog", "low"),
    "secret_in_response": ("secret_exposure", "medium"),
}

#: Kinds a debug page shows at any status: a real one answers 500.
ANY_STATUS_KINDS = frozenset({"debug_page", "debug_console"})

_HEX40 = re.compile(r"^[0-9a-f]{40}\s*$")
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=", re.M)
_HG_REQUIRES = frozenset({"revlogv1", "store", "fncache", "dotencode", "generaldelta",
                          "sparserevlog", "share-safe", "revlog-compression-zstd", "persistent-nodemap"})
_SQL_MARKERS = (b"-- MySQL dump", b"-- PostgreSQL database dump", b"CREATE TABLE", b"INSERT INTO")

_DJANGO = re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>|"
                     r"DEBUG\s*=\s*True.{0,200}Django|Django Version:", re.S)
_RAILS = re.compile(r"Action Controller: Exception caught")
_ASPNET = re.compile(r"Server Error in '/' Application")
_SPRING = re.compile(r"Whitelabel Error Page")
_JAVA_TRACE = re.compile(r"\bat (?:org|com|java|javax|jakarta)\.[\w.$]+\(|java\.lang\.\w+Exception")
_PHPINFO = re.compile(r"<title>phpinfo\(\)</title>|PHP Version\s*</?t[dh]|phpinfo\(\)", re.I)
_WERKZEUG = re.compile(r"__debugger__|EVALEX\s*=|Werkzeug Debugger", re.I)
_SYMFONY = re.compile(r"Symfony Profiler|sf-toolbar|_profiler/", re.I)
_PPROF = re.compile(r"Types of profiles available|/debug/pprof/goroutine")
_SERVER_STATUS = re.compile(r"Apache Server Status for|Server uptime:.{0,200}Total accesses", re.S)
_RAILS_ROUTES = re.compile(r"Routes</h2>|Helper.{0,80}HTTP Verb.{0,80}Path", re.S)

_INTERNAL_WORDS = re.compile(r"(^|[/_.-])(internal|admin|private|debug|management)([/_.-]|$)", re.I)


def _last(path: str) -> str:
    return (path or "").rstrip("/").rsplit("/", 1)[-1].lower()


def _hit(kind: str, signature: str, evidence: str, severity: Optional[str] = None) -> dict:
    return {"kind": kind, "signature": signature, "evidence": evidence,
            "severity": severity or KINDS[kind][1]}


def _vcs(path: str, body: bytes, text: str) -> Optional[dict]:
    low = path.lower()
    if low.endswith("/.git/head"):
        head = text.strip()
        if head.startswith("ref: refs/"):
            return _hit("vcs_exposure", "git_head", "ref: " + head[5:80].split()[0])
        if _HEX40.match(head):
            return _hit("vcs_exposure", "git_head", "detached HEAD (40-hex commit id)")
    if low.endswith("/.git/config") and "[core]" in text:
        return _hit("vcs_exposure", "git_config", "[core] section of a git config")
    if low.endswith("/.svn/wc.db") and body.startswith(b"SQLite format 3"):
        return _hit("vcs_exposure", "svn_wcdb", "SQLite working-copy database")
    if low.endswith("/.svn/entries"):
        first = text.lstrip().split("\n", 1)[0].strip()
        if first.isdigit() or first == "dir":
            return _hit("vcs_exposure", "svn_entries", "svn entries file")
    if low.endswith("/.hg/requires"):
        words = {w.strip() for w in text.split("\n") if w.strip()}
        if words and words <= _HG_REQUIRES | {""} and words & _HG_REQUIRES:
            return _hit("vcs_exposure", "hg_requires", "mercurial requires file")
    return None


def _env(path: str, text: str, content_class: str) -> Optional[dict]:
    name = _last(path)
    if not (name.startswith(".env") or name.endswith(".env")) or content_class == "html":
        return None
    keys = _ENV_LINE.findall(text)
    if len(keys) >= 2:
        return _hit("env_file", "env_lines", f"{len(keys)} KEY=value line(s)")
    return None


def _config(path: str, text: str) -> Optional[dict]:
    if _last(path) == "web.config" and "<configuration" in text:
        return _hit("config_file", "web_config", "<configuration> document")
    return None


def backup_magic(body: bytes, headers: dict) -> Optional[tuple]:
    """(signature, evidence) of an archive, dump or PHP source in the first bytes."""
    if body.startswith(b"PK\x03\x04"):
        return "zip_magic", "zip archive"
    if body.startswith(b"\x1f\x8b"):
        return "gzip_magic", "gzip archive"
    if body.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z_magic", "7z archive"
    if body.startswith(b"Rar!\x1a\x07"):
        return "rar_magic", "rar archive"
    if len(body) >= 262 and body[257:262] == b"ustar":
        return "tar_magic", "tar archive"
    if any(marker in body[:1024] for marker in _SQL_MARKERS):
        return "sql_dump", "SQL dump"
    ctype = (headers.get("content-type") or "").lower()
    if b"<?php" in body[:1024] and ("text/plain" in ctype or "octet-stream" in ctype or not ctype):
        return "php_source", "PHP source served as text"
    return None


def _debug_console(path: str, text: str) -> Optional[dict]:
    if _WERKZEUG.search(text):
        return _hit("debug_console", "werkzeug_debugger", "Werkzeug interactive debugger")
    if path.lower().rstrip("/").endswith("/_ignition/health-check"):
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict) and doc.get("can_execute_commands") is True:
            return _hit("debug_console", "ignition_exec", "Laravel Ignition can_execute_commands=true")
    if "/_profiler" in path.lower() and _SYMFONY.search(text):
        return _hit("debug_console", "symfony_profiler", "Symfony profiler")
    return None


def _debug_endpoint(path: str, method: str, text: str, headers: dict) -> Optional[dict]:
    low = path.lower().rstrip("/")
    if low.endswith(("/actuator/env", "/env")) and "propertySources" in text:
        try:
            doc = json.loads(text)
            count = len(doc.get("propertySources") or []) if isinstance(doc, dict) else 0
        except ValueError:
            count = 0
        return _hit("debug_endpoint", "actuator_env",
                    f"Spring actuator env ({count} property source(s))", "high")
    if low.endswith("/actuator/heapdump") and method == "HEAD":
        ctype = (headers.get("content-type") or "").lower()
        if "octet-stream" in ctype:
            return _hit("debug_endpoint", "actuator_heapdump", "Spring actuator heap dump (HEAD)", "high")
    if "/debug/pprof" in low and _PPROF.search(text):
        return _hit("debug_endpoint", "go_pprof", "Go pprof index")
    if low.endswith("/server-status") and _SERVER_STATUS.search(text):
        return _hit("debug_endpoint", "apache_server_status", "Apache server-status page")
    return None


def _debug_page(text: str) -> Optional[dict]:
    if _DJANGO.search(text):
        return _hit("debug_page", "django_debug", "Django DEBUG=True error page")
    if _RAILS.search(text):
        return _hit("debug_page", "rails_exception", "Rails exception page")
    if _ASPNET.search(text) and "Stack Trace:" in text:
        return _hit("debug_page", "aspnet_error", "ASP.NET error page with a stack trace")
    if _SPRING.search(text) and _JAVA_TRACE.search(text):
        return _hit("debug_page", "spring_whitelabel", "Spring Whitelabel page with a stack trace")
    if _PHPINFO.search(text) and "PHP Version" in text:
        return _hit("debug_page", "phpinfo", "phpinfo() page", "medium")
    return None


def is_api_spec(text: str) -> Optional[dict]:
    """The parsed OpenAPI/Swagger document, or None."""
    stripped = text.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        doc = json.loads(stripped)
    except ValueError:
        return None
    if isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger")) and isinstance(doc.get("paths"), dict):
        return doc
    return None


def _route_catalog(path: str, text: str) -> Optional[dict]:
    low = path.lower().rstrip("/")
    if low.endswith("/actuator/mappings"):
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("contexts"), dict) and "mappings" in text:
            return _hit("route_catalog", "actuator_mappings", "Spring actuator mappings")
    if low.endswith("/rails/info/routes") and _RAILS_ROUTES.search(text):
        return _hit("route_catalog", "rails_routes", "Rails route table")
    spec = is_api_spec(text)
    if spec is not None:
        # A public API's spec is documentation. One that lists internal or
        # admin routes is a map of what the operator meant to hide.
        tags = {str(t.get("name", "")) for t in spec.get("tags") or [] if isinstance(t, dict)}
        if any(_INTERNAL_WORDS.search(p) for p in spec["paths"]) or any(
                _INTERNAL_WORDS.search(t) for t in tags):
            return _hit("route_catalog", "openapi_internal",
                        f"API specification listing internal routes ({len(spec['paths'])} path(s))")
    return None


def match(*, path: str, method: str, status: Optional[int], headers: dict, body: bytes,
          content_class: str, generated_by: str, secret_types: list) -> Optional[dict]:
    """The first signature by specificity, each only on the statuses it declares."""
    if status is None:
        return None
    text = body[:256 * 1024].decode("utf-8", "replace")
    ok = 200 <= status < 300
    hit = None
    if ok:
        hit = (_vcs(path, body, text) or _env(path, text, content_class) or _config(path, text))
    if hit is None and ok and generated_by == "backup":
        magic = backup_magic(body, headers)
        if magic:
            hit = _hit("backup_file", magic[0], magic[1])
    if hit is None:
        hit = _debug_console(path, text)
    if hit is None and ok:
        hit = _debug_endpoint(path, method, text, headers)
    if hit is None:
        hit = _debug_page(text)
    if hit is None and ok:
        hit = _route_catalog(path, text)
    if hit is None and ok and secret_types:
        hit = _hit("secret_in_response", "secret_matcher", f"{len(secret_types)} secret type(s)")
    if hit is not None and not ok and hit["kind"] not in ANY_STATUS_KINDS:
        return None
    return hit
