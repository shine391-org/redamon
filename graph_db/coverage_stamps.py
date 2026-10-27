"""Per-host, per-module coverage stamps on BaseURL nodes (plan 09.1).

A recon module that works per web host stamps every BaseURL it considered, as
flat properties (a property cannot hold a map):

  <module>_at       when the module's run started
  <module>_status   complete | partial | no_input | failed
  <module>_inputs   what it had for that host: JS files read, URLs scanned
  <module>_outputs  findings it reported for that host
  <module>_reason   why the status is not complete; absent when it is

A BaseURL the module never considered carries no stamp, and that absence is
what "not scanned" means - but only in a project where the module stamped some
other host. A project scanned before stamps existed has none at all, and a
reader says "coverage not recorded" there, never "not scanned".

The rows come from recon (recon/helpers/coverage_stamps.py builds them).
"""
from datetime import datetime, timezone
from urllib.parse import urlsplit

#: The modules that stamp, in display order. The webapp keeps its own copy
#: (webapp/src/lib/coverageStamps.ts); tests/test_coverage_stamps_parity.py
#: holds the two together.
COVERAGE_MODULES = ("js_recon", "nuclei")
COVERAGE_STATUSES = ("complete", "partial", "no_input", "failed")
COVERAGE_FIELDS = ("at", "status", "inputs", "outputs", "reason")
COVERAGE_PROPERTIES = tuple(f"{m}_{f}" for m in COVERAGE_MODULES for f in COVERAGE_FIELDS)

_DEFAULT_PORTS = {"http": 80, "https": 443}

_LABELS = {"js_recon": "JS Recon", "nuclei": "Nuclei"}
_BUCKETS = (*COVERAGE_STATUSES, "not_scanned")


def _count(module: str, bucket: str) -> str:
    # A live host is one http_probe answered (it rewrites `source` on every
    # write); a module that left it unstamped never looked at it.
    test = (f"bu.{module}_status IS NULL AND bu.source = 'http_probe'" if bucket == "not_scanned"
            else f"bu.{module}_status = '{bucket}'")
    return f"sum(CASE WHEN {test} THEN 1 ELSE 0 END) AS {module}_{bucket}"


#: Per module, how many of the project's BaseURLs sit in each status, and how
#: many live ones carry no stamp. Fixed and server-side, with the tenant filter
#: written by hand like the label census; counts only, never a URL.
COVERAGE_SUMMARY_CYPHER = (
    "MATCH (bu:BaseURL {user_id: $tenant_user_id, project_id: $tenant_project_id}) "
    "RETURN " + ", ".join(_count(m, b) for m in COVERAGE_MODULES for b in _BUCKETS)
)


def coverage_summary(row) -> dict:
    """``{module: {"recorded": True, <status>: n, "not_scanned": n}}`` from one
    COVERAGE_SUMMARY_CYPHER row. A module no BaseURL carries a stamp for is
    ``{"recorded": False}`` and claims no count: its hosts are not "not
    scanned", the project predates the stamps or never ran the module."""
    row = row or {}
    out = {}
    for module in COVERAGE_MODULES:
        counts = {b: int(row.get(f"{module}_{b}") or 0) for b in _BUCKETS}
        if any(counts[s] for s in COVERAGE_STATUSES):
            out[module] = {"recorded": True, **counts}
        else:
            out[module] = {"recorded": False}
    return out


def coverage_summary_lines(summary: dict) -> list:
    """The coverage_summary as text, one line per module."""
    lines = []
    for module in COVERAGE_MODULES:
        c = summary.get(module) or {"recorded": False}
        if not c.get("recorded"):
            lines.append(f"  {_LABELS[module]}: coverage not recorded (scanned before coverage stamps "
                         f"existed, or never run)")
            continue
        lines.append(f"  {_LABELS[module]}: {c['complete']} complete, {c['partial']} partial, "
                     f"{c['no_input']} no input, {c['failed']} failed; "
                     f"{c['not_scanned']} live hosts not scanned")
    return lines


def base_url_variants(url: str) -> list:
    """The spellings one web service's ``BaseURL.url`` can have: as given, and
    with its scheme's default port added or dropped. ``[]`` when not http(s)."""
    try:
        parts = urlsplit(str(url or "").strip())
        port = parts.port
    except ValueError:
        return []
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in _DEFAULT_PORTS or not host:
        return []
    if ":" in host:
        host = f"[{host}]"
    default = _DEFAULT_PORTS[scheme]
    bare, explicit = f"{scheme}://{host}", f"{scheme}://{host}:{default}"
    if port is None:
        return [bare, explicit]
    if port == default:
        return [explicit, bare]
    return [f"{scheme}://{host}:{port}"]


def stamp_base_url_coverage(session, module: str, coverage: dict, user_id: str, project_id: str,
                            in_scope=None) -> int:
    """Stamp ``coverage = {"at", "hosts": {base_url: row}}`` on this tenant's
    existing BaseURLs; returns how many were stamped.

    MATCH, never MERGE: a stamp describes a host some writer already put in
    the graph, it never creates one. ``in_scope(hostname)`` drops a row the
    caller's scope does not cover. The module name is interpolated into the
    property names, so it must be one of COVERAGE_MODULES.
    """
    if module not in COVERAGE_MODULES:
        raise ValueError(f"unknown coverage module {module!r}")
    rows = []
    for url, row in ((coverage or {}).get("hosts") or {}).items():
        if not isinstance(row, dict) or row.get("status") not in COVERAGE_STATUSES:
            continue
        urls = base_url_variants(url)
        if not urls or (in_scope is not None and not in_scope(urlsplit(urls[0]).hostname or "")):
            continue
        rows.append({
            "urls": urls,
            "status": row["status"],
            "inputs": int(row.get("inputs") or 0),
            "outputs": int(row.get("outputs") or 0),
            "reason": str(row["reason"])[:200] if row.get("reason") else None,
        })
    if not rows:
        return 0
    at = (coverage or {}).get("at") or datetime.now(timezone.utc).isoformat()
    record = session.run(
        f"""
        UNWIND $rows AS row
        UNWIND row.urls AS url
        MATCH (bu:BaseURL {{url: url, user_id: $uid, project_id: $pid}})
        SET bu.{module}_at = datetime($at),
            bu.{module}_status = row.status,
            bu.{module}_inputs = row.inputs,
            bu.{module}_outputs = row.outputs,
            bu.{module}_reason = row.reason
        RETURN count(bu) AS stamped
        """,
        rows=rows, at=at, uid=user_id, pid=project_id,
    ).single()
    return int((record or {}).get("stamped", 0) or 0)
