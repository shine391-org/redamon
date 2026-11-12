"""Pre-download JS fetch admission, provenance and a context-isolated parse cache.

js_recon downloads JS files and then parses them. Two costs sit in front of the
analysis and are paid blindly:

* a URL is fetched because some source named it, with no record of WHY it was
  named. A crawler that observed the file, a ``sourceMappingURL`` the file
  itself declares, a chunk reference found inside another bundle, and a bare
  string a regex pulled out of minified code are all treated alike.
* the same bytes are parsed once per URL that served them. Two origins serving
  an identical bundle, or one bundle reached by two names, pay the analyzers
  twice, and a relative endpoint inside it is resolved against whichever URL
  happened to be parsed first.

This module is the admission layer in front of the download and the cache
behind the parse. It is evidence-only: it never decides what is discovered and
never drops a candidate silently.

Provenance is the axis. Every candidate carries the strongest evidence that
produced it:

``observed_app_js``         a crawler or probe observed the URL as a JS file
``content_type_exception``  no JS extension, but http_probe saw a JS media type
``dynamic_import``          a chunk/import reference found inside JS content
``source_map``              a sourceMappingURL comment/header, or a probe path
                            guessed from an observed JS URL
``candidate_string``        a bare string with no evidence chain

``candidate_string`` is the only class the planner defers, and it defers it
with a reason rather than dropping it: a string with no provenance is not
evidence that the file exists, and fetching it is how a bundle's debug
commentary becomes target traffic. The other four are admitted, ranked by how
much evidence backs them, and a candidate beyond the file budget is deferred
with reason ``file_budget`` rather than cut silently.

The cache is content-addressed and context-isolated. The key is the SHA-256 of
the bytes; the context is a hash of tenant/project/auth-reference, never a
header value. The cached value is the context-free part of the parse (the
references the content itself makes); resolution against an origin, a base or
an auth representation happens per lookup, so identical bytes served from two
origins still resolve their own relative endpoints. Authenticated content is
never reused under another tenant, project or auth context.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse

from recon.helpers import circuit_breaker as _cb
from recon.helpers.js_recon.urls import js_url_kind


class Provenance(str, Enum):
    """The evidence chain that produced a fetch candidate."""

    OBSERVED_APP_JS = "observed_app_js"
    CONTENT_TYPE_EXCEPTION = "content_type_exception"
    DYNAMIC_IMPORT = "dynamic_import"
    SOURCE_MAP = "source_map"
    CANDIDATE_STRING = "candidate_string"


#: Fetch order: the most-evidenced class first. A guessed probe path is still
#: admitted (it is derived from an observed file, not from nothing), but it
#: comes after every class that names the file directly.
PROVENANCE_RANK: Dict[Provenance, int] = {
    Provenance.OBSERVED_APP_JS: 0,
    Provenance.CONTENT_TYPE_EXCEPTION: 1,
    Provenance.DYNAMIC_IMPORT: 2,
    Provenance.SOURCE_MAP: 3,
    Provenance.CANDIDATE_STRING: 4,
}

#: A bare string with no provenance is deferred for this reason.
NO_PROVENANCE = "no_provenance"
#: A candidate beyond the file budget is deferred for this reason.
FILE_BUDGET = "file_budget"


@dataclass(frozen=True)
class FetchCandidate:
    """One URL considered for download, with the evidence that produced it."""

    url: str
    provenance: Provenance
    source_ref: str = ""
    reason: str = ""
    evidence: Tuple[Tuple[str, Any], ...] = ()

    def evidence_dict(self) -> Dict[str, Any]:
        return dict(self.evidence)


def classify_candidate(
    url: str,
    *,
    observed_app_js: bool = False,
    served_js: bool = False,
    from_dynamic_import: bool = False,
    from_source_map: bool = False,
    source_ref: str = "",
    reason: str = "",
) -> FetchCandidate:
    """Assign the strongest provenance the evidence supports.

    ``observed_app_js`` wins: a crawler or probe saw the file, which is
    stronger than any inference from its name or its content type. A JS media
    type on a URL whose name does not say JS is a content-type exception. A
    chunk reference from inside another bundle is a dynamic import. A
    sourceMappingURL comment/header, or a probe path guessed from an observed
    file, is source-map provenance. Anything else is a bare string.
    """
    if not isinstance(url, str) or not url.strip():
        return FetchCandidate(
            url="", provenance=Provenance.CANDIDATE_STRING,
            reason=reason or NO_PROVENANCE,
        )
    if observed_app_js:
        provenance = Provenance.OBSERVED_APP_JS
    elif served_js and not js_url_kind(url):
        provenance = Provenance.CONTENT_TYPE_EXCEPTION
    elif from_dynamic_import:
        provenance = Provenance.DYNAMIC_IMPORT
    elif from_source_map:
        provenance = Provenance.SOURCE_MAP
    else:
        provenance = Provenance.CANDIDATE_STRING
        reason = reason or NO_PROVENANCE
    return FetchCandidate(
        url=url.strip(), provenance=provenance, source_ref=source_ref or "",
        reason=reason or "",
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


@dataclass
class FetchMetrics:
    """The fetch-stage counters, kept apart so a reduction is provable.

    ``candidates`` counts every URL considered; ``admitted``/``deferred`` are
    its disjoint split; ``download_attempts`` counts real HTTP requests (a
    cache hit is not an attempt); ``bytes_downloaded`` is the bytes those
    requests returned; ``parses`` counts analyzer runs over distinct content;
    ``extracted`` counts endpoint findings handed to validation; ``admitted``
    in the plan sense is the number of candidates the planner would fetch.
    """

    candidates: int = 0
    admitted: int = 0
    deferred: int = 0
    download_attempts: int = 0
    download_skipped_cache: int = 0
    bytes_downloaded: int = 0
    parses: int = 0
    parse_skipped_cache: int = 0
    extracted: int = 0
    retries: int = 0
    by_provenance: Dict[str, int] = field(default_factory=dict)
    by_defer_reason: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "candidates": self.candidates,
            "admitted": self.admitted,
            "deferred": self.deferred,
            "download_attempts": self.download_attempts,
            "download_skipped_cache": self.download_skipped_cache,
            "bytes_downloaded": self.bytes_downloaded,
            "parses": self.parses,
            "parse_skipped_cache": self.parse_skipped_cache,
            "extracted": self.extracted,
            "retries": self.retries,
            "by_provenance": dict(sorted(self.by_provenance.items())),
            "by_defer_reason": dict(sorted(self.by_defer_reason.items())),
        }


# ---------------------------------------------------------------------------
# Outcomes: evidence, never a confirmed absence
# ---------------------------------------------------------------------------


@dataclass
class FetchOutcome:
    """What one fetch attempt saw.

    A timeout, a challenge, a 404 and a transport error are EVIDENCE about the
    exchange, not proof that the file is absent. ``confirmed_absence`` is
    therefore always False: the pipeline records the response and moves on,
    and a later phase (or a human) decides what the evidence means.
    """

    url: str
    status: str
    status_code: Optional[int] = None
    reason: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    retries: int = 0
    content: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def confirmed_absence(self) -> bool:
        """No transport outcome confirms absence. A 404 is a response, and a
        timeout or a challenge is not even that."""
        return False

    @property
    def ok(self) -> bool:
        return self.status == "ok"


#: Statuses worth another attempt, and the bound on those attempts. A 404 is
#: not retried: it is an answer, not a transport failure.
RETRYABLE = frozenset({"timeout", "challenge", "unreachable"})
MAX_RETRIES = 2


def should_retry(outcome: FetchOutcome, attempt: int, max_retries: int = MAX_RETRIES) -> bool:
    """Bounded retry: only transport failures, only up to ``max_retries``."""
    return outcome.status in RETRYABLE and attempt < max_retries


# ---------------------------------------------------------------------------
# Content-addressed, context-isolated parse cache
# ---------------------------------------------------------------------------


def content_hash(content: Any) -> str:
    """SHA-256 of the exact bytes. Equal content, equal key."""
    if isinstance(content, str):
        content = content.encode("utf-8", "replace")
    elif isinstance(content, (bytes, bytearray)):
        content = bytes(content)
    else:
        content = str(content).encode("utf-8", "replace")
    return hashlib.sha256(content).hexdigest()


def context_key(*, tenant: str = "", project_id: str = "", auth_ref: str = "") -> str:
    """A cache-context key that can never carry a credential.

    ``auth_ref`` is a profile id/name or ``"anonymous"`` — the same reference
    the discovery inventory already stores — never a header value or a token.
    """
    material = "|".join([str(tenant or ""), str(project_id or ""), str(auth_ref or "")])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class ContentParseCache:
    """Content-addressed parse cache, isolated per tenant/project/auth context.

    The stored value is the context-free part of a parse: the references the
    content itself makes. Origin/base/auth resolution is applied by the caller
    at lookup time, so the cache never flattens two serving contexts into one.
    """

    def __init__(self, context: str = ""):
        self.context = context or ""
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.parses = 0
        self.hits = 0

    def lookup(self, digest: str) -> Optional[Any]:
        with self._lock:
            entry = self._entries.get(digest)
            if entry is None or entry.get("context") != self.context:
                return None
            self.hits += 1
            return entry.get("parsed")

    def store(self, digest: str, parsed: Any) -> None:
        with self._lock:
            self.parses += 1
            self._entries[digest] = {"context": self.context, "parsed": parsed}

    def get(self, digest: str, parse_fn: Callable[[], Any]) -> Tuple[Any, bool]:
        """``(parsed, parsed_now)``; ``parsed_now`` False on a cache hit."""
        cached = self.lookup(digest)
        if cached is not None:
            return cached, False
        parsed = parse_fn()
        self.store(digest, parsed)
        return parsed, True

    def stats(self) -> Dict[str, int]:
        return {"parses": self.parses, "hits": self.hits, "entries": len(self._entries)}


class DownloadCache:
    """URL-addressed fetch cache for one run, isolated by the same context.

    The content-addressed parse cache avoids re-PARSING; this one avoids
    re-DOWNLOADING a URL the run already fetched. A hit is a real HTTP request
    saved, which is the fetch-stage reduction the metrics report.
    """

    def __init__(self, context: str = ""):
        self.context = context or ""
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.hits = 0

    def lookup(self, url: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._entries.get(url)
            if entry is None or entry.get("context") != self.context:
                return None
            self.hits += 1
            return entry.get("record")

    def store(self, url: str, record: Dict[str, Any]) -> None:
        with self._lock:
            self._entries[url] = {"context": self.context, "record": record}

    def stats(self) -> Dict[str, int]:
        return {"hits": self.hits, "entries": len(self._entries)}


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


@dataclass
class FetchPlan:
    planned: List[FetchCandidate]
    deferred: List[FetchCandidate]
    by_host: Dict[str, Dict[str, int]]
    metrics: FetchMetrics


def _host_key(url: str) -> str:
    return _cb.host_key(url) or url


def plan_fetches(
    candidates: Sequence[FetchCandidate],
    max_files: int,
    metrics: Optional[FetchMetrics] = None,
    key: Optional[Callable[[FetchCandidate], Any]] = None,
) -> FetchPlan:
    """Split candidates into an admission order and a deferred list.

    No-provenance strings are deferred with their reason and never fetched.
    The rest are ranked by provenance, then taken round-robin by host so one
    large site cannot take the whole budget; a candidate beyond the budget is
    deferred with reason ``file_budget``, not dropped.

    ``key`` orders candidates within each host (default: provenance rank,
    then URL). The legacy planner's per-host order is ``_js_fetch_rank``;
    passing it keeps the admission selection's fetch order identical to the
    previous behaviour when provenance does not reorder a host's queue.
    """
    metrics = metrics if metrics is not None else FetchMetrics()
    metrics.candidates += len(candidates)
    sort_key = key or (lambda c: (PROVENANCE_RANK.get(c.provenance, 9), c.url))

    admitted: List[FetchCandidate] = []
    deferred: List[FetchCandidate] = []
    for candidate in candidates:
        if candidate.provenance is Provenance.CANDIDATE_STRING:
            reason = candidate.reason or NO_PROVENANCE
            deferred.append(
                FetchCandidate(
                    url=candidate.url, provenance=candidate.provenance,
                    source_ref=candidate.source_ref, reason=reason,
                    evidence=candidate.evidence,
                )
            )
            metrics.deferred += 1
            metrics.by_defer_reason[reason] = metrics.by_defer_reason.get(reason, 0) + 1
            continue
        admitted.append(candidate)
        metrics.admitted += 1
        prov_key = candidate.provenance.value
        metrics.by_provenance[prov_key] = metrics.by_provenance.get(prov_key, 0) + 1

    # Round-robin by host; within a host, the provided key orders the queue.
    queues: Dict[str, List[FetchCandidate]] = {}
    for candidate in admitted:
        queues.setdefault(_host_key(candidate.url), []).append(candidate)
    for host_files in queues.values():
        host_files.sort(key=sort_key)

    budget = max(0, int(max_files))
    selected: List[FetchCandidate] = []
    taken: Dict[str, int] = {host: 0 for host in queues}
    hosts = sorted(queues)
    while len(selected) < budget:
        progressed = False
        for host in hosts:
            if len(selected) >= budget:
                break
            if taken[host] < len(queues[host]):
                selected.append(queues[host][taken[host]])
                taken[host] += 1
                progressed = True
        if not progressed:
            break

    for host in hosts:
        cut = len(queues[host]) - taken[host]
        if cut > 0:
            for candidate in queues[host][taken[host]:]:
                deferred.append(
                    FetchCandidate(
                        url=candidate.url, provenance=candidate.provenance,
                        source_ref=candidate.source_ref, reason=FILE_BUDGET,
                        evidence=candidate.evidence,
                    )
                )
                metrics.deferred += 1
                metrics.by_defer_reason[FILE_BUDGET] = \
                    metrics.by_defer_reason.get(FILE_BUDGET, 0) + 1

    by_host = {
        host: {
            "candidates": len(queues[host]),
            "selected": taken[host],
            "cut": len(queues[host]) - taken[host],
        }
        for host in hosts
    }
    return FetchPlan(planned=selected, deferred=deferred, by_host=by_host, metrics=metrics)


# ---------------------------------------------------------------------------
# Cached endpoint extraction: parse once, resolve per context
# ---------------------------------------------------------------------------


def _parse_representative(files: Sequence[dict], settings: dict,
                          parse_fn: Callable[[Sequence[dict], dict], List[dict]]) -> List[dict]:
    """Parse one copy of a content group, leaving ``source_js`` blank.

    The stored value carries the content's own references (relative literals
    included). The per-file resolution happens in ``_resolve_for_file``.
    """
    representative = dict(files[0])
    representative["url"] = ""
    return parse_fn([representative], settings)


def _resolve_for_file(parsed: Sequence[dict], js_file: dict) -> List[dict]:
    """Clone a cached parse for one serving URL.

    Relative references are resolved against THIS file's URL, so the same bytes
    served from two origins yield two correctly-resolved endpoint sets. The
    clone keeps the content-derived id, which lets the graph merge collapse a
    finding that really is the same path.
    """
    source_url = js_file.get("url", "") or ""
    out: List[dict] = []
    for endpoint in parsed:
        clone = dict(endpoint)
        clone["source_js"] = source_url
        full_url = clone.get("full_url") or ""
        if full_url and not full_url.startswith(("http://", "https://", "data:")):
            try:
                clone["resolved_url"] = urljoin(source_url, full_url) if source_url else full_url
            except ValueError:
                clone["resolved_url"] = full_url
        out.append(clone)
    return out


def extract_endpoints_cached(
    js_files: Sequence[dict],
    settings: dict,
    cache: Optional[ContentParseCache] = None,
    metrics: Optional[FetchMetrics] = None,
    parse_fn: Optional[Callable[[Sequence[dict], dict], List[dict]]] = None,
) -> List[dict]:
    """``extract_endpoints`` behind a content-addressed cache.

    Every distinct content is parsed once. A group's parse is then resolved
    per serving URL, so identical bytes under two origins are not collapsed
    into one origin's resolution. With no cache the original function runs
    unchanged.

    ``parse_fn`` injects the parser (defaults to the real ``extract_endpoints``);
    ``run_js_recon`` passes its own module global so a patched parser is
    honored by the cache path too.
    """
    from recon.helpers.js_recon.endpoints import extract_endpoints

    parse_fn = parse_fn or extract_endpoints

    if cache is None:
        return parse_fn(list(js_files), settings)

    groups: Dict[str, List[dict]] = {}
    for js_file in js_files:
        groups.setdefault(content_hash(js_file.get("content", "")), []).append(js_file)

    # Fast path: no shared content means nothing to reuse. Run the original
    # call so a run with all-unique files is byte-identical to before.
    if all(len(files) == 1 for files in groups.values()):
        if metrics is not None:
            metrics.parses += len(js_files)
        return parse_fn(list(js_files), settings)

    out: List[dict] = []
    seen: set = set()
    for digest, files in groups.items():
        parsed, parsed_now = cache.get(
            digest, lambda files=files: _parse_representative(files, settings, parse_fn=parse_fn)
        )
        if metrics is not None:
            if parsed_now:
                metrics.parses += 1
            else:
                metrics.parse_skipped_cache += 1
        for js_file in files:
            for endpoint in _resolve_for_file(parsed, js_file):
                key = (endpoint.get("id"), endpoint.get("resolved_url") or endpoint.get("full_url"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(endpoint)
    if metrics is not None:
        metrics.extracted += len(out)
    return out


