"""Catch-all control probe: does a path that cannot exist get the same answer?

Many servers answer every path alike: an SPA shell returns its index page, an
API router returns ``200 {"code":"NOT_FOUND"}``, an auth wall redirects
everything to /login. A check that reads only the status code then reports
things that do not exist. ``control_probe`` asks the same server for a random
path next to the hit; when both answers look the same, the hit means nothing.

The probe never sends traffic of its own kind: it takes the caller's request
function (bound to its method, headers, proxy, rate limit and host health) and
the caller's SSRF guard, so it runs exactly when, and only as, the check it
guards runs. It never raises: an error is "no conclusion" (``catch_all=None``),
and the caller then keeps its finding and records ``control_check: failed``.
"""

from __future__ import annotations

import difflib
import re
import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Iterable, Optional
from urllib.parse import quote, urlsplit, urlunsplit

from recon.helpers.roe_scope import _is_roe_excluded

CONTROL_PREFIX = "rdm-"

# Only the start of a body is read: a catch-all shell or a challenge page shows
# itself in its first few KB, and a 5 MB bundle must not be held twice per hit.
BODY_CAP = 64 * 1024

# Per-request values that make one template hash differently on every request:
# UUIDs, timestamps, Cloudflare Ray IDs and other hex request ids, Akamai
# references, Fastly cache-node names, epoch numbers, and long base64/ULID
# nonces (CSRF tokens included). They only feed "is this the same page"
# comparisons, never what is stored or shown, so erring toward normalising is
# safe: a real page differs in far more than ids.
VOLATILE_RULES: tuple[tuple[re.Pattern, bytes], ...] = (
    (re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I), b"{UUID}"),
    (re.compile(rb"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}| UTC)?"), b"{TS}"),
    (re.compile(rb"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT"), b"{TS}"),
    (re.compile(rb"reference(?:\s|&#32;)*(?:#|&#35;)\s*[0-9a-z.&#;]+", re.I), b"reference #{REF}"),
    # Akamai's reference also appears bare, in its errors.edgesuite.net link,
    # with plain or entity-encoded dots: 18.6bd3c917.1696512345.1a2b3c4d
    (re.compile(rb"\b\d{1,3}(?:\.|&#46;)[0-9a-f]{6,10}(?:\.|&#46;)\d{9,10}(?:\.|&#46;)[0-9a-f]{4,10}\b", re.I), b"{AKREF}"),
    # Azure Front Door's "Ref A/B/C" lines (edge node names, timestamps).
    (re.compile(rb"\bRef [ABC]:\s*[^<\n]*"), b"Ref {REF}"),
    # Upper-case alphanumeric request ids (S3's 16-character RequestId).
    (re.compile(rb"\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{16,}\b"), b"{ID}"),
    (re.compile(rb"\bcache-[a-z0-9-]+-[A-Z]{3}\b"), b"{EDGE}"),
    # No `/` in a token: two different redirect paths must stay different.
    (re.compile(rb"(?<![\w+=-])(?=[\w+=-]*\d)[\w+=-]{20,}"), b"{TOKEN}"),
    (re.compile(rb"\b(?=[0-9a-f]*\d)[0-9a-f]{12,}(?:-[A-Z]{3})?\b", re.I), b"{HEX}"),
    (re.compile(rb"\b\d{9,}\b"), b"{NUM}"),
)


def replace_hostnames(data: bytes, hostnames: Iterable[str]) -> bytes:
    """Replace each probed hostname (plain or with HTML-entity dots) by {HOST}."""
    for host in sorted({h.lower() for h in hostnames if h}, key=len, reverse=True):
        for variant in (host, host.replace(".", "&#46;")):
            data = re.sub(re.escape(variant.encode("ascii", "ignore")), b"{HOST}", data, flags=re.I)
    return data


def canonical_bytes(data: bytes, hostnames: Iterable[str] = ()) -> bytes:
    """``data`` with the probed hostnames replaced and per-request tokens stripped."""
    data = replace_hostnames((data or b"").replace(b"\r\n", b"\n"), hostnames)
    for pattern, replacement in VOLATILE_RULES:
        data = pattern.sub(replacement, data)
    return data


def _echo_variants(echoes: Iterable[str]) -> list[bytes]:
    """Each echoed value as a page may print it: raw, URL-encoded, JSON-escaped."""
    out = set()
    for value in echoes:
        if not value:
            continue
        for form in (value, quote(value, safe="/"), quote(value, safe=""), value.replace("/", "\\/")):
            if form:
                out.add(form.encode("utf-8", "ignore"))
    return sorted(out, key=len, reverse=True)


def normalise_body(data: bytes, *, hostnames: Iterable[str] = (), echoes: Iterable[str] = ()) -> bytes:
    """A body ready to compare: echoed values (the requested path, the control
    nonce, a probe payload) become {ECHO}, then ``canonical_bytes``. The same
    echo set must be applied to both sides of a comparison."""
    data = data or b""
    for variant in _echo_variants(echoes):
        data = re.sub(re.escape(variant), b"{ECHO}", data, flags=re.I)
    return canonical_bytes(data, hostnames)


# Two bodies are "the same page" when, after normalising, their lengths are
# within 64 bytes or 5%, their word counts within 5 words or 10%, AND at least
# 90% of their tokens line up. The length and word gates are cheap filters;
# the token ratio is what keeps two different short JSON bodies (always within
# 64 bytes of each other) from being called equal. The ratio is high on
# purpose: a false "catch-all" deletes a real finding, a missed one keeps a
# finding the review can still judge.
LENGTH_SLACK_BYTES = 64
LENGTH_SLACK_RATIO = 0.05
WORD_SLACK = 5
WORD_SLACK_RATIO = 0.10
SAME_PAGE_RATIO = 0.90
# Token cap for the ratio: SequenceMatcher is quadratic in the worst case, and
# the first 2,000 tokens of two pages say whether they share a template.
_TOKEN_CAP = 2000
_TOKEN_RE = re.compile(rb"\w+|[^\w\s]")


def _tokens(data: bytes) -> list[bytes]:
    return _TOKEN_RE.findall(data[:BODY_CAP])[:_TOKEN_CAP]


def similarity(a: bytes, b: bytes, *, floor: float = 0.0) -> float:
    """Share of tokens two normalised bodies have in common, 0.0 to 1.0.

    Below ``floor`` the cheap upper bound is returned instead of the exact
    ratio: a caller that only asks "at least X?" gets the same answer faster.
    """
    if a == b:
        return 1.0
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    # autojunk off: in a templated page every tag token is "popular", and
    # junking them scores two near-identical pages close to 0.
    matcher = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    bound = matcher.quick_ratio()
    if bound < floor:
        return bound
    return matcher.ratio()


def same_page(a: bytes, b: bytes, *, ratio: float = SAME_PAGE_RATIO) -> bool:
    """True when two NORMALISED bodies are the same page (see the gates above)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > max(LENGTH_SLACK_BYTES, LENGTH_SLACK_RATIO * max(la, lb)):
        return False
    wa, wb = len(a.split()), len(b.split())
    if abs(wa - wb) > max(WORD_SLACK, WORD_SLACK_RATIO * max(wa, wb)):
        return False
    return similarity(a, b, floor=ratio) >= ratio


# ---------------------------------------------------------------------------
# Response access that tolerates any requests-like object
# ---------------------------------------------------------------------------

def body_bytes(response) -> bytes:
    """The first ``BODY_CAP`` bytes of a response body, or b"" if unreadable."""
    try:
        content = getattr(response, "content", None)
        if isinstance(content, (bytes, bytearray)):
            return bytes(content[:BODY_CAP])
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return text[:BODY_CAP].encode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - an undecodable body is an empty one
        pass
    return b""


def header_map(response) -> dict:
    """Response headers as a lower-cased str -> str dict ({} if unreadable)."""
    try:
        headers = getattr(response, "headers", None) or {}
        return {str(k).lower(): v for k, v in dict(headers).items()
                if isinstance(k, str) and isinstance(v, str)}
    except Exception:  # noqa: BLE001
        return {}


def status_of(response) -> Optional[int]:
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) and not isinstance(status, bool) else None


# ---------------------------------------------------------------------------
# Challenge pages
# ---------------------------------------------------------------------------

_AKAMAI_REFERENCE = re.compile(rb"reference(?:\s|&#32;)*(?:#|&#35;)\s*[0-9a-z]", re.I)


def is_challenge(response) -> bool:
    """True when the answer is a bot challenge or edge deny page, not the site.

    Cloudflare marks a challenge with ``cf-mitigated`` and serves a page that
    loads ``challenge-platform`` ("Just a moment..."); Akamai's deny page is
    "Access Denied" with a reference number. A check that reads such a page as
    the target's answer reports an empty surface, or a finding on the edge.
    """
    try:
        headers = header_map(response)
        if headers.get("cf-mitigated"):
            return True
        head = body_bytes(response).lower()
        if b"challenge-platform" in head or b"just a moment..." in head:
            return True
        return b"access denied" in head and bool(_AKAMAI_REFERENCE.search(head))
    except Exception:  # noqa: BLE001
        return False


_noted_lock = threading.Lock()


def note_challenge(module: str, host: str) -> None:
    """One coverage note per (module, host) and run: the host answered with a
    challenge, so it was not really checked. No prune effect (an entry)."""
    try:
        from recon.helpers import circuit_breaker as cb
        seen = cb.run_cache("catchall_challenge_notes")
        key = (module, host)
        with _noted_lock:
            hit, _ = seen.get(key)
            if hit:
                return
            seen.put(key, True)
        cb.note_degraded(module, entries=[{"source": "challenge_blocked",
                                           "reason": cb.safe_text(host), "skipped": 1}])
    except Exception:  # noqa: BLE001 - a coverage note never breaks a check
        pass


# ---------------------------------------------------------------------------
# The control probe
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlVerdict:
    catch_all: Optional[bool]   # None = the control failed, no conclusion
    reason: str

    @property
    def control_check(self) -> str:
        """What a finding records: passed (a real hit), failed (no conclusion)."""
        if self.catch_all is None:
            return "failed"
        return "catch_all" if self.catch_all else "passed"


@dataclass(frozen=True)
class _Control:
    path: str
    nonce: str
    status: Optional[int] = None
    body: bytes = b""
    location: str = ""
    challenged: bool = False
    error: str = ""


class ControlCache:
    """One control answer per (scheme, host, port, parent prefix), shared by a
    check's worker threads. Use one cache per request method: a HEAD control
    says nothing about a GET hit."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict = {}
        self._key_locks: dict = {}
        self.requests = 0

    def _key_lock(self, key) -> threading.Lock:
        with self._lock:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = self._key_locks[key] = threading.Lock()
            return lock

    def fetch(self, key, send: Callable[[], _Control]) -> _Control:
        with self._key_lock(key):
            with self._lock:
                if key in self._data:
                    return self._data[key]
            control = send()
            with self._lock:
                self._data[key] = control
                self.requests += 1
            return control

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


def _parent_prefix(path: str) -> str:
    """``/api/v1`` -> ``/api/``, ``/api/v1/`` -> ``/api/``, ``/graphql`` -> ``/``."""
    trimmed = (path or "/").rstrip("/")
    head = trimmed.rsplit("/", 1)[0] if "/" in trimmed else ""
    return (head or "") + "/"


def _status_matches(a: Optional[int], b: Optional[int]) -> bool:
    # 2xx and 3xx compare by class (a 200 vs 204 shell, a 301 vs 302 login
    # redirect); everything else compares exactly, because a 401 or 403 where
    # a made-up path gets 404 is the very sign that the path exists.
    if a is None or b is None:
        return False
    if a == b:
        return True
    return a // 100 == b // 100 and a // 100 in (2, 3)


def _send_control(fetch, control_url: str, path: str, nonce: str) -> _Control:
    try:
        resp = fetch(control_url)
    except Exception as exc:  # noqa: BLE001 - a failed control is "no conclusion"
        return _Control(path, nonce, error=type(exc).__name__)
    status = status_of(resp)
    if status is None:
        return _Control(path, nonce, error="no status")
    return _Control(path, nonce, status=status, body=body_bytes(resp),
                    location=header_map(resp).get("location", ""),
                    challenged=is_challenge(resp))


def control_probe(fetch: Callable[[str], object], url: str, response, *,
                  url_guard: Optional[Callable[[str], bool]] = None,
                  cache: Optional[ControlCache] = None,
                  roe_excluded: Optional[Iterable[str]] = None,
                  note_module: str = "") -> ControlVerdict:
    """Compare ``response`` (the answer to ``url``) with the answer to a path
    that cannot exist next to it. Never raises.

    ``fetch(u)`` is the caller's own request function, bound to its method and
    headers, with ``allow_redirects=False``. ``url_guard`` is the caller's SSRF
    guard (None where the caller has none on purpose); a guard that refuses or
    raises means no control is sent. A host the RoE excludes is never sent a
    control. ``note_module``, when given, records a challenged host once as a
    coverage gap of that module.
    """
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not parts.scheme or not host:
            return ControlVerdict(None, "unparsable URL")
        if roe_excluded and _is_roe_excluded(host, list(roe_excluded)):
            return ControlVerdict(None, "host excluded by the rules of engagement")
        if is_challenge(response):
            if note_module:
                note_challenge(note_module, host)
            return ControlVerdict(None, "challenge page")

        real_status = status_of(response)
        if real_status is None:
            return ControlVerdict(None, "the hit has no status")

        prefix = _parent_prefix(parts.path)
        key = (parts.scheme.lower(), host, parts.port, prefix)
        nonce = f"{CONTROL_PREFIX}{uuid.uuid4().hex[:12]}"
        control_path = f"{prefix}{nonce}"
        control_url = urlunsplit((parts.scheme, parts.netloc, control_path, "", ""))
        if url_guard is not None:
            try:
                if not url_guard(control_url):
                    return ControlVerdict(None, "control refused by the SSRF guard")
            except Exception:  # noqa: BLE001 - a guard that faults fails closed
                return ControlVerdict(None, "SSRF guard failed")

        def send() -> _Control:
            return _send_control(fetch, control_url, control_path, nonce)

        control = cache.fetch(key, send) if cache is not None else send()
        if control.error:
            return ControlVerdict(None, f"control request failed ({control.error})")
        if control.challenged:
            if note_module:
                note_challenge(note_module, host)
            return ControlVerdict(None, "challenge page")

        if not _status_matches(real_status, control.status):
            return ControlVerdict(False, f"{control.path} answered {control.status}, the hit {real_status}")

        echoes = [parts.path, control.path, control.nonce]
        last = parts.path.rstrip("/").rsplit("/", 1)[-1]
        if len(last) >= 4:
            echoes.append(last)
        hostnames = [host]
        real = normalise_body(header_map(response).get("location", "").encode("utf-8", "ignore")
                              + b"\x00" + body_bytes(response), hostnames=hostnames, echoes=echoes)
        ctrl = normalise_body(control.location.encode("utf-8", "ignore")
                              + b"\x00" + control.body, hostnames=hostnames, echoes=echoes)
        if same_page(real, ctrl):
            return ControlVerdict(True, f"same status and body as {control.path}")
        return ControlVerdict(False, f"{control.path} answered {control.status} with a different body")
    except Exception as exc:  # noqa: BLE001 - never raises, by contract
        return ControlVerdict(None, f"control probe error ({type(exc).__name__})")
