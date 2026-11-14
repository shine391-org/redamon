"""Unit tests for the JS pre-download admission layer.

Covers recon/helpers/js_recon/fetch_admission.py (provenance classification,
fetch planning, content-addressed parse cache, context-isolated download
cache, cached endpoint extraction) and the fetch seams of
recon/main_recon_modules/js_recon.py (download attempts, bounded retries,
outcome evidence, cache hits).

Deterministic: recon.helpers is stubbed because its package __init__ imports
optional heavy deps (dnspython, docker, ...) absent here; the only real
network is 127.0.0.1 loopback receivers in LocalReceiverTests.

Run:
    python3 -m pytest tests/test_js_fetch_admission_context.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import threading
import types
import unittest
from unittest.mock import MagicMock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


def _module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m


# ``recon`` is a namespace package here; stub it so submodule imports resolve.
_recon = _module("recon")
_recon.__path__ = [str(_REPO / "recon")]

# ``recon.helpers`` real package __init__ pulls in heavy optional deps; stub
# the package and load only the submodules we actually need, by path.
helpers = _module("recon.helpers")
helpers.__path__ = [str(_REPO / "recon" / "helpers")]


def _load_path(name, relpath):
    spec = importlib.util.spec_from_file_location(name, str(_REPO / relpath))
    assert spec is not None and spec.loader is not None, relpath
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_cb = _load_path("recon.helpers.circuit_breaker", "recon/helpers/circuit_breaker.py")
helpers.circuit_breaker = _cb

_urls = _load_path("recon.helpers.js_recon.urls", "recon/helpers/js_recon/urls.py")
_jsrecon_pkg = _module("recon.helpers.js_recon")
_jsrecon_pkg.__path__ = [str(_REPO / "recon" / "helpers" / "js_recon")]
_jsrecon_pkg.urls = _urls

fa = _load_path("recon.helpers.js_recon.fetch_admission",
                "recon/helpers/js_recon/fetch_admission.py")

# Seams for loading recon.main_recon_modules.js_recon without the heavy
# recon.helpers submodules (patterns, sourcemap, ...). They are real objects
# where the code path under test touches them; MagicMock stubs elsewhere.
helpers.catchall = _module("recon.helpers.catchall")

# The 7.8 hop guard uses target_admission, which needs the complete scope
# normalizer API. roe_scope is stdlib-only; use its real policy rather than an
# incomplete permissive stub so newly added guards still execute in this suite.
_roe = _load_path("recon.helpers.roe_scope", "recon/helpers/roe_scope.py")
helpers.roe_scope = _roe

for _name, _attr in (
    ("recon.helpers.js_recon.patterns", "patterns"),
    ("recon.helpers.js_recon.validators", "validators"),
    ("recon.helpers.js_recon.trufflehog_bridge", "trufflehog_bridge"),
    ("recon.helpers.js_recon.sourcemap", "sourcemap"),
    ("recon.helpers.js_recon.dependency", "dependency"),
    ("recon.helpers.js_recon.framework", "framework"),
    ("recon.helpers.ai_signal_catalog", "ai_signal_catalog"),
):
    _stub = MagicMock()
    sys.modules[_name] = _stub
    setattr(_jsrecon_pkg, _attr, _stub)

# The real endpoints module: js_recon imports extract_endpoints from it, and
# the cache tests call the real parser. Load it by path (stdlib-only imports).
_real_endpoints = _load_path("recon.helpers.js_recon.endpoints",
                             "recon/helpers/js_recon/endpoints.py")
setattr(_jsrecon_pkg, "endpoints", _real_endpoints)
extract_endpoints = _real_endpoints.extract_endpoints

_ipf = _load_path("recon.main_recon_modules.ip_filter",
                  "recon/main_recon_modules/ip_filter.py")
_main_recon_pkg = _module("recon.main_recon_modules")
_main_recon_pkg.__path__ = [str(_REPO / "recon" / "main_recon_modules")]
_main_recon_pkg.ip_filter = _ipf

js_recon = _load_path("recon.main_recon_modules.js_recon",
                      "recon/main_recon_modules/js_recon.py")
_REAL_SAFE_REDIRECT_GET = js_recon._safe_redirect_get

Provenance = fa.Provenance
PROVENANCE_RANK = fa.PROVENANCE_RANK
RETRYABLE = fa.RETRYABLE
MAX_RETRIES = fa.MAX_RETRIES
FetchCandidate = fa.FetchCandidate
FetchMetrics = fa.FetchMetrics
FetchOutcome = fa.FetchOutcome
ContentParseCache = fa.ContentParseCache
DownloadCache = fa.DownloadCache
plan_fetches = fa.plan_fetches
extract_endpoints_cached = fa.extract_endpoints_cached
content_hash = fa.content_hash
context_key = fa.context_key
collect_candidates = js_recon._collect_js_candidates
download_js_files = js_recon._download_js_files
extract_endpoints = __import__("recon.helpers.js_recon.endpoints",
                               fromlist=["extract_endpoints"]).extract_endpoints


def _cand(url, provenance, reason="", source_ref="ref"):
    return FetchCandidate(url=url, provenance=provenance,
                          source_ref=source_ref, reason=reason)


class _Resp:
    """Fake requests.Response for the download seams."""

    def __init__(self, status_code, text="", headers=None, url=""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FetchAdmissionTests(unittest.TestCase):

    def test_classify_observed_app_js_wins(self):
        c = fa.classify_candidate("https://a.com/app.js",
                                  observed_app_js=True, served_js=True)
        self.assertEqual(c.provenance, Provenance.OBSERVED_APP_JS)
        self.assertEqual(c.url, "https://a.com/app.js")

    def test_classify_content_type_exception(self):
        c = fa.classify_candidate("https://a.com/x.json", served_js=True)
        self.assertEqual(c.provenance, Provenance.CONTENT_TYPE_EXCEPTION)

    def test_classify_served_js_confirms_only_non_js_names(self):
        # http_probe serving a JS media type on a URL whose name does not say
        # JS is a content-type exception (weaker than an observed JS file).
        c = fa.classify_candidate("https://a.com/x.json", served_js=True)
        self.assertEqual(c.provenance, Provenance.CONTENT_TYPE_EXCEPTION)
        # A URL whose name says JS must be marked observed by the caller
        # (_collect_js_candidates does so for http_probe hits); classify_candidate
        # itself does not promote it, so it stays a bare candidate string.
        c = fa.classify_candidate("https://a.com/x.js", served_js=True)
        self.assertEqual(c.provenance, Provenance.CANDIDATE_STRING)
        self.assertEqual(c.reason, fa.NO_PROVENANCE)

    def test_classify_observed_app_js_overrides_served_js(self):
        c = fa.classify_candidate("https://a.com/x.json",
                                  observed_app_js=True, served_js=True)
        self.assertEqual(c.provenance, Provenance.OBSERVED_APP_JS)

    def test_classify_dynamic_import(self):
        c = fa.classify_candidate("https://a.com/chunk.js",
                                  from_dynamic_import=True)
        self.assertEqual(c.provenance, Provenance.DYNAMIC_IMPORT)

    def test_classify_source_map(self):
        c = fa.classify_candidate("https://a.com/app.js.map",
                                  from_source_map=True)
        self.assertEqual(c.provenance, Provenance.SOURCE_MAP)

    def test_classify_bare_string_is_deferred_with_reason(self):
        c = fa.classify_candidate("https://a.com/debug.js")
        self.assertEqual(c.provenance, Provenance.CANDIDATE_STRING)
        self.assertEqual(c.reason, fa.NO_PROVENANCE)

    def test_classify_empty_url_is_deferred(self):
        c = fa.classify_candidate("")
        self.assertEqual(c.provenance, Provenance.CANDIDATE_STRING)
        self.assertEqual(c.url, "")

    def test_provenance_rank_order(self):
        order = [Provenance.OBSERVED_APP_JS, Provenance.CONTENT_TYPE_EXCEPTION,
                 Provenance.DYNAMIC_IMPORT, Provenance.SOURCE_MAP,
                 Provenance.CANDIDATE_STRING]
        self.assertEqual([PROVENANCE_RANK[p] for p in order],
                         list(range(len(order))))

    def test_plan_defers_no_provenance_with_reason(self):
        cands = [_cand("https://a.com/debug.js", Provenance.CANDIDATE_STRING)]
        metrics = FetchMetrics()
        plan = plan_fetches(cands, 10, metrics)
        self.assertEqual(plan.planned, [])
        self.assertEqual(len(plan.deferred), 1)
        self.assertEqual(plan.deferred[0].reason, fa.NO_PROVENANCE)
        self.assertEqual(metrics.candidates, 1)
        self.assertEqual(metrics.admitted, 0)
        self.assertEqual(metrics.deferred, 1)
        self.assertEqual(metrics.by_defer_reason, {fa.NO_PROVENANCE: 1})

    def test_plan_file_budget_defers_with_reason_and_counts(self):
        cands = [_cand(u, Provenance.OBSERVED_APP_JS)
                 for u in ("https://a.com/1.js", "https://a.com/2.js",
                           "https://a.com/3.js")]
        metrics = FetchMetrics()
        plan = plan_fetches(cands, 1, metrics)
        self.assertEqual(len(plan.planned), 1)
        self.assertEqual(len(plan.deferred), 2)
        self.assertTrue(all(d.reason == fa.FILE_BUDGET for d in plan.deferred))
        self.assertEqual(metrics.candidates, 3)
        self.assertEqual(metrics.admitted, 3)
        self.assertEqual(metrics.deferred, 2)
        self.assertEqual(metrics.by_defer_reason, {fa.FILE_BUDGET: 2})
        self.assertEqual(plan.by_host["a.com:443"],
                         {"candidates": 3, "selected": 1, "cut": 2})

    def test_plan_round_robin_across_hosts(self):
        cands = [_cand("https://a.com/1.js", Provenance.OBSERVED_APP_JS),
                 _cand("https://a.com/2.js", Provenance.OBSERVED_APP_JS),
                 _cand("https://b.com/1.js", Provenance.OBSERVED_APP_JS)]
        plan = plan_fetches(cands, 3, FetchMetrics())
        self.assertEqual([c.url for c in plan.planned],
                         ["https://a.com/1.js", "https://b.com/1.js",
                          "https://a.com/2.js"])

    def test_plan_ranks_within_host(self):
        cands = [_cand("https://a.com/vendors.js", Provenance.OBSERVED_APP_JS),
                 _cand("https://a.com/main.js", Provenance.OBSERVED_APP_JS)]
        plan = plan_fetches(cands, 1, FetchMetrics(),
                            key=lambda c: PROVENANCE_RANK[c.provenance])
        # js_fetch_rank puts first-party bundles (main.js) before vendor files.
        plan2 = plan_fetches(cands, 1, FetchMetrics(),
                             key=lambda c: js_recon._js_fetch_rank(c.url))
        self.assertEqual(plan2.planned[0].url, "https://a.com/main.js")

    def test_fetch_outcome_never_confirms_absence(self):
        for status in ("ok", "http_404", "timeout", "challenge",
                       "unreachable", "not_js", "too_large"):
            self.assertFalse(FetchOutcome("https://a.com/x.js", status)
                             .confirmed_absence)

    def test_fetch_outcome_ok(self):
        self.assertTrue(FetchOutcome("https://a.com/x.js", "ok").ok)
        self.assertFalse(FetchOutcome("https://a.com/x.js", "http_404").ok)

    def test_should_retry_is_bounded(self):
        self.assertTrue(fa.should_retry(FetchOutcome("u", "timeout"), 0))
        self.assertTrue(fa.should_retry(FetchOutcome("u", "challenge"), 0))
        self.assertTrue(fa.should_retry(FetchOutcome("u", "unreachable"), 0))
        self.assertFalse(fa.should_retry(FetchOutcome("u", "http_404"), 0))
        self.assertFalse(fa.should_retry(FetchOutcome("u", "ok"), 0))
        self.assertFalse(fa.should_retry(FetchOutcome("u", "timeout"), MAX_RETRIES))

    def test_content_hash_is_addressed_by_bytes(self):
        body = b"const x = 1;\n"
        self.assertEqual(content_hash(body), content_hash(body.decode()))
        self.assertEqual(content_hash(body), content_hash(bytearray(body)))
        self.assertNotEqual(content_hash(body), content_hash(b"const x = 2;\n"))

    def test_context_key_is_short_deterministic_and_isolated(self):
        k1 = context_key(tenant="t", project_id="p", auth_ref="r")
        k2 = context_key(tenant="t", project_id="p", auth_ref="r")
        k3 = context_key(tenant="t", project_id="p", auth_ref="other")
        self.assertEqual(len(k1), 16)
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, k3)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in k1))
        self.assertNotIn("r", k1)

    def test_parse_cache_miss_then_hit_counts_one_parse(self):
        cache = ContentParseCache(context_key(tenant="t", project_id="p"))
        calls = {"n": 0}

        def parse():
            calls["n"] += 1
            return {"endpoints": 1}

        parsed, now = cache.get("digest", parse)
        self.assertEqual(parsed, {"endpoints": 1})
        self.assertTrue(now)
        parsed2, now2 = cache.get("digest", parse)
        self.assertEqual(parsed2, {"endpoints": 1})
        self.assertFalse(now2)
        self.assertEqual(calls["n"], 1)
        stats = cache.stats()
        self.assertEqual(stats["parses"], 1)
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["entries"], 1)

    def test_parse_cache_is_isolated_by_context(self):
        cache_a = ContentParseCache(context_key(tenant="t", project_id="p1"))
        cache_b = ContentParseCache(context_key(tenant="t", project_id="p2"))
        calls = {"n": 0}

        def parse():
            calls["n"] += 1
            return "parsed"

        cache_a.get("digest", parse)
        self.assertIsNone(cache_b.lookup("digest"))
        parsed, _ = cache_b.get("digest", parse)
        self.assertEqual(parsed, "parsed")
        self.assertEqual(calls["n"], 2)

    def test_download_cache_hit_and_context_isolation(self):
        cache = DownloadCache(context_key(tenant="t", project_id="p"))
        rec = {"content": "body", "status_code": 200}
        self.assertIsNone(cache.lookup("https://a.com/x.js"))
        cache.store("https://a.com/x.js", rec)
        self.assertEqual(cache.lookup("https://a.com/x.js"), rec)
        other = DownloadCache(context_key(tenant="t", project_id="q"))
        self.assertIsNone(other.lookup("https://a.com/x.js"))
        self.assertEqual(cache.stats(), {"hits": 1, "entries": 1})

    def test_extract_endpoints_cached_parses_shared_content_once(self):
        body = 'fetch("/api/x");\n'
        files = [
            {"url": "http://a.com/x.js", "content": body},
            {"url": "http://b.com/x.js", "content": body},
        ]
        cache = ContentParseCache(context_key(tenant="t", project_id="p"))
        metrics = FetchMetrics()
        out = extract_endpoints_cached(files, {}, cache=cache, metrics=metrics,
                                       parse_fn=extract_endpoints)
        # Shared bytes are parsed once; the second file reuses the parse.
        self.assertEqual(metrics.parses, 1)
        self.assertEqual(metrics.parse_skipped_cache, 0)
        self.assertEqual(metrics.extracted, 2)
        resolved = {e["resolved_url"] for e in out}
        self.assertEqual(resolved,
                         {"http://a.com/api/x", "http://b.com/api/x"})
        sources = {e["source_js"] for e in out}
        self.assertEqual(sources, {"http://a.com/x.js", "http://b.com/x.js"})

        # A second call over the same content hits the cache.
        out2 = extract_endpoints_cached(files, {}, cache=cache,
                                        metrics=metrics,
                                        parse_fn=extract_endpoints)
        self.assertEqual(metrics.parses, 1)
        self.assertEqual(metrics.parse_skipped_cache, 1)
        self.assertEqual(len(out2), 2)

    def test_extract_endpoints_cached_without_cache_delegates(self):
        body = 'fetch("/api/x");\n'
        files = [{"url": "http://a.com/x.js", "content": body}]
        out = extract_endpoints_cached(files, {}, cache=None)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["full_url"], "/api/x")

    def test_extract_endpoints_cached_all_unique_fast_path(self):
        files = [
            {"url": "http://a.com/1.js", "content": "const a=1;\n"},
            {"url": "http://a.com/2.js", "content": "const b=2;\n"},
        ]
        cache = ContentParseCache(context_key(tenant="t", project_id="p"))
        metrics = FetchMetrics()
        out = extract_endpoints_cached(files, {}, cache=cache, metrics=metrics)
        self.assertEqual(metrics.parses, 2)
        self.assertEqual(metrics.parse_skipped_cache, 0)
        self.assertEqual(len(out), 0)


class CandidateTests(unittest.TestCase):

    def setUp(self):
        self.result = {
            "resource_enum": {
                "js_urls": ["https://a.com/app.js", "https://a.com/debug.js"],
                "discovered_urls": ["https://a.com/style.js"],
            },
            "http_probe": {
                "by_url": {
                    "https://a.com/manifest.json": {"content_type": "application/javascript"},
                    "https://a.com/app.js": {"content_type": "application/javascript"},
                },
            },
        }

    def test_collect_candidates_provenance(self):
        cands = collect_candidates(self.result, {})
        by_url = {c.url: c for c in cands}
        self.assertEqual(by_url["https://a.com/app.js"].provenance,
                         Provenance.OBSERVED_APP_JS)
        self.assertEqual(by_url["https://a.com/app.js"].source_ref, "resource_enum")
        self.assertEqual(by_url["https://a.com/debug.js"].provenance,
                         Provenance.OBSERVED_APP_JS)
        # .json that answered with a JS media type is a content-type exception,
        # weaker evidence than an observed JS file.
        self.assertEqual(by_url["https://a.com/manifest.json"].provenance,
                         Provenance.CONTENT_TYPE_EXCEPTION)
        self.assertEqual(by_url["https://a.com/manifest.json"].source_ref,
                         "http_probe")
        self.assertEqual(len(cands), 4)


class DownloadSeamTests(unittest.TestCase):

    def setUp(self):
        self.work = TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.calls = 0
        self.responses = iter([])
        self.fake_requests_module = js_recon.requests

        js_recon._js_skip = lambda url: False
        js_recon._js_alive = lambda url: None
        js_recon._js_failed = lambda url, exc: None
        js_recon._identity_request_headers = lambda settings: {}
        js_recon._download_allowed = lambda url: True

        def fake_get(url, *, timeout, headers, max_redirects=5, extra_headers=None,
                     session=None, settings=None):
            self.assertIsNotNone(session)
            self.assertFalse(session.trust_env)
            self.calls += 1
            try:
                return next(self.responses)
            except StopIteration:
                raise AssertionError("no more fake responses for %s" % url)

        js_recon._safe_redirect_get = fake_get

    def _one_ok(self, body=b"const x = 1;\n"):
        return _Resp(200, body.decode(),
                     {"Content-Type": "application/javascript"})

    def test_downloads_count_attempts_and_bytes(self):
        self.responses = iter([self._one_ok(), self._one_ok()])
        metrics = FetchMetrics()
        outcomes = []
        files = download_js_files(
            ["https://a.com/1.js", "https://a.com/2.js"],
            Path(self.work.name), max_files=10, concurrency=2, timeout=900,
            unreachable=[], settings={}, metrics=metrics, outcomes=outcomes)
        self.assertEqual(len(files), 2)
        self.assertEqual(metrics.download_attempts, 2)
        self.assertEqual(metrics.bytes_downloaded, 2 * len(self._one_ok().text))
        self.assertEqual([o.status for o in outcomes], ["ok", "ok"])
        self.assertEqual(self.calls, 2)

    def test_cache_hit_skips_download(self):
        cache = DownloadCache(context_key(tenant="t", project_id="p"))
        cache.store("https://a.com/1.js",
                    {"content": "cached-body", "status_code": 200,
                     "headers": {"Content-Type": "application/javascript"}})
        # url 2 is fetched for real; url 1 is served from the cache.
        self.responses = iter([self._one_ok()])
        metrics = FetchMetrics()
        outcomes = []
        files = download_js_files(
            ["https://a.com/1.js", "https://a.com/2.js"],
            Path(self.work.name), max_files=10, concurrency=2, timeout=900,
            unreachable=[], settings={}, download_cache=cache, metrics=metrics,
            outcomes=outcomes)
        by_url = {f["url"]: f for f in files}
        self.assertEqual(set(by_url), {"https://a.com/1.js", "https://a.com/2.js"})
        self.assertEqual(by_url["https://a.com/1.js"]["content"], "cached-body")
        self.assertEqual(by_url["https://a.com/2.js"]["content"], self._one_ok().text)
        # One cache hit (no attempt), one real download.
        self.assertEqual(metrics.download_attempts, 1)
        self.assertEqual(metrics.download_skipped_cache, 1)
        self.assertEqual(metrics.bytes_downloaded, len(self._one_ok().text))
        statuses = {o.status for o in outcomes}
        self.assertEqual(statuses, {"ok"})
        reasons = {o.reason for o in outcomes}
        self.assertEqual(reasons, {"cache_hit", ""})

    def test_http_404_is_evidence_not_confirmed_absence(self):
        self.responses = iter([_Resp(404, "", {"Content-Type": "text/plain"})])
        metrics = FetchMetrics()
        outcomes = []
        files = download_js_files(
            ["https://a.com/missing.js"], Path(self.work.name),
            max_files=10, concurrency=2, timeout=900,
            unreachable=[], settings={}, metrics=metrics, outcomes=outcomes)
        self.assertEqual(files, [])
        self.assertEqual(self.calls, 1)  # a 404 answer is not retried
        self.assertEqual(outcomes[0].status, "http_404")
        self.assertEqual(outcomes[0].status_code, 404)
        self.assertEqual(outcomes[0].retries, 0)
        self.assertFalse(outcomes[0].confirmed_absence)

    def test_timeout_retries_then_succeeds_within_bound(self):
        self.responses = iter([self.fake_requests_module.Timeout("boom"),
                               self.fake_requests_module.Timeout("boom"),
                               self._one_ok()])
        metrics = FetchMetrics()
        outcomes = []
        files = download_js_files(
            ["https://a.com/slow.js"], Path(self.work.name),
            max_files=10, concurrency=2, timeout=900,
            unreachable=[], settings={}, metrics=metrics, outcomes=outcomes)
        self.assertEqual(len(files), 1)
        self.assertEqual(outcomes[0].status, "ok")
        self.assertEqual(outcomes[0].retries, MAX_RETRIES)
        self.assertEqual(metrics.download_attempts, MAX_RETRIES + 1)
        self.assertEqual(self.calls, MAX_RETRIES + 1)

    def test_permanent_failure_retries_bounded(self):
        self.responses = iter([ConnectionError("refused"),
                               ConnectionError("refused"),
                               ConnectionError("refused")])
        metrics = FetchMetrics()
        outcomes = []
        unreachable = []
        files = download_js_files(
            ["https://a.com/dead.js"], Path(self.work.name),
            max_files=10, concurrency=2, timeout=900,
            unreachable=unreachable, settings={}, metrics=metrics,
            outcomes=outcomes)
        self.assertEqual(files, [])
        self.assertEqual(unreachable, ["https://a.com/dead.js"])
        self.assertEqual(outcomes[0].status, "unreachable")
        self.assertEqual(outcomes[0].retries, MAX_RETRIES)
        self.assertEqual(metrics.download_attempts, MAX_RETRIES + 1)
        self.assertFalse(outcomes[0].confirmed_absence)


class LocalReceiverTests(unittest.TestCase):
    """Real 127.0.0.1 receivers: two origins serving identical bytes.

    Proves the fetch-stage reduction (two URLs fetched once each) and the
    parse-cache reduction (shared content parsed once, resolved per origin).
    """

    BODY = 'const VERSION = "2.4.1";\nfetch("/api/x");\n'

    @classmethod
    def setUpClass(cls):
        cls.servers = []
        cls.threads = []
        cls.ports = []
        for _ in range(2):
            server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
            cls.ports.append(server.server_address[1])
            cls.servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.threads.append(thread)

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()

    def setUp(self):
        self.work = TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        js_recon._safe_redirect_get = _REAL_SAFE_REDIRECT_GET
        js_recon._js_skip = lambda url: False
        js_recon._js_alive = lambda url: None
        js_recon._js_failed = lambda url, exc: None
        js_recon._identity_request_headers = lambda settings: {}
        js_recon._download_allowed = lambda url: True

    def test_two_origins_same_bytes_fetch_once_each_parse_once(self):
        urls = [f"http://127.0.0.1:{p}/x.js" for p in self.ports]
        metrics = FetchMetrics()
        outcomes = []
        files = download_js_files(urls, Path(self.work.name), max_files=10,
                                  concurrency=2, timeout=900,
                                  unreachable=[], settings={},
                                  metrics=metrics, outcomes=outcomes)
        self.assertEqual(len(files), 2)
        self.assertEqual(metrics.download_attempts, 2)
        self.assertEqual(metrics.bytes_downloaded, 2 * len(self.BODY))
        self.assertTrue(all(o.status == "ok" for o in outcomes))

        cache = ContentParseCache(context_key(tenant="t", project_id="p"))
        metrics = FetchMetrics()
        out = extract_endpoints_cached(files, {}, cache=cache, metrics=metrics,
                                       parse_fn=extract_endpoints)
        # Identical bytes: one parse across both files; no repeat lookup yet.
        self.assertEqual(metrics.parses, 1)
        self.assertEqual(metrics.parse_skipped_cache, 0)
        # Relative endpoint resolved against each file's own origin.
        resolved = sorted({e["resolved_url"] for e in out if e.get("resolved_url")})
        expected = sorted(f"http://127.0.0.1:{p}/api/x" for p in self.ports)
        self.assertEqual(resolved, expected)
        sources = sorted({e["source_js"] for e in out})
        self.assertEqual(set(sources), set(urls))

        # A second call over the same content hits the cache.
        out2 = extract_endpoints_cached(files, {}, cache=cache, metrics=metrics,
                                        parse_fn=extract_endpoints)
        self.assertEqual(metrics.parses, 1)
        self.assertEqual(metrics.parse_skipped_cache, 1)
        self.assertEqual(len(out2), 2)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = LocalReceiverTests.BODY.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # noqa: N802
        return


if __name__ == "__main__":
    unittest.main()
