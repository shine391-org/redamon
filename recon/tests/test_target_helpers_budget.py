"""Regression tests for the Nuclei target-builder budget and scheme filter.

`build_target_urls_from_resource_enum` previously appended every observed
endpoint to the nuclei target list with no scheme check and no total budget,
so a large resource-enum corpus (thousands of path-only URLs, plus occasional
non-HTTP strings such as ``mailto:``) fanned straight into nuclei. The httpx
builder had the same admission hole in the final union.

These tests pin the fix:
- non-HTTP / hostless / malformed base URLs and composed URLs are rejected,
  never sent, and counted on the run summary;
- the httpx builder and the final `build_target_urls` union admit only
  absolute http/https URLs with a host;
- ordinary endpoints are capped at MAX_RESOURCE_ENUM_NUCLEI_URLS per run,
  parameter-bearing URLs first (any query/body/path bucket), path-only URLs
  filling the remaining budget, in deterministic (base URL, path) order;
- overflow and rejection counts are recorded on the run summary and are
  stable across repeated calls (no accumulation);
- ``declared_only`` GET/HEAD behaviour and its 500 cap are unchanged;
- legitimate fallback (uncovered hostname/IP) URLs are preserved, and the
  caps are per-builder only -- there is no global union cap.

Run (inside the recon Docker image, one file at a time):
    python3 -m pytest recon/tests/test_target_helpers_budget.py -v
or:
    python3 -m unittest recon.tests.test_target_helpers_budget -v
"""
import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

_RECON_DIR = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TH = _load_module("th_budget_under_test", _RECON_DIR / "helpers" / "target_helpers.py")


def _endpoint(methods=("GET",), declared_only=None, query=(), body=(), path_params=()):
    entry = {
        "methods": list(methods),
        "parameters": {
            "query": [{"name": n, "sample_values": [v] if v else []} for n, v in query],
            "body": list(body),
            "path": list(path_params),
        },
    }
    if declared_only is not None:
        entry["declared_only"] = declared_only
    return entry


def _silent(fn, *a, **kw):
    buf = io.StringIO()
    with redirect_stdout(buf):
        out = fn(*a, **kw)
    return out, buf.getvalue()


def _data(endpoints, base="https://a.example.com", summary=None):
    data = {"by_base_url": {base: {"endpoints": endpoints}}}
    if summary is not None:
        data["summary"] = summary
    return data


class TestIsHttpUrl(unittest.TestCase):
    def test_admits_http_and_https_with_host(self):
        for url in ("http://a.example.com", "https://a.example.com:8443/x?q=1",
                    "HTTP://a.example.com/x", "http://[::1]/", "http://1.2.3.4/"):
            self.assertTrue(TH._is_http_url(url), url)

    def test_rejects_non_http_schemes(self):
        for url in ("mailto:a@b.example", "ftp://a.example.com/x", "file:///etc/passwd",
                    "javascript:alert(1)", "//a.example.com/x", "a.example.com/x"):
            self.assertFalse(TH._is_http_url(url), url)

    def test_rejects_hostless_despite_netloc(self):
        # netloc-only check (the old helper) accepted these; hostname rejects.
        for url in ("https://:8080/x", "https://user@/x", "https://", "http://"):
            self.assertFalse(TH._is_http_url(url), url)

    def test_rejects_malformed_and_control_bearing(self):
        for url in ("https://[::1/x", "https://a.example.com/x\ny", "https://a b.example.com/",
                    "https://a.example.com:99999/x", "https://a.example.com:abc/x",
                    "https://a.example.com:99999/x?q=1",
                    "", None, 42):
            self.assertFalse(TH._is_http_url(url), repr(url))

    def test_admits_valid_explicit_port(self):
        self.assertTrue(TH._is_http_url("https://a.example.com:8443/x?q=1"))
        self.assertTrue(TH._is_http_url("http://[::1]:8080/"))


class TestNonHttpRejection(unittest.TestCase):
    def test_mailto_base_is_rejected(self):
        data = _data({"/x": _endpoint()}, base="mailto:a@b.example")
        (bases, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual((bases, urls), ([], []))

    def test_non_http_composed_urls_are_rejected(self):
        data = _data({"/x": _endpoint()}, base="None/odd")
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(urls, [])

    def test_rejection_counts_are_recorded(self):
        summary = {}
        data = _data({"/x": _endpoint()}, base="mailto:a@b.example", summary=summary)
        _silent(TH.build_target_urls_from_resource_enum, data)
        # 1 rejected base + 1 rejected composed endpoint URL.
        self.assertEqual(summary.get("nuclei_targets_rejected_non_http"), 2)
        self.assertEqual(summary.get("nuclei_targets_dropped_budget"), 0)

    def test_hostless_base_and_endpoint_rejected(self):
        summary = {}
        data = _data({"/x": _endpoint()}, base="https://:8080", summary=summary)
        (bases, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(bases, [])
        self.assertEqual(urls, [])
        self.assertGreaterEqual(summary["nuclei_targets_rejected_non_http"], 1)

    def test_repeated_calls_do_not_accumulate_counts(self):
        summary = {}
        data = _data({"/x": _endpoint()}, base="mailto:a@b.example", summary=summary)
        _silent(TH.build_target_urls_from_resource_enum, data)
        first = dict(summary)
        _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(summary, first)


class TestBudget(unittest.TestCase):
    def test_under_cap_everything_is_kept(self):
        endpoints = {"/p%d" % i: _endpoint() for i in range(10)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(len(urls), 10)

    def test_param_bearing_kept_first_over_cap(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/plain%d" % i: _endpoint() for i in range(cap + 50)}
        endpoints.update({"/with%d" % i: _endpoint(query=[("q", "1")])
                          for i in range(20)})
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints),
                               apply_observed_budget=True)
        self.assertEqual(len(urls), cap)
        with_q = [u for u in urls if "?" in u and "=" in u]
        self.assertEqual(len(with_q), 20)

    def test_path_only_fills_remaining_budget(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/with%d" % i: _endpoint(query=[("q", "1")]) for i in range(10)}
        endpoints.update({"/plain%d" % i: _endpoint() for i in range(cap)})
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints), apply_observed_budget=True)
        self.assertEqual(len(urls), cap)
        plain = [u for u in urls if u.endswith("plain0")]
        self.assertEqual(len(plain), 1)

    def test_overflow_count_recorded(self):
        summary = {}
        endpoints = {"/p%d" % i: _endpoint() for i in range(TH.MAX_RESOURCE_ENUM_NUCLEI_URLS + 7)}
        data = _data(endpoints, summary=summary)
        _silent(TH.build_target_urls_from_resource_enum, data, apply_observed_budget=True)
        self.assertEqual(summary.get("nuclei_targets_dropped_budget"), 7)

    def test_param_bearing_over_cap_drops_path_only_and_counts(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        summary = {}
        endpoints = {"/w%d" % i: _endpoint(query=[("q", "1")]) for i in range(cap + 5)}
        endpoints.update({"/plain%d" % i: _endpoint() for i in range(10)})
        data = _data(endpoints, summary=summary)
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data, apply_observed_budget=True)
        self.assertEqual(len(urls), cap)
        self.assertTrue(all("?" in u for u in urls))
        self.assertEqual(summary["nuclei_targets_dropped_budget"], 15)

    def test_body_and_path_buckets_count_as_param_bearing(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/plain%d" % i: _endpoint() for i in range(cap)}
        endpoints["/body"] = _endpoint(body=[{"name": "x"}])
        endpoints["/pathp"] = _endpoint(path_params=[{"name": "id"}])
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints), apply_observed_budget=True)
        self.assertEqual(len(urls), cap)
        self.assertIn("https://a.example.com/body", urls)
        self.assertIn("https://a.example.com/pathp", urls)

    def test_deterministic_regardless_of_dict_order(self):
        forward = {"/b": _endpoint(), "/a": _endpoint(), "/c": _endpoint(query=[("q", "1")])}
        reverse = dict(reversed(list(forward.items())))
        (_, urls1), _ = _silent(TH.build_target_urls_from_resource_enum, _data(forward))
        (_, urls2), _ = _silent(TH.build_target_urls_from_resource_enum, _data(reverse))
        self.assertEqual(urls1, urls2)
        # Param-bearing first, then path-only in (base, path) order.
        self.assertEqual(urls1, ["https://a.example.com/c?q=1",
                                 "https://a.example.com/a", "https://a.example.com/b"])

    def test_deterministic_across_bases(self):
        data = {"by_base_url": {
            "https://b.example.com": {"endpoints": {"/x": _endpoint()}},
            "https://a.example.com": {"endpoints": {"/x": _endpoint()}},
        }}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(urls, ["https://a.example.com/x", "https://b.example.com/x"])

    def test_declared_only_cap_unchanged(self):
        endpoints = {"/d%d" % i: _endpoint(declared_only=True) for i in range(600)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(len(urls), TH.MAX_DECLARED_NUCLEI_URLS)

    def test_declared_get_head_only_post_excluded_and_not_overflow(self):
        endpoints = {
            "/get": _endpoint(methods=("GET",), declared_only=True),
            "/head": _endpoint(methods=("head",), declared_only=True),
            "/post": _endpoint(methods=("POST",), declared_only=True),
            "/mixed": _endpoint(methods=("POST", "GET"), declared_only=True),
            "/observed-post": _endpoint(methods=("POST",)),
        }
        summary = {}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum,
                               _data(endpoints, summary=summary))
        self.assertIn("https://a.example.com/get", urls)
        self.assertIn("https://a.example.com/head", urls)
        self.assertIn("https://a.example.com/mixed", urls)
        self.assertIn("https://a.example.com/observed-post", urls)
        self.assertNotIn("https://a.example.com/post", urls)
        self.assertEqual(summary["nuclei_targets_dropped_budget"], 0)

    def test_declared_overflow_recorded_on_openapi_not_summary(self):
        endpoints = {"/d%d" % i: _endpoint(declared_only=True) for i in range(550)}
        endpoints["/obs"] = _endpoint()
        data = _data(endpoints)
        data["openapi"] = {"groups": [{"root": "example.com"}]}
        (_, urls), out = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(len([u for u in urls if "/d" in u]), 500)
        self.assertIn("https://a.example.com/obs", urls)
        self.assertEqual(data["openapi"]["groups"][0]["declared_not_sent_to_nuclei"], 50)
        self.assertIn("50 declared endpoints not sent", out)

    def test_empty_parameter_dict_is_not_param_bearing(self):
        endpoints = {"/x": {"methods": ["GET"],
                            "parameters": {"query": [], "body": [], "path": []}}}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(urls, ["https://a.example.com/x"])

    def test_templated_path_never_a_target(self):
        endpoints = {"/users/{id}": _endpoint(), "/users/1": _endpoint()}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(urls, ["https://a.example.com/users/1"])


class TestHttpxBuilderAdmission(unittest.TestCase):
    def test_synthetic_mailto_rejected_despite_status(self):
        data = {"by_url": {
            "mailto:a@b.example": {"status_code": 200},
            "https://ok.example.com": {"status_code": 200},
            "ftp://files.example.com": {"status_code": 200},
            "https://:8080": {"status_code": 200},
        }}
        self.assertEqual(TH.build_target_urls_from_httpx(data), ["https://ok.example.com"])

    def test_status_filter_preserved(self):
        data = {"by_url": {
            "https://a.example.com": {"status_code": 499},
            "https://b.example.com": {"status_code": 500},
            "https://c.example.com": {"status_code": 0},
            "https://d.example.com": {},
        }}
        self.assertEqual(TH.build_target_urls_from_httpx(data), ["https://a.example.com"])


class TestFinalUnionBuilder(unittest.TestCase):
    def _union(self, hostnames, ips, recon, scan_all_ips=False):
        urls, _ = _silent(TH.build_target_urls, hostnames, ips,
                          recon_data=recon, scan_all_ips=scan_all_ips)
        return urls

    def test_mailto_httpx_never_enters_union(self):
        recon = {"http_probe": {"by_url": {
            "mailto:a@b.example": {"status_code": 200},
            "https://ok.example.com": {"status_code": 200}}}}
        urls = self._union(set(), set(), recon)
        self.assertEqual(urls, ["https://ok.example.com"])
        self.assertTrue(all(u.startswith(("http://", "https://")) for u in urls))

    def test_mailto_resource_enum_never_enters_union(self):
        recon = {"resource_enum": {"by_base_url": {
            "mailto:a@b.example": {"endpoints": {"/x": _endpoint()}},
            "https://a.example.com": {"endpoints": {"/x": _endpoint()}}}}}
        urls = self._union({"a.example.com"}, set(), recon)
        self.assertIn("https://a.example.com", urls)
        self.assertIn("https://a.example.com/x", urls)
        self.assertTrue(all(u.startswith(("http://", "https://")) for u in urls))

    def test_legitimate_fallback_preserved(self):
        recon = {"http_probe": {"by_url": {"https://covered.example.com": {"status_code": 200}}}}
        urls = self._union({"covered.example.com", "new.example.com"}, {"1.2.3.4"}, recon,
                           scan_all_ips=True)
        self.assertIn("https://covered.example.com", urls)
        self.assertNotIn("http://covered.example.com", urls)
        self.assertIn("http://new.example.com", urls)
        self.assertIn("https://new.example.com", urls)
        self.assertIn("http://1.2.3.4", urls)

    def test_duplicates_deduped_across_sources(self):
        recon = {
            "resource_enum": {"by_base_url": {"https://a.example.com": {"endpoints": {}}}},
            "http_probe": {"by_url": {"https://a.example.com": {"status_code": 200}}},
        }
        urls = self._union({"a.example.com"}, set(), recon)
        self.assertEqual(urls.count("https://a.example.com"), 1)
        self.assertEqual(len(urls), len(set(urls)))

    def test_repeated_calls_identical(self):
        recon = {
            "resource_enum": {"by_base_url": {"https://a.example.com": {"endpoints": {
                "/x": _endpoint(query=[("q", "1")]), "/y": _endpoint()}}}},
            "http_probe": {"by_url": {"https://b.example.com": {"status_code": 200}}},
        }
        self.assertEqual(self._union({"c.example.com"}, set(), recon),
                         self._union({"c.example.com"}, set(), recon))

    def test_caps_are_per_builder_not_global(self):
        # 3000 capped resource_enum endpoints + bases + httpx + fallback can
        # legitimately exceed 3000 in the union: no global cap is promised.
        endpoints = {"/p%d" % i: _endpoint() for i in range(3005)}
        recon = {
            "resource_enum": {"by_base_url": {"https://a.example.com": {"endpoints": endpoints}}},
            "http_probe": {"by_url": {f"https://h{i}.example.com": {"status_code": 200}
                                      for i in range(5)}},
        }
        urls = self._union({"new.example.com"}, set(), recon)
        self.assertGreater(len(urls), TH.MAX_RESOURCE_ENUM_NUCLEI_URLS)
        self.assertIn("https://h0.example.com", urls)
        self.assertIn("http://new.example.com", urls)


class TestObservedBudgetOptIn(unittest.TestCase):
    def test_generic_preserves_over_3000_observed(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/p%d" % i: _endpoint() for i in range(cap + 100)}
        endpoints.update({"/w%d" % i: _endpoint(query=[("q", "1")]) for i in range(10)})
        summary = {}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum,
                               _data(endpoints, summary=summary))
        self.assertEqual(len(urls), cap + 110)
        self.assertEqual(summary.get("nuclei_targets_dropped_budget"), 0)

    def test_explicit_false_preserves_over_3000(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/p%d" % i: _endpoint() for i in range(cap + 5)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints),
                               apply_observed_budget=False)
        self.assertEqual(len(urls), cap + 5)

    def test_opt_in_caps_at_3000_and_records_overflow(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        summary = {}
        endpoints = {"/p%d" % i: _endpoint() for i in range(cap + 100)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum,
                               _data(endpoints, summary=summary), apply_observed_budget=True)
        self.assertEqual(len(urls), cap)
        self.assertEqual(summary.get("nuclei_targets_dropped_budget"), 100)

    def test_generic_union_preserves_over_3000_but_nuclei_opt_in_caps_slice(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/p%d" % i: _endpoint() for i in range(cap + 50)}
        recon = {"resource_enum": {"by_base_url": {"https://a.example.com": {"endpoints": endpoints}}}}
        generic, _ = _silent(TH.build_target_urls, set(), set(), recon_data=recon)
        nuclei, _ = _silent(TH.build_target_urls, set(), set(), recon_data=recon,
                            apply_observed_budget=True)
        # +1 base URL in each union.
        self.assertEqual(len(generic), cap + 51)
        self.assertEqual(len(nuclei), cap + 1)

    def test_generic_still_applies_declared_cap(self):
        endpoints = {"/d%d" % i: _endpoint(declared_only=True) for i in range(600)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(len(urls), TH.MAX_DECLARED_NUCLEI_URLS)

    def test_opt_in_never_drops_every_path_only_route(self):
        # Under the cap path-only routes are all kept; over the cap they fill
        # the remainder after param-bearing URLs (covered above).
        endpoints = {"/plain%d" % i: _endpoint() for i in range(20)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints),
                               apply_observed_budget=True)
        self.assertEqual(len(urls), 20)
        self.assertTrue(all("?" not in u for u in urls))


class TestDastSelection(unittest.TestCase):
    def test_selects_param_urls_sorted_and_deduped(self):
        urls = ["https://a.example.com/b?q=2", "https://a.example.com/a?q=1",
                "https://a.example.com/b?q=2", "https://a.example.com/plain"]
        selected, stats = TH.select_dast_target_urls(urls)
        self.assertEqual(selected, ["https://a.example.com/a?q=1", "https://a.example.com/b?q=2"])
        self.assertEqual(stats["dast_targets_selected"], 2)
        self.assertEqual(stats["dast_targets_filtered_non_param"], 1)
        self.assertEqual(stats["dast_targets_rejected_non_http"], 0)
        self.assertEqual(stats["dast_targets_dropped_budget"], 0)

    def test_rejects_non_http_bad_port_and_control(self):
        urls = ["mailto:a@b.example?x=1", "ftp://a.example.com/?x=1",
                "https://a.example.com:99999/?x=1", "https://a.example.com:abc/?x=1",
                "https://a.example.com/x\ny?q=1", "https://:8080/?x=1",
                "https://ok.example.com/?x=1", None, 42]
        selected, stats = TH.select_dast_target_urls(urls)
        self.assertEqual(selected, ["https://ok.example.com/?x=1"])
        self.assertEqual(stats["dast_targets_rejected_non_http"], 8)

    def test_equals_must_be_in_query_not_path(self):
        urls = ["https://a.example.com/a=b?x", "https://a.example.com/p?flag",
                "https://a.example.com/p?x=1"]
        selected, stats = TH.select_dast_target_urls(urls)
        self.assertEqual(selected, ["https://a.example.com/p?x=1"])
        self.assertEqual(stats["dast_targets_filtered_non_param"], 2)

    def test_cap_is_deterministic_and_accounted(self):
        urls = ["https://a.example.com/p%03d?q=1" % i for i in range(10)]
        selected, stats = TH.select_dast_target_urls(list(reversed(urls)), cap=4)
        self.assertEqual(selected, sorted(urls)[:4])
        self.assertEqual(stats["dast_targets_dropped_budget"], 6)
        self.assertEqual(stats["dast_targets_selected"], 4)

    def test_default_cap_bounds_at_3000(self):
        urls = ["https://a.example.com/p%04d?q=1" % i for i in range(3007)]
        selected, stats = TH.select_dast_target_urls(urls)
        self.assertEqual(len(selected), TH.MAX_DAST_NUCLEI_URLS)
        self.assertEqual(stats["dast_targets_dropped_budget"], 7)

    def test_empty_and_none_inputs(self):
        self.assertEqual(TH.select_dast_target_urls([])[0], [])
        self.assertEqual(TH.select_dast_target_urls(None)[0], [])


if __name__ == "__main__":
    unittest.main()
