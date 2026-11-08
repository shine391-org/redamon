"""Regression tests for the Nuclei target-builder budget and scheme filter.

`build_target_urls_from_resource_enum` previously appended every observed
endpoint to the nuclei target list with no scheme check and no total budget,
so a large resource-enum corpus (thousands of path-only URLs, plus occasional
non-HTTP strings such as ``mailto:``) fanned straight into nuclei.

These tests pin the fix:
- non-HTTP base URLs and non-HTTP composed URLs are rejected, never sent;
- ordinary endpoints are capped at MAX_RESOURCE_ENUM_NUCLEI_URLS per run,
  parameter-bearing URLs first, path-only URLs filling the remaining budget;
- overflow and rejection counts are recorded on the run summary;
- ``declared_only`` behaviour is unchanged.

Run:
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


def _endpoint(methods=("GET",), declared_only=None, query=(), body=()):
    entry = {
        "methods": list(methods),
        "parameters": {
            "query": [{"name": n, "sample_values": [v] if v else []} for n, v in query],
            "body": list(body),
            "path": [],
        },
    }
    if declared_only is not None:
        entry["declared_only"] = declared_only
    return entry


def _silent(fn, data):
    buf = io.StringIO()
    with redirect_stdout(buf):
        out = fn(data)
    return out, buf.getvalue()


def _data(endpoints, base="https://a.example.com", summary=None):
    data = {"by_base_url": {base: {"endpoints": endpoints}}}
    if summary is not None:
        data["summary"] = summary
    return data


class TestNonHttpRejection(unittest.TestCase):
    def test_mailto_base_is_rejected(self):
        data = _data({"/x": _endpoint()}, base="mailto:a@b.example")
        (bases, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(bases, [])
        self.assertEqual(urls, [])

    def test_non_http_composed_urls_are_rejected(self):
        data = _data({"/x": _endpoint()}, base="None/odd")
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(urls, [])

    def test_rejection_counts_are_recorded(self):
        summary = {}
        data = _data({"/x": _endpoint()}, base="mailto:a@b.example", summary=summary)
        _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertGreaterEqual(summary.get("nuclei_targets_rejected_non_http", 0), 1)


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
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(len(urls), cap)
        with_q = [u for u in urls if "?" in u and "=" in u]
        self.assertEqual(len(with_q), 20)

    def test_path_only_fills_remaining_budget(self):
        cap = TH.MAX_RESOURCE_ENUM_NUCLEI_URLS
        endpoints = {"/with%d" % i: _endpoint(query=[("q", "1")]) for i in range(10)}
        endpoints.update({"/plain%d" % i: _endpoint() for i in range(cap)})
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(len(urls), cap)
        plain = [u for u in urls if u.endswith("plain0")]
        self.assertEqual(len(plain), 1)

    def test_overflow_count_recorded(self):
        summary = {}
        endpoints = {"/p%d" % i: _endpoint() for i in range(TH.MAX_RESOURCE_ENUM_NUCLEI_URLS + 7)}
        data = _data(endpoints, summary=summary)
        _silent(TH.build_target_urls_from_resource_enum, data)
        self.assertEqual(summary.get("nuclei_targets_dropped_budget"), 7)

    def test_declared_only_cap_unchanged(self):
        endpoints = {"/d%d" % i: _endpoint(declared_only=True) for i in range(600)}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(len(urls), TH.MAX_DECLARED_NUCLEI_URLS)

    def test_empty_parameter_dict_is_not_param_bearing(self):
        # Truthy dict, empty buckets: must count as path-only, still kept.
        endpoints = {"/x": {"methods": ["GET"],
                            "parameters": {"query": [], "body": [], "path": []}}}
        (_, urls), _ = _silent(TH.build_target_urls_from_resource_enum, _data(endpoints))
        self.assertEqual(urls, ["https://a.example.com/x"])


if __name__ == "__main__":
    unittest.main()
