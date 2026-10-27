"""Regression: a js_recon run that re-checked nothing deleted the earlier js_recon findings.

run_js_recon catches its own errors, so main's `except` -> _note_phase_error
never fired, and nothing called note_degraded. When js_recon got no JS file
(resource_enum off or failed, a crawl that found nothing usable), crashed
inside, hit JS_RECON_MAX_FILES, or lost an analyzer to a failure or timeout,
the end-of-run prune read "not reported this run" as "gone" and deleted every
earlier JS secret and finding. A run with no live target at all is not a gap.

Downloads and Neo4j are fakes; the analyzers run for real on tiny files.
"""
from __future__ import annotations

import re
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

HOST_A, HOST_B, HOST_C = "192.0.2.10", "192.0.2.11", "198.51.100.7"

# Every analyzer off but the pattern scan: the run still goes end to end.
SETTINGS = {
    "JS_RECON_MAX_FILES": 500, "JS_RECON_REGEX_PATTERNS": True, "JS_RECON_SOURCE_MAPS": False,
    "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_EXTRACT_ENDPOINTS": False,
    "JS_RECON_FRAMEWORK_DETECT": False, "JS_RECON_DOM_SINKS": False, "JS_RECON_DEV_COMMENTS": False,
    "JS_RECON_AI_SDK_DETECTION_ENABLED": False, "JS_RECON_VALIDATE_KEYS": False,
    "JS_RECON_VALIDATE_ENDPOINTS": False, "JS_RECON_TIMEOUT": 30,
}


def _combined(live=True, discovered=()):
    by_url = {f"http://{HOST_A}": {"status_code": 200}} if live else {}
    return {"metadata": {}, "http_probe": {"by_url": by_url},
            "resource_enum": {"discovered_urls": list(discovered)}}


def _fake_download(urls, work_dir, max_files, **_kw):
    return [{"url": u, "filepath": "", "content": "var a = 1;\n", "headers": {}, "size": 11}
            for u in urls[:max_files]]


def _run(combined, settings=None, urls=None):
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(urls or [])), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_fake_download):
        return js_recon.run_js_recon(combined, dict(SETTINGS, **(settings or {})))


def _js_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "js_recon"]


class TestNoJsInput:
    def test_regression_live_urls_but_no_js_file_pruned_the_findings(self):
        out = _run(_combined(live=True))
        assert out["js_recon"]["scan_metadata"]["js_files_analyzed"] == 0
        report = cb.coverage_report()
        assert "js_recon" in report.degraded_sources
        assert any("no JS input" in g["reason"] for g in _js_gaps())

    def test_js_urls_that_all_failed_to_download_are_no_input_too(self):
        with mock.patch.object(js_recon, "_collect_js_urls", return_value=[f"http://{HOST_A}/a.js"]), \
                mock.patch.object(js_recon, "_download_js_files", return_value=[]):
            js_recon.run_js_recon(_combined(live=True), dict(SETTINGS))
        assert "js_recon" in cb.coverage_report().degraded_sources

    def test_an_uploaded_file_does_not_hide_that_the_pipeline_gave_none(self):
        upload = {"url": "upload://bundle.js", "filepath": "", "content": "var a=1;", "headers": {}, "size": 8}
        with mock.patch.object(js_recon, "_load_uploaded_files", return_value=[upload]):
            _run(dict(_combined(live=True), metadata={"project_id": "p1"}))
        assert "js_recon" in cb.coverage_report().degraded_sources

    def test_no_live_target_at_all_is_not_a_gap(self):
        _run(_combined(live=False))
        assert not cb.coverage_report().degraded

    def test_live_urls_listed_per_host_count_as_a_live_target(self):
        combined = _combined(live=False)
        combined["http_probe"]["by_host"] = {HOST_A: {"live_urls": [f"http://{HOST_A}/"]}}
        _run(combined)
        assert "js_recon" in cb.coverage_report().degraded_sources

    def test_only_5xx_answers_are_no_live_target(self):
        combined = _combined(live=False)
        combined["http_probe"]["by_url"] = {f"http://{HOST_A}": {"status_code": 502}}
        _run(combined)
        assert not cb.coverage_report().degraded

    def test_a_clean_run_degrades_nothing(self):
        _run(_combined(live=True), urls=[f"http://{HOST_A}/a.js"])
        assert not cb.coverage_report().degraded


class TestFatalError:
    def test_regression_a_crash_inside_pruned_the_findings(self):
        with mock.patch.object(js_recon, "_collect_js_urls", side_effect=RuntimeError("boom")):
            out = js_recon.run_js_recon(_combined(live=True), dict(SETTINGS))
        assert "boom" in out["js_recon"]["scan_metadata"]["error"]
        assert "js_recon" in cb.coverage_report().degraded_sources
        assert any("fatal: RuntimeError" in g["reason"] for g in _js_gaps())


class TestFileCap:
    URLS = [f"http://{HOST_A}/a.js", f"http://{HOST_A}/b.js", f"http://{HOST_B}/c.js",
            f"https://{HOST_C}/d.js"]

    def test_regression_a_capped_run_keeps_only_the_cut_files_hosts(self):
        # The budget is shared round-robin by host (plan 06.2): A's first file
        # and B's only one are analyzed, A's second and C's are cut.
        _run(_combined(live=True), settings={"JS_RECON_MAX_FILES": 2}, urls=self.URLS)
        report = cb.coverage_report()
        assert "js_recon" not in report.degraded_sources
        assert report.keep_hostnames("js_recon") == (HOST_A, HOST_C)
        # Cut for js_recon alone: every other source re-checked those hosts.
        assert report.keep_hostnames("nuclei") == ()
        assert any("file cap" in g["reason"] for g in _js_gaps())

    def test_an_uncapped_run_keeps_no_host(self):
        _run(_combined(live=True), settings={"JS_RECON_MAX_FILES": 10}, urls=self.URLS)
        assert cb.coverage_report().keep_hostnames("js_recon") == ()


class TestAnalyzerFailure:
    URLS = [f"http://{HOST_A}/a.js", f"http://{HOST_B}/b.js"]

    def test_a_failed_analyzer_keeps_every_analyzed_files_host(self):
        with mock.patch.object(js_recon, "extract_endpoints", side_effect=RuntimeError("parser")):
            _run(_combined(live=True), settings={"JS_RECON_EXTRACT_ENDPOINTS": True}, urls=self.URLS)
        report = cb.coverage_report()
        assert "js_recon" not in report.degraded_sources
        assert report.keep_hostnames("js_recon") == (HOST_A, HOST_B)
        assert any("analyzer" in g["reason"] for g in _js_gaps())

    def test_a_timed_out_analyzer_does_too(self):
        # JS_RECON_TIMEOUT 0 still waits the 1s floor in _run_analysis.
        release = threading.Event()

        def slow(*_a, **_k):
            release.wait(5)
            return []

        try:
            with mock.patch.object(js_recon, "extract_endpoints", side_effect=slow):
                _run(_combined(live=True), urls=self.URLS,
                     settings={"JS_RECON_EXTRACT_ENDPOINTS": True, "JS_RECON_TIMEOUT": 0})
        finally:
            release.set()
        assert cb.coverage_report().keep_hostnames("js_recon") == (HOST_A, HOST_B)

    def test_a_file_one_analyzer_failed_on_keeps_only_its_host(self):
        real = js_recon.scan_js_content

        def flaky(content, url, **kw):
            if HOST_B in url:
                raise ValueError("bad file")
            return real(content, url, **kw)

        with mock.patch.object(js_recon, "scan_js_content", side_effect=flaky):
            _run(_combined(live=True), urls=self.URLS)
        assert cb.coverage_report().keep_hostnames("js_recon") == (HOST_B,)


class TestCoverageNotes:
    def test_every_gap_source_is_a_token_the_recon_delta_accepts(self):
        with mock.patch.object(js_recon, "_collect_js_urls", side_effect=RuntimeError("boom")):
            js_recon.run_js_recon(_combined(live=True), dict(SETTINGS))
        _run(_combined(live=True), settings={"JS_RECON_MAX_FILES": 1}, urls=TestFileCap.URLS)
        gaps = cb.coverage_report().gaps
        assert gaps
        assert all(re.fullmatch(r"[a-z0-9_]{1,64}", g["source"]) for g in gaps)


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': [HOST_A],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['js_recon'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        yield rm


def _prunes(rm, monkeypatch):
    calls = []

    class _Graph:
        def __call__(self, *a, **k):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def verify_connection(self):
            return True

        def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
            calls.append((list(sources), tuple(keep_hosts)))

    monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
    monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", True)
    monkeypatch.setattr(rm, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")
    monkeypatch.setattr(rm, "_COVERAGE_WRITE_FAILED", False)
    rm._prune_recon_findings()
    return calls


class TestThePrune:
    def test_no_js_input_leaves_js_recon_out_of_the_prune(self, recon_main, monkeypatch):
        _run(_combined(live=True))
        calls = _prunes(recon_main, monkeypatch)
        assert calls and all("js_recon" not in sources for sources, _ in calls)

    def test_a_capped_run_still_prunes_the_hosts_it_analyzed(self, recon_main, monkeypatch):
        _run(_combined(live=True), settings={"JS_RECON_MAX_FILES": 2}, urls=TestFileCap.URLS)
        calls = _prunes(recon_main, monkeypatch)
        js = [keep for sources, keep in calls if "js_recon" in sources]
        assert js == [(HOST_A, HOST_C)]
        others = [keep for sources, keep in calls if "js_recon" not in sources]
        assert others and all(keep == () for keep in others)
