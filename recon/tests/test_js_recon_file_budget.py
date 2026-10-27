"""js_recon shares JS_RECON_MAX_FILES fairly between hosts and records the cut (plan 06.2).

The list was ``list(set(...))[:max_files]``: arbitrary order, no per-host
fairness, and one large site could take the whole budget while a small one got
nothing. Files are now taken round-robin by host, in a deterministic order,
first-party bundles before vendor ones; each host's candidates / selected / cut
lands in scan_metadata; the cut hosts (only those) are kept out of the prune;
and the cut reaches the report's Coverage Limitations as a file-cap note.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

BIG, SMALL_A, SMALL_B = "big.example.com", "a.example.com", "b.example.com"
BIG_URLS = [f"https://{BIG}/static/js/{n}.js" for n in (
    "vendors~main.11", "framework-22", "main.33", "chunk-44", "chunk-55",
    "polyfills-66", "app-77", "runtime-88", "pages/index-99", "lib-00")]
URLS = BIG_URLS + [f"https://{SMALL_A}/js/site.js", f"https://{SMALL_B}/assets/widget.js"]

SETTINGS = {
    "JS_RECON_MAX_FILES": 6, "JS_RECON_REGEX_PATTERNS": True, "JS_RECON_SOURCE_MAPS": False,
    "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_EXTRACT_ENDPOINTS": False,
    "JS_RECON_FRAMEWORK_DETECT": False, "JS_RECON_DOM_SINKS": False, "JS_RECON_DEV_COMMENTS": False,
    "JS_RECON_AI_SDK_DETECTION_ENABLED": False, "JS_RECON_VALIDATE_KEYS": False, "JS_RECON_TIMEOUT": 30,
}


def _host(u):
    return u.split("/")[2]


def test_every_host_is_represented_under_the_cap():
    selected, _ = js_recon._select_js_urls(list(URLS), 6)
    assert len(selected) == 6
    assert {_host(u) for u in selected} == {BIG, SMALL_A, SMALL_B}


def test_the_order_is_deterministic_whatever_the_input_order():
    first, _ = js_recon._select_js_urls(list(URLS), 6)
    for shuffled in (list(reversed(URLS)), URLS[5:] + URLS[:5], sorted(URLS)):
        assert js_recon._select_js_urls(shuffled, 6)[0] == first


def test_first_party_bundles_go_first_and_vendor_files_last():
    selected, _ = js_recon._select_js_urls(BIG_URLS, 10)
    names = [u.rsplit("/static/js/", 1)[1] for u in selected]
    first_party = {"main.33.js", "app-77.js", "pages/index-99.js"}
    vendor = {"vendors~main.11.js", "framework-22.js", "polyfills-66.js", "runtime-88.js", "lib-00.js"}
    assert set(names[:3]) == first_party
    assert set(names[-5:]) == vendor


def test_per_host_counts():
    _, by_host = js_recon._select_js_urls(list(URLS), 6)
    big = by_host[f"{BIG}:443"]
    assert (big["candidates"], big["selected"], big["cut"]) == (10, 4, 6)
    assert by_host[f"{SMALL_A}:443"] == {"candidates": 1, "selected": 1, "cut": 0}
    assert by_host[f"{SMALL_B}:443"] == {"candidates": 1, "selected": 1, "cut": 0}


def test_no_cap_reached_selects_everything():
    selected, by_host = js_recon._select_js_urls(list(URLS), 100)
    assert sorted(selected) == sorted(URLS)
    assert all(v["cut"] == 0 for v in by_host.values())


def _fake_download(urls, work_dir, max_files, **_kw):
    return [{"url": u, "filepath": "", "content": "var a = 1;\n", "headers": {}, "size": 11}
            for u in urls[:max_files]]


def _run(settings=None):
    combined = {"metadata": {}, "http_probe": {"by_url": {}}, "resource_enum": {"discovered_urls": []}}
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(URLS)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_fake_download) as dl:
        out = js_recon.run_js_recon(combined, dict(SETTINGS, **(settings or {})))
    return out, dl


def test_the_run_downloads_the_fair_selection_and_records_it():
    out, dl = _run()
    assert sorted(dl.call_args.args[0]) == sorted(js_recon._select_js_urls(list(URLS), 6)[0])
    budget = out["js_recon"]["scan_metadata"]["file_budget"]
    assert (budget["max_files"], budget["candidates"], budget["selected"], budget["cut"]) == (6, 12, 6, 6)
    assert budget["by_host"][f"{BIG}:443"]["cut"] == 6


def test_only_the_cut_host_is_kept_out_of_the_prune():
    _run()
    report = cb.coverage_report()
    assert "js_recon" not in report.degraded_sources
    assert report.keep_hostnames("js_recon") == (BIG,)


def test_the_cut_reaches_the_coverage_limitations_as_a_file_cap_note():
    _run()
    [gap] = [g for g in cb.coverage_report().gaps if g["source"] == "js_recon_file_cap"]
    assert gap["skipped"] == 6
    assert "file cap" in gap["reason"]
    assert re.fullmatch(r"[a-z0-9_]{1,64}", gap["source"])


def test_an_uncut_run_records_no_file_cap():
    out, _ = _run({"JS_RECON_MAX_FILES": 100})
    assert out["js_recon"]["scan_metadata"]["file_budget"]["cut"] == 0
    assert not [g for g in cb.coverage_report().gaps if g["source"] == "js_recon_file_cap"]
    assert cb.coverage_report().keep_hostnames("js_recon") == ()


def test_the_code_fallback_is_the_settings_default():
    from recon.project_settings import DEFAULT_SETTINGS
    assert js_recon._default_max_files() == DEFAULT_SETTINGS["JS_RECON_MAX_FILES"]
