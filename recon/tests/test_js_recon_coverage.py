"""js_recon records, per web host, what it analyzed (plan 09.1).

Before, the only coverage record was per run and per org (what was CUT), so "no
Secret on app.example.com" could mean analyzed-and-clean, js_recon off, no JS
from the crawler, or the file cap. run_js_recon now writes
``scan_metadata.coverage = {"at", "hosts": {base_url: row}}`` with one row per
host it considered: http_probe's live hosts, the hosts it was handed pages on,
and the hosts serving a JS candidate. A host it never considered gets no row,
so the graph writer leaves its BaseURL unstamped and a reader can say "not
scanned" instead of "clean".
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.coverage_stamps import STATUSES, base_url_key  # noqa: E402
from recon.main_recon_modules import js_recon  # noqa: E402

APP, WWW, CDN = "app.example.com", "www.example.com", "static.example.com"
APP_JS = [f"https://{APP}/static/js/main.{n}.js" for n in (1, 2)]

SETTINGS = {"JS_RECON_MAX_FILES": 100, "JS_RECON_TIMEOUT": 30, "JS_RECON_VALIDATE_KEYS": False}


def _combined(live=(APP, WWW), discovered=(), status=200):
    return {
        "metadata": {},
        "http_probe": {"by_url": {f"https://{h}": {"status_code": status} for h in live}},
        "resource_enum": {"discovered_urls": list(discovered)},
    }


def _analysis(secret_urls=(), unanalyzed=()):
    return {
        "secrets": [{"id": f"s{i}", "name": "Generic Token", "matched_text": "x" * 24,
                     "source_url": u, "severity": "low"} for i, u in enumerate(secret_urls)],
        "endpoints": [], "source_maps": [], "dependencies": [], "dom_sinks": [], "frameworks": [],
        "dev_comments": [], "cloud_assets": [], "emails": [], "ip_addresses": [],
        "object_references": [], "dev_references": [], "ai_sdk_findings": [],
        "_source_map_files": 0, "_endpoint_extraction_files": 0,
        "_unanalyzed_urls": list(unanalyzed),
    }


def _download_ok(urls, work_dir, max_files, unreachable=None, **_kw):
    return [{"url": u, "filepath": "", "content": "var a = 1;\n", "headers": {}, "size": 11}
            for u in urls[:max_files]]


def _download_failing(dead_hosts):
    def fake(urls, work_dir, max_files, unreachable=None, **_kw):
        out = []
        for u in urls[:max_files]:
            if u.split("/")[2] in dead_hosts:
                if unreachable is not None:
                    unreachable.append(u)
                continue
            out.append({"url": u, "filepath": "", "content": "var a = 1;\n", "headers": {}, "size": 11})
        return out
    return fake


def _run(combined, js_urls, *, download=_download_ok, analysis=None, settings=None):
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(js_urls)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=download), \
            mock.patch.object(js_recon, "_run_analysis", return_value=analysis or _analysis()):
        out = js_recon.run_js_recon(combined, dict(SETTINGS, **(settings or {})))
    return out["js_recon"]["scan_metadata"]["coverage"]


def _row(coverage, host):
    return coverage["hosts"].get(base_url_key(f"https://{host}"))


def test_a_host_whose_js_was_read_is_complete_with_its_counts():
    cov = _run(_combined(), APP_JS, analysis=_analysis(secret_urls=[APP_JS[0]]))
    assert _row(cov, APP) == {"status": "complete", "inputs": 2, "outputs": 1, "reason": None}


def test_a_live_host_with_no_js_is_no_input():
    cov = _run(_combined(), APP_JS)
    assert _row(cov, WWW) == {"status": "no_input", "inputs": 0, "outputs": 0, "reason": None}


def test_a_host_the_run_never_considered_gets_no_row():
    # A 5xx answer is not live (the same test as _has_live_urls), and a host
    # the Rules of Engagement exclude is never looked at.
    combined = _combined(live=(APP, WWW, "down.example.com", "secret.example.com"))
    combined["http_probe"]["by_url"]["https://down.example.com"]["status_code"] = 503
    cov = _run(combined, APP_JS, settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["secret.example.com"]})
    assert _row(cov, "down.example.com") is None
    assert _row(cov, "secret.example.com") is None
    assert set(cov["hosts"]) == {base_url_key(f"https://{APP}"), base_url_key(f"https://{WWW}")}


def test_a_host_serving_a_candidate_is_considered_even_unprobed():
    cdn_js = f"https://{CDN}/bundle.js"
    cov = _run(_combined(), APP_JS + [cdn_js])
    assert _row(cov, CDN)["status"] == "complete"


def test_the_file_cap_makes_the_cut_host_partial():
    big = [f"https://{APP}/static/js/chunk-{n}.js" for n in range(5)]
    small = [f"https://{WWW}/site.js"]
    cov = _run(_combined(), big + small, settings={"JS_RECON_MAX_FILES": 3})
    assert _row(cov, APP) == {"status": "partial", "inputs": 2, "outputs": 0, "reason": "file cap"}
    assert _row(cov, WWW)["status"] == "complete"


def test_an_unreachable_host_failed_and_a_half_reached_one_is_partial():
    other = [f"https://{WWW}/site.js"]
    cov = _run(_combined(), APP_JS + other, download=_download_failing({APP}))
    assert _row(cov, APP) == {"status": "failed", "inputs": 0, "outputs": 0, "reason": "host unreachable"}
    assert _row(cov, WWW)["status"] == "complete"

    def half(urls, work_dir, max_files, unreachable=None, **_kw):
        unreachable.append(APP_JS[1])
        return _download_ok([APP_JS[0]], work_dir, max_files)
    cov = _run(_combined(), APP_JS, download=half)
    assert _row(cov, APP) == {"status": "partial", "inputs": 1, "outputs": 0, "reason": "host unreachable"}


def test_a_file_an_analyzer_dropped_makes_its_host_partial():
    cov = _run(_combined(), APP_JS, analysis=_analysis(unanalyzed=[APP_JS[1]]))
    assert _row(cov, APP) == {"status": "partial", "inputs": 2, "outputs": 0,
                              "reason": "analyzer failed or timed out"}


def test_candidates_that_were_not_javascript_leave_the_host_no_input():
    # Every candidate answered, none was JS (a catch-all serving HTML for *.js).
    cov = _run(_combined(), APP_JS, download=lambda *a, **k: [])
    assert _row(cov, APP)["status"] == "no_input"


def test_a_fatal_error_fails_every_considered_host_with_the_reason():
    with mock.patch.object(js_recon, "_collect_js_urls", return_value=list(APP_JS)), \
            mock.patch.object(js_recon, "_download_js_files", side_effect=_download_ok), \
            mock.patch.object(js_recon, "_run_analysis", side_effect=RuntimeError("boom")):
        out = js_recon.run_js_recon(_combined(), dict(SETTINGS))
    cov = out["js_recon"]["scan_metadata"]["coverage"]
    assert {row["status"] for row in cov["hosts"].values()} == {"failed"}
    assert _row(cov, APP)["reason"] == "fatal: RuntimeError"
    assert _row(cov, WWW)["reason"] == "fatal: RuntimeError"


def test_a_run_with_no_js_anywhere_still_records_coverage():
    cov = _run(_combined(), [])
    assert {row["status"] for row in cov["hosts"].values()} == {"no_input"}
    assert len(cov["hosts"]) == 2


def test_a_partial_run_considers_the_hosts_it_was_handed():
    # Partial JS Recon has no http_probe answers: its targets arrive as pages.
    combined = {"metadata": {}, "http_probe": {"by_url": {}},
                "resource_enum": {"discovered_urls": [f"https://{WWW}/about"], "js_urls": APP_JS}}
    cov = _run(combined, APP_JS)
    assert _row(cov, APP)["status"] == "complete"
    assert _row(cov, WWW)["status"] == "no_input"


def test_uploaded_files_are_no_host():
    with mock.patch.object(js_recon, "_load_uploaded_files", return_value=[
            {"url": "upload://bundle.js", "filepath": "", "content": "var a;", "headers": {}, "size": 6}]):
        cov = _run(dict(_combined(), metadata={"project_id": "p1"}), [])
    assert all(not key.startswith("upload") for key in cov["hosts"])


def test_the_stamp_time_is_the_run_start_in_utc_and_every_status_is_known():
    before = datetime.now().astimezone()
    cov = _run(_combined(), APP_JS)
    at = datetime.fromisoformat(cov["at"])
    assert at.tzinfo is not None and at.utcoffset().total_seconds() == 0
    assert (at - before).total_seconds() < 60
    assert all(row["status"] in STATUSES for row in cov["hosts"].values())


def test_base_url_key_is_one_spelling_per_web_service():
    assert base_url_key("https://App.Example.com/x.js") == "https://app.example.com:443"
    assert base_url_key("https://app.example.com:443") == "https://app.example.com:443"
    assert base_url_key("http://app.example.com:8080/a?b=1") == "http://app.example.com:8080"
    assert base_url_key("https://[2001:db8::1]/a.js") == "https://[2001:db8::1]:443"
    assert base_url_key("https://cdn.example.com/x.js.map#src/app.ts") == "https://cdn.example.com:443"
    assert base_url_key("upload://bundle.js") == ""
    assert base_url_key("") == ""
