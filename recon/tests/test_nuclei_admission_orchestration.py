"""Fresh orchestration tests for Nuclei target admission (not helper-only).

Invokes the real ``run_vuln_scan`` with Docker/scanner/network stubbed,
asserting:
- the detection consumer passes ``apply_observed_budget=True`` (explicit
  Nuclei opt-in; generic ``build_target_urls`` callers stay uncapped);
- the detection target file built by the real builder contains the
  param-bearing and path-only endpoints;
- the DAST target file is built from ``resource_enum.discovered_urls`` via
  the bounded selector: non-HTTP / bad-port / control URLs are excluded,
  non-param URLs are excluded, the per-pass cap (3000) is honoured, and
  dropped/rejected counts land in ``scan_metadata``;
- ``build_nuclei_command`` consumer args for both passes (detection vs
  ``force_dast_pass`` DAST, distinct targets files).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import nuclei_helpers as nh  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402
from recon.helpers.target_helpers import MAX_DAST_NUCLEI_URLS  # noqa: E402

SECURITY_RESULT = {"security_checks": {"findings": []}}


def _settings(**extra):
    base = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"],
            "NUCLEI_DAST_MODE": True, "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
            "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False,
            "NUCLEI_MAX_RUNTIME": 0, "NUCLEI_SCAN_ALL_IPS": False}
    base.update(extra)
    return base


@pytest.fixture
def harness(monkeypatch):
    """Stub everything around the Nuclei passes; capture files + commands."""
    state = {"passes": [], "commands": [], "build_calls": [], "build_urls_calls": []}
    real_build = nh.build_nuclei_command

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        # The docker command maps the host temp dir to /targets inside the
        # container ("-v HOST:/targets:ro", "-l /targets/<file>"): read the
        # host side, not the container path.
        host_dir = next((a.rsplit(":/targets:ro", 1)[0]
                         for a in cmd if a.endswith(":/targets:ro")), None)
        name = next((Path(a).name for a in cmd
                     if a.endswith(("targets_detection.txt", "targets_dast.txt"))), None)
        targets = str(Path(host_dir) / name) if host_dir and name else None
        lines = Path(targets).read_text().splitlines() if targets else []
        state["passes"].append({"label": label, "cmd": list(cmd),
                                "targets_file": targets, "targets": lines})
        return [], [], 1.0, 0

    def spy_build(**kwargs):
        state["build_calls"].append(kwargs)
        state["commands"].append(real_build(**kwargs))
        return state["commands"][-1]

    def recording_build_urls(hostnames, ips, recon_data, scan_all_ips=False, **kw):
        state["build_urls_calls"].append({"scan_all_ips": scan_all_ips, **kw})
        # Delegate to the real builder so the target file is genuinely built.
        from recon.helpers.target_helpers import build_target_urls as real
        return real(hostnames, ips, recon_data, scan_all_ips=scan_all_ips, **kw)

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon",
                        lambda rd: ([], ["example.com"], {}))
    monkeypatch.setattr(vs, "build_target_urls", recording_build_urls)
    monkeypatch.setattr(vs, "build_nuclei_command", spy_build)
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    monkeypatch.setattr(vs, "run_security_checks", lambda **kw: SECURITY_RESULT)
    monkeypatch.setattr(vs, "run_cve_lookup", lambda **kw: {})
    return state


def _endpoint(query=()):
    return {"methods": ["GET"], "parameters": {
        "query": [{"name": n, "sample_values": ["1"]} for n, _ in query],
        "body": [], "path": []}}


def _recon(discovered):
    return {
        "domain": "example.com",
        "http_probe": {"by_url": {}},
        "resource_enum": {
            "by_base_url": {"https://example.com": {"endpoints": {
                "/search": _endpoint(query=[("q", "x")]),
                "/about": _endpoint(),
            }}},
            "discovered_urls": discovered,
        },
    }


class TestDetectionOptIn:
    def test_detection_consumer_opts_in_and_files_are_built(self, harness):
        out = vs.run_vuln_scan(_recon(["https://example.com/search?q=1"]),
                               settings=_settings())
        # 1. Explicit opt-in from the Nuclei detection consumer.
        assert harness["build_urls_calls"] == [
            {"scan_all_ips": False, "apply_observed_budget": True}]
        # 2. Two passes, ordered, with distinct targets files.
        assert [p["label"] for p in harness["passes"]] == ["DETECTION", "DAST"]
        detection, dast = harness["passes"]
        assert detection["targets_file"].endswith("targets_detection.txt")
        assert dast["targets_file"].endswith("targets_dast.txt")
        assert detection["targets_file"] != dast["targets_file"]
        # 3. Real builder output: base + param endpoint + path-only endpoint
        #    (path-only routes are never all dropped from detection).
        assert "https://example.com" in detection["targets"]
        assert "https://example.com/search?q=1" in detection["targets"]
        assert "https://example.com/about" in detection["targets"]
        # 4. DAST file: only the param URL.
        assert dast["targets"] == ["https://example.com/search?q=1"]
        # 5. Consumer args: detection is not DAST, DAST forces the flag.
        assert harness["build_calls"][0].get("force_dast_pass", False) is False
        assert harness["build_calls"][1].get("force_dast_pass") is True
        assert harness["build_calls"][0]["targets_file"] == detection["targets_file"]
        assert harness["build_calls"][1]["targets_file"] == dast["targets_file"]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_pass_executed"] is True
        assert meta["dast_urls_discovered"] == 1
        assert meta["dast_urls_rejected_non_http"] == 0
        assert meta["dast_urls_dropped_budget"] == 0


class TestDastAdmissionThroughOrchestration:
    def test_bad_urls_excluded_and_accounted(self, harness):
        discovered = [
            "https://example.com/search?q=1",
            "https://example.com/search?q=1",          # duplicate
            "https://example.com/plain",                # non-param
            "mailto:a@b.example?x=1",
            "ftp://example.com/?x=1",
            "https://example.com:99999/?x=1",
            "https://example.com/x\ny?q=1",
            "https://example.com/a=b?x",                # '=' in path only
        ]
        out = vs.run_vuln_scan(_recon(discovered), settings=_settings())
        dast = harness["passes"][1]
        assert dast["targets"] == ["https://example.com/search?q=1"]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_urls_rejected_non_http"] == 4
        assert meta["dast_urls_filtered_non_param"] == 2
        assert meta["dast_urls_dropped_budget"] == 0
        assert out["vuln_scan"]["discovered_urls"]["dast_urls_with_params"] == [
            "https://example.com/search?q=1"]

    def test_dast_per_pass_cap_and_dropped_accounting(self, harness):
        discovered = [f"https://example.com/p{i:04d}?q=1"
                      for i in range(MAX_DAST_NUCLEI_URLS + 7)]
        out = vs.run_vuln_scan(_recon(discovered), settings=_settings())
        dast = harness["passes"][1]
        assert len(dast["targets"]) == MAX_DAST_NUCLEI_URLS
        assert dast["targets"] == sorted(discovered)[:MAX_DAST_NUCLEI_URLS]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_urls_dropped_budget"] == 7
        assert meta["dast_urls_discovered"] == MAX_DAST_NUCLEI_URLS

    def test_no_param_urls_falls_back_to_single_pass(self, harness):
        out = vs.run_vuln_scan(_recon(["https://example.com/plain"]),
                               settings=_settings())
        assert [p["label"] for p in harness["passes"]] == ["DETECTION"]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_pass_executed"] is False
        assert meta["dast_urls_filtered_non_param"] == 1

    def test_dast_off_runs_only_detection_even_with_param_urls(self, harness):
        out = vs.run_vuln_scan(_recon(["https://example.com/search?q=1"]),
                               settings=_settings(NUCLEI_DAST_MODE=False))
        assert [p["label"] for p in harness["passes"]] == ["DETECTION"]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_mode"] is False
        assert meta["dast_urls_discovered"] == 0
