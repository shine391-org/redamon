"""Pin upstream admission after withdrawing Group B, without active scans.

The real run_vuln_scan builds both target files; only Docker/scanner/network
boundaries are replaced. These tests do not implement a new planner or dedup.
"""
from pathlib import Path

from recon.helpers import target_helpers as th
from recon.helpers.target_helpers import (
    MAX_DECLARED_NUCLEI_URLS,
    build_target_urls_from_resource_enum,
)


def _observed_data(n: int) -> dict:
    return {
        "by_base_url": {
            "https://a.example.com": {
                "endpoints": {
                    f"/p{i:05d}": {
                        "parameters": {"query": [{"name": "q", "sample_values": ["1"]}]},
                    }
                    for i in range(n)
                }
            }
        }
    }


def test_no_budget_symbols_present():
    assert not hasattr(th, "MAX_RESOURCE_ENUM_NUCLEI_URLS")
    assert not hasattr(th, "MAX_DAST_NUCLEI_URLS")
    assert not hasattr(th, "select_dast_target_urls")


def test_large_observed_inputs_preserved_above_3000():
    n = 3001
    _, urls = build_target_urls_from_resource_enum(_observed_data(n))
    assert len(urls) == n
    assert len(set(urls)) == n


def test_declared_only_500_cap_still_holds():
    endpoints = {
        f"/d{i:05d}": {"declared_only": True, "methods": ["GET"], "parameters": {}}
        for i in range(MAX_DECLARED_NUCLEI_URLS + 25)
    }
    data = {"by_base_url": {"https://a.example.com": {"endpoints": endpoints}}}
    _, urls = build_target_urls_from_resource_enum(data)
    assert len(urls) == MAX_DECLARED_NUCLEI_URLS == 500


def _run_pipeline(monkeypatch, resource, dast):
    from recon.helpers import nuclei_helpers as nh
    from recon.main_recon_modules import vuln_scan as vs
    from helpers import proxy_routing

    state = {"passes": [], "builder_kwargs": []}
    real_command = nh.build_nuclei_command

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        host_dir = next(a.rsplit(":/targets:ro", 1)[0]
                        for a in cmd if a.endswith(":/targets:ro"))
        filename = Path(cmd[cmd.index("-l") + 1]).name
        lines = (Path(host_dir) / filename).read_text().splitlines()
        state["passes"].append({"label": label, "targets": lines})
        return [], [], 1.0, 0

    def spy_urls(hostnames, ips, recon_data, scan_all_ips=False, **kwargs):
        state["builder_kwargs"].append(kwargs)
        return th.build_target_urls(hostnames, ips, recon_data,
                                    scan_all_ips=scan_all_ips, **kwargs)

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd: ([], ["a.example.com"], {}))
    monkeypatch.setattr(vs, "build_target_urls", spy_urls)
    monkeypatch.setattr(vs, "build_nuclei_command", real_command)
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kwargs: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    monkeypatch.setattr(vs, "run_security_checks", lambda **kwargs: {"security_checks": {"findings": []}})
    monkeypatch.setattr(vs, "run_cve_lookup", lambda **kwargs: {})
    monkeypatch.setattr(proxy_routing, "get_capture_routing", lambda tool: (None, None))
    settings = {
        "NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"],
        "NUCLEI_DAST_MODE": dast, "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
        "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False,
        "NUCLEI_MAX_RUNTIME": 0, "NUCLEI_SCAN_ALL_IPS": False,
    }
    recon = {"domain": "example.com", "http_probe": {"by_url": {}},
             "resource_enum": resource}
    result = vs.run_vuln_scan(recon, settings=settings)
    return state, result


def test_detection_actual_target_file_keeps_more_than_3000(monkeypatch):
    n = 3001
    state, result = _run_pipeline(monkeypatch, _observed_data(n), dast=False)
    assert [p["label"] for p in state["passes"]] == ["DETECTION"]
    assert state["builder_kwargs"] == [{}]
    targets = set(state["passes"][0]["targets"])
    expected = {f"https://a.example.com/p{i:05d}?q=1" for i in range(n)}
    assert expected <= targets
    assert "https://a.example.com" in targets
    assert result["vuln_scan"]["scan_metadata"]["dast_pass_executed"] is False


def test_dast_actual_target_file_keeps_large_list_order_and_variants(monkeypatch):
    # Preserve the author's URL-list behavior, including its existing limitations.
    # No new sorting, cap or semantic dedup may be hidden behind the consumer.
    expected = [f"https://a.example.com/s{i:05d}?q=1" for i in reversed(range(3001))]
    expected.append(expected[0])
    resource = _observed_data(1)
    resource["discovered_urls"] = expected + ["https://a.example.com/no-param"]
    state, result = _run_pipeline(monkeypatch, resource, dast=True)
    assert [p["label"] for p in state["passes"]] == ["DETECTION", "DAST"]
    assert state["passes"][1]["targets"] == expected
    assert state["builder_kwargs"] == [{}]
    meta = result["vuln_scan"]["scan_metadata"]
    assert meta["dast_pass_executed"] is True
    assert meta["dast_urls_discovered"] == len(expected)
    assert "dast_urls_dropped_budget" not in meta
