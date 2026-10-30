"""route_exposure pipeline and lifecycle registration (plan §9.3).

One Phase A key does five jobs (the combined_result key, the modules_executed
entry, the writer name, the phase_errors key and the _PHASE_FINDING_SOURCES
lookup); a typo in any of them fails silently, so each is pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import recon.main as rm
from recon.helpers.finding_sources import RECON_FINDING_SOURCES
from recon.helpers.isolated_result import TopLevelKeys

MAIN_SRC = (Path(rm.__file__)).read_text(encoding="utf-8")


def test_source_is_a_recon_finding_source():
    assert "route_exposure" in RECON_FINDING_SOURCES


def test_phase_finding_sources_entry_is_a_subset():
    assert rm._PHASE_FINDING_SOURCES["route_exposure"] == ("route_exposure",)
    assert set(rm._PHASE_FINDING_SOURCES["route_exposure"]) <= set(RECON_FINDING_SOURCES)


def test_legacy_path_never_prunes_it():
    """T21: domain discovery off never runs Phase A, so its findings are kept."""
    assert "route_exposure" not in rm._LEGACY_PATH_SOURCES


@pytest.mark.parametrize("settings_var,tools_var", [("_settings", "phase_a_tools"), ("settings", "ip_phase_a")])
def test_both_modes_register_the_isolated_wrapper(settings_var, tools_var):
    """T30: domain mode reads `_settings`, IP mode reads `settings`."""
    pattern = (rf"if {settings_var}\.get\('ROUTE_EXPOSURE_ENABLED', False\):\s*\n"
               rf"\s*from recon\.route_exposure import run_route_exposure_isolated\s*\n"
               rf"\s*{tools_var}\['route_exposure'\] = run_route_exposure_isolated")
    assert re.search(pattern, MAIN_SRC), f"{tools_var} does not register route_exposure"


def test_the_wrapper_and_the_writer_exist():
    from graph_db import Neo4jClient
    from recon.route_exposure import run_route_exposure_isolated
    assert callable(run_route_exposure_isolated)
    # _run_phase_a_fan_out queues f"update_graph_from_{key}" through getattr.
    assert callable(getattr(Neo4jClient, "update_graph_from_route_exposure", None))


def test_jev_shadow_is_merged_per_hook():
    combined = {"jev_shadow": {"page_type": {"decisions": [1]}}, "metadata": {}}
    answer = TopLevelKeys(route_exposure={"summary": {}},
                          jev_shadow={"route_exposure_assess": {"decisions": [2]}})
    rm._merge_isolated_result(combined, "route_exposure", answer)
    assert combined["route_exposure"] == {"summary": {}}
    assert combined["jev_shadow"] == {"page_type": {"decisions": [1]},
                                      "route_exposure_assess": {"decisions": [2]}}


def test_jev_shadow_merge_creates_the_key_when_absent():
    combined = {}
    rm._merge_isolated_result(combined, "route_exposure",
                              TopLevelKeys(route_exposure={}, jev_shadow={"route_privacy_rank": {}}))
    assert combined["jev_shadow"] == {"route_privacy_rank": {}}


def test_other_top_level_keys_still_replace():
    """The vuln_scan TopLevelKeys path is unchanged."""
    combined = {"technology_cves": {"old": 1}}
    rm._merge_isolated_result(combined, "vuln_scan",
                              TopLevelKeys(vuln_scan={"v": 1}, technology_cves={"new": 2}))
    assert combined == {"vuln_scan": {"v": 1}, "technology_cves": {"new": 2}}
    plain = {}
    rm._merge_isolated_result(plain, "cache_scan", {"jev_shadow": {"x": 1}})
    assert plain == {"cache_scan": {"jev_shadow": {"x": 1}}}
