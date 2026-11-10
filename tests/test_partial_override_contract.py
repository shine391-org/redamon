"""G2-R2 (B3) — restore the partial-recon modal override contract.

The G2 run49 review rejected 98b68a93 because F09 replaced the blind
``settings[key] = value`` override loops in the partial callers with a narrow
allowlist that dropped the UI-supported ``CVE_LOOKUP_ENABLED`` /
``MITRE_ENABLED`` / ``SECURITY_CHECK_ENABLED`` toggles: requesting all three
``false`` from the Partial Recon modal still passed all three ``true`` to
``run_vuln_scan``.

These tests exercise the REAL callers (with the graph and the tool dispatch
boundary replaced by fakes — no DB, no Neo4j, no network) and the real
allowlist helper. They fail on the rejected base and pass on this repair.

Caller inventory (every caller whose override loop F09 replaced):
  vulnerability_scanning.run_nuclei                    — settings reach run_vuln_scan
  vulnerability_scanning.run_subdomain_takeover_partial — settings reach run_subdomain_takeover
  vulnerability_scanning.run_vhost_sni_partial          — settings reach run_vhost_sni_enrichment
  cache_scanning.run_webcachepoison                     — settings reach run_cache_scan
  graphql_scanning.run_graphqlscan                      — settings reach run_graphql_scan
  route_exposure_scanning.run_route_exposure_partial    — settings reach run_route_exposure
  serialized_scanning.run_serialized_scan_partial       — settings reach run_serialized_scan
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "recon"))

from recon.partial_recon_modules import vulnerability_scanning as vuln_caller  # noqa: E402
from recon.partial_recon_modules import cache_scanning as cache_caller  # noqa: E402
from recon.partial_recon_modules import graphql_scanning as graphql_caller  # noqa: E402
from recon.partial_recon_modules import route_exposure_scanning as route_caller  # noqa: E402
from recon.partial_recon_modules import serialized_scanning as serialized_caller  # noqa: E402
from recon.main_recon_modules import vuln_scan  # noqa: E402
from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402

TOGGLE_KEYS = ("CVE_LOOKUP_ENABLED", "MITRE_ENABLED", "SECURITY_CHECK_ENABLED")


class _Halt(BaseException):
    """Abort the caller right at the tool-dispatch boundary."""


def _silence_graph_writes():
    """Neo4jClient is imported inside the caller body (deferred import), so we
    stub the module itself to prevent any graph connection attempt."""
    import types as _types
    fake = _types.ModuleType("graph_db")

    class _Neo4jClient:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def __getattr__(self, _name): return lambda *a, **k: {}

    fake.Neo4jClient = _Neo4jClient  # type: ignore[attr-defined]
    return patch.dict(sys.modules, {"graph_db": fake})


# ---------------------------------------------------------------------------
# B3 primary counterexample: the exact G2 review probe. Modal asks for all
# three toggles false; run_vuln_scan must receive all three false. On the
# rejected base the allowlist drops them and run_vuln_scan gets true.
# ---------------------------------------------------------------------------
def _run_nuclei_capturing_settings(settings_overrides, saved_settings):
    """Run the real run_nuclei with the graph builder faked to a synthetic
    target and run_vuln_scan replaced by a capture. Returns the settings dict
    exactly as handed to run_vuln_scan."""
    captured: dict = {}

    def _capture(recon_data, settings=None, **kwargs):
        captured["settings"] = settings
        raise _Halt()

    synthetic = {
        "domain": "synthetic.test",
        "domains": ["synthetic.test"],
        "subdomains": [],
        "dns": {"domain": {"has_records": False}, "subdomains": {}},
        "http_probe": {"by_url": {"https://synthetic.test/a":
                                  {"host": "synthetic.test"}}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
    }
    config = {
        "graph_inputs": {"domains": ["synthetic.test"]},
        "settings_overrides": settings_overrides,
        "include_graph_targets": True,  # builder is faked; mirrors the review probe
    }
    with patch.object(vuln_caller, "partial_settings",
                      return_value=dict(saved_settings)), \
         patch.object(vuln_caller, "_build_vuln_scan_data_from_graph",
                      return_value=synthetic), \
         patch.object(vuln_scan, "run_vuln_scan", side_effect=_capture), \
         contextlib.redirect_stdout(io.StringIO()):
        try:
            vuln_caller.run_nuclei(config)
        except _Halt:
            pass
    assert "settings" in captured, "run_nuclei never reached run_vuln_scan"
    return captured["settings"]


def test_b3_modal_false_toggles_reach_run_vuln_scan():
    saved = {k: True for k in TOGGLE_KEYS}
    effective = _run_nuclei_capturing_settings({k: False for k in TOGGLE_KEYS}, saved)
    assert {k: effective.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


def test_b3_modal_true_toggles_reach_run_vuln_scan():
    saved = {k: False for k in TOGGLE_KEYS}
    effective = _run_nuclei_capturing_settings({k: True for k in TOGGLE_KEYS}, saved)
    assert {k: effective.get(k) for k in TOGGLE_KEYS} == {k: True for k in TOGGLE_KEYS}


def test_b3_unrelated_saved_settings_preserved_through_run_nuclei():
    saved = {**{k: True for k in TOGGLE_KEYS},
             "NUCLEI_RATE_LIMIT": 42, "TAKEOVER_SEVERITY": "high"}
    effective = _run_nuclei_capturing_settings({"CVE_LOOKUP_ENABLED": False}, saved)
    assert effective["CVE_LOOKUP_ENABLED"] is False
    assert effective["MITRE_ENABLED"] is True
    assert effective["NUCLEI_RATE_LIMIT"] == 42
    assert effective["TAKEOVER_SEVERITY"] == "high"


# ---------------------------------------------------------------------------
# Helper-level strictness: enum/boolean validation without truthiness
# coercion, observable rejection of invalid and unsupported input.
# ---------------------------------------------------------------------------
def test_helper_rejects_unsupported_key_observably():
    seen: list[str] = []
    out = partial_helpers.apply_settings_overrides(
        {"UNRELATED": "keep"}, {"NOT_A_SETTING": True}, log=seen.append)
    assert out["UNRELATED"] == "keep"
    assert "NOT_A_SETTING" not in out
    assert any("NOT_A_SETTING" in line for line in seen), "rejection not observable"


def test_helper_rejects_non_bool_without_coercion():
    seen: list[str] = []
    out = partial_helpers.apply_settings_overrides(
        {"CVE_LOOKUP_ENABLED": True}, {"CVE_LOOKUP_ENABLED": "false"},
        log=seen.append)
    assert out["CVE_LOOKUP_ENABLED"] is True  # saved value wins, no coercion
    assert any("CVE_LOOKUP_ENABLED" in line for line in seen)


def test_helper_enum_invalid_preserves_saved_value_observably():
    seen: list[str] = []
    out = partial_helpers.apply_settings_overrides(
        {"PLANNER_MODE": "shadow"}, {"PLANNER_MODE": "nonsense"}, log=seen.append)
    assert out["PLANNER_MODE"] == "shadow"
    assert any("PLANNER_MODE" in line for line in seen)
    # absent setting falls back to the off default, still observably
    seen.clear()
    out = partial_helpers.apply_settings_overrides(
        {}, {"PLANNER_MODE": 7}, log=seen.append)
    assert out["PLANNER_MODE"] == "off"
    assert seen


def test_helper_accepts_full_supported_surface():
    seen: list[str] = []
    overrides = {
        "CVE_LOOKUP_ENABLED": False, "MITRE_ENABLED": False,
        "SECURITY_CHECK_ENABLED": False, "NUCLEI_ENABLED": True,
        "SUBDOMAIN_TAKEOVER_ENABLED": True,
        "PLANNER_MODE": "shadow", "PLANNER_MANIFEST_ENABLED": True,
        "PLANNER_CONSUMER_AI_TAGS": True,
        "PLANNER_CONSUMER_TARGET_SELECTION": True,
        "PLANNER_CONSUMER_TWO_PASS": True,
    }
    out = partial_helpers.apply_settings_overrides({}, overrides, log=seen.append)
    for key, value in overrides.items():
        assert out[key] == value, key
    assert seen == []


# ---------------------------------------------------------------------------
# Caller inventory: every replaced caller must apply allowlisted overrides and
# reject unknown keys. Each caller is intercepted at its tool-dispatch
# boundary with a synthetic graph (no DB, no Neo4j, no network).
# ---------------------------------------------------------------------------
def _capture_settings(captured):
    def _capture(*args, **kwargs):
        settings = kwargs.get("settings")
        if settings is None:
            # positional: the settings dict conventionally follows recon_data
            dicts = [a for a in args if isinstance(a, dict)]
            settings = dicts[-1] if dicts else None
        captured["reached"] = True
        captured["settings"] = settings
        raise _Halt()
    return _capture


def _base_config():
    # scope_roots reads config["domains"], not graph_inputs — mirror the
    # orchestrator's flattened config shape.
    return {
        "domains": ["synthetic.test"],
        "graph_inputs": {"domains": ["synthetic.test"]},
        "settings_overrides": {k: False for k in TOGGLE_KEYS},
        "include_graph_targets": False,
        # Typed in-scope targets carry each caller past its empty-target guard
        # to the real tool-dispatch boundary.
        "user_targets": {"urls": ["https://synthetic.test/a"],
                         "subdomains": ["app.synthetic.test"]},
    }


_SYNTHETIC_GRAPH = {
    "domain": "synthetic.test",
    "domains": ["synthetic.test"],
    "subdomains": ["synthetic.test"],
    "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
            "subdomains": {"synthetic.test": {"ips": {"ipv4": [], "ipv6": []},
                                              "has_records": True}}},
    "http_probe": {"by_url": {"https://synthetic.test/a":
                              {"host": "synthetic.test"}},
                   "live_urls": []},
    "resource_enum": {"by_base_url": {}, "discovered_urls": [],
                      "endpoints": {}, "parameters": {}},
    "js_recon": {"findings": []},
    "port_scan": {"by_host": {}},
}


def _run_caller(caller_module, entry, tool_module_path, tool_name,
                extra_patches=None, config_extra=None):
    captured: dict = {}
    patches = [
        patch.object(caller_module, "partial_settings",
                     return_value={k: True for k in TOGGLE_KEYS}),
        patch(tool_module_path + "." + tool_name,
              side_effect=_capture_settings(captured), create=True),
    ]
    # Every graph builder the module imported at its top level gets a
    # synthetic graph: no Neo4j, no network.
    for name in dir(caller_module):
        if name.startswith("_build_") and name.endswith("_from_graph"):
            patches.append(patch.object(caller_module, name,
                                        return_value=dict(_SYNTHETIC_GRAPH)))
    for target, repl in (extra_patches or []):
        patches.append(patch.object(caller_module, target, repl))
    config = _base_config()
    config.update(config_extra or {})
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)  # type: ignore[arg-type]
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                getattr(caller_module, entry)(config)
            except _Halt:
                pass
    return captured.get("settings")


def test_inventory_cache_scanning_caller_preserves_toggles():
    settings = _run_caller(cache_caller, "run_webcachepoison",
                           "recon.cache_scan", "run_cache_scan")
    assert settings is not None, "dispatch boundary never reached"
    assert {k: settings.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


def test_inventory_graphql_scanning_caller_preserves_toggles():
    settings = _run_caller(graphql_caller, "run_graphqlscan",
                           "recon.graphql_scan", "run_graphql_scan")
    assert settings is not None, "dispatch boundary never reached"
    assert {k: settings.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


def test_inventory_route_exposure_caller_preserves_toggles():
    settings = _run_caller(route_caller, "run_route_exposure_partial",
                           "recon.route_exposure", "run_route_exposure")
    assert settings is not None, "dispatch boundary never reached"
    assert {k: settings.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


def test_inventory_serialized_scanning_caller_preserves_toggles():
    settings = _run_caller(serialized_caller, "run_serialized_scan_partial",
                           "recon.serialized_scan", "run_serialized_scan")
    assert settings is not None, "dispatch boundary never reached"
    assert {k: settings.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


def test_inventory_takeover_caller_preserves_toggles():
    config_extra = {"user_targets": {"subdomains": ["app.synthetic.test"]}}
    settings = _run_caller(vuln_caller, "run_subdomain_takeover_partial",
                           "recon.main_recon_modules.subdomain_takeover",
                           "run_subdomain_takeover",
                           config_extra=config_extra)
    assert settings is not None, "dispatch boundary never reached"
    assert {k: settings.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


def test_inventory_vhost_caller_preserves_toggles():
    config_extra = {"user_targets": {"subdomains": ["app.synthetic.test"]}}
    settings = _run_caller(vuln_caller, "run_vhost_sni_partial",
                           "recon.main_recon_modules.vhost_sni_enum",
                           "run_vhost_sni_enrichment",
                           extra_patches=[("attach_graph_ownership",
                                           lambda *a, **k: None)],
                           config_extra=config_extra)
    assert settings is not None, "dispatch boundary never reached"
    assert {k: settings.get(k) for k in TOGGLE_KEYS} == {k: False for k in TOGGLE_KEYS}


# ---------------------------------------------------------------------------
# Settings-boundary contracts: the partial allowlist surface must stay a
# subset of the registry's known runtime keys, and every allowlisted key must
# exist in recon DEFAULT_SETTINGS with a type-consistent default (so
# 'absent -> default' never invents a dormant key). create/update/import/
# preset/MCP writers all persist through the same registry-validated path;
# the shared contract is the registry plus this allowlist.
# ---------------------------------------------------------------------------
def test_partial_allowlist_keys_exist_in_registry():
    registry = json.loads((REPO / "recon_settings" / "registry.json").read_text())
    fields = registry.get("fields") or {}
    runtime_keys = {
        field.get("runtime_key")
        for field in fields.values()
        if isinstance(field, dict) and field.get("runtime_key")
    }
    missing = [k for k in partial_helpers.PARTIAL_SETTINGS_ALLOWLIST
               if k not in runtime_keys]
    assert not missing, f"allowlist keys absent from registry runtime keys: {missing}"


def test_partial_allowlist_defaults_match_recon_defaults():
    from recon.project_settings import DEFAULT_SETTINGS
    for key, spec in partial_helpers.PARTIAL_SETTINGS_ALLOWLIST.items():
        assert key in DEFAULT_SETTINGS, f"{key} has no recon default"
        default = DEFAULT_SETTINGS[key]
        if spec["type"] == "bool":
            assert isinstance(default, bool), f"{key} default not bool"
            assert default == spec["default"], (
                f"{key} allowlist default {spec['default']} != "
                f"DEFAULT_SETTINGS {default}")
        elif spec["type"] == "enum":
            assert default in spec["values"], f"{key} default outside enum"
            assert default == spec["default"]


def test_webapp_registry_parity_files_unchanged():
    """The webapp registry copy must be structurally identical to the
    canonical recon_settings build output (key order may differ between
    generators; content must not)."""
    canonical = json.loads((REPO / "recon_settings" / "registry.json").read_text())
    webapp = json.loads((REPO / "webapp" / "src" / "lib" / "reconSettings" /
                         "registry.json").read_text())
    assert canonical == webapp, "registry.json drifted between recon_settings and webapp"
