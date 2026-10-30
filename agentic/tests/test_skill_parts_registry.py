"""The registry of built-in skill workflow parts a plugin may override (skill.text).

The registry is the contract the plugin platform builds on: the webapp stores an
override against a part's id and the SHA-256 of its factory text, and the agent only
applies it while both still match. These tests pin that every entry is exactly the
constant the builder appends, with the right kind and placeholders.
"""

import hashlib
import importlib
import string

import pytest

from prompts import skill_parts

# Kind at the append site (01_current_state.md §1.7): "template" only where the builder
# calls .format on the constant. Cross-checked against the real call sites in
# test_skill_parts_seam.py::test_registry_matches_call_sites.
EXPECTED = [
    ("brute_force_credential_guess", "tools", "template"),
    ("brute_force_credential_guess", "wordlist_guidance", "plain"),
    ("phishing_social_engineering", "tools", "plain"),
    ("phishing_social_engineering", "payload_format", "plain"),
    ("denial_of_service", "tools", "template"),
    ("denial_of_service", "vector_selection", "template"),
    ("denial_of_service", "verification_guide", "plain"),
    ("sql_injection", "tools", "template"),
    ("sql_injection", "oob_workflow", "plain"),
    ("sql_injection", "payload_reference", "plain"),
    ("xss", "tools", "template"),
    ("xss", "blind_workflow", "plain"),
    ("xss", "payload_reference", "plain"),
    ("ssrf", "tools", "template"),
    ("ssrf", "oob_workflow", "plain"),
    ("ssrf", "gopher_chains", "plain"),
    ("ssrf", "dns_rebinding", "plain"),
    ("ssrf", "payload_reference", "plain"),
    ("path_traversal", "tools", "template"),
    ("path_traversal", "safe_values", "plain"),
    ("path_traversal", "safe_state", "plain"),
    ("path_traversal", "php_wrappers", "plain"),
    ("path_traversal", "oob_workflow", "plain"),
    ("path_traversal", "archive_extraction", "plain"),
    ("path_traversal", "payload_reference", "plain"),
    ("path_traversal", "exposed_files", "template"),
    ("path_traversal", "git_reconstruct", "plain"),
    ("path_traversal", "validate_secrets", "plain"),
    ("deserialization", "tools", "template"),
    ("deserialization", "find_sinks", "plain"),
    ("deserialization", "oob_workflow", "template"),
    ("deserialization", "timing", "plain"),
    ("deserialization", "phar", "plain"),
    ("deserialization", "payload_reference", "plain"),
    ("rce", "tools", "template"),
    ("rce", "oob_workflow", "plain"),
    ("rce", "deserialization_workflow", "plain"),
    ("rce", "payload_reference", "plain"),
    ("rce", "route_exposure_consoles", "template"),
    ("rce", "heapdump_analysis", "plain"),
    ("cve_exploit", "tools", "plain"),
    ("cve_exploit", "payload_guidance_statefull", "plain"),
    ("cve_exploit", "payload_guidance_stateless", "plain"),
    ("cve_exploit", "no_module_fallback_statefull", "plain"),
    ("cve_exploit", "no_module_fallback_stateless", "plain"),
    ("access_control", "tools", "plain"),
    ("access_control", "safe_values", "plain"),
    ("access_control", "safe_state", "plain"),
    ("access_control", "route_exposure_leads", "plain"),
    ("access_control", "route_exposure_browser_leads", "plain"),
    ("http_request_smuggling", "tools", "plain"),
    ("http_request_smuggling", "zero_cl_step", "plain"),
    ("http_request_smuggling", "expect_step", "plain"),
    ("http_request_smuggling", "mutation_fuzzing_step", "plain"),
    ("http_request_smuggling", "h2_step", "plain"),
    ("http_request_smuggling", "client_side_step", "plain"),
    ("xxe", "tools", "plain"),
    ("crypto_attack", "tools", "plain"),
]

EXPECTED_PLACEHOLDERS = {
    "brute_force_credential_guess/tools": {"hydra_flags", "hydra_flags_no_t", "hydra_max_attempts"},
    "denial_of_service/tools": {"dos_assessment_only_block", "dos_connections",
                                "dos_max_attempts", "dos_max_duration"},
    "denial_of_service/vector_selection": {"dos_connections", "dos_max_duration"},
    "sql_injection/tools": {"sqli_level", "sqli_risk", "sqli_tamper_scripts"},
    "xss/tools": {"xss_blind_callback_enabled", "xss_csp_bypass_enabled", "xss_dalfox_enabled"},
    "ssrf/tools": {"ssrf_cloud_metadata_enabled", "ssrf_cloud_providers", "ssrf_cloud_section",
                   "ssrf_custom_targets_section", "ssrf_dns_rebinding_enabled",
                   "ssrf_gopher_enabled", "ssrf_internal_ranges", "ssrf_oob_callback_enabled",
                   "ssrf_oob_provider", "ssrf_payload_reference_enabled",
                   "ssrf_port_scan_ports", "ssrf_request_timeout"},
    "path_traversal/tools": {"path_traversal_archive_extraction_enabled",
                             "path_traversal_oob_callback_enabled", "path_traversal_oob_provider",
                             "path_traversal_payload_reference_enabled",
                             "path_traversal_php_wrappers_enabled",
                             "path_traversal_request_timeout"},
    "deserialization/tools": {"deser_exec_gadgets_enabled", "deser_find_sinks_enabled",
                              "deser_oob_callback_enabled", "deser_oob_channel",
                              "deser_oob_provider", "deser_phar_enabled", "deser_runtimes",
                              "deser_timing_channel", "deser_timing_enabled"},
    "deserialization/oob_workflow": {"deser_oob_provider"},
    "rce/tools": {"rce_aggressive_block", "rce_aggressive_payloads",
                  "rce_deserialization_enabled", "rce_oob_callback_enabled"},
    "path_traversal/exposed_files": {"git_reconstruct", "validate_secrets"},
    "rce/route_exposure_consoles": {"heapdump_analysis"},
}


def _resolve(constant: str):
    module_name, _, attr = constant.rpartition(".")
    return getattr(importlib.import_module(f"prompts.{module_name}"), attr)


def test_parts_and_order_are_the_published_list():
    got = [(p.skill_id, p.part_id, p.kind) for p in skill_parts.all_parts()]
    assert got == EXPECTED
    assert len(got) == 58


def test_text_is_the_module_constant_itself():
    for part in skill_parts.all_parts():
        assert part.text is _resolve(part.constant), part.key


def test_sha256_is_the_digest_of_the_factory_text():
    for part in skill_parts.all_parts():
        assert part.sha256 == hashlib.sha256(part.text.encode("utf-8")).hexdigest(), part.key


def test_template_placeholders_equal_the_formatter_fields():
    for part in skill_parts.all_parts():
        if part.kind == "template":
            fields = {f for _, f, _, _ in string.Formatter().parse(part.text) if f is not None}
            assert part.placeholders == fields == EXPECTED_PLACEHOLDERS[part.key], part.key
        else:
            # Plain parts are appended verbatim; some do not even parse as format strings.
            assert part.placeholders == frozenset(), part.key
    templates = {p.key for p in skill_parts.all_parts() if p.kind == "template"}
    assert templates == set(EXPECTED_PLACEHOLDERS)


def test_every_known_attack_path_has_parts():
    from state import KNOWN_ATTACK_PATHS
    assert set(skill_parts.skill_ids()) == set(KNOWN_ATTACK_PATHS)
    for skill_id in KNOWN_ATTACK_PATHS:
        assert skill_parts.parts_of(skill_id), skill_id


def test_order_is_contiguous_per_skill_and_constants_unique():
    for skill_id in skill_parts.skill_ids():
        assert [p.order for p in skill_parts.parts_of(skill_id)] == list(
            range(1, len(skill_parts.parts_of(skill_id)) + 1))
    constants = [p.constant for p in skill_parts.all_parts()]
    assert len(constants) == len(set(constants))
    assert len({id(p.text) for p in skill_parts.all_parts()}) == len(constants)


def test_every_part_names_its_gate():
    for part in skill_parts.all_parts():
        assert part.gate.strip(), part.key


def test_lookup():
    part = skill_parts.get_part("ssrf", "oob_workflow")
    assert part is skill_parts.get_part_by_key("ssrf/oob_workflow")
    assert part.key == "ssrf/oob_workflow"
    assert skill_parts.get_part("ssrf", "nope") is None
    assert skill_parts.get_part("nope", "tools") is None
    assert skill_parts.get_part_by_key("ssrf") is None
    assert skill_parts.parts_of("nope") == ()


def test_registry_is_built_on_first_use(monkeypatch):
    monkeypatch.setattr(skill_parts, "_registry", None)
    assert skill_parts._registry is None
    skill_parts.all_parts()
    assert skill_parts._registry is not None


def test_prompt_modules_never_import_the_registry_at_module_level():
    """deserialization_prompts reaches the seam inside a function; a module-level import
    would form a cycle with the registry, which imports the prompt modules."""
    import pathlib
    import re
    prompts_dir = pathlib.Path(skill_parts.__file__).parent
    for path in prompts_dir.glob("*_prompts.py"):
        top_level = [line for line in path.read_text(encoding="utf-8").splitlines()
                     if re.match(r"^(from|import)\s", line)]
        assert not any("skill_part" in line for line in top_level), path.name


@pytest.mark.parametrize("skill_id", ["ssrf", "cve_exploit"])
def test_parts_of_is_ordered_and_immutable(skill_id):
    parts = skill_parts.parts_of(skill_id)
    assert isinstance(parts, tuple)
    with pytest.raises(Exception):
        parts[0].text = "changed"
