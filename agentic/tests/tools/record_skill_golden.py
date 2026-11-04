"""Render every built-in skill workflow under fixed scenarios and print golden hashes.

The golden test (tests/test_skill_workflow_golden.py) re-renders the same scenarios and
compares. It exists so a change to how skill text is assembled (the plugin platform's
skill.text seam) can prove it changes nothing when no override applies.

Re-record ONLY after confirming that a changed hash comes from an intended edit of a
built-in skill prompt, from the repository root:

    docker run --rm -v "$PWD:/repo" -w /repo/agentic --user "$(id -u):$(id -g)" \\
        -e PYTHONPATH=/repo/agentic:/repo --entrypoint python redamon-agent:latest \\
        tests/tools/record_skill_golden.py > agentic/tests/fixtures/skill_workflow_golden.json

Settings come from a dict, never from a project: the builder's own inline defaults are
the "defaults" scenario. The tool table, tool descriptions, Kali install block, session
config and mode matrix are fixed strings, so the hashes pin the skill text and the
get_phase_tools assembly rather than the tool registry, which changes for other reasons.
Synthetic addresses only (RFC 5737, example.com).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
from unittest.mock import patch

SKILLS = (
    "brute_force_credential_guess",
    "phishing_social_engineering",
    "denial_of_service",
    "sql_injection",
    "xss",
    "ssrf",
    "path_traversal",
    "deserialization",
    "rce",
    "cve_exploit",
    "access_control",
    "http_request_smuggling",
    "xxe",
    "crypto_attack",
)

ALL_TOOLS = (
    "execute_hydra",
    "kali_shell",
    "execute_curl",
    "execute_code",
    "metasploit_console",
    "execute_playwright",
)

# The tool each branch of build_builtin_skill_workflow gates on; phishing and DoS have none.
REQUIRED_TOOL = {
    "brute_force_credential_guess": "execute_hydra",
    "sql_injection": "kali_shell",
    "xss": "execute_curl",
    "ssrf": "execute_curl",
    "path_traversal": "execute_curl",
    "deserialization": "kali_shell",
    "rce": "kali_shell",
    "cve_exploit": "metasploit_console",
    "access_control": "execute_curl",
    "http_request_smuggling": "execute_code",
    "xxe": "execute_curl",
    "crypto_attack": "execute_code",
}

ALL_ON = {
    "HYDRA_MAX_WORDLIST_ATTEMPTS": 5,
    "PHISHING_SMTP_CONFIG": "SMTP_HOST: 192.0.2.25\nSMTP_PORT: 587\nSMTP_USER: tester@example.com",
    "DOS_ASSESSMENT_ONLY": True,
    "SQLI_LEVEL": 3,
    "SQLI_RISK": 2,
    "SQLI_TAMPER_SCRIPTS": "space2comment,between",
    "XSS_DALFOX_ENABLED": True,
    "XSS_BLIND_CALLBACK_ENABLED": True,
    "XSS_CSP_BYPASS_ENABLED": True,
    "SSRF_OOB_CALLBACK_ENABLED": True,
    "SSRF_CLOUD_METADATA_ENABLED": True,
    "SSRF_GOPHER_ENABLED": True,
    "SSRF_DNS_REBINDING_ENABLED": True,
    "SSRF_PAYLOAD_REFERENCE_ENABLED": True,
    "SSRF_CLOUD_PROVIDERS": "aws,gcp,azure,digitalocean,alibaba",
    "SSRF_CUSTOM_INTERNAL_TARGETS": "192.0.2.10\n198.51.100.20:8080",
    "PATH_TRAVERSAL_OOB_CALLBACK_ENABLED": True,
    "PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED": True,
    "PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED": True,
    "PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED": True,
    "DESERIALIZATION_OOB_CALLBACK_ENABLED": True,
    "DESERIALIZATION_TIMING_ENABLED": True,
    "DESERIALIZATION_FIND_SINKS_ENABLED": True,
    "DESERIALIZATION_RUNTIMES": "java,java_typed,python,php,node,ruby,dotnet",
    "DESERIALIZATION_EXEC_GADGETS_ENABLED": True,
    "DESERIALIZATION_PHAR_ENABLED": True,
    "RCE_OOB_CALLBACK_ENABLED": True,
    "RCE_DESERIALIZATION_ENABLED": True,
    "RCE_AGGRESSIVE_PAYLOADS": True,
    "CAPTURE_PROXY_ENABLED": False,
    # Recon's route exposure module and the switches of its agent parts; the
    # RoE allowances the two gated parts also need.
    "ROUTE_EXPOSURE_ENABLED": True,
    "PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True,
    "PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": True,
    "RCE_HEAPDUMP_ANALYSIS_ENABLED": True,
    "ROE_ALLOW_DATA_EXFILTRATION": True,
    "ROE_SENSITIVE_DATA_HANDLING": "limited_collection",
}

ALL_OFF = {
    "PHISHING_SMTP_CONFIG": "",
    "DOS_ASSESSMENT_ONLY": False,
    "SQLI_TAMPER_SCRIPTS": "",
    "XSS_DALFOX_ENABLED": False,
    "XSS_BLIND_CALLBACK_ENABLED": False,
    "XSS_CSP_BYPASS_ENABLED": False,
    "SSRF_OOB_CALLBACK_ENABLED": False,
    "SSRF_CLOUD_METADATA_ENABLED": False,
    "SSRF_GOPHER_ENABLED": False,
    "SSRF_DNS_REBINDING_ENABLED": False,
    "SSRF_PAYLOAD_REFERENCE_ENABLED": False,
    "SSRF_CUSTOM_INTERNAL_TARGETS": "",
    "PATH_TRAVERSAL_OOB_CALLBACK_ENABLED": False,
    "PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED": False,
    "PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED": False,
    "PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED": False,
    "DESERIALIZATION_OOB_CALLBACK_ENABLED": False,
    "DESERIALIZATION_TIMING_ENABLED": False,
    "DESERIALIZATION_FIND_SINKS_ENABLED": False,
    "DESERIALIZATION_EXEC_GADGETS_ENABLED": False,
    "DESERIALIZATION_PHAR_ENABLED": False,
    "RCE_OOB_CALLBACK_ENABLED": False,
    "RCE_DESERIALIZATION_ENABLED": False,
    "RCE_AGGRESSIVE_PAYLOADS": False,
    "CAPTURE_PROXY_ENABLED": True,
    "ROUTE_EXPOSURE_ENABLED": False,
    "PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": False,
    "PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": False,
    "RCE_HEAPDUMP_ANALYSIS_ENABLED": False,
}

ROE_RESTRICTED = {
    "ROE_ENABLED": True,
    "ROE_ALLOW_ACCOUNT_LOCKOUT": False,
    "ROE_ALLOW_SOCIAL_ENGINEERING": False,
    "ROE_ALLOW_DOS": False,
}

FAILED_SEARCH_TRACE = [{
    "tool_name": "metasploit_console",
    "tool_args": {"command": "search cve-2099-0001"},
    "tool_output": "[-] No results from search",
}]

PHASES = ("informational", "exploitation")


def scenarios():
    """(name, skill, settings, allowed_tools, is_statefull, execution_trace) for every render."""
    out = []
    for skill in SKILLS:
        out.append(("defaults", skill, {}, ALL_TOOLS, False, []))
        out.append(("all_on", skill, ALL_ON, ALL_TOOLS, False, []))
        out.append(("all_off", skill, ALL_OFF, ALL_TOOLS, False, []))
        out.append(("roe_restricted", skill, ROE_RESTRICTED, ALL_TOOLS, False, []))
        missing = REQUIRED_TOOL.get(skill)
        allowed = tuple(t for t in ALL_TOOLS if t != missing) if missing else ()
        out.append(("tool_missing", skill, {}, allowed, False, []))
    for statefull in (True, False):
        mode = "statefull" if statefull else "stateless"
        for traced, trace in (("no_search", []), ("failed_search", FAILED_SEARCH_TRACE)):
            out.append((f"cve_{mode}_{traced}", "cve_exploit", {}, ALL_TOOLS, statefull, trace))
    return out


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@contextlib.contextmanager
def stubbed(settings: dict, allowed_tools):
    """Stub everything the builder and get_phase_tools read, as test_ssrf_skill.py does."""
    with patch("prompts.get_setting", side_effect=lambda k, d=None: settings.get(k, d)), \
         patch("project_settings.get_enabled_builtin_skills", return_value=set(SKILLS)), \
         patch("prompts.get_hydra_flags_from_settings", return_value="-t 16 -f -e nsr -V"), \
         patch("prompts.get_dos_settings_dict", return_value={
             "dos_max_duration": 60, "dos_max_attempts": 3, "dos_connections": 1000}), \
         patch("prompts.get_allowed_tools_for_phase", return_value=list(allowed_tools)), \
         patch("prompts.build_kali_install_prompt", return_value="KALI-INSTALL-RULES"), \
         patch("prompts.build_tool_availability_table", return_value="TOOL-TABLE"), \
         patch("prompts.build_informational_tool_descriptions", return_value="TOOL-DESCRIPTIONS"), \
         patch("prompts.get_session_config_prompt", return_value="SESSION-CONFIG"), \
         patch("prompts.MODE_DECISION_MATRIX", "MODE {mode} {target_types} {post_expl_note}"):
        yield


def render_workflow(skill, settings, allowed_tools, is_statefull, trace) -> list:
    import prompts
    with stubbed(settings, allowed_tools):
        return prompts.build_builtin_skill_workflow(skill, list(allowed_tools), is_statefull, trace)


def render_phase_tools(phase, skill, settings, allowed_tools, is_statefull, trace) -> str:
    import prompts
    with stubbed(settings, allowed_tools):
        return prompts.get_phase_tools(
            phase,
            activate_post_expl=True,
            post_expl_type="statefull" if is_statefull else "stateless",
            attack_path_type=skill,
            execution_trace=trace,
        )


def render_all() -> dict:
    """Every scenario's render as {key: text-or-parts}, keyed the way the fixture is."""
    workflow, phase_tools = {}, {}
    for name, skill, settings, allowed, statefull, trace in scenarios():
        workflow[f"{name}/{skill}"] = render_workflow(skill, settings, allowed, statefull, trace)
        for phase in PHASES:
            phase_tools[f"{name}/{phase}/{skill}"] = render_phase_tools(
                phase, skill, settings, allowed, statefull, trace)
    return {"workflow": workflow, "phase_tools": phase_tools}


def digest(rendered: dict) -> dict:
    """Hashes only: the fixture stays small and never holds prompt text."""
    return {
        "workflow": {
            key: {
                "sha256": _sha("\n".join(parts)),
                "chars": len("\n".join(parts)),
                "parts": [_sha(p) for p in parts],
            }
            for key, parts in rendered["workflow"].items()
        },
        "phase_tools": {
            key: {"sha256": _sha(text), "chars": len(text)}
            for key, text in rendered["phase_tools"].items()
        },
    }


if __name__ == "__main__":
    json.dump(digest(render_all()), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
