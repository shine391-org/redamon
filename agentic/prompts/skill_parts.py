"""Registry of the built-in skill workflow parts a plugin may override (skill.text).

A part is one static constant that build_builtin_skill_workflow (or
build_deserialization_parts) appends. Parts that carry operator data or are assembled
from dicts (the phishing SMTP block, SSRF cloud blocks and custom targets, the RCE
aggressive blocks, deserialization runtime oracles and exec gadgets) are not here, so no
override can replace them.

The webapp stores an override against a part's key and the SHA-256 of its factory text;
the agent renders it only while that hash still matches (skill_part_seam.py). A new
built-in skill must register its parts here, or overrides never reach it.

Built on first use: the registry imports the prompt modules, and
deserialization_prompts reaches the seam from inside a function, so a module-level
import in either direction would form a cycle.
"""

from __future__ import annotations

import hashlib
import importlib
import logging
import math
import os
import re
import string
import unicodedata
from dataclasses import dataclass

logger = logging.getLogger(__name__)

TEMPLATE = "template"
PLAIN = "plain"


@dataclass(frozen=True)
class SkillPart:
    skill_id: str
    part_id: str
    constant: str                  # "<module>.<CONSTANT>" under prompts/
    kind: str                      # TEMPLATE where the append site calls .format, else PLAIN
    placeholders: frozenset        # TEMPLATE only: the exact names a value must use
    text: str                      # the factory text (the constant itself)
    sha256: str
    order: int                     # 1-based position in the skill's assembly order
    gate: str                      # when the builder includes the part

    @property
    def key(self) -> str:
        return f"{self.skill_id}/{self.part_id}"


_ALWAYS = "always, when the skill renders"

# (skill_id, part_id, constant, kind, placeholders, gate), in assembly order. The skill's
# branch gate (enabled, its required tool allowed, the RoE for three skills) applies to
# every part on top of the gate named here.
_SPECS = (
    ("brute_force_credential_guess", "tools", "brute_force_credential_guess_prompts.HYDRA_BRUTE_FORCE_TOOLS",
     TEMPLATE, ("hydra_flags", "hydra_flags_no_t", "hydra_max_attempts"), _ALWAYS),
    ("brute_force_credential_guess", "wordlist_guidance",
     "brute_force_credential_guess_prompts.HYDRA_WORDLIST_GUIDANCE", PLAIN, (), _ALWAYS),

    ("phishing_social_engineering", "tools",
     "phishing_social_engineering_prompts.PHISHING_SOCIAL_ENGINEERING_TOOLS", PLAIN, (), _ALWAYS),
    ("phishing_social_engineering", "payload_format",
     "phishing_social_engineering_prompts.PHISHING_PAYLOAD_FORMAT_GUIDANCE", PLAIN, (), _ALWAYS),

    ("denial_of_service", "tools", "denial_of_service_prompts.DOS_TOOLS", TEMPLATE,
     ("dos_assessment_only_block", "dos_connections", "dos_max_attempts", "dos_max_duration"), _ALWAYS),
    ("denial_of_service", "vector_selection", "denial_of_service_prompts.DOS_VECTOR_SELECTION",
     TEMPLATE, ("dos_connections", "dos_max_duration"), _ALWAYS),
    ("denial_of_service", "verification_guide", "denial_of_service_prompts.DOS_VERIFICATION_GUIDE",
     PLAIN, (), _ALWAYS),

    ("sql_injection", "tools", "sql_injection_prompts.SQLI_TOOLS", TEMPLATE,
     ("sqli_level", "sqli_risk", "sqli_tamper_scripts"), _ALWAYS),
    ("sql_injection", "oob_workflow", "sql_injection_prompts.SQLI_OOB_WORKFLOW", PLAIN, (), _ALWAYS),
    ("sql_injection", "payload_reference", "sql_injection_prompts.SQLI_PAYLOAD_REFERENCE", PLAIN, (),
     _ALWAYS),

    ("xss", "tools", "xss_prompts.XSS_TOOLS", TEMPLATE,
     ("xss_blind_callback_enabled", "xss_csp_bypass_enabled", "xss_dalfox_enabled"), _ALWAYS),
    ("xss", "blind_workflow", "xss_prompts.XSS_BLIND_WORKFLOW", PLAIN, (),
     "XSS_BLIND_CALLBACK_ENABLED and kali_shell allowed"),
    ("xss", "payload_reference", "xss_prompts.XSS_PAYLOAD_REFERENCE", PLAIN, (), _ALWAYS),

    ("ssrf", "tools", "ssrf_prompts.SSRF_TOOLS", TEMPLATE,
     ("ssrf_cloud_metadata_enabled", "ssrf_cloud_providers", "ssrf_cloud_section",
      "ssrf_custom_targets_section", "ssrf_dns_rebinding_enabled", "ssrf_gopher_enabled",
      "ssrf_internal_ranges", "ssrf_oob_callback_enabled", "ssrf_oob_provider",
      "ssrf_payload_reference_enabled", "ssrf_port_scan_ports", "ssrf_request_timeout"), _ALWAYS),
    ("ssrf", "oob_workflow", "ssrf_prompts.SSRF_OOB_WORKFLOW", PLAIN, (),
     "SSRF_OOB_CALLBACK_ENABLED and kali_shell allowed"),
    ("ssrf", "gopher_chains", "ssrf_prompts.SSRF_GOPHER_CHAINS", PLAIN, (), "SSRF_GOPHER_ENABLED"),
    ("ssrf", "dns_rebinding", "ssrf_prompts.SSRF_DNS_REBINDING", PLAIN, (), "SSRF_DNS_REBINDING_ENABLED"),
    ("ssrf", "payload_reference", "ssrf_prompts.SSRF_PAYLOAD_REFERENCE", PLAIN, (),
     "SSRF_PAYLOAD_REFERENCE_ENABLED"),

    ("path_traversal", "tools", "path_traversal_prompts.PATH_TRAVERSAL_TOOLS", TEMPLATE,
     ("path_traversal_archive_extraction_enabled", "path_traversal_oob_callback_enabled",
      "path_traversal_oob_provider", "path_traversal_payload_reference_enabled",
      "path_traversal_php_wrappers_enabled", "path_traversal_request_timeout"), _ALWAYS),
    ("path_traversal", "safe_values", "safe_handling_prompts.PATH_TRAVERSAL_SAFE_VALUES", PLAIN, (),
     "ROE_SENSITIVE_DATA_HANDLING not full_access"),
    ("path_traversal", "safe_state", "safe_handling_prompts.PATH_TRAVERSAL_SAFE_STATE", PLAIN, (), _ALWAYS),
    ("path_traversal", "php_wrappers", "path_traversal_prompts.PATH_TRAVERSAL_PHP_WRAPPERS", PLAIN, (),
     "PATH_TRAVERSAL_PHP_WRAPPERS_ENABLED"),
    ("path_traversal", "oob_workflow", "path_traversal_prompts.PATH_TRAVERSAL_OOB_WORKFLOW", PLAIN, (),
     "PATH_TRAVERSAL_OOB_CALLBACK_ENABLED and kali_shell allowed"),
    ("path_traversal", "archive_extraction", "path_traversal_prompts.PATH_TRAVERSAL_ARCHIVE_EXTRACTION",
     PLAIN, (), "PATH_TRAVERSAL_ARCHIVE_EXTRACTION_ENABLED and execute_code allowed"),
    ("path_traversal", "payload_reference", "path_traversal_prompts.PATH_TRAVERSAL_PAYLOAD_REFERENCE",
     PLAIN, (), "PATH_TRAVERSAL_PAYLOAD_REFERENCE_ENABLED"),
    ("path_traversal", "exposed_files", "path_traversal_prompts.PATH_TRAVERSAL_EXPOSED_FILES", TEMPLATE,
     ("git_reconstruct", "validate_secrets"), "ROUTE_EXPOSURE_ENABLED"),
    ("path_traversal", "git_reconstruct", "path_traversal_prompts.PATH_TRAVERSAL_GIT_RECONSTRUCT", PLAIN, (),
     "ROUTE_EXPOSURE_ENABLED, PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED, ROE_ALLOW_DATA_EXFILTRATION and "
     "execute_code allowed"),
    ("path_traversal", "validate_secrets", "path_traversal_prompts.PATH_TRAVERSAL_VALIDATE_SECRETS", PLAIN, (),
     "ROUTE_EXPOSURE_ENABLED, PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED and execute_code allowed"),

    ("deserialization", "tools", "deserialization_prompts.DESERIALIZATION_TOOLS", TEMPLATE,
     ("deser_exec_gadgets_enabled", "deser_find_sinks_enabled", "deser_oob_callback_enabled",
      "deser_oob_channel", "deser_oob_provider", "deser_phar_enabled", "deser_runtimes",
      "deser_timing_channel", "deser_timing_enabled"), _ALWAYS),
    ("deserialization", "find_sinks", "deserialization_prompts.DESERIALIZATION_FIND_SINKS", PLAIN, (),
     "DESERIALIZATION_FIND_SINKS_ENABLED"),
    ("deserialization", "oob_workflow", "deserialization_prompts.DESERIALIZATION_OOB_WORKFLOW",
     TEMPLATE, ("deser_oob_provider",), "DESERIALIZATION_OOB_CALLBACK_ENABLED"),
    ("deserialization", "timing", "deserialization_prompts.DESERIALIZATION_TIMING", PLAIN, (),
     "DESERIALIZATION_TIMING_ENABLED"),
    ("deserialization", "phar", "deserialization_prompts.DESERIALIZATION_PHAR", PLAIN, (),
     "DESERIALIZATION_PHAR_ENABLED and php among DESERIALIZATION_RUNTIMES"),
    ("deserialization", "payload_reference", "deserialization_prompts.DESERIALIZATION_PAYLOAD_REFERENCE",
     PLAIN, (), "DESERIALIZATION_FIND_SINKS_ENABLED"),

    ("rce", "tools", "rce_prompts.RCE_TOOLS", TEMPLATE,
     ("rce_aggressive_block", "rce_aggressive_payloads", "rce_deserialization_enabled",
      "rce_oob_callback_enabled"), _ALWAYS),
    ("rce", "oob_workflow", "rce_prompts.RCE_OOB_WORKFLOW", PLAIN, (), "RCE_OOB_CALLBACK_ENABLED"),
    ("rce", "deserialization_workflow", "rce_prompts.RCE_DESERIALIZATION_WORKFLOW", PLAIN, (),
     "RCE_DESERIALIZATION_ENABLED"),
    ("rce", "payload_reference", "rce_prompts.RCE_PAYLOAD_REFERENCE", PLAIN, (), _ALWAYS),
    ("rce", "route_exposure_consoles", "rce_prompts.RCE_ROUTE_EXPOSURE_CONSOLES", TEMPLATE,
     ("heapdump_analysis",), "ROUTE_EXPOSURE_ENABLED"),
    ("rce", "heapdump_analysis", "rce_prompts.RCE_HEAPDUMP_ANALYSIS", PLAIN, (),
     "ROUTE_EXPOSURE_ENABLED, RCE_HEAPDUMP_ANALYSIS_ENABLED, ROE_ALLOW_DATA_EXFILTRATION, "
     "ROE_SENSITIVE_DATA_HANDLING above no_access and execute_code allowed"),

    ("cve_exploit", "tools", "cve_exploit_prompts.CVE_EXPLOIT_TOOLS", PLAIN, (), _ALWAYS),
    ("cve_exploit", "payload_guidance_statefull", "cve_exploit_prompts.CVE_PAYLOAD_GUIDANCE_STATEFULL",
     PLAIN, (), "statefull post-exploitation mode"),
    ("cve_exploit", "payload_guidance_stateless", "cve_exploit_prompts.CVE_PAYLOAD_GUIDANCE_STATELESS",
     PLAIN, (), "stateless post-exploitation mode"),
    ("cve_exploit", "no_module_fallback_statefull", "cve_exploit_prompts.NO_MODULE_FALLBACK_STATEFULL",
     PLAIN, (), "statefull mode and a Metasploit search returned no module"),
    ("cve_exploit", "no_module_fallback_stateless", "cve_exploit_prompts.NO_MODULE_FALLBACK_STATELESS",
     PLAIN, (), "stateless mode and a Metasploit search returned no module"),

    ("access_control", "tools", "access_control_prompts.ACCESS_CONTROL_TOOLS", PLAIN, (), _ALWAYS),
    ("access_control", "safe_values", "safe_handling_prompts.ACCESS_CONTROL_SAFE_VALUES", PLAIN, (),
     "ROE_SENSITIVE_DATA_HANDLING not full_access"),
    ("access_control", "safe_state", "safe_handling_prompts.ACCESS_CONTROL_SAFE_STATE", PLAIN, (), _ALWAYS),
    ("access_control", "route_exposure_leads", "access_control_prompts.ACCESS_CONTROL_ROUTE_EXPOSURE_LEADS",
     PLAIN, (), "ROUTE_EXPOSURE_ENABLED"),
    ("access_control", "route_exposure_browser_leads",
     "access_control_prompts.ACCESS_CONTROL_ROUTE_EXPOSURE_BROWSER_LEADS", PLAIN, (), "ROUTE_EXPOSURE_ENABLED"),

    ("http_request_smuggling", "tools", "http_smuggling_prompts.HTTP_SMUGGLING_TOOLS", PLAIN, (), _ALWAYS),
    ("http_request_smuggling", "zero_cl_step", "http_smuggling_prompts.HTTP_SMUGGLING_ZERO_CL_STEP",
     PLAIN, (), _ALWAYS),
    ("http_request_smuggling", "expect_step", "http_smuggling_prompts.HTTP_SMUGGLING_EXPECT_STEP",
     PLAIN, (), _ALWAYS),
    ("http_request_smuggling", "mutation_fuzzing_step",
     "http_smuggling_prompts.HTTP_SMUGGLING_MUTATION_FUZZING_STEP", PLAIN, (), _ALWAYS),
    ("http_request_smuggling", "h2_step", "http_smuggling_prompts.HTTP_SMUGGLING_H2_STEP", PLAIN, (),
     _ALWAYS),
    ("http_request_smuggling", "client_side_step", "http_smuggling_prompts.HTTP_SMUGGLING_CLIENT_SIDE_STEP",
     PLAIN, (), "execute_playwright allowed and CAPTURE_PROXY_ENABLED off"),

    ("xxe", "tools", "xxe_prompts.XXE_TOOLS", PLAIN, (), _ALWAYS),

    ("crypto_attack", "tools", "crypto_attack_prompts.CRYPTO_ATTACK_TOOLS", PLAIN, (), _ALWAYS),
)

_registry: dict | None = None


def _build() -> dict:
    by_key: dict[str, SkillPart] = {}
    by_skill: dict[str, list[SkillPart]] = {}
    for skill_id, part_id, constant, kind, placeholders, gate in _SPECS:
        module_name, _, attr = constant.rpartition(".")
        text = getattr(importlib.import_module(f"prompts.{module_name}"), attr)
        siblings = by_skill.setdefault(skill_id, [])
        part = SkillPart(
            skill_id=skill_id,
            part_id=part_id,
            constant=constant,
            kind=kind,
            placeholders=frozenset(placeholders),
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            order=len(siblings) + 1,
            gate=gate,
        )
        siblings.append(part)
        by_key[part.key] = part
    return {
        "all": tuple(p for parts in by_skill.values() for p in parts),
        "by_key": by_key,
        "by_skill": {k: tuple(v) for k, v in by_skill.items()},
    }


def _get() -> dict:
    global _registry
    if _registry is None:
        _registry = _build()
    return _registry


def all_parts() -> tuple:
    return _get()["all"]


def skill_ids() -> tuple:
    return tuple(_get()["by_skill"])


def parts_of(skill_id: str) -> tuple:
    return _get()["by_skill"].get(skill_id, ())


def get_part(skill_id: str, part_id: str) -> SkillPart | None:
    return _get()["by_key"].get(f"{skill_id}/{part_id}")


def get_part_by_key(key: str) -> SkillPart | None:
    return _get()["by_key"].get(key)


# ── validation ──────────────────────────────────────────────────────────────

# The agent's untrusted-data fences (prompt_safety.py) and the prompt-cache split marker
# (base.py). A value holding one could fake the end of a fenced tool output or move the
# cache boundary.
RESERVED_MARKERS = ("<<<UNTRUSTED_", "<<<END_UNTRUSTED_", "<<REDAMON_CACHE_")
# Matched the way the agent reads them: prompt_safety._MARKER_PREFIX_RE allows whitespace
# after "<<<", and the cache split is found by a plain search for its markers. The single
# "<<REDAMON_CACHE_" prefix covers all three cache-tier markers (base.CACHE_MARKERS).
_MARKER_RES = (
    (re.compile(r"<<<\s*untrusted_", re.IGNORECASE), "<<<UNTRUSTED_"),
    (re.compile(r"<<<\s*end_untrusted_", re.IGNORECASE), "<<<END_UNTRUSTED_"),
    (re.compile(r"<<\s*redamon_cache_[a-z0-9_]*\s*>>", re.IGNORECASE), "<<REDAMON_CACHE_"),
)

# Headings of the sections the think node places AFTER the skill text (think_node.py,
# base.build_roe_prompt_section). Skill text must not impersonate them: an override that
# opened its own "SCOPE GUARDRAIL" or "USER GUIDANCE" could contradict the real one with
# equal authority.
RESERVED_HEADINGS = (
    "SCOPE GUARDRAIL",
    "RULES OF ENGAGEMENT (MANDATORY)",
    "RoE TIMING WARNINGS",
    "UNPRODUCTIVE STREAK DETECTED",
    "PRODUCTIVITY HINT",
    "Prior Productivity Claim Was Downgraded",
    "USER GUIDANCE (IMPORTANT)",
    "SKILL FIT CHECK",
)
# A heading-like line naming the RoE: decorated (#, >, **, __, =, |) or written in capitals.
# Prose that merely mentions the rules of engagement stays allowed.
_ROE_LINE = re.compile(r"^(?P<lead>[\s#>*_=|-]*)(?P<words>rules[\W_]+of[\W_]+engagement)\b", re.IGNORECASE)
_SETEXT_UNDERLINE = re.compile(r"^\s*(=+|-+)\s*$")

# Invisible to the person who approves a version but read by the model: format characters
# (zero-width, bidi controls, Unicode tag characters), private-use and surrogate code points,
# line/paragraph separators, and control characters other than tab and line breaks.
_HIDDEN_CATEGORIES = {"Cf", "Co", "Cs", "Zl", "Zp"}

# Cyrillic and Greek letters that read as Latin ones and survive NFKC.
_LOOKALIKES = str.maketrans(dict(zip(
    "АВСЕНІЈКМОРЅТХУаеһіјорсѕхуԁԛԝΑΒΕΖΗΙΚΜΝΟΡΤΥΧαικνορτυχ",
    "ABCEHIJKMOPSTXYaehijopcsxydqwABEZHIKMNOPTYXaikvoptux",
)))
_PLACEHOLDER_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")

DEFAULT_SKILL_GROWTH = 1.5


def max_chars_for(factory: str) -> int:
    return max(2 * len(factory), len(factory) + 20_000)


def max_part_chars(part: SkillPart) -> int:
    return max_chars_for(part.text)


def _hidden_chars(text: str) -> set:
    return {ch for ch in text
            if unicodedata.category(ch) in _HIDDEN_CATEGORIES
            or (unicodedata.category(ch) == "Cc" and ch not in "\t\n\r")}


def _factory_counts(part: SkillPart) -> dict:
    counts: dict = {}
    for _literal, field, _spec, _conv in string.Formatter().parse(part.text):
        if field:
            counts[field] = counts.get(field, 0) + 1
    return counts


def _as_read(text: str) -> str:
    """The text as a model reads it: compatibility forms folded (full-width letters),
    invisible format characters dropped (zero-width space, word joiner, soft hyphen),
    and common Cyrillic and Greek look-alikes mapped to Latin. Used only to detect
    reserved strings; the value itself is never altered."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.translate(_LOOKALIKES)


def _letters(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.casefold())


def reserved_errors(value: str) -> list:
    """The reserved markers and prompt-section headings `value` would show the model."""
    errors = []
    read = _as_read(value)
    for pattern, marker in _MARKER_RES:
        if pattern.search(read):
            errors.append(f"value contains the reserved marker {marker!r}")
    # Letters only: separators, spacing and punctuation cannot split a heading apart.
    letters = _letters(read)
    for heading in RESERVED_HEADINGS:
        if _letters(heading) in letters:
            errors.append(f"value contains the heading of the {heading!r} prompt section")
    lines = read.splitlines()
    for i, line in enumerate(lines):
        match = _ROE_LINE.match(line)
        underlined = i + 1 < len(lines) and _SETEXT_UNDERLINE.match(lines[i + 1])
        if match and (re.search(r"[#*_=|]", match.group("lead")) or match.group("words").isupper()
                      or underlined):
            errors.append("value opens a 'Rules of Engagement' heading; that prompt section is the agent's own")
            break
    return errors


def _template_errors(part: SkillPart, value: str) -> list:
    try:
        fields = list(string.Formatter().parse(value))
    except ValueError as exc:
        return [f"not a valid template: {exc}"]
    errors, names = [], set()
    for _literal, field, spec, conversion in fields:
        if field is None:
            continue
        if not _PLACEHOLDER_NAME.match(field):
            errors.append(f"placeholder {{{field}}} must be a plain lower-case name")
            continue
        if conversion:
            errors.append(f"placeholder {{{field}}} must not use a conversion (!{conversion})")
        if spec:
            errors.append(f"placeholder {{{field}}} must not use a format spec (:{spec})")
        names.add(field)
    factory_counts = _factory_counts(part)
    used: dict = {}
    for _literal, field, _spec, _conv in fields:
        if field in part.placeholders:
            used[field] = used.get(field, 0) + 1
    for name, count in sorted(used.items()):
        # A placeholder renders operator data of any size: repeating it multiplies the
        # rendered prompt while the template stays small.
        if count > 2 * factory_counts.get(name, 1):
            errors.append(f"placeholder {{{name}}} appears {count} times; at most "
                          f"{2 * factory_counts.get(name, 1)} (twice the factory text)")
    missing = sorted(part.placeholders - names)
    unknown = sorted(names - part.placeholders)
    if missing:
        errors.append(f"missing placeholders: {', '.join(missing)}")
    if unknown:
        errors.append(f"unknown placeholders: {', '.join(unknown)}")
    if not errors:
        for fill in ("", "x"):
            try:
                rendered = value.format(**{name: fill for name in part.placeholders})
                factory = part.text.format(**{name: fill for name in part.placeholders})
            except Exception as exc:  # noqa: BLE001 - any render failure refuses the value
                errors.append(f"not a valid template: {exc}")
                break
            # A placeholder can render empty (dos_assessment_only_block by default), so a
            # reserved string split around one must be judged once the placeholders are filled.
            for error in reserved_errors(rendered):
                if error not in reserved_errors(factory) and f"{error} (once its placeholders are filled)" not in errors:
                    errors.append(f"{error} (once its placeholders are filled)")
    return errors


def validate_part_value(part: SkillPart, value) -> list:
    """Every reason `value` cannot replace `part`; an empty list means it can."""
    if not isinstance(value, str):
        return ["value must be a string"]
    errors = []
    if not value.strip():
        errors.append("value is empty")
    if "\x00" in value:
        errors.append("value contains a NUL character")
    limit = max_part_chars(part)
    if len(value) > limit:
        errors.append(f"value is {len(value)} characters; the limit for {part.key} is {limit}")
    hidden = sorted(_hidden_chars(value) - _hidden_chars(part.text))
    if hidden:
        shown = ", ".join(f"U+{ord(ch):04X}" for ch in hidden[:5])
        errors.append(f"value contains invisible or control characters ({shown}); the person "
                      "approving a version could not see them")
    errors.extend(reserved_errors(value))
    if part.kind == TEMPLATE:
        errors.extend(_template_errors(part, value))
    return errors


def max_skill_growth() -> float:
    """PLUGIN_SKILL_TEXT_MAX_GROWTH: how many times its factory size a whole skill may grow."""
    raw = os.environ.get("PLUGIN_SKILL_TEXT_MAX_GROWTH", "")
    try:
        growth = float(raw)
    except ValueError:
        growth = math.nan
    if not math.isfinite(growth) or growth < 1.0:
        if raw.strip():
            logger.warning("[skill.text] PLUGIN_SKILL_TEXT_MAX_GROWTH=%r is not a number >= 1; "
                           "using %s", raw, DEFAULT_SKILL_GROWTH)
        return DEFAULT_SKILL_GROWTH
    return growth


def skill_total_limit(skill_id: str) -> int:
    return int(sum(len(p.text) for p in parts_of(skill_id)) * max_skill_growth())


def validate_skill_total(skill_id: str, parts: dict) -> list:
    """The whole skill with `parts` ({part_id: value}) applied over its factory text must
    stay within the growth bound, so successive versions cannot grow it part by part."""
    factory_parts = parts_of(skill_id)
    if not factory_parts:
        return [f"unknown skill {skill_id!r}"]
    known = {p.part_id for p in factory_parts}
    errors = [f"unknown part {skill_id}/{pid}" for pid in sorted(set(parts) - known)]
    errors += [f"{skill_id}/{pid}: value must be a string"
               for pid, v in sorted(parts.items()) if pid in known and not isinstance(v, str)]
    if errors:
        return errors
    total = sum(len(parts.get(p.part_id, p.text)) for p in factory_parts)
    factory_total = sum(len(p.text) for p in factory_parts)
    limit = skill_total_limit(skill_id)
    if total > limit:
        errors.append(f"{skill_id}: the whole skill would be {total} characters; the limit is "
                      f"{limit} ({max_skill_growth()} x its factory {factory_total})")
    return errors
