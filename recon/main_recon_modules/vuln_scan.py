"""
RedAmon - Vulnerability Scanner Module
======================================
Template-based vulnerability scanning.
Enriches reconnaissance data with comprehensive web application vulnerability detection:
- CVE detection (8000+ templates)
- Web application vulnerabilities (SQLi, XSS, RCE, etc.)
- Exposed panels and sensitive files
- Misconfigurations
- Default credentials
- Cloud security issues
- Technology fingerprinting

Scans both IPs and hostnames (subdomains) for complete coverage.
Organizes results by target in the JSON output.
Supports proxy/Tor for anonymous scanning.
"""

import copy
import ipaddress
import json
import os
import shutil
import ipaddress
import subprocess
import threading
import time
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import sys


def _url_host_is_ip(url: str) -> bool:
    """Return True if the URL's host is a literal IPv4/IPv6 address."""
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


def _build_tech_fingerprint(http_probe: dict) -> dict:
    """Aggregate Wappalyzer technologies and Server headers from http_probe
    into a single fingerprint for the Nuclei AI tag selector."""
    techs, servers = set(), set()
    for entry in (http_probe.get('by_url') or {}).values():
        for t in (entry.get('technologies') or []):
            techs.add(str(t).lower())
        srv = (entry.get('server') or '').lower().split('/')[0].strip()
        if srv:
            servers.add(srv)
    for k in (http_probe.get('technologies_found') or {}).keys():
        techs.add(str(k).lower())
    return {"technologies": sorted(techs), "servers": sorted(servers)}

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Settings are passed from main.py to avoid multiple database queries

# Import helpers from organized modules
from recon.helpers import (
    # Docker utilities
    is_docker_installed,
    is_docker_running,
    fix_file_ownership,
    pull_nuclei_docker_image,
    ensure_templates_volume,
    # Target extraction
    extract_targets_from_recon,
    build_target_urls,
    filter_nuclei_detection_targets,
    # Nuclei helpers
    build_nuclei_command,
    NucleiEmptySelectionError,
    parse_nuclei_finding,
    is_false_positive,
    set_fp_ai_ctx,
    # CVE lookup
    run_cve_lookup,
    # Security checks
    run_security_checks,
)
from recon.helpers.template_classification import (
    TemplateCategory,
    TemplateClassificationRegistry,
    get_registry,
    classify_template,
    batch_templates_by_category,
    get_compatibility_lane_templates,
    analyze_template_capability,
    RequestCapability,
    validate_auth_batch_safety,
    resolve_routing_mode,
    routing_consumer_enabled,
    MODE_OFF,
    MODE_SHADOW,
    MODE_ENFORCE,
)
from recon.helpers.auth_profile import (
    resolve_scope_hosts,
    profile_from_settings,
)
from recon.helpers.planner_runtime import enforcing, plan_dispatch, persist_dispatch, routing_compatibility_reason
from recon.helpers.security_checks import page_content_enabled
from recon.helpers.isolated_result import TopLevelKeys
from recon.helpers.selection_coverage import (
    KEY as SELECTION_KEY,
    build_plan,
    is_exhaustive,
    persist_plan,
    plan_hosts,
    record_outcome,
    record_execution,
)
from recon.helpers.target_admission import admission_context, admit_urls

# Every top-level key run_vuln_scan writes; the security checks nest inside
# vuln_scan. technology_cves exists only when the CVE lookup ran.
# selection_coverage is the persisted plan of what this run selected; it is
# written BEFORE the tool launches and carried through every merge boundary.
_VULN_SCAN_RESULT_KEYS = ("vuln_scan", "technology_cves", SELECTION_KEY, "planner_manifest")


def _nuclei_watch_stats(line: str, label: str, state: dict) -> None:
    """Warn ONCE if 10 min pass with >50% of requests erroring and zero matches.

    Reads the JSON `-stats` heartbeat nuclei already prints; every field is a
    string. A tarpit or a dead target set looks like this, and the warning is
    the operator's cue to lower NUCLEI_MAX_RUNTIME. Never raises.
    """
    if state.get("warned"):
        return
    text = line.lstrip()
    if not (text.startswith("{") and '"requests"' in text and '"errors"' in text):
        return
    try:
        stats = json.loads(text)
        requests_n = int(stats.get("requests") or 0)
        errors_n = int(stats.get("errors") or 0)
        matched_n = int(stats.get("matched") or 0)
    except Exception:  # noqa: BLE001
        return
    bad = requests_n >= 100 and matched_n == 0 and errors_n > requests_n * 0.5
    now = time.monotonic()
    if not bad:
        state["since"] = None
        return
    if state["since"] is None:
        state["since"] = now
    elif now - state["since"] >= 600:
        state["warned"] = True
        pct = int(100 * errors_n / requests_n) if requests_n else 0
        print(f"[!][Nuclei] {label}: {pct}% of {requests_n:,} requests are erroring "
              f"with no matches after 10 min - consider lowering NUCLEI_MAX_RUNTIME", flush=True)


def _keep_nuclei_findings(reason: str) -> None:
    """Record that Nuclei re-checked nothing this run, so the prune keeps its findings."""
    try:
        from recon.helpers import circuit_breaker
        circuit_breaker.note_degraded("vuln_scan", sources=["nuclei", "vuln_scan"], reason=reason)
    except Exception:  # noqa: BLE001
        pass


def _nuclei_pass_outcome(returncode, duration, runtime_cap, parsed) -> tuple:
    """``(status, reason)`` for every host one pass targeted. A pass stopped at
    NUCLEI_MAX_RUNTIME never says which targets it reached, so all are partial;
    the watchdog fires at the cap, so the pass lasted at least that long."""
    if returncode == -124:
        return "partial", "runtime cap"
    if returncode == 0:
        return "complete", None
    if runtime_cap and duration >= runtime_cap:
        return "partial", "runtime cap"
    return ("partial" if parsed else "failed"), f"nuclei exited {returncode}"


# Nuclei's own fatal when its template loader ends up with zero templates after
# the policy is applied. Matched as a substring so the surrounding level prefix
# ([FTL]/[ERR]) and minor wording changes do not hide it.
_NUCLEI_NO_TEMPLATES_MARKER = "no templates provided for scan"


def _nuclei_no_templates_fatal(lines):
    """The nuclei fatal proving the effective selection was empty, or None.

    Returns the matching fatal line, prefixed with nuclei's own loader error
    when there is one (a bad explicit template path), so the recorded
    ``policy_empty`` detail distinguishes an exclusion-emptied pool from a
    misconfigured template path. Distinct from a generic non-zero exit: it means
    the pass had nothing to run.
    """
    fatal = None
    loader_error = None
    for line in lines or ():
        if _NUCLEI_NO_TEMPLATES_MARKER in line:
            fatal = line
        elif fatal is None and loader_error is None and (
                "Could not find template" in line or "could not find file" in line):
            loader_error = line
    if fatal is None:
        return None
    if loader_error:
        return f"{loader_error}\n{fatal}"
    return fatal


def _nuclei_coverage(at: str, passes, findings=(), exhaustive: bool = True) -> dict:
    """``{"at", "hosts"}`` from ``passes = [(urls, status, reason, ran)]``.

    A host's inputs are the URLs the passes that ran sent it; it is complete
    only when every pass that targeted it completed, failed only when every
    one failed, partial otherwise. A run whose selection is a strict subset of
    its configured baseline never says "complete": an origin covered only in
    part is partial, however cleanly the selected pass exited.
    """
    from collections import Counter, defaultdict
    from recon.helpers.coverage_stamps import base_url_key, coverage_row

    inputs, statuses, reasons = Counter(), defaultdict(set), defaultdict(list)
    for urls, status, reason, ran in passes:
        for url in urls:
            key = base_url_key(url)
            if not key:
                continue
            inputs[key] += 1 if ran else 0
            statuses[key].add(status)
            if reason and reason not in reasons[key]:
                reasons[key].append(reason)
    found = Counter(base_url_key(f.get("matched_at") or f.get("target")) for f in findings)

    hosts = {}
    for key, seen in sorted(statuses.items()):
        if len(seen) == 1:
            status = next(iter(seen))
        else:
            status = "partial"
        # A selective run (AI-pruned tags, partial-run limits, a deferred pass)
        # re-checked only part of what the host could have been checked for,
        # so even a clean selected pass is partial, never complete.
        if not exhaustive and status == "complete":
            status = "partial"
            if "selected targets/templates" not in reasons[key]:
                reasons[key] = list(reasons[key]) + ["selected targets/templates"]
        hosts[key] = coverage_row(status, inputs[key], found[key], ", ".join(reasons[key]))
    return {"at": at, "hosts": hosts}


def _record_unrun_nuclei(recon_data: dict, coverage: dict) -> None:
    """Carry the coverage of a Nuclei that never ran to the graph writer; a
    record naming no host has nothing to stamp."""
    if coverage["hosts"]:
        recon_data["vuln_scan"] = {"scan_metadata": {"coverage": coverage}}


def _selection_plan(*, targets, saved_tags, effective_tags, ai_pruned=False,
                    partial_scope=False, deferred=False, severity=None, exclude_tags=None,
                    templates=None, exclude_templates=None, custom_templates=None,
                    selected_custom_templates=None, dast_targets=None, dast_mode=False) -> dict:
    """The persisted plan of what THIS Nuclei run selected (F07).

    ``exhaustive`` is True only when the effective selection is exactly the
    configured baseline: no AI pruning removed a tag, no partial-run limit
    narrowed the targets, and no pass was deferred. The operator's saved
    tags/templates/severity are the baseline by design - counting them as a
    selection would make every default run selective and disable the prune.

    The plan is written BEFORE the first pass launches, so a cancellation or
    crash keeps the accounting; it is a plan, never a result checkpoint.
    """
    saved = list(saved_tags or [])
    effective = list(effective_tags or [])
    removed = [t for t in saved if t not in set(effective)]
    templates_block = {
        "tags": effective,
        "tags_saved": saved,
        "tags_removed": removed,
        "exclude_tags": list(exclude_tags or []),
        "templates": list(templates or []),
        "exclude_templates": list(exclude_templates or []),
        "custom_templates": list(custom_templates or []),
        "selected_custom_templates": list(selected_custom_templates or []),
        "severity": list(severity or []),
        "ai_pruned": bool(ai_pruned),
    }
    reasons = []
    if ai_pruned:
        reasons.append(f"AI tag pruning removed {len(removed)} tag(s)")
    if partial_scope:
        reasons.append("partial run: targets/templates limited to the requested scope")
    if deferred:
        reasons.append("a planned pass was deferred")
    exhaustive = not reasons
    plan = build_plan(
        module="vuln_scan",
        targets=list(targets or []),
        templates=templates_block,
        exhaustive=exhaustive,
        reason="; ".join(reasons) or None,
        scope="partial" if partial_scope else "full",
    )
    plan["passes"] = [
        {"name": "detection", "targets": len(list(targets or [])),
         "templates": "tags" if effective else "none", "ran": False},
    ]
    if dast_mode and dast_targets:
        plan["passes"].append({"name": "dast", "targets": len(list(dast_targets)),
                               "templates": "dast", "ran": False})
    return plan


def _note_selection_cut(plan: dict) -> None:
    """Record a non-exhaustive run's selection cut for the prune.

    The cut is host-level and per-source, so a Nuclei selection never resets
    the security_check or CVE coverage of the same host. It carries the plan
    id, which is what makes the cut provable; without one the accumulator
    marks the run's coverage unknown and the prune fails closed.
    """
    if is_exhaustive(plan):
        return
    try:
        from recon.helpers import circuit_breaker
        circuit_breaker.note_selection_cut(
            "vuln_scan", sources=["nuclei"], hosts=plan_hosts(plan),
            plan_id=plan.get("plan_id") or "", reason=plan.get("reason") or "",
        )
    except Exception:  # noqa: BLE001 - a plan is never worth failing a scan over
        pass



def _live_web_urls(recon_data: dict) -> list:
    """The URLs http_probe got an answer under 500 from: the hosts a Nuclei
    that could not start would have scanned."""
    from recon.helpers.target_helpers import build_target_urls_from_httpx
    return build_target_urls_from_httpx(recon_data.get("http_probe"))


# ---------------------------------------------------------------------------
# Template Classification & Routing (F14)
# ---------------------------------------------------------------------------

def _classify_and_route_templates(
    template_tags: List[str],
    template_paths: List[str],
    custom_templates: List[str],
    selected_custom_templates: List[str],
    exclude_templates: List[str],
    exclude_tags: List[str],
    resource_enum_data: Optional[dict] = None,
    http_probe_data: Optional[dict] = None,
    admitted_targets: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Classify templates by semantics and route them to appropriate target sets.
    
    Returns a dict with routing plan:
    {
        "by_category": {category: [template_ids]},
        "target_sets": {category: [urls]},
        "compatibility_templates": [template_ids],
        "routing_metadata": {...}
    }
    """
    from urllib.parse import urlparse
    registry = get_registry()
    
    # Separate tag-based selection from explicit template paths
    tag_based = list(template_tags or [])  # These are tag names like "cve", "xss"
    # Explicit templates (paths + custom) - deduplicated
    explicit_templates = []
    seen_explicit = set()
    for tpl in (template_paths or []) + (custom_templates or []) + (selected_custom_templates or []):
        if tpl and tpl not in seen_explicit:
            explicit_templates.append(tpl)
            seen_explicit.add(tpl)
    
    # Classify explicit templates by content if available, or by path prefix
    explicit_classified = {}
    for tpl in explicit_templates:
        classified = registry.classify(tpl)
        explicit_classified[tpl] = classified
    
    # Classify tag-based selection using registry's tag classification
    # (not hardcoded ENDPOINT default)
    tag_classified = {}
    for tag in tag_based:
        # Use registry's tag-based heuristic classification
        category = registry._classify_by_tags((tag,))
        tag_classified[tag] = category
    
    # Build target sets from resource_enum and http_probe
    base_urls = []
    endpoint_urls = []
    origin_urls = []  # Just the origin (scheme://host)
    
    if resource_enum_data:
        by_base_url = resource_enum_data.get("by_base_url", {})
        for base_url, base_data in by_base_url.items():
            origin = base_url
            base_urls.append(base_url)
            endpoints = base_data.get("endpoints", {})
            for path, ep_info in endpoints.items():
                if isinstance(path, str) and path.startswith("/") and "{" not in path:
                    # Has parameters?
                    params = ep_info.get("parameters", {})
                    has_params = False
                    if isinstance(params, dict):
                        query_params = params.get("query", [])
                        body_params = params.get("body", [])
                        has_params = bool(query_params or body_params)
                    if has_params:
                        endpoint_urls.append(f"{base_url}{path}")
            # Origin URL (base)
            origin_urls.append(origin)
    
    if http_probe_data:
        by_url = http_probe_data.get("by_url", {})
        for url, url_data in by_url.items():
            if url not in base_urls:
                base_urls.append(url)
            # Extract origin
            from urllib.parse import urlparse
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin not in origin_urls:
                origin_urls.append(origin)
    
    # Deduplicate
    base_urls = sorted(set(base_urls))
    endpoint_urls = sorted(set(endpoint_urls))
    origin_urls = sorted(set(origin_urls))
    
    # Route templates to target sets
    routing = {
        "by_category": {cat.value: [] for cat in TemplateCategory},
        "target_sets": {
            TemplateCategory.ORIGIN_SAFE.value: origin_urls,
            TemplateCategory.APP_PREFIX.value: base_urls,  # App prefix checks run on base URLs
            TemplateCategory.ENDPOINT.value: endpoint_urls if endpoint_urls else base_urls,
            TemplateCategory.BODY_MULTIPART.value: endpoint_urls if endpoint_urls else base_urls,
            TemplateCategory.MULTI_REQUEST.value: base_urls,
            TemplateCategory.RAW_HTTP.value: base_urls,
            TemplateCategory.UNKNOWN.value: base_urls,  # Compatibility lane runs on all
        },
        "compatibility_templates": [],
        "routing_metadata": {
            "total_templates": len(tag_based) + len(explicit_templates),
            "tag_based_count": len(tag_based),
            "explicit_count": len(explicit_templates),
            "origin_urls": len(origin_urls),
            "base_urls": len(base_urls),
            "endpoint_urls": len(endpoint_urls),
        }
    }
    
    if admitted_targets is not None:
        # Routing must not synthesize URLs from inventory (which may be
        # declared-only or carry a different encoded query). Missing root or
        # request-transport proof keeps the admitted legacy list intact.
        admitted = list(admitted_targets)
        roots = [u for u in admitted if urlparse(u).path in ('', '/') and not urlparse(u).query]
        origins = {f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in admitted}
        root_origins = {f"{urlparse(u).scheme}://{urlparse(u).netloc}" for u in roots}
        for category in TemplateCategory:
            routing['target_sets'][category.value] = (
                roots if category == TemplateCategory.ORIGIN_SAFE and origins == root_origins
                and all(ref in ('ssl', 'tls', 'certificate') or ref.startswith(('ssl/', 'tls/', 'certificate/'))
                        for ref in list(template_tags or []) + explicit_templates) else admitted)
        routing['routing_metadata']['input_contract'] = 'admitted legacy URLs only; unsupported semantics compatibility'

    # Add explicit templates to routing (each goes to exactly ONE category)
    for tpl, classified in explicit_classified.items():
        routing["by_category"][classified.category.value].append(tpl)
        if classified.category == TemplateCategory.UNKNOWN:
            routing["compatibility_templates"].append(tpl)
    
    # Add tag-based templates to routing (each tag goes to exactly ONE category)
    for tag, cat in tag_classified.items():
        routing["by_category"][cat.value].append(f"tag:{tag}")
        if cat == TemplateCategory.UNKNOWN:
            routing["compatibility_templates"].append(f"tag:{tag}")
    
    return routing


def _build_routed_nuclei_commands(
    routing: Dict[str, Any],
    nuclei_temp_dir: Path,
    base_settings: Dict[str, Any],
    auth_headers: List[str],
    container_prefix: str,
    scope_hosts: List[str],
) -> List[Dict[str, Any]]:
    """
    Build separate nuclei commands for each template category with appropriate targets.
    
    Returns list of command configs:
    [
        {
            "category": "origin_safe",
            "targets_file": "...",
            "output_file": "...",
            "container_name": "...",
            "cmd": [...],
            "template_selection": {...},
        },
        ...
    ]
    """
    commands = []
    
    # Category to target set mapping
    target_sets = routing["target_sets"]
    by_category = routing["by_category"]
    
    # Collect all template IDs for capability analysis
    all_template_ids = []
    for templates in by_category.values():
        all_template_ids.extend([t for t in templates if not t.startswith("tag:")])
    
    # Analyze capabilities for auth batch safety
    template_capabilities = {}
    for tpl in all_template_ids:
        cap = analyze_template_capability(tpl)
        template_capabilities[tpl] = cap
    
    # Validate auth batch safety if we have auth headers
    if auth_headers:
        target_origins = []
        for targets in target_sets.values():
            target_origins.extend(targets)
        is_safe, warnings = validate_auth_batch_safety(
            templates=all_template_ids,
            auth_headers=auth_headers,
            target_origins=target_origins,
            scope_hosts=scope_hosts,
        )
        if warnings:
            for w in warnings:
                print(f"[!][Nuclei-Routing] Auth safety: {w}")
        if not is_safe:
            print(f"[!][Nuclei-Routing] Auth batch safety check FAILED - some templates may leak credentials")
    
    for cat_value, templates in by_category.items():
        if not templates:
            continue
        
        category = TemplateCategory(cat_value)
        targets = target_sets.get(cat_value, [])
        
        if not targets:
            print(f"[!][Nuclei-Routing] No targets for category {cat_value}, skipping")
            continue
        
        # Write targets file for this category
        targets_file = str(nuclei_temp_dir / f"targets_{cat_value}.txt")
        with open(targets_file, 'w') as f:
            for url in targets:
                f.write(url + "\n")
        
        output_file = str(nuclei_temp_dir / f"nuclei_{cat_value}.jsonl")
        container_name = f"{container_prefix}-{cat_value}-{uuid.uuid4().hex[:8]}"
        
        # Build template selection for this category
        # Separate tags from explicit templates (custom templates already routed to correct category)
        cat_tags = [t.replace("tag:", "") for t in templates if t.startswith("tag:")]
        cat_explicit = [t for t in templates if not t.startswith("tag:")]
        
        # Build command - NO custom_templates injection (already routed per category)
        cmd = build_nuclei_command(
            targets_file=targets_file,
            output_file=output_file,
            docker_image=base_settings.get("NUCLEI_DOCKER_IMAGE", "projectdiscovery/nuclei:latest"),
            severity=base_settings.get("NUCLEI_SEVERITY", ["critical", "high", "medium", "low"]),
            templates=cat_explicit if cat_explicit else None,
            exclude_templates=base_settings.get("NUCLEI_EXCLUDE_TEMPLATES", []),
            custom_templates=[],  # Already routed per category, don't re-inject
            selected_custom_templates=[],  # Already routed per category, don't re-inject
            tags=cat_tags if cat_tags else None,
            exclude_tags=base_settings.get("NUCLEI_EXCLUDE_TAGS", []),
            rate_limit=base_settings.get("NUCLEI_RATE_LIMIT", 100),
            bulk_size=base_settings.get("NUCLEI_BULK_SIZE", 25),
            concurrency=base_settings.get("NUCLEI_CONCURRENCY", 25),
            timeout=base_settings.get("NUCLEI_TIMEOUT", 10),
            retries=base_settings.get("NUCLEI_RETRIES", 1),
            dast_mode=False,
            new_templates_only=base_settings.get("NUCLEI_NEW_TEMPLATES_ONLY", False),
            headless=base_settings.get("NUCLEI_HEADLESS", False),
            system_resolvers=base_settings.get("NUCLEI_SYSTEM_RESOLVERS", True),
            follow_redirects=base_settings.get("NUCLEI_FOLLOW_REDIRECTS", True),
            max_redirects=base_settings.get("NUCLEI_MAX_REDIRECTS", 10),
            interactsh=base_settings.get("NUCLEI_INTERACTSH", True),
            auth_headers=auth_headers,
            container_name=container_name,
            max_host_error=base_settings.get("NUCLEI_MAX_HOST_ERROR", 30),
        )
        
        commands.append({
            "category": cat_value,
            "targets_file": targets_file,
            "output_file": output_file,
            "container_name": container_name,
            "cmd": cmd,
            "template_selection": {
                "tags": cat_tags,
                "explicit_templates": cat_explicit,
                "target_count": len(targets),
            },
            "target_urls": targets,
        })
    
    return commands


def _execute_routed_passes(
    routed_commands: List[Dict[str, Any]],
    runtime_cap: float,
    label_prefix: str = "DETECTION",
) -> Tuple[List[Dict], List[Dict], float, List[Dict]]:
    """
    Execute multiple routed nuclei passes and collect results.
    
    Returns: (all_findings, all_false_positives, total_duration, coverage_passes)
    """
    all_findings = []
    all_false_positives = []
    total_duration = 0.0
    coverage_passes = []
    
    for cmd_info in routed_commands:
        category = cmd_info["category"]
        targets = cmd_info["target_urls"]
        container_name = cmd_info["container_name"]
        cmd = cmd_info["cmd"]
        output_file = cmd_info["output_file"]
        
        label = f"{label_prefix}-{category.upper()}"
        print(f"[*][Nuclei] Running {label} pass on {len(targets)} targets with {len(cmd_info['template_selection']['tags'])} tags + {len(cmd_info['template_selection']['explicit_templates'])} explicit templates")
        
        try:
            findings, fps, duration, rc = _execute_nuclei_pass(
                cmd, output_file, label=label,
                runtime_cap=runtime_cap, container_name=container_name,
            )
            all_findings.extend(findings)
            all_false_positives.extend(fps)
            total_duration += duration
            coverage_passes.append((targets, *_nuclei_pass_outcome(
                rc, duration, runtime_cap, findings or fps), True))
        except NucleiEmptySelectionError as exc:
            print(f"[!][Nuclei] {label} pass not executed (policy_empty): {exc}")
            _keep_nuclei_findings(f"nuclei {label} pass not executed: policy_empty")
            coverage_passes.append((targets, "failed", f"policy_empty: {exc}", False))
        except Exception as exc:
            print(f"[!][Nuclei] {label} pass failed: {exc}")
            _keep_nuclei_findings(f"nuclei {label} pass failed: {type(exc).__name__}")
            coverage_passes.append((targets, "failed", str(exc), False))
    
    return all_findings, all_false_positives, total_duration, coverage_passes


def _nuclei_kill_container(container_name: str) -> None:
    """`docker kill` a named nuclei container. The daemon owns it, so killing the
    docker CLI (process.terminate) would leave it running. Never raises."""
    from recon.helpers.docker_helpers import kill_container
    kill_container(container_name)


def _execute_nuclei_pass(cmd: list, output_file: str, label: str,
                         runtime_cap: float = 0, container_name: str = None) -> tuple:
    """
    Run a single nuclei invocation and parse the JSONL output.

    ``runtime_cap`` (seconds, with ``container_name``) is a wall-clock ceiling
    enforced by a watchdog: at the cap the container is killed, the partial
    JSONL already on disk is still parsed, and the run is recorded as truncated
    (a 21.5h field run sat at 31% because process.wait() had no timeout).

    Returns (findings, false_positives, duration_seconds, return_code).
    """
    print(f"[*][Nuclei] Running {label} pass [DOCKER]...")
    print(f"[*][Nuclei] {label} command: {' '.join(cmd[:12])}...")

    start_time = datetime.now()
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    truncated = {"hit": False}
    watchdog = None
    if runtime_cap and runtime_cap > 0 and container_name:
        def _fire():
            truncated["hit"] = True
            hrs = runtime_cap / 3600.0
            print(f"[!][Nuclei] {label} hit the {hrs:.1f}h runtime cap "
                  f"(NUCLEI_MAX_RUNTIME) - stopping it, keeping partial results", flush=True)
            _nuclei_kill_container(container_name)
        watchdog = threading.Timer(runtime_cap, _fire)
        watchdog.daemon = True
        watchdog.start()

    stat_watch = {"since": None, "warned": False}
    stderr_lines = []
    try:
        for line in process.stdout:
            line = line.rstrip()
            if not line:
                continue
            print(f"[*][Nuclei][{label}] {line}", flush=True)
            stderr_lines.append(line)
            _nuclei_watch_stats(line, label, stat_watch)
        process.wait()
    finally:
        if watchdog is not None:
            watchdog.cancel()
    duration = (datetime.now() - start_time).total_seconds()

    if truncated["hit"]:
        try:
            from recon.helpers import circuit_breaker
            circuit_breaker.note_degraded("vuln_scan", sources=["nuclei"],
                                          nuclei_truncated=True,
                                          reason="NUCLEI_MAX_RUNTIME reached")
        except Exception:  # noqa: BLE001
            pass

    if process.returncode != 0 and stderr_lines:
        # Skip noise: nuclei [WRN]/[INF] lines, the pipe-format stats heartbeat
        # (`| Duration: 0:00:30 | ...`), and the JSON-format stats heartbeat
        # ({"duration":...,"matched":...}) so they don't masquerade as errors.
        error_lines = [
            l for l in stderr_lines
            if l
            and 'WRN' not in l
            and 'INF' not in l
            and '| Duration:' not in l
            and not (l.lstrip().startswith('{') and '"duration"' in l)
        ]
        if error_lines:
            print(f"[!][Nuclei] {label} warnings: {error_lines[0][:100]}")

    findings = []
    false_positives = []
    parsed_lines = 0
    if Path(output_file).exists():
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw_finding = json.loads(line)
                    parsed_lines += 1
                    is_fp, fp_reason = is_false_positive(raw_finding)
                    if is_fp:
                        false_positives.append({
                            "template_id": raw_finding.get("template-id", "unknown"),
                            "matched_at": raw_finding.get("matched-at", "unknown"),
                            "reason": fp_reason,
                        })
                        continue
                    findings.append(parse_nuclei_finding(raw_finding))
                except json.JSONDecodeError:
                    continue

    # Nuclei exits 0 whether or not it matched anything (no flag build_nuclei_command
    # passes changes that); a non-zero exit is a docker error (125-127), a kill
    # such as an OOM (137) or a fatal nuclei error. Whatever it wrote before
    # stopping is still ingested, but the targets and templates it never reached
    # were not re-checked, so their findings are kept. A run truncated by the
    # cap is recorded above.
    if process.returncode != 0 and not truncated["hit"]:
        # Nuclei fatals with "no templates provided for scan" when the policy
        # leaves its loader zero templates: every template the selection picked
        # was then removed by the exclusions. That is a policy-empty outcome,
        # not a scan failure, so raise the same refusal the builder uses and let
        # the caller record ``policy_empty`` (keeping the previous findings)
        # instead of a generic exit-1. No partial output exists for this fatal --
        # nuclei stops at load time, before any request.
        fatal = _nuclei_no_templates_fatal(stderr_lines)
        if fatal:
            _keep_nuclei_findings(f"nuclei {label} pass not executed: policy_empty")
            raise NucleiEmptySelectionError(fatal)
        if parsed_lines:
            print(f"[!][Nuclei] {label} pass stopped (exit {process.returncode}) after "
                  f"{parsed_lines} result(s) - previous Nuclei findings are kept")
        else:
            print(f"[!][Nuclei] {label} pass failed (exit {process.returncode}) with no "
                  f"results - previous Nuclei findings are kept")
        _keep_nuclei_findings(f"nuclei {label} pass exited {process.returncode}")

    # Preserve watchdog evidence even if the killed process reports exit zero.
    return findings, false_positives, duration, -124 if truncated["hit"] else process.returncode


# =============================================================================
# Severity Definitions
# =============================================================================

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

SEVERITY_COLORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚫"
}


def run_vuln_scan(recon_data: dict, output_file: Path = None, settings: dict = None,
                  selection_hint: dict = None, plan_output_file: Path = None) -> dict:
    """
    Run nuclei scan on all URLs derived from recon data.

    Args:
        recon_data: Domain reconnaissance data dictionary
        output_file: Optional path to save incremental results
        settings: Settings dictionary from main.py
        selection_hint: Optional partial-run marker (scope/deferred) that makes
            the plan non-exhaustive
        plan_output_file: Optional path the selection plan is MERGED into before
            the first pass launches. Used by the isolated wrapper, which runs on
            a deep copy in a fan-out thread and must not overwrite the canonical
            artifact with that copy; the merge is locked against save_recon_file.

    Returns:
        Updated recon_data with nuclei results added
    """
    print("\n" + "=" * 70)
    print("[*][Nuclei] RedAmon - Nuclei Vulnerability Scanner")
    print("=" * 70)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    NUCLEI_SEVERITY = settings.get('NUCLEI_SEVERITY', ['critical', 'high', 'medium', 'low'])
    NUCLEI_TEMPLATES = settings.get('NUCLEI_TEMPLATES', [])
    NUCLEI_EXCLUDE_TEMPLATES = settings.get('NUCLEI_EXCLUDE_TEMPLATES', [])
    NUCLEI_RATE_LIMIT = settings.get('NUCLEI_RATE_LIMIT', 100)
    NUCLEI_BULK_SIZE = settings.get('NUCLEI_BULK_SIZE', 25)
    NUCLEI_CONCURRENCY = settings.get('NUCLEI_CONCURRENCY', 25)
    NUCLEI_TIMEOUT = settings.get('NUCLEI_TIMEOUT', 10)
    NUCLEI_RETRIES = settings.get('NUCLEI_RETRIES', 1)
    NUCLEI_MAX_RUNTIME = settings.get('NUCLEI_MAX_RUNTIME', 86400)
    NUCLEI_MAX_HOST_ERROR = settings.get('NUCLEI_MAX_HOST_ERROR', 30)
    NUCLEI_TAGS = settings.get('NUCLEI_TAGS', ['cve', 'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'xxe', 'ssti'])
    # The configured baseline, captured before the AI tag selector may prune
    # it: F07 compares the effective selection against this to decide whether
    # the run covered everything it was configured to cover.
    saved_nuclei_tags = list(NUCLEI_TAGS or [])
    NUCLEI_EXCLUDE_TAGS = settings.get('NUCLEI_EXCLUDE_TAGS', ['dos', 'fuzz'])
    NUCLEI_DAST_MODE = settings.get('NUCLEI_DAST_MODE', False)
    NUCLEI_NEW_TEMPLATES_ONLY = settings.get('NUCLEI_NEW_TEMPLATES_ONLY', False)
    NUCLEI_CUSTOM_TEMPLATES = settings.get('NUCLEI_CUSTOM_TEMPLATES', [])
    NUCLEI_SELECTED_CUSTOM_TEMPLATES = settings.get('NUCLEI_SELECTED_CUSTOM_TEMPLATES', [])
    NUCLEI_HEADLESS = settings.get('NUCLEI_HEADLESS', False)
    NUCLEI_SYSTEM_RESOLVERS = settings.get('NUCLEI_SYSTEM_RESOLVERS', True)
    NUCLEI_FOLLOW_REDIRECTS = settings.get('NUCLEI_FOLLOW_REDIRECTS', True)
    NUCLEI_MAX_REDIRECTS = settings.get('NUCLEI_MAX_REDIRECTS', 10)
    NUCLEI_SCAN_ALL_IPS = settings.get('NUCLEI_SCAN_ALL_IPS', False)
    NUCLEI_INTERACTSH = settings.get('NUCLEI_INTERACTSH', True)
    NUCLEI_DOCKER_IMAGE = settings.get('NUCLEI_DOCKER_IMAGE', 'projectdiscovery/nuclei:latest')
    NUCLEI_AI_TAGS = settings.get('NUCLEI_AI_TAGS', False)
    NUCLEI_TAGS_AI_USE_JEV = settings.get('NUCLEI_TAGS_AI_USE_JEV', False)
    WAF_AI_CLASSIFIER = settings.get('WAF_AI_CLASSIFIER', False)
    WAF_AI_USE_JEV = settings.get('WAF_AI_USE_JEV', False)
    NUCLEI_AI_RESPONSE_FILTER = settings.get('NUCLEI_AI_RESPONSE_FILTER', False)
    AI_PIPELINE_MODEL = settings.get('AI_PIPELINE_MODEL', 'claude-opus-4-6')
    KATANA_DEPTH = settings.get('KATANA_DEPTH', 2)
    NUCLEI_AUTO_UPDATE_TEMPLATES = settings.get('NUCLEI_AUTO_UPDATE_TEMPLATES', True)
    CVE_LOOKUP_ENABLED = settings.get('CVE_LOOKUP_ENABLED', True)
    CVE_LOOKUP_SOURCE = settings.get('CVE_LOOKUP_SOURCE', 'nvd')
    CVE_LOOKUP_MAX_CVES = settings.get('CVE_LOOKUP_MAX_CVES', 20)
    CVE_LOOKUP_MIN_CVSS = settings.get('CVE_LOOKUP_MIN_CVSS', 0.0)
    VULNERS_API_KEY = settings.get('VULNERS_API_KEY', '')
    NVD_API_KEY = settings.get('NVD_API_KEY', '')
    NVD_KEY_ROTATOR = settings.get('NVD_KEY_ROTATOR')
    VULNERS_KEY_ROTATOR = settings.get('VULNERS_KEY_ROTATOR')
    SECURITY_CHECK_ENABLED = settings.get('SECURITY_CHECK_ENABLED', True)
    SECURITY_CHECK_DIRECT_IP_HTTP = settings.get('SECURITY_CHECK_DIRECT_IP_HTTP', True)
    SECURITY_CHECK_DIRECT_IP_HTTPS = settings.get('SECURITY_CHECK_DIRECT_IP_HTTPS', True)
    SECURITY_CHECK_IP_API_EXPOSED = settings.get('SECURITY_CHECK_IP_API_EXPOSED', True)
    SECURITY_CHECK_WAF_BYPASS = settings.get('SECURITY_CHECK_WAF_BYPASS', True)
    SECURITY_CHECK_TLS_EXPIRING_SOON = settings.get('SECURITY_CHECK_TLS_EXPIRING_SOON', True)
    SECURITY_CHECK_TLS_EXPIRY_DAYS = settings.get('SECURITY_CHECK_TLS_EXPIRY_DAYS', 30)
    SECURITY_CHECK_MISSING_REFERRER_POLICY = settings.get('SECURITY_CHECK_MISSING_REFERRER_POLICY', True)
    SECURITY_CHECK_MISSING_PERMISSIONS_POLICY = settings.get('SECURITY_CHECK_MISSING_PERMISSIONS_POLICY', True)
    SECURITY_CHECK_MISSING_COOP = settings.get('SECURITY_CHECK_MISSING_COOP', True)
    SECURITY_CHECK_MISSING_CORP = settings.get('SECURITY_CHECK_MISSING_CORP', True)
    SECURITY_CHECK_MISSING_COEP = settings.get('SECURITY_CHECK_MISSING_COEP', True)
    SECURITY_CHECK_CACHE_CONTROL_MISSING = settings.get('SECURITY_CHECK_CACHE_CONTROL_MISSING', True)
    SECURITY_CHECK_LOGIN_NO_HTTPS = settings.get('SECURITY_CHECK_LOGIN_NO_HTTPS', True)
    SECURITY_CHECK_SESSION_NO_SECURE = settings.get('SECURITY_CHECK_SESSION_NO_SECURE', True)
    SECURITY_CHECK_SESSION_NO_HTTPONLY = settings.get('SECURITY_CHECK_SESSION_NO_HTTPONLY', True)
    SECURITY_CHECK_BASIC_AUTH_NO_TLS = settings.get('SECURITY_CHECK_BASIC_AUTH_NO_TLS', True)
    SECURITY_CHECK_SPF_MISSING = settings.get('SECURITY_CHECK_SPF_MISSING', True)
    SECURITY_CHECK_DMARC_MISSING = settings.get('SECURITY_CHECK_DMARC_MISSING', True)
    SECURITY_CHECK_DNSSEC_MISSING = settings.get('SECURITY_CHECK_DNSSEC_MISSING', True)
    SECURITY_CHECK_ZONE_TRANSFER = settings.get('SECURITY_CHECK_ZONE_TRANSFER', True)
    SECURITY_CHECK_ADMIN_PORT_EXPOSED = settings.get('SECURITY_CHECK_ADMIN_PORT_EXPOSED', True)
    SECURITY_CHECK_DATABASE_EXPOSED = settings.get('SECURITY_CHECK_DATABASE_EXPOSED', True)
    SECURITY_CHECK_REDIS_NO_AUTH = settings.get('SECURITY_CHECK_REDIS_NO_AUTH', True)
    SECURITY_CHECK_KUBERNETES_API_EXPOSED = settings.get('SECURITY_CHECK_KUBERNETES_API_EXPOSED', True)
    SECURITY_CHECK_SMTP_OPEN_RELAY = settings.get('SECURITY_CHECK_SMTP_OPEN_RELAY', True)
    SECURITY_CHECK_CSP_UNSAFE_INLINE = settings.get('SECURITY_CHECK_CSP_UNSAFE_INLINE', True)
    SECURITY_CHECK_INSECURE_FORM_ACTION = settings.get('SECURITY_CHECK_INSECURE_FORM_ACTION', True)
    SECURITY_CHECK_NO_RATE_LIMITING = settings.get('SECURITY_CHECK_NO_RATE_LIMITING', True)
    SECURITY_CHECK_TIMEOUT = settings.get('SECURITY_CHECK_TIMEOUT', 10)
    SECURITY_CHECK_MAX_WORKERS = settings.get('SECURITY_CHECK_MAX_WORKERS', 10)

    # Check if Nuclei scanner is enabled
    NUCLEI_ENABLED = settings.get('NUCLEI_ENABLED', True)

    from recon.helpers.coverage_stamps import run_started_at
    coverage_at = run_started_at()

    # F08: the detection consumer's own input accounting, bound on every path
    # (the metadata block below is outside the ``if run_nuclei:`` scope).
    _target_admission: dict = {}
    _declared_report: dict = {}

    if not NUCLEI_ENABLED:
        print("[*][Nuclei] Vulnerability scanner disabled -- skipping")
        # Initialize empty vuln_scan structure so downstream code doesn't break
        recon_data["vuln_scan"] = {
            "scan_metadata": {
                "scan_timestamp": datetime.now().isoformat(),
                "scan_duration_seconds": 0,
                "nuclei_version": "N/A (disabled)",
                "templates_available": 0,
                "execution_mode": "disabled",
                "docker_image": NUCLEI_DOCKER_IMAGE,
                "anonymous_mode": False,
                "severity_filter": NUCLEI_SEVERITY,
                "tags_filter": NUCLEI_TAGS,
                "exclude_tags": NUCLEI_EXCLUDE_TAGS,
                "rate_limit": NUCLEI_RATE_LIMIT,
                "dast_mode": NUCLEI_DAST_MODE,
                "dast_urls_discovered": 0,
                "katana_crawl_depth": None,
                "total_urls_scanned": 0,
                "total_hostnames": 0,
                "total_ips": 0,
                "false_positives_filtered": 0,
            },
            "discovered_urls": {
                "base_urls": [],
                "dast_urls_with_params": [],
                "all_scanned_urls": [],
            },
            "by_target": {},
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "vulnerabilities": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "all_cves": [],
            "by_category": {},
            "by_template": {},
            "false_positives": [],
        }

    if NUCLEI_ENABLED:
        from recon.helpers import print_effective_settings
        print_effective_settings(
            "Nuclei",
            settings,
            keys=[
                ("NUCLEI_ENABLED", "Toggle"),
                ("NUCLEI_DOCKER_IMAGE", "Image"),
                ("NUCLEI_SEVERITY", "Severity & templates"),
                ("NUCLEI_TEMPLATES", "Severity & templates"),
                ("NUCLEI_EXCLUDE_TEMPLATES", "Severity & templates"),
                ("NUCLEI_TAGS", "Severity & templates"),
                ("NUCLEI_EXCLUDE_TAGS", "Severity & templates"),
                ("NUCLEI_CUSTOM_TEMPLATES", "Severity & templates"),
                ("NUCLEI_SELECTED_CUSTOM_TEMPLATES", "Severity & templates"),
                ("NUCLEI_DAST_MODE", "Advanced modes"),
                ("NUCLEI_NEW_TEMPLATES_ONLY", "Advanced modes"),
                ("NUCLEI_HEADLESS", "Advanced modes"),
                ("NUCLEI_RATE_LIMIT", "Performance"),
                ("NUCLEI_BULK_SIZE", "Performance"),
                ("NUCLEI_CONCURRENCY", "Performance"),
                ("NUCLEI_TIMEOUT", "Performance"),
                ("NUCLEI_RETRIES", "Performance"),
                ("NUCLEI_MAX_RUNTIME", "Performance"),
                ("NUCLEI_MAX_HOST_ERROR", "Performance"),
                ("NUCLEI_SYSTEM_RESOLVERS", "Network"),
                ("NUCLEI_FOLLOW_REDIRECTS", "Network"),
                ("NUCLEI_MAX_REDIRECTS", "Network"),
                ("NUCLEI_INTERACTSH", "Network"),
                ("NUCLEI_AI_TAGS", "AI cascade"),
                ("NUCLEI_AUTO_UPDATE_TEMPLATES", "Templates lifecycle"),
                ("NUCLEI_SCAN_ALL_IPS", "Targeting"),
                ("KATANA_DEPTH", "Targeting"),
                ("CVE_LOOKUP_ENABLED", "CVE enrichment"),
                ("CVE_LOOKUP_SOURCE", "CVE enrichment"),
                ("CVE_LOOKUP_MAX_CVES", "CVE enrichment"),
                ("CVE_LOOKUP_MIN_CVSS", "CVE enrichment"),
                ("VULNERS_API_KEY", "CVE enrichment credentials"),
                ("NVD_API_KEY", "CVE enrichment credentials"),
                ("VULNERS_KEY_ROTATOR", "CVE enrichment credentials"),
                ("NVD_KEY_ROTATOR", "CVE enrichment credentials"),
            ],
        )

    # Nuclei being unavailable skips only the Nuclei passes: the CVE lookup and
    # the security checks below need neither Docker nor templates.
    nuclei_unavailable = ""
    if NUCLEI_ENABLED:
        # Docker mode is required
        if not is_docker_installed():
            print("[!][Nuclei] Docker not found. Please install Docker to use Nuclei scanner.")
            print("[!][Nuclei] Skipping nuclei scan.")
            nuclei_unavailable = "Docker not found"
        elif not is_docker_running():
            print("[!][Nuclei] Docker daemon is not running. Start it with: sudo systemctl start docker")
            print("[!][Nuclei] Skipping nuclei scan.")
            nuclei_unavailable = "Docker daemon not running"
        else:
            # Pull image if needed (will skip if already present)
            pull_nuclei_docker_image(NUCLEI_DOCKER_IMAGE)

            # Ensure templates volume exists and has templates
            if not ensure_templates_volume(NUCLEI_DOCKER_IMAGE, NUCLEI_AUTO_UPDATE_TEMPLATES):
                print("[!][Nuclei] Could not setup nuclei templates. Skipping scan.")
                nuclei_unavailable = "nuclei templates unavailable"
        if nuclei_unavailable:
            _keep_nuclei_findings(nuclei_unavailable)
            _record_unrun_nuclei(recon_data, _nuclei_coverage(
                coverage_at, [(_live_web_urls(recon_data), "failed", nuclei_unavailable, False)]))

    # Cleared by the two checks below that leave the Nuclei passes nothing to
    # run; the CVE lookup and the security checks after them still run.
    early_selection_plan = None
    early_coverage_passes = []
    target_urls_after_admission = None
    run_nuclei = NUCLEI_ENABLED and not nuclei_unavailable
    if run_nuclei:
        print(f"[*][Nuclei] Execution Mode: DOCKER ({NUCLEI_DOCKER_IMAGE})")
        nuclei_version = f"Docker: {NUCLEI_DOCKER_IMAGE}"
        template_count = 8000  # Approximate, Docker image includes templates

        print(f"[*][Nuclei] Nuclei Version: {nuclei_version}")
        print(f"[*][Nuclei] Templates Available: ~{template_count}")

        # Extract targets
        ips, hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data, settings)

        if not hostnames and not ips:
            # Not degraded: this run resolved no host at all, which every other
            # scanner also takes as nothing left to re-check. Keeping Nuclei's
            # findings here would make those of a target that stopped
            # resolving permanent.
            print("[!][Nuclei] No targets found in recon data")
            run_nuclei = False

    if run_nuclei:
        # Build target URLs using httpx/naabu data if available. F08: the
        # builder's own admission report and declared-only accounting are kept
        # so the inventory can say which sources this consumer's input carried
        # and which it refused, instead of leaving the gap silent.
        _target_admission = {}
        _declared_report = {}
        _target_filter = {}
        target_urls = build_target_urls(
            hostnames, ips, recon_data, scan_all_ips=NUCLEI_SCAN_ALL_IPS,
            admission_report=_target_admission, declared_report=_declared_report)
        # The crawler's and httpx's URLs (build_target_urls sources 1-2) name
        # whatever host those tools reached, a redirect or a link included, not
        # only the gated DNS targets; Nuclei resolves each host itself.
        target_urls, _ = admit_urls(settings, recon_data, target_urls, module="nuclei")
        # Crawler inventory is not an application-target list: static assets and
        # measured CDN edge addresses only spend requests and memory. Drop them
        # before the planner/routing see the list so coverage and execution
        # account for the same targets.
        target_urls, _target_filter = filter_nuclei_detection_targets(target_urls, recon_data)
        target_urls_after_admission = list(target_urls)
        if not target_urls:
            print("[-][Nuclei] No target URL is left after the Rules of Engagement, the "
                  "target list and the detection-target filter - skipping Nuclei")
            run_nuclei = False

    if run_nuclei:
        # IP mode keeps Nuclei's redirects on the host it was given (B-07).
        nuclei_ip_mode = bool((recon_data.get("metadata") or {}).get("ip_mode") or settings.get("IP_MODE"))
        # The target list is admitted, but a target's redirect is not: under
        # RoE exclusions an admitted host's 302 into an excluded one would be
        # followed by every template (R-2).
        nuclei_roe_exclusions = bool(admission_context(settings, recon_data).excluded)
        if nuclei_roe_exclusions and NUCLEI_FOLLOW_REDIRECTS:
            print("[*][Nuclei] Redirects followed on the same host only: RoE exclusions are in force")
        elif nuclei_roe_exclusions:
            print("[*][Nuclei] Template redirects held (-disable-redirects): RoE exclusions are in force")

        # Initialize the per-scan AI context for the false-positive response
        # filter. Consumed by is_false_positive() in _execute_nuclei_pass().
        # Safe to call unconditionally -- when off, the cascade is a no-op.
        set_fp_ai_ctx(
            enabled=NUCLEI_AI_RESPONSE_FILTER,
            model=AI_PIPELINE_MODEL,
            user_id=os.environ.get('USER_ID', ''),
            project_id=os.environ.get('PROJECT_ID', ''),
        )
        if NUCLEI_AI_RESPONSE_FILTER:
            print(f"[*][Nuclei-FP-AI] Response filter cascade enabled, model={AI_PIPELINE_MODEL}")

        # AI tag pruning (cascade-gated; replaces NUCLEI_TAGS with a tech-aware
        # subset chosen by an LLM based on http_probe fingerprint). Applies to
        # the detection pass only; the DAST pass ignores tags by design.
        # F04 pruning contract: the result must be a subset of the
        # policy-filtered saved selection. vuln_scan re-clamps defensively so
        # a mocked/legacy/planner implementation cannot expand the selection
        # (no 'takeover', no tech tags, no out-of-whitelist tags), and records
        # saved/effective/added/removed + reason in scan_metadata.
        ai_tags_used = False
        ai_selection = None
        if (NUCLEI_AI_TAGS or enforcing(settings, 'ai_tags')) and NUCLEI_TAGS:
            from recon.helpers.ai_planner.nuclei_tags import (
                get_ai_tags,
                policy_filtered_selection,
                selection_report,
            )
            saved_tags = policy_filtered_selection(NUCLEI_TAGS, NUCLEI_EXCLUDE_TAGS)
            tech_fp = _build_tech_fingerprint(recon_data.get('http_probe', {}))
            fallback_urls = (
                target_urls if not tech_fp['technologies'] and not tech_fp['servers']
                else None
            )
            ai_tags = get_ai_tags(
                tech_fingerprint=tech_fp,
                current_tags=NUCLEI_TAGS,
                model=AI_PIPELINE_MODEL,
                user_id=os.environ.get('USER_ID', ''),
                project_id=os.environ.get('PROJECT_ID', ''),
                fallback_urls=fallback_urls,
                engine=('jev' if NUCLEI_TAGS_AI_USE_JEV else 'llm'),
                settings=settings,
                exclude_tags=NUCLEI_EXCLUDE_TAGS,
            )
            # Defensive clamp at the consumer: only saved, non-excluded tags.
            saved_set = set(saved_tags)
            clamped = [t for t in dict.fromkeys(ai_tags) if t in saved_set]
            ai_succeeded = clamped != saved_tags
            ai_selection = selection_report(
                NUCLEI_TAGS, clamped,
                exclude_tags=NUCLEI_EXCLUDE_TAGS,
                ai_succeeded=ai_succeeded,
            )
            # A helper that returned the policy-filtered selection verbatim
            # means the AI fell back; anything else is a real prune.
            if clamped != saved_tags:
                ai_tags_used = True
                print(f"[*][Nuclei-AI] Tag pruning: {len(NUCLEI_TAGS)} -> {len(clamped)} tags")
                print(f"[*][Nuclei-AI] Selected: {clamped}")
                print("[*][Nuclei-AI] Removed: " + str(ai_selection['removed_tags'])
                      + " (reason=" + ai_selection['reason'] + ")")
                NUCLEI_TAGS = clamped
            else:
                NUCLEI_TAGS = saved_tags
                print(f"[*][Nuclei-AI] Falling back to user tags (no signal or LLM unavailable)")

        # For DAST mode, we need URLs with parameters from resource_enum
        dast_urls = []
        if NUCLEI_DAST_MODE:
            print(f"[*][Nuclei] DAST Mode: ENABLED (active fuzzing for XSS, SQLi, etc.)")

            # Get URLs with parameters from resource_enum (must be run before vuln_scan)
            resource_enum_data = recon_data.get("resource_enum")
            if resource_enum_data:
                discovered_urls = resource_enum_data.get("discovered_urls", [])
                # Filter for URLs with parameters
                from recon.helpers.target_helpers import admit_http_urls
                admission = recon_data.setdefault("metadata", {}).setdefault("http_admission", {})
                valid_urls = admit_http_urls(discovered_urls, "resource_enum_dast", admission)
                from urllib.parse import urlparse
                dast_urls = [url for url in valid_urls if '=' in urlparse(url).query]
                dast_urls, _ = admit_urls(settings, recon_data, dast_urls, module="nuclei")
                if dast_urls:
                    print(f"[*][Nuclei] Using {len(dast_urls)} URLs with parameters from resource_enum")
                else:
                    print(f"[!][Nuclei] No URLs with parameters found in resource_enum - DAST scan may not find vulnerabilities")
            else:
                print(f"[!][Nuclei] resource_enum not found - run resource_enum before vuln_scan for DAST mode")
    
        # Planner runs on real built inputs with endpoint evidence, never on
        # an upstream estimate. Shadow does no additional HTTP/LLM calls.
        target_urls, dast_urls, planner_routing, planner_tasks, planner_details = plan_dispatch(
            settings, target_urls, dast_urls, tags=NUCLEI_TAGS,
            templates=NUCLEI_TEMPLATES, custom_templates=NUCLEI_CUSTOM_TEMPLATES,
            selected_custom_templates=NUCLEI_SELECTED_CUSTOM_TEMPLATES,
            inventory=recon_data.get('resource_enum'))
        if ai_selection:
            planner_details['selection']['ai_tags'] = ai_selection

        # Break down what will actually be scanned (target_urls is the real list)
        ip_target_count = sum(1 for u in target_urls if _url_host_is_ip(u))
        host_target_count = len(target_urls) - ip_target_count
        print(f"[*][Nuclei] Hostnames discovered: {len(hostnames)} | IPs discovered: {len(ips)}")
        print(f"[*][Nuclei] Targets to scan: {len(target_urls)} URLs ({host_target_count} hostname-based, {ip_target_count} IP-based)")
        if NUCLEI_DAST_MODE and dast_urls:
            print(f"[*][Nuclei] DAST URLs (with params): {len(dast_urls)}")
        print(f"[*][Nuclei] Scan IPs: {'YES' if NUCLEI_SCAN_ALL_IPS else 'NO (hostnames only)'}")
        print(f"[*][Nuclei] Severity Filter: {', '.join(NUCLEI_SEVERITY) if NUCLEI_SEVERITY else 'ALL'}")
        print(f"[*][Nuclei] Rate Limit: {NUCLEI_RATE_LIMIT} req/s")
        print(f"[*][Nuclei] Bulk Size: {NUCLEI_BULK_SIZE}")
        print(f"[*][Nuclei] Concurrency: {NUCLEI_CONCURRENCY}")
        print(f"[*][Nuclei] Timeout: {NUCLEI_TIMEOUT}s")
        print(f"[*][Nuclei] Retries: {NUCLEI_RETRIES}")
        if NUCLEI_TAGS:
            print(f"[*][Nuclei] Tags: {', '.join(NUCLEI_TAGS)}")
        if NUCLEI_EXCLUDE_TAGS:
            print(f"[*][Nuclei] Exclude Tags: {', '.join(NUCLEI_EXCLUDE_TAGS)}")
        if NUCLEI_TEMPLATES:
            print(f"[*][Nuclei] Templates: {', '.join(NUCLEI_TEMPLATES)}")
        if NUCLEI_EXCLUDE_TEMPLATES:
            print(f"[*][Nuclei] Exclude Templates: {', '.join(NUCLEI_EXCLUDE_TEMPLATES)}")
        print(f"[*][Nuclei] Headless: {NUCLEI_HEADLESS}")
        print(f"[*][Nuclei] Interactsh: {NUCLEI_INTERACTSH}")
        print(f"[*][Nuclei] Follow Redirects: {NUCLEI_FOLLOW_REDIRECTS} (max {NUCLEI_MAX_REDIRECTS})")
        print(f"[*][Nuclei] New Templates Only: {NUCLEI_NEW_TEMPLATES_ONLY}")
        print(f"[*][Nuclei] Auto Update Templates: {NUCLEI_AUTO_UPDATE_TEMPLATES}")
        if NUCLEI_SELECTED_CUSTOM_TEMPLATES:
            print(f"[*][Nuclei] Custom Templates Selected: {len(NUCLEI_SELECTED_CUSTOM_TEMPLATES)}")
            for tpl in NUCLEI_SELECTED_CUSTOM_TEMPLATES:
                print(f"[*][Nuclei]   - {tpl}")
        # CVE lookup settings
        print(f"[*][Nuclei] CVE Lookup: {CVE_LOOKUP_ENABLED}")
        if CVE_LOOKUP_ENABLED:
            print(f"[*][Nuclei]   Source: {CVE_LOOKUP_SOURCE}")
            print(f"[*][Nuclei]   Max CVEs: {CVE_LOOKUP_MAX_CVES}")
            print(f"[*][Nuclei]   Min CVSS: {CVE_LOOKUP_MIN_CVSS}")
        # Security checks summary
        print(f"[*][Nuclei] Security Checks: {SECURITY_CHECK_ENABLED}")
        if SECURITY_CHECK_ENABLED:
            sec_checks_count = sum(1 for v in [
                SECURITY_CHECK_DIRECT_IP_HTTP, SECURITY_CHECK_DIRECT_IP_HTTPS,
                SECURITY_CHECK_IP_API_EXPOSED, SECURITY_CHECK_WAF_BYPASS,
                SECURITY_CHECK_TLS_EXPIRING_SOON, SECURITY_CHECK_MISSING_REFERRER_POLICY,
                SECURITY_CHECK_MISSING_PERMISSIONS_POLICY, SECURITY_CHECK_MISSING_COOP,
                SECURITY_CHECK_MISSING_CORP, SECURITY_CHECK_MISSING_COEP,
                SECURITY_CHECK_CACHE_CONTROL_MISSING, SECURITY_CHECK_LOGIN_NO_HTTPS,
                SECURITY_CHECK_SESSION_NO_SECURE, SECURITY_CHECK_SESSION_NO_HTTPONLY,
                SECURITY_CHECK_BASIC_AUTH_NO_TLS, SECURITY_CHECK_SPF_MISSING,
                SECURITY_CHECK_DMARC_MISSING, SECURITY_CHECK_DNSSEC_MISSING,
                SECURITY_CHECK_ZONE_TRANSFER, SECURITY_CHECK_ADMIN_PORT_EXPOSED,
                SECURITY_CHECK_DATABASE_EXPOSED, SECURITY_CHECK_REDIS_NO_AUTH,
                SECURITY_CHECK_KUBERNETES_API_EXPOSED, SECURITY_CHECK_SMTP_OPEN_RELAY,
                SECURITY_CHECK_CSP_UNSAFE_INLINE, SECURITY_CHECK_INSECURE_FORM_ACTION,
                SECURITY_CHECK_NO_RATE_LIMITING,
            ] if v) + sum(page_content_enabled(settings).values())
            print(f"[*][Nuclei]   Active checks: {sec_checks_count}/35")
            print(f"[*][Nuclei]   Timeout: {SECURITY_CHECK_TIMEOUT}s")
            print(f"[*][Nuclei]   Max workers: {SECURITY_CHECK_MAX_WORKERS}")
        print("=" * 70 + "\n")
    
        # Use /tmp/redamon to avoid spaces in paths (snap Docker issue). It is a
        # host bind mount shared by every concurrent scan, so each run gets its
        # own directory and only ever removes that one.
        nuclei_temp_dir = Path(f"/tmp/redamon/.nuclei_temp_{uuid.uuid4().hex}")

        # Two-pass design:
        #   Pass A (DETECTION) — always runs when Nuclei is enabled. Honours all
        #     user-configured templates, tags, custom templates. Targets the
        #     full base URL set.
        #   Pass B (DAST) — only when NUCLEI_DAST_MODE is on AND we have URLs
        #     with parameters from resource_enum. Forces -dast and ignores
        #     tags/templates filters (they would empty-intersect with the DAST
        #     template set). Targets the parameterized URLs only.
        do_dast_pass = NUCLEI_DAST_MODE and bool(dast_urls)
        if NUCLEI_DAST_MODE and not dast_urls:
            print(f"[!][Nuclei] DAST pass skipped (no parameterized URLs available); detection pass still runs")

        # Empty Include Tags now means "no built-in templates". The detection
        # pass only has something to scan if either tags is non-empty OR the
        # user picked custom templates. If both are empty, refuse before
        # building the command -- otherwise nuclei would fall back to scanning
        # all ~8000 default templates which is the OPPOSITE of what we want.
        has_tags = bool(NUCLEI_TAGS)
        has_custom = bool(NUCLEI_SELECTED_CUSTOM_TEMPLATES) or bool(NUCLEI_TEMPLATES) or bool(NUCLEI_CUSTOM_TEMPLATES)
        if not has_tags and not has_custom:
            print("[!][Nuclei] Include Tags is empty AND no custom templates are selected.")
            print("[!][Nuclei] Skipping detection pass (empty tags now means 'custom templates only').")
            print("[!][Nuclei] Either add tags (e.g. cve, xss, sqli) or select a custom template.")
            # If DAST has parameterized URLs we can still run the DAST pass --
            # DAST has its own template set and doesn't depend on tags.
            if not do_dast_pass:
                # Nuclei is on but this configuration gives it no template to
                # run, so none of its findings was re-checked: keep them.
                _keep_nuclei_findings("no Nuclei templates selected")
                run_nuclei = False
                _record_unrun_nuclei(recon_data, _nuclei_coverage(
                    coverage_at, [(target_urls, "failed", "no Nuclei templates selected", False)]))
            # Mark detection as skipped; downstream merge handles empty findings.
            skip_detection_pass = True
        else:
            skip_detection_pass = False

    if run_nuclei:
        nuclei_temp_dir.mkdir(parents=True, exist_ok=True)

        # ---- F07: the selection plan, persisted BEFORE any pass launches.
        # A cancellation or a crash keeps this accounting; it is a plan, never
        # a result checkpoint. ``selection_hint`` comes from a partial run and
        # marks the run as target/template-limited.
        _partial_scope = bool(selection_hint and selection_hint.get("scope") == "partial")
        _deferred = bool(selection_hint and selection_hint.get("deferred")) or bool(
            planner_details['consumers']['two_pass'].get('deferred_count'))
        planner_selective = planner_routing is not None and any(
            urls != target_urls for urls in planner_routing['target_sets'].values())
        selection_plan = _selection_plan(
            targets=target_urls,
            saved_tags=saved_nuclei_tags,
            effective_tags=NUCLEI_TAGS,
            ai_pruned=ai_tags_used,
            partial_scope=_partial_scope or planner_selective or resolve_routing_mode(settings) == MODE_ENFORCE,
            deferred=_deferred,
            severity=NUCLEI_SEVERITY,
            exclude_tags=NUCLEI_EXCLUDE_TAGS,
            templates=NUCLEI_TEMPLATES,
            exclude_templates=NUCLEI_EXCLUDE_TEMPLATES,
            custom_templates=NUCLEI_CUSTOM_TEMPLATES,
            selected_custom_templates=NUCLEI_SELECTED_CUSTOM_TEMPLATES,
            dast_targets=dast_urls if do_dast_pass else None,
            dast_mode=bool(do_dast_pass and NUCLEI_DAST_MODE),
        )
        recon_data[SELECTION_KEY] = selection_plan
        _note_selection_cut(selection_plan)
        if plan_output_file is not None:
            # Isolated path: this runs in a fan-out thread, so the plan is
            # MERGED into the canonical artifact under the shared save lock
            # instead of overwriting it with this deep copy (another tool's
            # results may have merged a moment earlier). See persist_plan.
            persist_plan(plan_output_file, recon_data[SELECTION_KEY])
        elif output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)
            fix_file_ownership(output_file)

        # DAST pass targets (parameterized URLs only)
        dast_targets_file = None
        dast_output_file = None
        if do_dast_pass:
            dast_targets_file = str(nuclei_temp_dir / "targets_dast.txt")
            with open(dast_targets_file, 'w') as f:
                for url in dast_urls:
                    f.write(url + "\n")
            dast_output_file = str(nuclei_temp_dir / "nuclei_dast.jsonl")
            print(f"[*][Nuclei] Two-pass plan: DETECTION (routed) + DAST on {len(dast_urls)} parameterized URLs")
        else:
            print(f"[*][Nuclei] Single-pass plan: DETECTION (routed)")

        # scan_urls is the union for reporting/metadata
        scan_urls = sorted(set(target_urls + (dast_urls if do_dast_pass else [])))

        # Authenticated-session profile: attach the operator's auth headers to
        # nuclei when every scanned host is in scope (no-op otherwise). Nuclei
        # has no header support of its own, so these flow via the new
        # build_nuclei_command auth_headers arg.
        from urllib.parse import urlparse as _urlparse
        from recon.helpers.auth_profile import merge_auth_headers as _merge_auth
        _nuclei_hosts = sorted({_urlparse(u).hostname for u in scan_urls if _urlparse(u).hostname})
        _nuclei_auth = _merge_auth([], settings, _nuclei_hosts)
        # Engagement identity header: appended AFTER the scope-gated auth lines
        # so the ordering (auth first, identity last) is stable, deduped, and
        # the header rides the tool's -H path (direct AND capture proxy alike).
        from recon.helpers.auth_profile import append_engagement_identity as _append_identity
        _nuclei_auth = _append_identity(_nuclei_auth, settings)

        # Resolve compatibility *before* recording the detailed dispatch plan.
        # Mixed -t/-tags and custom mount selections cannot be split without
        # changing the policy intersection. Auth/identity stays indivisible too.
        routing_fallback = routing_compatibility_reason(settings)
        if _nuclei_auth:
            routing_fallback = 'authenticated/identity transport requires legacy builder'
        if routing_fallback:
            planner_routing = None
            planner_details['consumers']['target_selection'].update(
                executing=False, reason='compatibility: ' + routing_fallback)
        planner_details['selection']['routing_mode'] = resolve_routing_mode(settings)
        planner_details['selection']['routing_compatibility_reason'] = routing_fallback
        persist_dispatch(settings, recon_data, plan_output_file or output_file,
                         planner_tasks, planner_details, target_urls, dast_urls)

        try:
            findings = []
            false_positives_filtered = []

            # ---- Pass A: DETECTION (Routed by Template Category - F14) ----
            start_time = datetime.now()
            coverage_passes = []
            # Set only when a pass was attempted and refused. The metadata block
            # is outside this ``if run_nuclei:`` scope, so both must be bound on
            # every path -- including the Nuclei-disabled early return.
            dast_not_executed = None
            detection_not_executed = None
            routing = {"routing_metadata": {"skipped": True}, "by_category": {}, "compatibility_templates": []}
            
            # Check routing mode gate (off/shadow/enforce)
            routing_mode = resolve_routing_mode(settings)
            use_routed = routing_mode == MODE_ENFORCE or planner_routing is not None
            if routing_fallback:
                # Preserve the existing builder's scoped credential and custom
                # mount mapping; category heuristics cannot prove safe transport.
                use_routed = False
            # Shadow mode: compute routing for observation but execute legacy
            compute_routing_for_shadow = routing_mode == MODE_SHADOW
            
            if not target_urls:
                print("[*][Nuclei] DETECTION pass not scanned (no selected targets)")
                d_findings, d_fps, d_duration = [], [], 0
                # Nothing was selected, so nothing of Nuclei's was re-checked:
                # its earlier findings are kept, and a failed pass is recorded
                # BEFORE record_execution so plan, coverage and the prune guard
                # all agree that this run proved nothing.
                _keep_nuclei_findings("no selected Nuclei targets")
                coverage_passes.append((_live_web_urls(recon_data), "failed",
                                        "no selected targets", False))
            elif skip_detection_pass:
                print("[*][Nuclei] DETECTION pass skipped (no tags + no custom templates)")
                d_findings, d_fps, d_duration = [], [], 0
                # The detection pass did not run even though DAST may have:
                # keep the previous Nuclei findings this pass would have
                # re-checked, and record the pass as failed for the plan.
                _keep_nuclei_findings("no Nuclei templates selected")
                coverage_passes.append((target_urls, "failed", "no Nuclei templates selected", False))
            elif not use_routed:
                # Off/shadow mode: run legacy single detection pass
                mode_desc = "legacy" if routing_mode == MODE_OFF else "legacy (shadow: routing computed but not executed)"
                print(f"[*][Nuclei] DETECTION pass running in {mode_desc} mode (NUCLEI_ROUTING_MODE={routing_mode})")
                
                # In shadow mode, compute routing for observation/logging
                if compute_routing_for_shadow:
                    routing = _classify_and_route_templates(
                        template_tags=NUCLEI_TAGS,
                        template_paths=NUCLEI_TEMPLATES,
                        custom_templates=NUCLEI_CUSTOM_TEMPLATES,
                        selected_custom_templates=NUCLEI_SELECTED_CUSTOM_TEMPLATES,
                        exclude_templates=NUCLEI_EXCLUDE_TEMPLATES,
                        exclude_tags=NUCLEI_EXCLUDE_TAGS,
                        resource_enum_data=recon_data.get("resource_enum"),
                        http_probe_data=recon_data.get("http_probe"),
                        admitted_targets=target_urls,
                    )
                    # Log routing summary for observation
                    print(f"[*][Nuclei-Routing] Shadow mode - template routing summary (not executed):")
                    for cat, tpls in routing["by_category"].items():
                        if tpls:
                            target_count = len(routing["target_sets"].get(cat, []))
                            print(f"[*][Nuclei-Routing]   {cat}: {len(tpls)} templates -> {target_count} targets")
                    if routing["compatibility_templates"]:
                        print(f"[*][Nuclei-Routing]   Compatibility lane: {len(routing['compatibility_templates'])} templates with unknown semantics -> legacy behavior on all targets")
                else:
                    routing = {"routing_metadata": {"skipped": True}, "by_category": {}, "compatibility_templates": []}
                
                # Build legacy detection command (single pass, all targets)
                legacy_targets_file = str(nuclei_temp_dir / "targets_legacy.txt")
                with open(legacy_targets_file, 'w') as f:
                    for url in target_urls:
                        f.write(url + "\n")
                legacy_output_file = str(nuclei_temp_dir / "nuclei_legacy.jsonl")
                legacy_container_name = f"redamon-nuclei-legacy-{uuid.uuid4().hex[:8]}"
                # The build sits inside the try, like the routed branch below:
                # the builder's fail-closed refusal (empty selection) is a
                # policy_empty outcome, not an exception that skips the CVE
                # lookup and security checks.
                try:
                    legacy_cmd = build_nuclei_command(
                        targets_file=legacy_targets_file,
                        output_file=legacy_output_file,
                        docker_image=NUCLEI_DOCKER_IMAGE,
                        severity=NUCLEI_SEVERITY,
                        templates=NUCLEI_TEMPLATES if NUCLEI_TEMPLATES else None,
                        exclude_templates=NUCLEI_EXCLUDE_TEMPLATES,
                        custom_templates=NUCLEI_CUSTOM_TEMPLATES,
                        selected_custom_templates=NUCLEI_SELECTED_CUSTOM_TEMPLATES,
                        tags=NUCLEI_TAGS if NUCLEI_TAGS else None,
                        exclude_tags=NUCLEI_EXCLUDE_TAGS,
                        rate_limit=NUCLEI_RATE_LIMIT,
                        bulk_size=NUCLEI_BULK_SIZE,
                        concurrency=NUCLEI_CONCURRENCY,
                        timeout=NUCLEI_TIMEOUT,
                        retries=NUCLEI_RETRIES,
                        dast_mode=False,
                        new_templates_only=NUCLEI_NEW_TEMPLATES_ONLY,
                        headless=NUCLEI_HEADLESS,
                        system_resolvers=NUCLEI_SYSTEM_RESOLVERS,
                        follow_redirects=NUCLEI_FOLLOW_REDIRECTS,
                        max_redirects=NUCLEI_MAX_REDIRECTS,
                        interactsh=NUCLEI_INTERACTSH,
                        auth_headers=_nuclei_auth,
                        container_name=legacy_container_name,
                        max_host_error=NUCLEI_MAX_HOST_ERROR,
                    )
                    d_findings, d_fps, d_duration, d_rc = _execute_nuclei_pass(
                        legacy_cmd, legacy_output_file, label="DETECTION",
                        runtime_cap=NUCLEI_MAX_RUNTIME, container_name=legacy_container_name,
                    )
                    coverage_passes.append((target_urls, *_nuclei_pass_outcome(
                        d_rc, d_duration, NUCLEI_MAX_RUNTIME, d_findings or d_fps), True))
                except NucleiEmptySelectionError as exc:
                    print(f"[!][Nuclei] DETECTION pass not executed (policy_empty): {exc}")
                    _keep_nuclei_findings(f"nuclei DETECTION pass not executed: policy_empty")
                    detection_not_executed = {
                        "pass": "DETECTION",
                        "state": "not_executed",
                        "reason": "policy_empty",
                        "detail": str(exc),
                    }
                    coverage_passes.append((target_urls, "failed", f"policy_empty: {exc}", False))
                    d_findings, d_fps, d_duration = [], [], 0
                except Exception as exc:
                    _keep_nuclei_findings(f"nuclei DETECTION pass failed: {type(exc).__name__}")
                    coverage_passes.append((target_urls, "failed", str(exc), False))
                    d_findings, d_fps, d_duration = [], [], 0
            else:
                # Enforce mode: run routed detection passes
                print(f"[*][Nuclei] DETECTION pass running in routed mode (NUCLEI_ROUTING_MODE={routing_mode})")
                # F14: Classify templates by semantics and route to appropriate targets
                # This replaces the single detection pass with category-routed passes
                routing = planner_routing or _classify_and_route_templates(
                    template_tags=NUCLEI_TAGS,
                    template_paths=NUCLEI_TEMPLATES,
                    custom_templates=NUCLEI_CUSTOM_TEMPLATES,
                    selected_custom_templates=NUCLEI_SELECTED_CUSTOM_TEMPLATES,
                    exclude_templates=NUCLEI_EXCLUDE_TEMPLATES,
                    exclude_tags=NUCLEI_EXCLUDE_TAGS,
                    resource_enum_data=recon_data.get("resource_enum"),
                    http_probe_data=recon_data.get("http_probe"),
                    admitted_targets=target_urls,
                )
                
                # Log routing summary
                print(f"[*][Nuclei-Routing] Template routing summary:")
                for cat, tpls in routing["by_category"].items():
                    if tpls:
                        target_count = len(routing["target_sets"].get(cat, []))
                        print(f"[*][Nuclei-Routing]   {cat}: {len(tpls)} templates -> {target_count} targets")
                
                # Compatibility lane templates (unknown semantics) run with legacy behavior
                if routing["compatibility_templates"]:
                    print(f"[*][Nuclei-Routing] Compatibility lane: {len(routing['compatibility_templates'])} templates with unknown semantics -> legacy behavior on all targets")
                
                # Build routed commands (wrapped to catch build-time NucleiEmptySelectionError)
                base_settings = {
                    "NUCLEI_DOCKER_IMAGE": NUCLEI_DOCKER_IMAGE,
                    "NUCLEI_SEVERITY": NUCLEI_SEVERITY,
                    "NUCLEI_EXCLUDE_TEMPLATES": NUCLEI_EXCLUDE_TEMPLATES,
                    "NUCLEI_CUSTOM_TEMPLATES": NUCLEI_CUSTOM_TEMPLATES,
                    "NUCLEI_SELECTED_CUSTOM_TEMPLATES": NUCLEI_SELECTED_CUSTOM_TEMPLATES,
                    "NUCLEI_EXCLUDE_TAGS": NUCLEI_EXCLUDE_TAGS,
                    "NUCLEI_RATE_LIMIT": NUCLEI_RATE_LIMIT,
                    "NUCLEI_BULK_SIZE": NUCLEI_BULK_SIZE,
                    "NUCLEI_CONCURRENCY": NUCLEI_CONCURRENCY,
                    "NUCLEI_TIMEOUT": NUCLEI_TIMEOUT,
                    "NUCLEI_RETRIES": NUCLEI_RETRIES,
                    "NUCLEI_NEW_TEMPLATES_ONLY": NUCLEI_NEW_TEMPLATES_ONLY,
                    "NUCLEI_HEADLESS": NUCLEI_HEADLESS,
                    "NUCLEI_SYSTEM_RESOLVERS": NUCLEI_SYSTEM_RESOLVERS,
                    "NUCLEI_FOLLOW_REDIRECTS": NUCLEI_FOLLOW_REDIRECTS,
                    "NUCLEI_MAX_REDIRECTS": NUCLEI_MAX_REDIRECTS,
                    "NUCLEI_INTERACTSH": NUCLEI_INTERACTSH,
                    "NUCLEI_MAX_HOST_ERROR": NUCLEI_MAX_HOST_ERROR,
                }
                
                try:
                    # Get scope hosts from engagement settings
                    auth_profile = profile_from_settings(settings)
                    scope_hosts = resolve_scope_hosts(auth_profile, settings) if auth_profile else []
                    
                    routed_commands = _build_routed_nuclei_commands(
                        routing=routing,
                        nuclei_temp_dir=nuclei_temp_dir,
                        base_settings=base_settings,
                        auth_headers=_nuclei_auth,
                        container_prefix="redamon-nuclei-detection",
                        scope_hosts=scope_hosts,
                    )
                except NucleiEmptySelectionError as exc:
                    print(f"[!][Nuclei] DETECTION pass not executed (policy_empty at build): {exc}")
                    _keep_nuclei_findings(f"nuclei DETECTION pass not executed: policy_empty")
                    detection_not_executed = {
                        "pass": "DETECTION",
                        "state": "not_executed",
                        "reason": "policy_empty",
                        "detail": str(exc),
                    }
                    routed_commands = []
                    coverage_passes.append((target_urls, "failed", f"policy_empty: {exc}", False))
                    d_findings, d_fps, d_duration = [], [], 0
                else:
                    # Execute routed passes
                    d_findings, d_fps, d_duration, routed_coverage = _execute_routed_passes(
                        routed_commands=routed_commands,
                        runtime_cap=NUCLEI_MAX_RUNTIME,
                        label_prefix="DETECTION",
                    )
                    coverage_passes.extend(routed_coverage)
            
            findings.extend(d_findings)
            false_positives_filtered.extend(d_fps)

            # ---- Pass B: DAST (additive) ----
            dast_duration = 0
            if do_dast_pass:
                # Inclusion filters are deliberately NOT passed: a DAST pass
                # selects Nuclei's own ``-dast`` template set, so an explicit
                # -t/-tags would empty-intersect with it and fatal. The
                # operator's EXCLUSIONS are passed explicitly -- they are the
                # denylist, not an inclusion filter, and must constrain the
                # DAST pass exactly as they constrain the detection pass.
                # ``force_dast_pass`` drops the inclusion filters in the
                # builder; it no longer drops these.
                dast_exclude_tags = NUCLEI_EXCLUDE_TAGS
                dast_exclude_templates = NUCLEI_EXCLUDE_TEMPLATES
                try:
                    dast_container_name = f"redamon-nuclei-dast-{uuid.uuid4().hex[:12]}"
                    dast_cmd = build_nuclei_command(
                        targets_file=dast_targets_file,
                        output_file=dast_output_file,
                        docker_image=NUCLEI_DOCKER_IMAGE,
                        severity=NUCLEI_SEVERITY,
                        exclude_templates=dast_exclude_templates,
                        exclude_tags=dast_exclude_tags,
                        rate_limit=NUCLEI_RATE_LIMIT,
                        bulk_size=NUCLEI_BULK_SIZE,
                        concurrency=NUCLEI_CONCURRENCY,
                        timeout=NUCLEI_TIMEOUT,
                        retries=NUCLEI_RETRIES,
                        headless=NUCLEI_HEADLESS,
                        system_resolvers=NUCLEI_SYSTEM_RESOLVERS,
                        follow_redirects=NUCLEI_FOLLOW_REDIRECTS,
                        max_redirects=NUCLEI_MAX_REDIRECTS,
                        interactsh=NUCLEI_INTERACTSH,
                        force_dast_pass=True,
                        auth_headers=_nuclei_auth,
                        container_name=dast_container_name,
                        max_host_error=NUCLEI_MAX_HOST_ERROR,
                        ip_mode=nuclei_ip_mode,
                        roe_exclusions=nuclei_roe_exclusions,
                    )
                    b_findings, b_fps, b_duration, b_rc = _execute_nuclei_pass(
                        dast_cmd, dast_output_file, label="DAST",
                        runtime_cap=NUCLEI_MAX_RUNTIME, container_name=dast_container_name,
                    )
                except NucleiEmptySelectionError as exc:
                    # The policy left the DAST pass nothing to run: either the
                    # builder refused, or nuclei fatals with "no templates
                    # provided for scan" because the operator's exclusions
                    # removed every template from its -dast pool. That is a
                    # policy-empty outcome, not a scan failure, so it is recorded
                    # as such; the previous findings are kept and there is NO
                    # fallback to the full template pool.
                    print(f"[!][Nuclei] DAST pass not executed (policy_empty): {exc}")
                    _keep_nuclei_findings("nuclei DAST pass not executed: policy_empty")
                    b_findings, b_fps, b_duration = [], [], 0
                    dast_not_executed = {
                        "pass": "DAST",
                        "state": "not_executed",
                        "reason": "policy_empty",
                        "detail": str(exc),
                    }
                    coverage_passes.append((dast_urls, "failed",
                                            "policy_empty: no templates provided for scan", False))
                except Exception as exc:
                    _keep_nuclei_findings(f"nuclei DAST pass failed: {type(exc).__name__}")
                    coverage_passes.append((dast_urls, "failed", str(exc), False))
                else:
                    coverage_passes.append((dast_urls, *_nuclei_pass_outcome(
                        b_rc, b_duration, NUCLEI_MAX_RUNTIME, b_findings or b_fps), True))
                    findings.extend(b_findings)
                    false_positives_filtered.extend(b_fps)
                    dast_duration = b_duration

            duration = d_duration + dast_duration

            # Log filtered false positives
            if false_positives_filtered:
                print(f"[*][Nuclei] Filtered {len(false_positives_filtered)} false positive(s):")
                for fp in false_positives_filtered[:5]:
                    print(f"[*][Nuclei]   - {fp['template_id']}: {fp['reason'][:60]}...")
                if len(false_positives_filtered) > 5:
                    print(f"[*][Nuclei]   ... and {len(false_positives_filtered) - 5} more")
        
            # Reconcile the no-executable-chunk guard BEFORE recording the
            # plan, so execution and per-host coverage tell the same story.
            if not coverage_passes and target_urls:
                _keep_nuclei_findings("no selected Nuclei chunks executed")
                coverage_passes.append((target_urls, "failed", "no selected chunks executed", False))
            selection_plan = record_execution(selection_plan, coverage_passes, deferred=_deferred)
            execution = selection_plan["execution"]
            attempted_urls = sorted({u for urls, _, _, ran in coverage_passes if ran for u in urls})
            completed_urls = sorted(
                {u for urls, status, _, ran in coverage_passes if ran and status == "complete" for u in urls}
                - {u for urls, status, _, _ in coverage_passes if status != "complete" for u in urls})
            # No executable routed chunks is not proof of coverage. Keep the
            # existing conservative host guard, without inventing an executed pass.
            host_passes = coverage_passes

            # Organize results
            nuclei_results = {
                "scan_metadata": {
                    "scan_timestamp": start_time.isoformat(),
                    "scan_duration_seconds": duration,
                    "nuclei_version": nuclei_version,
                    "templates_available": template_count,
                    "execution_mode": "docker",
                    "docker_image": NUCLEI_DOCKER_IMAGE,
                    "anonymous_mode": False,
                    "severity_filter": NUCLEI_SEVERITY,
                    "tags_filter": NUCLEI_TAGS,
                    "tags_ai_selected": ai_tags_used,
                    "tags_saved": (ai_selection or {}).get("saved_tags", NUCLEI_TAGS),
                    "tags_policy_saved": (ai_selection or {}).get("policy_saved_tags", NUCLEI_TAGS),
                    "tags_effective": (ai_selection or {}).get("effective_tags", NUCLEI_TAGS),
                    "tags_added": (ai_selection or {}).get("added_tags", []),
                    "tags_removed": (ai_selection or {}).get("removed_tags", []),
                    "tags_selection_reason": (ai_selection or {}).get("reason", "ai_disabled"),
                    "exclude_tags": NUCLEI_EXCLUDE_TAGS,
                    "rate_limit": NUCLEI_RATE_LIMIT,
                    "dast_mode": NUCLEI_DAST_MODE,
                    "dast_pass_executed": do_dast_pass and dast_not_executed is None,
                    "http_admission": recon_data.get("metadata", {}).get("http_admission", {}),
                    # F08: the detection consumer's own input accounting.
                    "target_admission": _target_admission,
                    "target_filter": _target_filter,
                    "declared_only": _declared_report,
                    "dast_urls_discovered": len(dast_urls) if NUCLEI_DAST_MODE else 0,
                    # F03: the DAST pass is a separate consumer of the operator's
                                        # denylist. Record what it actually received and whether the
                                        # builder was asked to drop it, so a policy regression is
                                        # visible in the artifact rather than only in the argv.
                                        "dast_exclude_tags": NUCLEI_EXCLUDE_TAGS,
                                        "dast_exclude_templates": NUCLEI_EXCLUDE_TEMPLATES,
                                        # F14: Template routing metadata
                                        "template_routing": routing.get("routing_metadata", {}),
                                        # Absent means no DAST pass was attempted: nothing was
                                        # skipped, so there is no policy state to report.
                                        **( {"dast_not_executed": dast_not_executed}
                                           if dast_not_executed is not None else {}),
                                        # Same contract for the DETECTION pass: present only when the
                                        # builder's fail-closed refusal or nuclei's "no templates
                                        # provided for scan" fatal left it nothing to run.
                                        **( {"detection_not_executed": detection_not_executed}
                                           if detection_not_executed is not None else {}),
                                        "katana_crawl_depth": KATANA_DEPTH if NUCLEI_DAST_MODE else None,
                    "total_urls_scanned": len(completed_urls),
                    "total_urls_selected": len(scan_urls),
                    "total_urls_attempted": len(attempted_urls),
                    "execution": execution,
                    "total_hostnames": len(hostnames),
                    "total_ips": len(ips),
                    "false_positives_filtered": len(false_positives_filtered),
                    "coverage": _nuclei_coverage(
                        coverage_at, host_passes, findings,
                        exhaustive=bool(selection_plan.get("exhaustive", False)),
                    ),
                },
                "discovered_urls": {
                    "base_urls": sorted(target_urls),
                    "dast_urls_with_params": sorted(dast_urls) if dast_urls else [],
                    "all_scanned_urls": completed_urls,
                    "attempted_urls": attempted_urls,
                },
                "by_target": {},
                "summary": {
                    "total_findings": len(findings),
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                },
                "vulnerabilities": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                    "unknown": 0,
                },
                "all_cves": [],
                "by_category": {},
                "by_template": {},
                "false_positives": false_positives_filtered if false_positives_filtered else [],
            }
        
            # Process findings
            all_cves = []
        
            for finding in findings:
                severity = finding["severity"]
                target = finding["target"]
                template_id = finding["template_id"]
                category = finding["category"]
            
                # Count by severity
                if severity in nuclei_results["summary"]:
                    nuclei_results["summary"][severity] += 1
                else:
                    nuclei_results["summary"]["unknown"] += 1
            
                # Group by target
                if target not in nuclei_results["by_target"]:
                    nuclei_results["by_target"][target] = {
                        "findings": [],
                        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                    }
                nuclei_results["by_target"][target]["findings"].append(finding)
                if severity in nuclei_results["by_target"][target]["severity_counts"]:
                    nuclei_results["by_target"][target]["severity_counts"][severity] += 1
            
                # Add to severity-based vulnerability list
                finding_summary = {
                    "template_id": template_id,
                    "name": finding["name"],
                    "target": target,
                    "matched_at": finding["matched_at"],
                    "category": category,
                    "cves": [c["id"] for c in finding["cves"]],
                    "cvss": finding["cvss_score"],
                }
            
                if severity in nuclei_results["vulnerabilities"]:
                    nuclei_results["vulnerabilities"][severity] += 1
                else:
                    nuclei_results["vulnerabilities"]["unknown"] += 1
            
                # Collect CVEs
                all_cves.extend(finding["cves"])
            
                # Group by category
                if category not in nuclei_results["by_category"]:
                    nuclei_results["by_category"][category] = []
                nuclei_results["by_category"][category].append(finding_summary)
            
                # Group by template
                if template_id not in nuclei_results["by_template"]:
                    nuclei_results["by_template"][template_id] = {
                        "name": finding["name"],
                        "severity": severity,
                        "findings_count": 0,
                        "targets": []
                    }
                nuclei_results["by_template"][template_id]["findings_count"] += 1
                if target not in nuclei_results["by_template"][template_id]["targets"]:
                    nuclei_results["by_template"][template_id]["targets"].append(target)
        
            # Deduplicate and sort CVEs
            seen_cves = set()
            unique_cves = []
            for cve in all_cves:
                if cve["id"] not in seen_cves:
                    seen_cves.add(cve["id"])
                    unique_cves.append(cve)
            unique_cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
            nuclei_results["all_cves"] = unique_cves
        
            # Add to recon data
            recon_data["vuln_scan"] = nuclei_results

            # F07: record what the passes actually proved, so the plan is not
            # just a launch-time intent. A failed pass cuts its source (see
            # _keep_nuclei_findings) regardless of this status.
            recon_data[SELECTION_KEY] = selection_plan
            if plan_output_file is not None:
                persist_plan(plan_output_file, selection_plan)
        
            # Save incrementally if output file provided
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(recon_data, f, indent=2)
                fix_file_ownership(output_file)  # Ensure correct ownership when running under sudo
        
            # Print summary
            print(f"\n{'=' * 70}")
            print(f"[*][Nuclei] NUCLEI SCAN {execution['status'].upper()}")
            print(f"[+][Nuclei] Duration: {duration:.2f} seconds")
            print(f"[+][Nuclei] Execution mode: DOCKER")
            print(f"[*][Nuclei] URLs attempted: {len(attempted_urls)}; "
                  f"all selected passes successfully completed: {len(completed_urls)}")
            print(f"[*][Nuclei] Passes/chunks completed: {execution['completed_passes']} / "
                  f"{execution['attempted_passes']} attempted (not per-target/template verification)")
            if execution['status'] != 'complete':
                print("[!][Nuclei] Coverage incomplete; zero findings is not an all-clear")
            print(f"[+][Nuclei] Total findings: {len(findings)}")
        
            # Vulnerability summary
            summary = nuclei_results["summary"]
            vuln_total = summary["total_findings"]

            if vuln_total > 0:
                print(f"\n[+][Nuclei] VULNERABILITY SUMMARY:")
                if summary['critical'] > 0:
                    print(f"[+][Nuclei]   CRITICAL: {summary['critical']}")
                if summary['high'] > 0:
                    print(f"[+][Nuclei]   HIGH: {summary['high']}")
                if summary['medium'] > 0:
                    print(f"[+][Nuclei]   MEDIUM: {summary['medium']}")
                if summary['low'] > 0:
                    print(f"[+][Nuclei]   LOW: {summary['low']}")

            if summary['info'] > 0:
                print(f"[*][Nuclei]   INFO: {summary['info']}")
        
            # CVE summary
            cve_count = len(unique_cves)
            if cve_count > 0:
                print(f"\n[+][Nuclei] CVEs FOUND: {cve_count}")
                for cve in unique_cves[:5]:
                    cvss_str = f"CVSS {cve['cvss']}" if cve.get('cvss') else "CVSS N/A"
                    print(f"[+][Nuclei]   - {cve['id']} ({cvss_str})")
                if cve_count > 5:
                    print(f"[+][Nuclei]   ... and {cve_count - 5} more")
        
            # Top affected targets
            if nuclei_results["by_target"]:
                print(f"\n[+][Nuclei] FINDINGS BY TARGET:")
                sorted_targets = sorted(
                    nuclei_results["by_target"].items(),
                    key=lambda x: len(x[1]["findings"]),
                    reverse=True
                )[:5]
                for target, data in sorted_targets:
                    counts = data["severity_counts"]
                    count_str = ", ".join([
                        f"{SEVERITY_COLORS.get(s, '')}{counts[s]}" 
                        for s in ["critical", "high", "medium", "low", "info"] 
                        if counts.get(s, 0) > 0
                    ])
                    print(f"[+][Nuclei]   - {target[:50]}: {len(data['findings'])} findings ({count_str})")
        
            # Top categories
            if nuclei_results["by_category"]:
                print(f"\n[+][Nuclei] TOP VULNERABILITY CATEGORIES:")
                sorted_cats = sorted(
                    nuclei_results["by_category"].items(),
                    key=lambda x: len(x[1]),
                    reverse=True
                )[:5]
                for cat, findings_list in sorted_cats:
                    print(f"[+][Nuclei]   - {cat}: {len(findings_list)} findings")
        
            print(f"{'=' * 70}")

        finally:
            # Cleanup temporary files and directory.
            # Docker may create output files as root, so fall back to a docker-based
            # rm when a PermissionError is raised.
            cleanup_paths = [
                dast_targets_file,
                dast_output_file,
            ]
            # Add routed detection output files (they follow pattern nuclei_<category>.jsonl)
            for cat in TemplateCategory:
                routed_output = str(nuclei_temp_dir / f"nuclei_{cat.value}.jsonl")
                cleanup_paths.append(routed_output)
                routed_targets = str(nuclei_temp_dir / f"targets_{cat.value}.txt")
                cleanup_paths.append(routed_targets)
            
            for path_str in cleanup_paths:
                if not path_str:
                    continue
                try:
                    Path(path_str).unlink(missing_ok=True)
                except PermissionError:
                    from recon.helpers.docker_helpers import run_tool_container
                    run_tool_container(
                        ["docker", "run", "--rm", "-v", f"{nuclei_temp_dir}:/cleanup",
                         "alpine", "rm", "-f", f"/cleanup/{Path(path_str).name}"],
                        tool="nuclei-cleanup", timeout=60)

            # The directory is this run's alone, so whatever is left in it can go.
            shutil.rmtree(nuclei_temp_dir, ignore_errors=True)

    if NUCLEI_ENABLED and not run_nuclei:
        # Early exits still need a durable outcome, not an absent/planned success.
        early_targets = locals().get("target_urls", _live_web_urls(recon_data))
        empty_selection = (
            target_urls_after_admission is not None and not target_urls_after_admission
        )
        if empty_selection:
            # An enabled detector whose admission produced no executable input
            # re-checked nothing: retain earlier findings and make the prune fail
            # closed instead of treating this as a clean, complete pass.
            _keep_nuclei_findings("no selected Nuclei targets")
            early_coverage_reason = "no selected Nuclei targets"
            early_coverage_passes = [(early_targets, "failed",
                                      early_coverage_reason, False)]
            _record_unrun_nuclei(recon_data, _nuclei_coverage(
                coverage_at,
                early_coverage_passes))
        early_reason = nuclei_unavailable or (
            "no Nuclei templates selected" if locals().get("skip_detection_pass") else "no targets")
        if empty_selection:
            early_reason = "no selected Nuclei targets"
        early_plan = _selection_plan(
            targets=early_targets, saved_tags=saved_nuclei_tags, effective_tags=NUCLEI_TAGS,
            partial_scope=bool(selection_hint and selection_hint.get("scope") == "partial"))
        early_passes = early_coverage_passes or ([(early_targets, "failed", early_reason, False)]
                                                 if early_reason != "no targets" else [])
        early_plan = record_execution(early_plan, early_passes)
        if empty_selection:
            for executed in early_plan.get("execution", {}).get("passes") or []:
                if executed.get("reason") == "no selected targets":
                    executed["reason"] = "no selected Nuclei targets"
        early_plan["reason"] = early_reason
        early_selection_plan = early_plan
        # The plan persists to the canonical artifact under the same lock the
        # main path uses. The in-memory top-level result stays the scanner
        # result contract; a failed launch is reported through the coverage
        # circuit breaker rather than a new result key.
        if plan_output_file is not None:
            persist_plan(plan_output_file, early_plan)
        print(f"[*][Nuclei] NUCLEI SCAN {early_plan['status'].upper()}: {early_reason}")

    # Run CVE lookup for detected technologies (like Nmap's vulners)
    if CVE_LOOKUP_ENABLED and recon_data.get("http_probe"):
        cve_results = run_cve_lookup(
            recon_data=recon_data,
            enabled=CVE_LOOKUP_ENABLED,
            source=CVE_LOOKUP_SOURCE,
            max_cves=CVE_LOOKUP_MAX_CVES,
            min_cvss=CVE_LOOKUP_MIN_CVSS,
            vulners_api_key=VULNERS_API_KEY,
            nvd_api_key=NVD_API_KEY,
            nvd_key_rotator=NVD_KEY_ROTATOR,
            vulners_key_rotator=VULNERS_KEY_ROTATOR,
        )
        recon_data.update(cve_results)

        # Save with CVE data
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)
            fix_file_ownership(output_file)

    # Run custom security checks (Direct IP Access, TLS/SSL, Security Headers)
    # Skip entirely if global switch is disabled
    if not SECURITY_CHECK_ENABLED:
        print(f"\n[-][Nuclei] Custom security checks disabled (SECURITY_CHECK_ENABLED=False)")
    else:
        security_checks_enabled = {
            # Direct IP Access checks (unique - not covered by Nuclei)
            "direct_ip_http": SECURITY_CHECK_DIRECT_IP_HTTP,
            "direct_ip_https": SECURITY_CHECK_DIRECT_IP_HTTPS,
            "ip_api_exposed": SECURITY_CHECK_IP_API_EXPOSED,
            "waf_bypass": SECURITY_CHECK_WAF_BYPASS,
            # TLS/SSL checks
            "tls_expiring_soon": SECURITY_CHECK_TLS_EXPIRING_SOON,
            # TLS-hygiene checks derived from tlsx/httpx certificate data
            "tls_expired": settings.get('SECURITY_CHECK_TLS_EXPIRED', True),
            "tls_self_signed": settings.get('SECURITY_CHECK_TLS_SELF_SIGNED', True),
            "tls_hostname_mismatch": settings.get('SECURITY_CHECK_TLS_HOSTNAME_MISMATCH', True),
            "tls_weak_version": settings.get('SECURITY_CHECK_TLS_WEAK_VERSION', True),
            "tls_weak_cipher": settings.get('SECURITY_CHECK_TLS_WEAK_CIPHER', True),
            "tls_wildcard_overbroad": settings.get('SECURITY_CHECK_TLS_WILDCARD_OVERBROAD', True),
            # Security Headers checks (only headers not covered by Nuclei)
            "missing_referrer_policy": SECURITY_CHECK_MISSING_REFERRER_POLICY,
            "missing_permissions_policy": SECURITY_CHECK_MISSING_PERMISSIONS_POLICY,
            "missing_coop": SECURITY_CHECK_MISSING_COOP,
            "missing_corp": SECURITY_CHECK_MISSING_CORP,
            "missing_coep": SECURITY_CHECK_MISSING_COEP,
            "cache_control_missing": SECURITY_CHECK_CACHE_CONTROL_MISSING,
            # Authentication security checks
            "login_no_https": SECURITY_CHECK_LOGIN_NO_HTTPS,
            "session_no_secure": SECURITY_CHECK_SESSION_NO_SECURE,
            "session_no_httponly": SECURITY_CHECK_SESSION_NO_HTTPONLY,
            "basic_auth_no_tls": SECURITY_CHECK_BASIC_AUTH_NO_TLS,
            # DNS security checks
            "spf_missing": SECURITY_CHECK_SPF_MISSING,
            "dmarc_missing": SECURITY_CHECK_DMARC_MISSING,
            "dnssec_missing": SECURITY_CHECK_DNSSEC_MISSING,
            "zone_transfer": SECURITY_CHECK_ZONE_TRANSFER,
            # Port/Service security checks
            "admin_port_exposed": SECURITY_CHECK_ADMIN_PORT_EXPOSED,
            "database_exposed": SECURITY_CHECK_DATABASE_EXPOSED,
            "redis_no_auth": SECURITY_CHECK_REDIS_NO_AUTH,
            "kubernetes_api_exposed": SECURITY_CHECK_KUBERNETES_API_EXPOSED,
            "smtp_open_relay": SECURITY_CHECK_SMTP_OPEN_RELAY,
            # Application security checks
            "csp_unsafe_inline": SECURITY_CHECK_CSP_UNSAFE_INLINE,
            "insecure_form_action": SECURITY_CHECK_INSECURE_FORM_ACTION,
            # Rate limiting checks
            "no_rate_limiting": SECURITY_CHECK_NO_RATE_LIMITING,
            # Page Content: titles, Server headers and issuers already collected
            **page_content_enabled(settings),
        }

        # Only run if at least one check is enabled
        if any(security_checks_enabled.values()):
            security_results = run_security_checks(
                recon_data=recon_data,
                enabled_checks=security_checks_enabled,
                timeout=SECURITY_CHECK_TIMEOUT,
                tls_expiry_days=SECURITY_CHECK_TLS_EXPIRY_DAYS,
                max_workers=SECURITY_CHECK_MAX_WORKERS,
                ai_classifier_enabled=WAF_AI_CLASSIFIER,
                ai_model=AI_PIPELINE_MODEL,
                ai_user_id=os.environ.get('USER_ID', ''),
                ai_project_id=os.environ.get('PROJECT_ID', ''),
                ai_engine=('jev' if WAF_AI_USE_JEV else 'llm'),
                roe_excluded_hosts=(settings.get('ROE_EXCLUDED_HOSTS') or None)
                if settings.get('ROE_ENABLED') else None,
                settings=settings,
            )

            # Merge security checks into vuln_scan results
            if "vuln_scan" in recon_data:
                recon_data["vuln_scan"]["security_checks"] = security_results.get("security_checks", {})
            else:
                recon_data["vuln_scan"] = {"security_checks": security_results.get("security_checks", {})}

            # Save with security check data
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(recon_data, f, indent=2)
                fix_file_ownership(output_file)

    if early_selection_plan is not None:
        recon_data[SELECTION_KEY] = early_selection_plan

    if NUCLEI_ENABLED and not run_nuclei and not SECURITY_CHECK_ENABLED:
        recon_data["vuln_scan"] = {"scan_metadata": {"coverage": {"at": coverage_at, "hosts": {}}}}
        recon_data["vuln_scan"]["scan_metadata"]["total_urls_scanned"] = 0
        recon_data["vuln_scan"]["scan_metadata"]["total_urls_selected"] = 0

    return recon_data


def enrich_recon_file(recon_file: Path) -> dict:
    """Load a recon JSON file, enrich it with nuclei data, and save it back.
        recon_file: Path to the recon JSON file

    Returns:
        Enriched recon data
    """
    # Load settings for standalone usage
    from recon.project_settings import get_settings
    settings = get_settings()

    # Load existing data
    with open(recon_file, 'r') as f:
        recon_data = json.load(f)

    # Run nuclei scan
    enriched_data = run_vuln_scan(recon_data, output_file=recon_file, settings=settings)

    # Save enriched data
    with open(recon_file, 'w') as f:
        json.dump(enriched_data, f, indent=2)

    print(f"[+][Nuclei] Enriched data saved to: {recon_file}")

    return enriched_data



def run_vuln_scan_isolated(combined_result: dict, settings: dict,
                           output_file: Path = None) -> TopLevelKeys:
    """
    Thread-safe isolated wrapper for Nuclei vuln scanning.

    Deep-copies combined_result, runs the scan on the copy (without incremental
    file saves), and returns a TopLevelKeys holding vuln_scan and, when the CVE
    lookup ran, its technology_cves. Used by Group 6 Phase A fan-out in main.py
    so Nuclei and GraphQL can run concurrently without racing on shared state.

    ``output_file`` is the group's canonical artifact. The selection plan is
    merged into it BEFORE the Nuclei pass launches - from this fan-out thread,
    under the same lock save_recon_file takes - so a cancellation or a crash
    keeps the planned-input accounting. The scan itself still runs on the deep
    copy and the incremental saves stay with the fan-out's merged result, which
    is what main.py persists once the future completes.
    """
    snapshot = copy.deepcopy(combined_result)
    # output_file=None => skip the function's own incremental saves (main.py
    # persists the merged result after the fan-out completes); plan_output_file
    # carries the plan to disk before the pass launches instead.
    run_vuln_scan(snapshot, output_file=None, settings=settings,
                  plan_output_file=output_file)
    result = TopLevelKeys(vuln_scan=snapshot.get("vuln_scan", {}))
    for key in _VULN_SCAN_RESULT_KEYS[1:]:
        if key in snapshot:
            result[key] = snapshot[key]
    return result
