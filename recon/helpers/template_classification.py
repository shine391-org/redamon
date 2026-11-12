"""
RedAmon - Nuclei Template Classification Registry
==================================================

Classifies Nuclei templates by their semantics to enable precise routing:
- origin-safe: checks that only need the origin (SSL, headers, DNS, tech detection)
- app-prefix: checks for mounted apps at known paths (/wp-admin/, /admin/, /api/)
- endpoint: parameterized endpoint checks (query/body params, specific paths)
- multi-request: templates that execute multiple requests (flows, redirects chains)
- raw-http: templates with raw HTTP request definitions
- body-multipart: templates that send POST/PUT/PATCH with body content
- unknown: templates with unrecognized semantics -> compatibility lane

The registry is populated from the official Nuclei templates stats and can be
extended with custom rules. Unknown templates always go to the compatibility
lane (legacy behavior), never silently excluded.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Classification categories
# ---------------------------------------------------------------------------

class TemplateCategory(str, Enum):
    """Semantic category of a Nuclei template."""
    ORIGIN_SAFE = "origin_safe"        # Only needs origin (SSL, headers, tech, DNS)
    APP_PREFIX = "app_prefix"          # Checks known app paths (/wp-admin, /admin, etc.)
    ENDPOINT = "endpoint"              # Parameterized endpoint with query/body params
    MULTI_REQUEST = "multi_request"    # Multiple requests (flows, redirect chains)
    RAW_HTTP = "raw_http"              # Raw HTTP request definitions
    BODY_MULTIPART = "body_multipart"  # POST/PUT/PATCH with body content
    UNKNOWN = "unknown"                # Unrecognized -> compatibility lane

ALL_CATEGORIES = tuple(TemplateCategory)

# Routing mode (mirrors planner's off/shadow/enforce pattern)
MODE_OFF = "off"
MODE_SHADOW = "shadow"
MODE_ENFORCE = "enforce"
MODES = (MODE_OFF, MODE_SHADOW, MODE_ENFORCE)

def resolve_routing_mode(settings: dict[str, Any]) -> str:
    """Effective routing mode from settings: off | shadow | enforce.
    
    Defaults to off (patched legacy behaviour). An unrecognised value is
    treated as off rather than silently escalating to enforce.
    """
    mode = settings.get("NUCLEI_ROUTING_MODE", settings.get("nuclei_routing_mode", MODE_OFF))
    return mode if mode in MODES else MODE_OFF

def routing_consumer_enabled(settings: dict[str, Any]) -> bool:
    """Whether routed execution is honoured for this run.
    
    Only honoured when the mode is shadow or enforce; off means
    patched legacy behaviour with no routing optimization.
    """
    return resolve_routing_mode(settings) != MODE_OFF


# ---------------------------------------------------------------------------
# Classification rules (prefix -> category)
# Order matters: more specific prefixes first
# ---------------------------------------------------------------------------

# Prefix-based classification rules from official Nuclei template structure
TEMPLATE_PREFIX_RULES: Tuple[Tuple[str, TemplateCategory, str], ...] = (
    # SSL/TLS/Certificate checks - origin safe
    ("ssl/", TemplateCategory.ORIGIN_SAFE, "rule:ssl-check"),
    ("tls/", TemplateCategory.ORIGIN_SAFE, "rule:tls-check"),
    ("certificate/", TemplateCategory.ORIGIN_SAFE, "rule:certificate-check"),
    
    # DNS/Subdomain takeover - origin safe
    ("dns/", TemplateCategory.ORIGIN_SAFE, "rule:dns-check"),
    ("takeover/", TemplateCategory.ORIGIN_SAFE, "rule:takeover-check"),
    
    # Technology detection - origin safe
    ("technologies/", TemplateCategory.ORIGIN_SAFE, "rule:technology-detection"),
    ("fingerprint/", TemplateCategory.ORIGIN_SAFE, "rule:fingerprint"),
    
    # Exposure/Information disclosure - origin safe (headers, files at root)
    ("exposure/", TemplateCategory.ORIGIN_SAFE, "rule:exposure-check"),
    ("misconfig/", TemplateCategory.ORIGIN_SAFE, "rule:misconfig-check"),
    
    # Default login panels - app prefix (known paths)
    ("default-login/", TemplateCategory.APP_PREFIX, "rule:default-login"),
    ("panel/", TemplateCategory.APP_PREFIX, "rule:admin-panel"),
    
    # CVE checks - typically endpoint or origin safe depending on path
    # We classify by sub-path
    ("cves/202", TemplateCategory.ENDPOINT, "rule:cve-endpoint"),  # Year-based CVEs
    ("cve/", TemplateCategory.ENDPOINT, "rule:cve-endpoint"),
    
    # Vulnerability classes - typically endpoint checks
    ("vulns/", TemplateCategory.ENDPOINT, "rule:vuln-endpoint"),
    ("vulnerabilities/", TemplateCategory.ENDPOINT, "rule:vuln-endpoint"),
    
    # Specific vulnerability types - endpoint with params
    ("xss/", TemplateCategory.ENDPOINT, "rule:xss-endpoint"),
    ("sqli/", TemplateCategory.ENDPOINT, "rule:sqli-endpoint"),
    ("rce/", TemplateCategory.ENDPOINT, "rule:rce-endpoint"),
    ("lfi/", TemplateCategory.ENDPOINT, "rule:lfi-endpoint"),
    ("rfi/", TemplateCategory.ENDPOINT, "rule:rfi-endpoint"),
    ("ssrf/", TemplateCategory.ENDPOINT, "rule:ssrf-endpoint"),
    ("xxe/", TemplateCategory.ENDPOINT, "rule:xxe-endpoint"),
    ("ssti/", TemplateCategory.ENDPOINT, "rule:ssti-endpoint"),
    ("idor/", TemplateCategory.ENDPOINT, "rule:idor-endpoint"),
    ("csrf/", TemplateCategory.ENDPOINT, "rule:csrf-endpoint"),
    ("redirect/", TemplateCategory.ENDPOINT, "rule:redirect-endpoint"),
    ("crlf/", TemplateCategory.ENDPOINT, "rule:crlf-endpoint"),
    ("injection/", TemplateCategory.ENDPOINT, "rule:injection-endpoint"),
    ("traversal/", TemplateCategory.ENDPOINT, "rule:traversal-endpoint"),
    ("file-upload/", TemplateCategory.BODY_MULTIPART, "rule:file-upload"),
    ("disclosure/", TemplateCategory.ENDPOINT, "rule:disclosure-endpoint"),
    
    # Fuzz/Brute force - multi-request or body
    ("fuzz/", TemplateCategory.MULTI_REQUEST, "rule:fuzz-multi"),
    ("brute/", TemplateCategory.MULTI_REQUEST, "rule:brute-multi"),
    
    # WordPress/Joomla/Drupal specific - app prefix
    ("wordpress/", TemplateCategory.APP_PREFIX, "rule:wordpress-app"),
    ("wp-plugin/", TemplateCategory.APP_PREFIX, "rule:wp-plugin"),
    ("wp-theme/", TemplateCategory.APP_PREFIX, "rule:wp-theme"),
    ("joomla/", TemplateCategory.APP_PREFIX, "rule:joomla-app"),
    ("drupal/", TemplateCategory.APP_PREFIX, "rule:drupal-app"),
    
    # Cloud/Infrastructure - origin safe
    ("aws/", TemplateCategory.ORIGIN_SAFE, "rule:aws-check"),
    ("azure/", TemplateCategory.ORIGIN_SAFE, "rule:azure-check"),
    ("gcp/", TemplateCategory.ORIGIN_SAFE, "rule:gcp-check"),
    ("kubernetes/", TemplateCategory.ORIGIN_SAFE, "rule:k8s-check"),
    ("docker/", TemplateCategory.ORIGIN_SAFE, "rule:docker-check"),
    
    # Network/Protocol - origin safe
    ("network/", TemplateCategory.ORIGIN_SAFE, "rule:network-check"),
    ("protocol/", TemplateCategory.ORIGIN_SAFE, "rule:protocol-check"),
    
    # Generic paths that need content inspection
    ("generic/", TemplateCategory.UNKNOWN, "rule:generic-unknown"),
    ("http/", TemplateCategory.UNKNOWN, "rule:http-generic"),
)

# Content-based classification patterns (inspect template YAML)
CONTENT_PATTERNS: Tuple[Tuple[re.Pattern, TemplateCategory, str], ...] = (
    # Multi-request: requests array with multiple entries
    (re.compile(r'requests:\s*\n(\s*-\s*(method|path|raw):)'), TemplateCategory.MULTI_REQUEST, "pattern:multi-request"),
    
    # Raw HTTP request (raw: | or raw: > or raw: '...' or raw: "...")
    (re.compile(r'raw:\s*[\|>]\s*\n\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s'), TemplateCategory.RAW_HTTP, "pattern:raw-http"),
    (re.compile(r'raw:\s*[\'"]\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s'), TemplateCategory.RAW_HTTP, "pattern:raw-http-quoted"),
    
    # Body content (POST/PUT with body)
    (re.compile(r'method:\s*[\'"]?(POST|PUT|PATCH)[\'"]?\s*\n\s*body:'), TemplateCategory.BODY_MULTIPART, "pattern:body-request"),
    
    # Multipart form data
    (re.compile(r'content_type:\s*[\'"]?multipart/form-data'), TemplateCategory.BODY_MULTIPART, "pattern:multipart"),
    
    # Redirect chains (multiple requests with redirects)
    (re.compile(r'follow_redirects:\s*true'), TemplateCategory.MULTI_REQUEST, "pattern:redirect-chain"),
    
    # Flow/conditional logic
    (re.compile(r'(condition:|expression:|eval:)'), TemplateCategory.MULTI_REQUEST, "pattern:flow-logic"),
    
    # App prefix paths (known admin/mounted paths)
    (re.compile(r'path:\s*[\'"]?(/(wp-admin|admin|administrator|phpmyadmin|manager|console|api/v|graphql|swagger|actuator|health|metrics|debug|status|server-status))'), TemplateCategory.APP_PREFIX, "pattern:app-prefix-path"),
)


# ---------------------------------------------------------------------------
# Template metadata from stats
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TemplateMeta:
    """Lightweight template metadata from TEMPLATES-STATS.json."""
    name: str
    count: int
    tags: Tuple[str, ...] = ()
    severity: str = ""
    author: str = ""
    
    @property
    def primary_tag(self) -> str:
        return self.tags[0] if self.tags else ""


@dataclass(frozen=True)
class ClassifiedTemplate:
    """A template with its resolved classification."""
    template_id: str
    category: TemplateCategory
    provenance: str  # rule/pattern that classified it
    confidence: float  # 1.0 = explicit rule, 0.8 = content pattern, 0.5 = tag heuristic
    meta: Optional[TemplateMeta] = None
    
    def is_known(self) -> bool:
        return self.category != TemplateCategory.UNKNOWN
    
    def requires_body_support(self) -> bool:
        """Whether this template needs body/multipart request support."""
        return self.category in (TemplateCategory.BODY_MULTIPART, TemplateCategory.RAW_HTTP)
    
    def is_multi_request(self) -> bool:
        return self.category == TemplateCategory.MULTI_REQUEST


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TemplateClassificationRegistry:
    """
    Registry of classified Nuclei templates.
    
    Loads from TEMPLATES-STATS.json (official templates) and classifies each
    template by prefix rules, content patterns, and tag heuristics.
    Unknown templates are classified as UNKNOWN -> compatibility lane.
    """
    
    def __init__(self, stats_path: Optional[str] = None):
        self.stats_path = stats_path or '/opt/nuclei-templates-official/TEMPLATES-STATS.json'
        self._templates: Dict[str, ClassifiedTemplate] = {}
        self._loaded = False
        self._fallback_categories: Dict[str, TemplateCategory] = {}
    
    def load(self) -> None:
        """Load and classify all templates from stats file."""
        if self._loaded:
            return
        
        templates_meta = self._load_stats()
        for meta in templates_meta:
            classified = self._classify_template(meta)
            self._templates[meta.name] = classified
        
        self._loaded = True
    
    def _load_stats(self) -> List[TemplateMeta]:
        """Load template metadata from TEMPLATES-STATS.json."""
        try:
            with open(self.stats_path) as f:
                stats = json.load(f)
            result = []
            # TEMPLATES-STATS.json structure: {"tags": {"tag_name": {"count": N, "templates": [...]} ...}}
            # Invert to get per-template metadata
            template_map: Dict[str, Dict[str, Any]] = {}
            for tag_name, tag_info in stats.get('tags', {}).items():
                if not isinstance(tag_info, dict):
                    continue
                count = tag_info.get('count', 0)
                templates = tag_info.get('templates', [])
                for tpl in templates:
                    if not isinstance(tpl, str):
                        continue
                    if tpl not in template_map:
                        template_map[tpl] = {"name": tpl, "count": 0, "tags": [], "severity": "", "author": ""}
                    template_map[tpl]["count"] += count
                    template_map[tpl]["tags"].append(tag_name)
            for tpl_data in template_map.values():
                result.append(TemplateMeta(
                    name=tpl_data["name"],
                    count=tpl_data["count"],
                    tags=tuple(tpl_data["tags"]),
                    severity=tpl_data.get("severity", ""),
                    author=tpl_data.get("author", ""),
                ))
            return result
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return []
    
    def classify(self, template_id: str, template_content: Optional[str] = None) -> ClassifiedTemplate:
        """Classify a single template by ID and optional content."""
        if template_id in self._templates:
            return self._templates[template_id]
        
        # Create minimal meta for classification
        meta = TemplateMeta(name=template_id, count=0)
        classified = self._classify_template(meta, template_content)
        self._templates[template_id] = classified
        return classified
    
    def _classify_template(self, meta: TemplateMeta, content: Optional[str] = None) -> ClassifiedTemplate:
        """Classify a template using prefix rules, content patterns, and tag heuristics."""
        template_id = meta.name
        
        # 1. Prefix-based rules (highest confidence)
        for prefix, category, provenance in TEMPLATE_PREFIX_RULES:
            if template_id.startswith(prefix):
                return ClassifiedTemplate(
                    template_id=template_id,
                    category=category,
                    provenance=provenance,
                    confidence=1.0,
                    meta=meta,
                )
        
        # 2. Content-based patterns (if content provided)
        if content:
            for pattern, category, provenance in CONTENT_PATTERNS:
                if pattern.search(content):
                    return ClassifiedTemplate(
                        template_id=template_id,
                        category=category,
                        provenance=provenance,
                        confidence=0.8,
                        meta=meta,
                    )
        
        # 3. Tag-based heuristic (lower confidence)
        tag_category = self._classify_by_tags(meta.tags)
        if tag_category != TemplateCategory.UNKNOWN:
            return ClassifiedTemplate(
                template_id=template_id,
                category=tag_category,
                provenance="heuristic:tag-based",
                confidence=0.5,
                meta=meta,
            )
        
        # 4. Unknown -> compatibility lane
        return ClassifiedTemplate(
            template_id=template_id,
            category=TemplateCategory.UNKNOWN,
            provenance="rule:template-unknown",
            confidence=0.0,
            meta=meta,
        )
    
    def _classify_by_tags(self, tags: Tuple[str, ...]) -> TemplateCategory:
        """Heuristic classification based on template tags."""
        tags_set = set(tags)
        
        # Origin-safe tags
        if tags_set & {'ssl', 'tls', 'certificate', 'dns', 'takeover', 'tech', 'fingerprint', 'exposure', 'misconfig'}:
            return TemplateCategory.ORIGIN_SAFE
        
        # App prefix tags
        if tags_set & {'default-login', 'panel', 'wordpress', 'wp-plugin', 'wp-theme', 'joomla', 'drupal'}:
            return TemplateCategory.APP_PREFIX
        
        # Body/multipart tags
        if tags_set & {'file-upload', 'multipart'}:
            return TemplateCategory.BODY_MULTIPART
        
        # Multi-request tags
        if tags_set & {'fuzz', 'brute', 'flow', 'redirect-chain'}:
            return TemplateCategory.MULTI_REQUEST
        
        # Endpoint vulnerability tags
        if tags_set & {'cve', 'vuln', 'xss', 'sqli', 'rce', 'lfi', 'rfi', 'ssrf', 'xxe', 'ssti', 'idor', 'csrf', 'redirect', 'crlf', 'injection', 'traversal', 'disclosure'}:
            return TemplateCategory.ENDPOINT
        
        # Cloud/Infrastructure tags -> origin safe
        if tags_set & {'aws', 'azure', 'gcp', 'kubernetes', 'docker', 'cloud'}:
            return TemplateCategory.ORIGIN_SAFE
        
        # HTTP/misc tags that don't indicate a specific category -> UNKNOWN (compatibility lane)
        if tags_set & {'http', 'misc', 'generic', 'network', 'protocol'}:
            return TemplateCategory.UNKNOWN
        
        return TemplateCategory.UNKNOWN
    
    def get_category(self, template_id: str, template_content: Optional[str] = None) -> TemplateCategory:
        """Get the category for a template."""
        return self.classify(template_id, template_content).category
    
    def get_provenance(self, template_id: str, template_content: Optional[str] = None) -> str:
        """Get the provenance rule for a template."""
        return self.classify(template_id, template_content).provenance
    
    def is_known(self, template_id: str, template_content: Optional[str] = None) -> bool:
        """Whether the template has known semantics (not UNKNOWN)."""
        return self.classify(template_id, template_content).is_known()
    
    def requires_body_support(self, template_id: str, template_content: Optional[str] = None) -> bool:
        """Whether the template needs body/multipart request support."""
        return self.classify(template_id, template_content).requires_body_support()
    
    def is_multi_request(self, template_id: str, template_content: Optional[str] = None) -> bool:
        """Whether the template executes multiple requests."""
        return self.classify(template_id, template_content).is_multi_request()
    
    def batch_by_category(self, template_ids: List[str], template_contents: Optional[Dict[str, str]] = None) -> Dict[TemplateCategory, List[str]]:
        """Group templates by category for batched execution."""
        result: Dict[TemplateCategory, List[str]] = {cat: [] for cat in ALL_CATEGORIES}
        contents = template_contents or {}
        for tid in template_ids:
            cat = self.get_category(tid, contents.get(tid))
            result[cat].append(tid)
        return result
    
    def get_compatibility_templates(self, template_ids: List[str], template_contents: Optional[Dict[str, str]] = None) -> List[str]:
        """Get templates that fall into the compatibility lane (UNKNOWN)."""
        return [tid for tid in template_ids if not self.is_known(tid, (template_contents or {}).get(tid))]


# ---------------------------------------------------------------------------
# Global registry instance (lazy-loaded)
# ---------------------------------------------------------------------------

_registry: Optional[TemplateClassificationRegistry] = None

def get_registry(stats_path: Optional[str] = None) -> TemplateClassificationRegistry:
    """Get the global template classification registry."""
    global _registry
    if _registry is None:
        _registry = TemplateClassificationRegistry(stats_path)
    return _registry

def classify_template(template_id: str, template_content: Optional[str] = None, stats_path: Optional[str] = None) -> ClassifiedTemplate:
    """Convenience: classify a single template."""
    return get_registry(stats_path).classify(template_id, template_content)

def get_template_category(template_id: str, template_content: Optional[str] = None, stats_path: Optional[str] = None) -> TemplateCategory:
    """Convenience: get template category."""
    return get_registry(stats_path).get_category(template_id, template_content)

def batch_templates_by_category(template_ids: List[str], template_contents: Optional[Dict[str, str]] = None, stats_path: Optional[str] = None) -> Dict[TemplateCategory, List[str]]:
    """Convenience: batch templates by category."""
    return get_registry(stats_path).batch_by_category(template_ids, template_contents)

def get_compatibility_lane_templates(template_ids: List[str], template_contents: Optional[Dict[str, str]] = None, stats_path: Optional[str] = None) -> List[str]:
    """Convenience: get templates that go to compatibility lane."""
    return get_registry(stats_path).get_compatibility_templates(template_ids, template_contents)


# ---------------------------------------------------------------------------
# Request capability adapter (for body/multipart/auth variants)
# ---------------------------------------------------------------------------

@dataclass
class RequestCapability:
    """Describes what request capabilities a template needs."""
    method: str = "GET"
    has_body: bool = False
    content_type: str = ""
    is_multipart: bool = False
    auth_required: bool = False
    follows_redirects: bool = False
    max_redirects: int = 0
    is_multi_request: bool = False
    raw_http: bool = False
    supported: bool = True  # False = not supported by current transport
    unsupported_reason: str = ""

def analyze_template_capability(template_id: str, template_content: Optional[str] = None) -> RequestCapability:
    """
    Analyze what request capabilities a template requires.
    Returns RequestCapability with supported=False if current transport can't handle it.
    """
    classified = classify_template(template_id, template_content)
    cap = RequestCapability()
    
    if classified.category == TemplateCategory.ORIGIN_SAFE:
        cap.method = "GET"
        cap.supported = True
    
    elif classified.category == TemplateCategory.APP_PREFIX:
        cap.method = "GET"
        cap.supported = True
    
    elif classified.category == TemplateCategory.ENDPOINT:
        cap.method = "GET"  # Default, could be overridden by content inspection
        cap.supported = True
    
    elif classified.category == TemplateCategory.BODY_MULTIPART:
        cap.method = "POST"
        cap.has_body = True
        cap.is_multipart = "multipart" in (template_content or "").lower()
        cap.content_type = "multipart/form-data" if cap.is_multipart else "application/x-www-form-urlencoded"
        # Current nuclei transport supports -dast and body via templates
        cap.supported = True  # Nuclei native supports this
    
    elif classified.category == TemplateCategory.RAW_HTTP:
        cap.raw_http = True
        cap.supported = True  # Nuclei supports raw HTTP
    
    elif classified.category == TemplateCategory.MULTI_REQUEST:
        cap.is_multi_request = True
        cap.supported = True  # Nuclei supports flows
    
    else:  # UNKNOWN
        cap.supported = True  # Compatibility lane runs legacy behavior
        cap.unsupported_reason = "unknown semantics -> compatibility lane"
    
    # Inspect content for more precise capability detection
    if template_content:
        content_lower = template_content.lower()
        if 'method:' in content_lower:
            for m in ['post', 'put', 'patch', 'delete']:
                if f'method: {m}' in content_lower or f'method: \'{m}\'' in content_lower or f'method: "{m}"' in content_lower:
                    cap.method = m.upper()
                    cap.has_body = True
                    break
        if 'content_type:' in content_lower:
            if 'multipart/form-data' in content_lower:
                cap.is_multipart = True
                cap.content_type = 'multipart/form-data'
            elif 'application/json' in content_lower:
                cap.content_type = 'application/json'
            elif 'application/x-www-form-urlencoded' in content_lower:
                cap.content_type = 'application/x-www-form-urlencoded'
        if 'follow_redirects: true' in content_lower:
            cap.follows_redirects = True
        if 'max_redirects:' in content_lower:
            import re
            m = re.search(r'max_redirects:\s*(\d+)', content_lower)
            if m:
                cap.max_redirects = int(m.group(1))
    
    return cap


# ---------------------------------------------------------------------------
# Auth batch safety
# ---------------------------------------------------------------------------

def validate_auth_batch_safety(
    templates: List[str],
    template_contents: Optional[Dict[str, str]] = None,
    auth_headers: Optional[List[str]] = None,
    target_origins: Optional[List[str]] = None,
    scope_hosts: Optional[List[str]] = None,
) -> Tuple[bool, List[str]]:
    """
    Validate that an auth header batch is safe for the given templates.
    
    Returns (is_safe, warnings). Checks:
    - No template sends auth to foreign origins (redirect/OAST)
    - No raw HTTP template with auth that could leak
    - Multi-request flows don't silently de-auth
    - Target origins are in scope (when scope_hosts provided)
    """
    warnings = []
    is_safe = True
    
    if not auth_headers:
        return True, []
    
    contents = template_contents or {}
    registry = get_registry()
    
    for template_id in templates:
        content = contents.get(template_id)
        classified = registry.classify(template_id, content)
        capability = analyze_template_capability(template_id, content)
        
        # Check for foreign origin redirects with auth
        if capability.follows_redirects and not capability.raw_http:
            warnings.append(f"{template_id}: follows redirects with auth headers - ensure scope check passes")
        
        # Check for OAST (interactsh) with auth
        if 'interactsh' in (content or '').lower() or 'oast' in (content or '').lower():
            warnings.append(f"{template_id}: uses OAST (interactsh) - auth headers will be sent to third-party collector")
            is_safe = False
        
        # Check for raw HTTP with auth
        if capability.raw_http and auth_headers:
            warnings.append(f"{template_id}: raw HTTP request with auth - verify no credential leakage")
        
        # Check for multi-request flows that might drop auth
        if capability.is_multi_request:
            warnings.append(f"{template_id}: multi-request flow - verify auth persists across all requests")
    
    # Check for foreign origins in target list (only when scope_hosts provided)
    if target_origins and scope_hosts:
        try:
            from recon.helpers.auth_profile import host_in_scope
        except Exception:
            host_in_scope = None
        for origin in target_origins:
            try:
                host = urlsplit(origin).hostname or ""
                if host and host_in_scope is not None and not host_in_scope(host.lower(), scope_hosts):
                    warnings.append(f"Target origin {origin} may be out of scope for attached auth")
                    is_safe = False
            except Exception:
                pass
    elif target_origins and not scope_hosts:
        warnings.append("Scope hosts not provided - cannot verify target origins are in scope")
    
    return is_safe, warnings


# ---------------------------------------------------------------------------
# Controlled receiver fixtures for testing
# ---------------------------------------------------------------------------

class RoutingFixture:
    """Test fixture for verifying routing behavior with a controlled receiver."""
    
    def __init__(self):
        self.received_requests: List[Dict[str, Any]] = []
        self.expected_categories: Dict[str, TemplateCategory] = {}
    
    def record_request(self, template_id: str, method: str, path: str, 
                       headers: Dict[str, str], body: str, origin: str):
        """Record a request received by the controlled receiver."""
        self.received_requests.append({
            "template_id": template_id,
            "method": method,
            "path": path,
            "headers": headers,
            "body": body,
            "origin": origin,
        })
    
    def verify_routing(self, template_ids: List[str], template_contents: Dict[str, str]) -> Dict[str, Any]:
        """Verify that templates were routed to correct endpoints."""
        results = {
            "total_templates": len(template_ids),
            "received": len(self.received_requests),
            "by_category": {},
            "duplicates": 0,
            "missing": [],
        }
        
        # Group received by template
        received_by_template = {}
        for req in self.received_requests:
            tid = req["template_id"]
            if tid not in received_by_template:
                received_by_template[tid] = []
            received_by_template[tid].append(req)
        
        # Check each template
        for tid in template_ids:
            content = template_contents.get(tid, "")
            classified = classify_template(tid, content)
            cat = classified.category
            
            if cat not in results["by_category"]:
                results["by_category"][cat.value] = {"expected": 0, "received": 0}
            results["by_category"][cat.value]["expected"] += 1
            
            if tid in received_by_template:
                results["by_category"][cat.value]["received"] += len(received_by_template[tid])
                if len(received_by_template[tid]) > 1:
                    results["duplicates"] += len(received_by_template[tid]) - 1
            else:
                results["missing"].append(tid)
        
        return results


# ---------------------------------------------------------------------------
# Integration with ScanPlanner
# ---------------------------------------------------------------------------

def enhance_planner_with_classification(
    planner,  # ScanPlanner instance
    template_ids: List[str],
    template_contents: Optional[Dict[str, str]] = None,
) -> None:
    """
    Enhance a ScanPlanner with template classification for better routing.
    
    This adds classification provenance to planned tasks and routes
    UNKNOWN templates to the compatibility lane explicitly.
    """
    registry = get_registry()
    contents = template_contents or {}
    
    # Classify all templates
    classified = {tid: registry.classify(tid, contents.get(tid)) for tid in template_ids}
    
    # Store classification on planner for use in _classify_task
    planner._template_classifications = classified
    
    # Count by category for reporting
    planner._category_counts = {}
    for ct in classified.values():
        planner._category_counts[ct.category.value] = planner._category_counts.get(ct.category.value, 0) + 1


# ---------------------------------------------------------------------------
# CLI for testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    
    # Test classification
    registry = TemplateClassificationRegistry()
    
    test_templates = [
        "ssl/tls-version",
        "cves/2024/cve-2024-1234",
        "xss/reflected",
        "wordpress/wp-admin-detect",
        "fuzz/directory",
        "generic/unknown-template",
        "http/misconfig/security-headers",
        "vulns/sqli/basic",
        "file-upload/webshell",
        "aws/s3-bucket-enum",
    ]
    
    print("Template Classification Results:")
    print("=" * 80)
    
    for tid in test_templates:
        classified = registry.classify(tid)
        print(f"{tid:40s} -> {classified.category.value:20s} ({classified.provenance}) [{classified.confidence}]")
    
    print("\nBatch by category:")
    batched = registry.batch_by_category(test_templates)
    for cat, tids in batched.items():
        if tids:
            print(f"  {cat.value}: {tids}")
    
    print("\nCompatibility lane (UNKNOWN):")
    compat = registry.get_compatibility_templates(test_templates)
    print(f"  {compat}")