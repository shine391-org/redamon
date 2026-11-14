"""
RedAmon - Target Extraction Helpers
====================================
Functions for extracting and building target URLs from reconnaissance data.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


def http_url_rejection(url) -> Optional[str]:
    """Pure syntax admission, NOT a scope/SSRF/response validator.

    Never normalize the input: urllib silently removes some controls. Existing
    scope, auth, RoE and redirect guards remain the consumers' responsibility.
    """
    if not isinstance(url, str) or not url:
        return "empty_or_non_string"
    if any(ord(c) <= 32 or 127 <= ord(c) <= 159 or c.isspace() for c in url):
        return "control_or_whitespace"
    if "\\" in url:
        return "ambiguous_authority"
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return "non_http_scheme"
        host = parsed.hostname
        if not parsed.netloc or not host:
            return "missing_host"
        if parsed.username is not None or parsed.password is not None:
            return "userinfo_not_supported"
        port = parsed.port  # validates numeric range and malformed authorities
        if parsed.netloc.endswith(":") or (port is not None and port == 0):
            return "invalid_port"
        if ":" in host:
            ipaddress.IPv6Address(host)
            if not parsed.netloc.startswith("[") or not re.fullmatch(r"\[[^\]]+\](?::[0-9]+)?", parsed.netloc):
                return "malformed_authority"
        else:
            # Validate IDNs and internal underscore labels without rewriting.
            ascii_host = host.encode('idna').decode('ascii')
            if len(ascii_host.rstrip('.')) > 253 or not re.fullmatch(r"[A-Za-z0-9_~-]+(?:\.[A-Za-z0-9_~-]+)*\.?", ascii_host):
                return "invalid_host"
    except (ValueError, TypeError, AttributeError, UnicodeError):
        return "malformed_authority"
    return None


def admit_http_urls(urls, source: str, report: Optional[dict] = None) -> List[str]:
    """Keep exact valid strings; aggregate reasons without copying secrets/URLs.

    Raw observations stay in the producer artifact. report is a disposition
    summary, not proof that any admitted input was reached or responded.
    """
    kept = []
    rejected = {}
    for url in urls:
        reason = http_url_rejection(url)
        if reason:
            rejected[reason] = rejected.get(reason, 0) + 1
        else:
            kept.append(url)
    if report is not None:
        prior = report.get(source)
        merged = dict(prior) if isinstance(prior, dict) else {"admitted": 0, "rejected": {}}
        merged["admitted"] = int(merged.get("admitted") or 0) + len(kept)
        prior_rejected = merged.get("rejected")
        merged_rejected = dict(prior_rejected) if isinstance(prior_rejected, dict) else {}
        for reason, count in rejected.items():
            merged_rejected[reason] = merged_rejected.get(reason, 0) + count
        merged["rejected"] = merged_rejected
        report[source] = merged
    elif rejected:
        print(f"[*][HTTP admission] {source}: {rejected}")
    return kept


def add_supplied_http_targets(recon_data: dict, urls) -> None:
    """Represent explicit partial seeds as supplied, never observed HTTP 200.

    Retain invalid raw strings for disposition reporting; parsing only follows
    syntax admission. Do not replace existing measured HTTP evidence.
    """
    by_url = recon_data.setdefault("http_probe", {}).setdefault("by_url", {})
    for url in urls:
        by_url.setdefault(url, {"url": url, "host": (
            urlparse(url).hostname if http_url_rejection(url) is None else ""),
            "status_code": None, "content_type": "", "headers": {},
            "provenance": "supplied"})


# =============================================================================
# Target Extraction from Recon Data
# =============================================================================

def _as_str_list(value) -> List[str]:
    """Normalize a DNS address list, tolerating null/malformed entries."""
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if isinstance(item, str) and item]
    return []


def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract all unique IPs, hostnames, and build IP-to-hostname mapping.

    Honors recon_data["metadata"]["include_root_domain"]: when explicitly
    False, the apex/root domain is NOT added to the hostname set, even when
    dns.domain is populated. The apex's addresses are also withheld: an
    address it resolves to is not a target when the operator left the root
    out. The full pipeline sets this flag in main.py (parse_target +
    GROUP-2/3 branches); partial-recon graph builders set it from project
    settings. Default (flag missing) is True, preserving legacy behavior
    where the apex is always included.

    Malformed DNS payloads (null sections, non-dict records, null address
    lists) are skipped rather than raising.

    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    ips = set()
    hostnames = set()
    ip_to_hostnames = {}

    dns_data = (recon_data or {}).get("dns") or {}
    if not isinstance(dns_data, dict) or not dns_data:
        return ips, hostnames, ip_to_hostnames

    metadata = recon_data.get("metadata") or {}
    # A file written before scope_mode existed keeps the old default (the apex
    # is in scope); a current one always stamps the flag.
    include_root_domain = metadata.get("include_root_domain", "scope_mode" not in metadata)

    # Extract from root domain. The apex mapping is built ONLY with the apex:
    # recording an out-of-scope root's addresses would let an IP-only consumer
    # widen the active target set later.
    domain = recon_data.get("domain", "") or metadata.get("target", "")
    domain_dns = dns_data.get("domain") or {}
    if domain_dns and include_root_domain and isinstance(domain_dns, dict):
        domain_ips = domain_dns.get("ips") or {}
        ipv4_list = _as_str_list(domain_ips.get("ipv4"))
        ipv6_list = _as_str_list(domain_ips.get("ipv6"))

        ips.update(ipv4_list)
        ips.update(ipv6_list)

        if domain:
            hostnames.add(domain)
            for ip in ipv4_list + ipv6_list:
                if domain not in ip_to_hostnames.setdefault(ip, []):
                    ip_to_hostnames[ip].append(domain)

    # Extract from all subdomains
    subdomains_dns = dns_data.get("subdomains") or {}
    if isinstance(subdomains_dns, dict):
        for subdomain, subdomain_data in subdomains_dns.items():
            if not isinstance(subdomain, str) or not subdomain:
                continue
            if not isinstance(subdomain_data, dict):
                continue
            if subdomain_data.get("has_records"):
                hostnames.add(subdomain)

            subdomain_ips = subdomain_data.get("ips")
            if isinstance(subdomain_ips, dict):
                ipv4_list = _as_str_list(subdomain_ips.get("ipv4"))
                ipv6_list = _as_str_list(subdomain_ips.get("ipv6"))
            else:
                ipv4_list, ipv6_list = [], []

            ips.update(ipv4_list)
            ips.update(ipv6_list)

            for ip in ipv4_list + ipv6_list:
                if subdomain not in ip_to_hostnames.setdefault(ip, []):
                    ip_to_hostnames[ip].append(subdomain)

    return ips, hostnames, ip_to_hostnames


# =============================================================================
# URL Building from httpx Data
# =============================================================================

_CLOUDFLARE_1003_SIGNATURES = ("error 1003", "error code 1003")
_CF_ATTRIBUTION_HEADERS = ("cf-ray", "cf-request-id", "cf-mitigated")
_CF_ATTRIBUTION_TEXT_KEYS = ("server", "webserver", "cdn", "cdn_name")


def _cloudflare_attribution(entry: dict) -> bool:
    """True when the response itself is attributed to Cloudflare."""
    raw_headers = entry.get("headers")
    headers = raw_headers if isinstance(raw_headers, dict) else {}
    for key, value in headers.items():
        name = str(key).lower()
        text = str(value or "").lower()
        if name in _CF_ATTRIBUTION_HEADERS and text.strip():
            return True
        if name in ("server", "content-type") and "cloudflare" in text:
            return True
    for key in _CF_ATTRIBUTION_TEXT_KEYS:
        value = entry.get(key)
        if isinstance(value, str) and "cloudflare" in value.lower():
            return True
    return False


def _cloudflare_1003_signature(entry: dict) -> bool:
    """True only for an explicit Cloudflare 1003 error signature."""
    for key in ("title", "body"):
        value = entry.get(key)
        if isinstance(value, str):
            text = value.lower()
        elif isinstance(value, (bytes, bytearray)):
            text = bytes(value).decode("utf-8", "ignore").lower()
        else:
            continue
        if any(signature in text for signature in _CLOUDFLARE_1003_SIGNATURES):
            return True
    return False


def _observed_http_verdict(entry: dict):
    """Why an observed HTTP response is NOT a distinct application route.

    Deliberately narrow. A status code, ``Server: cloudflare``, a short body
    and a small content length are all compatible with a real application
    response (a login page, an API policy error, an origin failure), so none of
    them is evidence of an edge error page. Only an explicit Cloudflare 1003
    signature ("Error 1003 ...") on a measured 4xx/5xx response that is also
    attributed to Cloudflare is excluded.

    Returns a stable reason string, or None when the observation may still
    represent a distinct route.
    """
    if not isinstance(entry, dict):
        return None
    status = entry.get("status_code")
    if isinstance(status, bool) or not isinstance(status, int) or not (400 <= status <= 599):
        return None
    if not (_cloudflare_1003_signature(entry) and _cloudflare_attribution(entry)):
        return None
    return "edge_error_page_cloudflare_1003"


def build_target_urls_from_httpx(httpx_data: Optional[dict], report=None) -> List[str]:
    """
    Build list of target URLs from httpx scan results.

    Uses live URLs discovered by httpx for more accurate targeting. Observed
    edge-infrastructure error pages are excluded from downstream application
    work; genuine 401/403/5xx application responses (for example a titled login
    page) remain. Raw httpx evidence is never mutated.

    Measured statuses 1..599 (including 5xx) are admitted. A missing status is
    admitted only when it was explicitly supplied; otherwise it stays
    unverified and is neither admitted nor claimed as retained.

    Args:
        httpx_data: httpx scan results containing live URLs

    Returns:
        List of live URLs to scan
    """
    urls = []
    excluded = {}

    if httpx_data:
        # Use live URLs from httpx (already verified to be responding)
        by_url = httpx_data.get("by_url", {})
        if isinstance(by_url, dict):
            for url, url_data in by_url.items():
                if not isinstance(url_data, dict):
                    continue
                reason = _observed_http_verdict(url_data)
                if reason is not None:
                    excluded[reason] = excluded.get(reason, 0) + 1
                    continue
                status_code = url_data.get("status_code")
                if (isinstance(status_code, int) and not isinstance(status_code, bool)
                        and 1 <= status_code <= 599):
                    urls.append(url)
                elif status_code is None and url_data.get("provenance") == "supplied":
                    urls.append(url)

    disposition = {"excluded": excluded}
    if report is not None:
        # Preserve the syntax-admission summary this call also writes. A caller
        # that passes one report must receive both dispositions, not a partial
        # view with the edge-error decisions silently discarded. The admitted
        # count is deliberately left to admit_http_urls below: counting it here
        # too would accumulate the same URLs twice in one call.
        prior = report.get("httpx_or_supplied")
        merged = dict(prior) if isinstance(prior, dict) else {}
        merged.update(disposition)
        report["httpx_or_supplied"] = merged
    elif excluded:
        print(f"[*][HTTP admission] httpx_or_supplied: edge error pages {excluded}")
    return sorted(set(admit_http_urls(urls, "httpx_or_supplied", report)))



# =============================================================================
# URL Building from Resource Enumeration Data
# =============================================================================

#: Endpoints known only from an API specification sent to nuclei per run. Both
#: nuclei passes (main detection and DAST) read this function, so the cap bounds
#: both; a specification can declare thousands of operations.
MAX_DECLARED_NUCLEI_URLS = 500


from urllib.parse import quote as _q


def _endpoint_url(base_url: str, path: str, endpoint_info: dict) -> Optional[str]:
    """The URL with sample query values for GET-style scanning, else the bare path.

    Preserve a raw discovered sample URL verbatim when one is available so that
    its original encoding (and any decoded/ambiguous characters) is not
    re-encoded or lost. Only rebuild the query string from decoded parameter
    tuples when no sample URL exists, encoding each component so the result
    round-trips through the standard parsers without double-encoding.
    """
    if endpoint_info is None:
        endpoint_info = {}
    variants = endpoint_info.get("request_variants") or []
    if variants:
        # The path-keyed legacy schema cannot flatten method variants safely.
        # Retain all variants in the artifact, and prefer the GET/HEAD projection
        # for this URL-only consumer without relabeling a POST observation.
        endpoint_info = next((v for v in variants if v.get("method") in ("GET", "HEAD")), variants[0])
    sample_urls = endpoint_info.get("sample_urls") or []
    if isinstance(sample_urls, str):
        sample_urls = [sample_urls]
    if sample_urls and isinstance(sample_urls[0], str) and sample_urls[0].strip():
        return sample_urls[0]
    single = endpoint_info.get("sample_url")
    if isinstance(single, str) and single.strip():
        return single

    if endpoint_info.get("query_fidelity_unknown_without_raw"):
        endpoint_info["fidelity_unknown"] = True
    parameters = endpoint_info.get("parameters")
    if isinstance(parameters, dict):
        method = endpoint_info.get("method") or next(
            (m for m in endpoint_info.get("methods", []) if m in ("GET", "HEAD")),
            next(iter(endpoint_info.get("methods") or []), None))
        raw_params = (endpoint_info.get("query_by_method") or {}).get(method, parameters.get("query"))
        if raw_params is None:
            if any(k not in ("body", "path") for k in parameters):
                endpoint_info["fidelity_unknown"] = True
                endpoint_info.setdefault("fidelity_unknown_reasons", []).append("legacy_name_keyed_order_duplicates_encoding")
            # A pre-F01 name-keyed projection had no "query" bucket.
            raw_params = [{"name": name, **value} if isinstance(value, dict) else {"name": name}
                          for name, value in parameters.items()
                          if name not in ("body", "path")]
    else:
        raw_params = []
    params = raw_params or []
    # A name-keyed/aggregated projection cannot recover source order or
    # duplicate keys. Keep that loss explicit rather than claiming fidelity.
    if endpoint_info.get("fidelity_unknown") and "fidelity_unknown" not in endpoint_info.setdefault("fidelity", []):
        endpoint_info["fidelity"].append("fidelity_unknown")
    # Older serialized projections keyed parameters by name. Accept that shape
    # without inventing values, and never treat an encoded value as decoded.
    normalized_params = []
    for param in params:
        if isinstance(param, str):
            param = {"name": param}
        if not isinstance(param, dict):
            continue
        if "name" not in param and isinstance(param.get("sample_values"), dict):
            # Name-keyed legacy projection: {"q": {"sample_values": [...]}}.
            for name, value in param.items():
                if isinstance(value, dict):
                    normalized_params.append({**value, "name": name})
                else:
                    normalized_params.append({"name": name})
            continue
        normalized_params.append(param)
    parts = []
    for param in normalized_params:
        name = param.get("name")
        if not name:
            continue
        sample_values = param.get("sample_values")
        if sample_values:
            # Preserve an explicit empty value rather than substituting '1'.
            value = sample_values[0]
            if value is None:
                value = ""
        else:
            value = "1"
        encoding = param.get("sample_values_encoding")
        if encoding not in ("percent-encoded", "decoded-observation"):
            # Legacy samples have mixed producer encodings. Keep the legacy
            # percent tokens (no heuristic unquote), but do not claim this is a
            # recovered request. Raw observations/new producers avoid this lane.
            endpoint_info["fidelity_unknown"] = True
            reasons = endpoint_info.setdefault("fidelity_unknown_reasons", [])
            if "legacy_sample_encoding_order_duplicates" not in reasons:
                reasons.append("legacy_sample_encoding_order_duplicates")
            if "fidelity_unknown" not in endpoint_info.setdefault("fidelity", []):
                endpoint_info["fidelity"].append("fidelity_unknown")
        if any(ord(c) <= 31 or 127 <= ord(c) <= 159 for c in str(name) + str(value)):
            return None
        if encoding == "percent-encoded":
            # OpenAPI's producer already serialized this example.
            encoded_value = str(value)
        else:
            encoded_value = _q(str(value), safe='' if encoding == 'decoded-observation' else '%')
        parts.append(f"{_q(str(name), safe='')}={encoded_value}")
    if not parts:
        return f"{base_url}{path}"
    return f"{base_url}{path}?{'&'.join(parts)}"


def build_target_urls_from_resource_enum(
        resource_enum_data: Optional[dict], report: Optional[dict] = None,
        declared_report: Optional[dict] = None,
) -> Tuple[List[str], List[str]]:
    """
    Build list of target URLs from resource_enum data.

    A path that still holds a template (``/users/{id}``) is never a target. An
    endpoint known only from an API specification (``declared_only``) is a
    target only when it declares GET or HEAD, and at most
    MAX_DECLARED_NUCLEI_URLS of them are, in (base URL, path) order; how many
    were left out is recorded on the run's OpenAPI inventory.

    Args:
        resource_enum_data: Resource enumeration data with endpoints
        report: admission counters, as ``build_target_urls`` has always taken
        declared_report: F08 accounting of the declared-only decision. The
            cap and the GET/HEAD rule are unchanged; this only names what they
            excluded, so an absence in a consumer is not read as an absence in
            the target.

    Returns:
        Tuple of (base_urls, endpoint_urls_with_params)
    """
    base_urls = []
    endpoint_urls = []
    rejected_endpoints = {}

    if not resource_enum_data:
        return base_urls, endpoint_urls

    by_base_url = resource_enum_data.get("by_base_url", {})
    declared = []
    rejected_endpoints = {}
    # F08: which producers the consumer's own input actually carried.
    sources_present = set()
    templated_paths = 0
    non_relative_paths = 0
    # The declared-only counters accumulate across calls, so every key the
    # report exposes is present from the first call: an absence reads as a
    # measured zero, never as an unmeasured value.
    if declared_report is not None:
        declared_report.setdefault("declared_only_non_get_head", 0)

    for base_url, base_data in by_base_url.items():
        if http_url_rejection(base_url) is not None:
            continue
        base_urls.append(base_url)

        endpoints = base_data.get("endpoints", {})
        for path, endpoint_info in endpoints.items():
            # Endpoint keys are relative paths, never arbitrary URI schemes.
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
                non_relative_paths += 1
                if report is not None:
                    bucket = report.setdefault("resource_enum_path", {"admitted": 0, "rejected": {}})["rejected"]
                    bucket["not_relative_path"] = bucket.get("not_relative_path", 0) + 1
                continue
            if "{" in path:
                templated_paths += 1
                continue
            sources_present.update(
                s for s in (endpoint_info.get("sources") or [])
                if isinstance(s, str) and s
            )
            if report is not None:
                report.setdefault("resource_enum_path", {"admitted": 0, "rejected": {}})["admitted"] += 1
            url = _endpoint_url(base_url, path, endpoint_info)
            reason = "control_or_whitespace" if url is None else http_url_rejection(url)
            if reason:
                rejected_endpoints[reason] = rejected_endpoints.get(reason, 0) + 1
                continue
            if endpoint_info.get("declared_only") is True:
                methods = {str(m).upper() for m in endpoint_info.get("methods") or []}
                if methods & {"GET", "HEAD"}:
                    declared.append((base_url, path, url))
                elif declared_report is not None:
                    declared_report["declared_only_non_get_head"] = (
                        declared_report.get("declared_only_non_get_head", 0) + 1)
                continue
            endpoint_urls.append(url)

    declared.sort(key=lambda item: (item[0], item[1]))
    endpoint_urls.extend(url for _, _, url in declared[:MAX_DECLARED_NUCLEI_URLS])
    overflow = max(0, len(declared) - MAX_DECLARED_NUCLEI_URLS)
    if overflow:
        print(f"[-][OpenAPI] {overflow} declared endpoints not sent to nuclei (cap {MAX_DECLARED_NUCLEI_URLS})")
        openapi = resource_enum_data.get("openapi")
        groups = openapi.get("groups") if isinstance(openapi, dict) else None
        if groups:
            # This run's own group: a batch group's file holds only its own.
            groups[-1]["declared_not_sent_to_nuclei"] = overflow

    if declared_report is not None:
        declared_report["declared_only_total"] = (
            declared_report.get("declared_only_total", 0) + len(declared))
        declared_report["declared_only_get_head"] = (
            declared_report.get("declared_only_get_head", 0) + len(declared))
        declared_report["declared_only_admitted"] = (
            declared_report.get("declared_only_admitted", 0)
            + len(declared[:MAX_DECLARED_NUCLEI_URLS]))
        declared_report["declared_only_cap_dropped"] = (
            declared_report.get("declared_only_cap_dropped", 0) + overflow)
        declared_report["declared_only_cap"] = MAX_DECLARED_NUCLEI_URLS
        declared_report["templated_paths_skipped"] = (
            declared_report.get("templated_paths_skipped", 0) + templated_paths)
        declared_report["non_relative_paths_skipped"] = (
            declared_report.get("non_relative_paths_skipped", 0) + non_relative_paths)
        declared_report["sources_present"] = sorted(sources_present)
        declared_report["admitted_endpoints"] = len(endpoint_urls)
        declared_report["admitted_bases"] = len(base_urls)

    admit_http_urls(list(by_base_url), "resource_enum_base", report)
    if report is not None:
        report["resource_enum_endpoint"] = {"admitted": len(endpoint_urls), "rejected": rejected_endpoints}
    elif rejected_endpoints:
        print(f"[*][HTTP admission] resource_enum_endpoint: {rejected_endpoints}")
    return base_urls, endpoint_urls


# =============================================================================
# Combined URL Building
# =============================================================================

def _hosts_in_urls(urls: Set[str]) -> Set[str]:
    """Extract the set of lowercased hostnames present in a URL set."""
    hosts: Set[str] = set()
    for u in urls:
        try:
            host = urlparse(u).hostname
        except (ValueError, TypeError):
            continue
        if host:
            hosts.add(host.lower())
    return hosts


# Mock hostnames minted for IPs with no PTR record: recon/main.py replaces the
# separators with dashes ("192.88.99.10" -> "192-88-99-10", "fe80::1" ->
# "fe80--1"). They exist so the graph can label the host; they are NOT
# resolvable and must never reach a crawler. See build_target_urls source 3.
_MOCK_IPV4_RE = re.compile(r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$")


def _is_mock_ip_hostname(hostname: str) -> bool:
    """True when `hostname` is a dashed-IP placeholder rather than a real host.

    Deliberately narrow: only a label that is ENTIRELY digits and dashes (or
    hex and dashes, for IPv6) and that maps back to a valid IP literal. A real
    domain like "mail-01.example.com" contains dots and is never matched.
    """
    if not hostname or "." in hostname:
        return False
    candidate = hostname.strip().lower()
    if _MOCK_IPV4_RE.match(candidate):
        try:
            ipaddress.ip_address(candidate.replace("-", "."))
            return True
        except ValueError:
            return False
    # IPv6 placeholders: only hex digits and dashes, and round-trips to an IP.
    if candidate and all(c in "0123456789abcdef-" for c in candidate) and "-" in candidate:
        try:
            ipaddress.ip_address(candidate.replace("-", ":"))
            return True
        except ValueError:
            return False
    return False


def build_target_urls(
    hostnames: Set[str],
    ips: Set[str],
    recon_data: Optional[dict] = None,
    scan_all_ips: bool = False,
    admission_report: Optional[dict] = None,
    declared_report: Optional[dict] = None,
    ip_to_hostnames: Optional[Dict[str, List[str]]] = None,
) -> List[str]:
    """
    Build the list of target URLs for nuclei scanning as the UNION of every
    available source, deduplicated.

    Sources (all merged, none shadowed):
      1. Endpoint URLs from resource_enum (parameterized URLs, e.g. /api?q=1).
      2. BaseURL nodes from httpx (live URLs, e.g. https://A.com).
      3. http(s)://{hostname} for every hostname/subdomain whose host is NOT
         already represented by sources 1 or 2 (so newly-discovered subdomains
         that haven't been probed yet still get scanned).
      4. http(s)://{ip} for IPs not already covered, only if scan_all_ips=True.

    A hostname is "already covered" iff some URL in sources 1+2 has that exact
    hostname (httpx already picked the working scheme; re-scanning the other
    scheme would just waste rate-limit budget).

    Source 4 only ever iterates the DNS-derived ``ips`` set. The optional
    ``ip_to_hostnames`` mapping is accepted for backward-compatible call
    signatures but is deliberately NOT consulted: a mapping key is an address
    discovered for some hostname, not an extra target, and wiring it in would
    widen scope beyond the caller's own IP list.

    Args:
        hostnames: Set of hostnames/subdomains discovered via DNS.
        ips: Set of IPs discovered via DNS.
        recon_data: Full recon data dict with optional 'resource_enum' and
                    'http_probe' keys.
        scan_all_ips: Whether to include IP addresses (default False).
        admission_report: Syntax-admission dispositions, updated in place.
        declared_report: OpenAPI declared-only accounting, updated in place.
        ip_to_hostnames: Compatibility only; never used to widen the target set.

    Returns:
        Sorted, deduplicated list of URLs to scan.
    """
    url_set: Set[str] = set()
    admission = {}
    counts = {
        "resource_enum_base": 0,
        "resource_enum_endpoint": 0,
        "httpx": 0,
        "fallback_subdomain": 0,
        "fallback_ip": 0,
        "skipped_mock_hostname": 0,
    }

    # Source 1: resource_enum (BaseURLs + parameterized endpoint URLs)
    resource_enum_data = recon_data.get("resource_enum") if recon_data else None
    if resource_enum_data:
        base_urls, endpoint_urls = build_target_urls_from_resource_enum(
            resource_enum_data, admission, declared_report)
        for u in base_urls:
            if u not in url_set:
                url_set.add(u)
                counts["resource_enum_base"] += 1
        for u in endpoint_urls:
            if u not in url_set:
                url_set.add(u)
                counts["resource_enum_endpoint"] += 1

    # Source 2: httpx live URLs (BaseURLs verified by httpx)
    httpx_data = recon_data.get("http_probe") if recon_data else None
    if httpx_data:
        for u in build_target_urls_from_httpx(httpx_data, admission):
            if u not in url_set:
                url_set.add(u)
                counts["httpx"] += 1

    # Compute which hostnames sources 1+2 already cover (host-only match,
    # ignoring scheme/port/path) so we don't re-add them as fallback URLs.
    covered_hosts = _hosts_in_urls(url_set)

    # Source 3: hostnames not covered by httpx/resource_enum → both schemes.
    # This catches newly discovered subdomains that haven't been probed yet.
    for hostname in sorted(hostnames):
        if not hostname or hostname.lower() in covered_hosts:
            continue
        if http_url_rejection(f"http://{hostname}") is not None or any(c in hostname for c in '/?#@:'):
            reasons = admission.setdefault("fallback_hostname", {"admitted": 0, "rejected": {}})["rejected"]
            reasons["invalid_host"] = reasons.get("invalid_host", 0) + 1
            continue
        # Skip MOCK hostnames. When an IP has no PTR record, recon/main.py
        # labels it with the IP's dots turned into dashes ("192.88.99.10" ->
        # "192-88-99-10") so the graph has something to show. That label is a
        # DISPLAY ARTIFACT - it has no DNS record and never will.
        #
        # Handing it to the crawlers is not merely wasteful, it is destructive:
        # a non-resolving seed makes hakrawler return ZERO urls overall (not
        # merely zero for that seed) and collapses katana's stdout to zero
        # lines, while both still exit 0 with no stderr. Every real URL they
        # crawled is discarded. Bisected against the guinea pig on 2026-08-07:
        #
        #   real seeds only ............. katana 25, hakrawler 48
        #   + the two mock seeds ........ katana  0, hakrawler  0
        #
        # depth and crawl-duration were ruled out; the mock seeds alone flip it.
        # This hit EVERY IP-only target, silently, and downstream it looked
        # like "the target serves no JavaScript" - which in the supply-chain
        # pipeline reads as a clean bill of health.
        #
        # Nothing is lost by skipping them: the real IP URLs are already in the
        # set from httpx (source 2), and source 4 covers un-probed IPs.
        if _is_mock_ip_hostname(hostname):
            counts["skipped_mock_hostname"] += 1
            continue
        before = len(url_set)
        url_set.add(f"http://{hostname}")
        url_set.add(f"https://{hostname}")
        if len(url_set) > before:
            counts["fallback_subdomain"] += 1

    # Source 4: IPs not covered (opt-in). Only the caller's DNS-derived IP set
    # is scanned; mapping keys are never treated as extra target IPs.
    raw_ips = {ip for ip in (ips or set()) if isinstance(ip, str) and ip}
    covered_ips = {ip for ip in raw_ips if ip in covered_hosts}

    if scan_all_ips:
        # A shared edge address is skipped only when an EXACT-IP httpx probe
        # measured a proven Cloudflare 1003 error page on that same address.
        # A hostname-mapped observation must never be extrapolated to every
        # address sharing the CDN range: that would drop unrelated customers'
        # infrastructure along with the project's own host.
        by_url = (httpx_data or {}).get("by_url", {}) if isinstance(httpx_data, dict) else {}
        cf1003_ips = {
            (urlparse(u).hostname or "")
            for u, entry in by_url.items()
            if isinstance(entry, dict) and _observed_http_verdict(entry) is not None
        }
        error_ips = {ip for ip in raw_ips - covered_ips if ip in cf1003_ips}
        covered_ips |= error_ips
        if error_ips:
            print(f"[*][Targets] Skipped {len(error_ips)} shared CDN IP(s) serving edge error pages only")

        for ip in sorted(raw_ips):
            if not ip or ip in covered_ips:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                reasons = admission.setdefault("fallback_ip", {"admitted": 0, "rejected": {}})["rejected"]
                reasons["invalid_ip"] = reasons.get("invalid_ip", 0) + 1
                continue
            # IPv6 literals need brackets in URLs: http://[::1]/ not http://::1/.
            # An IPv6 contains ':' (IPv4 does not).
            ip_for_url = f"[{ip}]" if ":" in ip else ip
            before = len(url_set)
            url_set.add(f"http://{ip_for_url}")
            url_set.add(f"https://{ip_for_url}")
            if len(url_set) > before:
                counts["fallback_ip"] += 1

    parts = []
    if counts["resource_enum_base"]:
        parts.append(f"{counts['resource_enum_base']} resource_enum base URLs")
    if counts["resource_enum_endpoint"]:
        parts.append(f"{counts['resource_enum_endpoint']} endpoint URLs")
    if counts["httpx"]:
        parts.append(f"{counts['httpx']} additional httpx URLs")
    if counts["fallback_subdomain"]:
        parts.append(f"{counts['fallback_subdomain']} unprobed subdomains")
    if counts["fallback_ip"]:
        parts.append(f"{counts['fallback_ip']} unprobed IPs")

    if parts:
        print(f"[*][Targets] Merged {len(url_set)} URLs: " + " + ".join(parts))
    else:
        print(f"[*][Targets] No targets available")

    urls = sorted(set(admit_http_urls(sorted(url_set), "final_union", admission)))
    if admission_report is not None:
        admission_report.update(admission)
    for source, disposition in admission.items():
        if disposition["rejected"]:
            print(f"[*][HTTP admission] {source}: {disposition['rejected']}")
    return urls



# =============================================================================
# Discovered-hostname feedback (certificate SANs, JS-recon subdomains, ...)
# =============================================================================

def _is_valid_injected_hostname(hostname: str) -> bool:
    """Mirror of ``vhost_sni_enum._is_valid_hostname``.

    The ``\\Z`` anchor is load-bearing: Python's ``$`` also matches *before* a
    trailing newline, and the nuclei / subjack target files are newline
    delimited, so a newline embedded in a SAN would split one entry into two.
    """
    if not hostname or len(hostname) > 253:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)\Z", re.IGNORECASE)
    return all(allowed.match(label) for label in hostname.split("."))


def _resolver_down() -> bool:
    """True when the shared DNS resolver is already known down this run."""
    try:
        from recon.main_recon_modules.domain_recon import resolver_breaker
        return resolver_breaker.is_open()
    except Exception:  # noqa: BLE001
        return False


def _san_resolve_cache():
    """Per-run cache (a circuit_breaker RunCache) so the second SAN merge does
    not re-resolve the first's names (the two calls at main.py:1643,1753)."""
    try:
        from recon.helpers import circuit_breaker as cb
        return cb.run_cache("san_resolve")
    except Exception:  # noqa: BLE001
        return None


def _resolves_to_routable(hostname: str) -> bool:
    """Resolve-and-check for a SAN-derived name.

    Returns False when the name resolves to at least one non-routable address
    (the SSRF / scope-escape case we must drop), and while the resolver is
    known down: then the name cannot be checked, and httpx and Nuclei would
    resolve it themselves, so it is recorded as a skipped host and not
    injected. An unresolvable name returns True: it is in scope and cannot be
    an internal pivot; it simply will not be probed if nothing answers.
    """
    import socket
    from recon.main_recon_modules.ip_filter import is_non_routable_ip

    cache = _san_resolve_cache()
    if cache is not None:
        found, value = cache.get(hostname)
        if found:
            return value

    def _remember(result: bool) -> bool:
        if cache is not None:
            cache.put(hostname, result)
        return result

    # A resolver already proven down would make every getaddrinfo a timeout.
    # Fail closed, uncached: the resolver may recover and a later pass can
    # resolve the name.
    if _resolver_down():
        try:
            from recon.main_recon_modules.domain_recon import resolver_breaker
            resolver_breaker.note_skipped(hostname)
        except Exception:  # noqa: BLE001
            pass
        return False

    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return _remember(True)
    for info in infos:
        try:
            addr = info[4][0]
        except (IndexError, TypeError):
            continue
        if is_non_routable_ip(addr):
            return _remember(False)
    return _remember(True)


def injection_scope(recon_data: dict) -> Optional[dict]:
    """What a group lets a discovered name join (§4.6 hostname injection), from
    the recon dict's metadata, or None for a file written before scope_mode.

    ``{"mode": "exact"}`` admits nothing; ``{"mode": "enumerate", "scan_root",
    "include_root"}`` admits strict subdomains of the scan root, and the root
    itself only when it is a target.
    """
    metadata = (recon_data or {}).get("metadata") or {}
    mode = metadata.get("scope_mode")
    if mode not in ("exact", "enumerate"):
        return None
    return {"mode": mode,
            "scan_root": str(metadata.get("root_domain") or recon_data.get("domain") or "").lower(),
            "include_root": bool(metadata.get("include_root_domain"))}


def merge_discovered_hostnames(
    combined_result: dict,
    hostnames: list,
    source: str,
    root_domain=None,
    settings: Optional[dict] = None,
    max_injected: Optional[int] = None,
    scope: Optional[dict] = None,
) -> dict:
    """Merge discovered hostnames into ``dns.subdomains`` (the DICT shape read by
    ``extract_targets_from_recon``) + ``discovered_external_domains``, mirroring
    ``domain_recon``'s in-scope / out-of-scope split.

    SECURITY — a certificate SAN list is chosen by the scanned target, so every
    name here is attacker-influenced. Containment, in order:

      1. Apex-suffix allow-list: keep a name only if it equals ``root_domain`` or
         ends with ``"." + root_domain`` (``root_domain`` may be a list of roots,
         matched one by one). Every other name is recorded in
         ``discovered_external_domains`` and never becomes an active-scan target.
      2. RoE narrowing (``_filter_roe_excluded``) — additive, never sufficient
         on its own (it is off by default).
      3. Hostname syntax validation (``\\Z``-anchored; blocks newline injection
         into the newline-delimited target files).
      4. Resolve-and-check: drop any name resolving to a non-routable IP.
      5. Cap the injected count (``max_injected``).
      6. Wildcard DNS (``wildcard_control``): drop a name that answers only
         through its zone's wildcard. The zones checked are recorded in
         ``combined_result["wildcard_zones"]``.

    Fails closed: without ``root_domain`` nothing is injected (names are still
    recorded as external), because there is no apex to test against — e.g. batch
    mode, where ``metadata['root_domain']`` is deliberately empty (a joined
    string once became a literal scan target).

    ``scope`` (default: ``injection_scope(combined_result)``) narrows step 1 to
    the group's rule: an EXACT group injects nothing, since it scans exactly
    the hosts the operator listed; an ENUMERATE group injects strict
    subdomains of its scan root, and the root only when it is a target.
    """
    settings = settings or {}
    result = combined_result

    candidates = []
    seen = set()
    for h in hostnames or []:
        if not isinstance(h, str):
            continue
        name = h.strip().lower().lstrip("*.")
        if name and name not in seen:
            seen.add(name)
            candidates.append(name)

    external = result.setdefault("discovered_external_domains", [])
    existing_external = {e.get("domain") for e in external if isinstance(e, dict)}

    def _record_external(name):
        if name not in existing_external:
            external.append({"domain": name, "source": source})
            existing_external.add(name)

    roots = [root_domain] if isinstance(root_domain, str) else list(root_domain or [])
    roots = [r.strip().lower() for r in roots if isinstance(r, str) and r.strip()]

    # Fail closed without an apex to test against.
    if not roots:
        for name in candidates:
            _record_external(name)
        return result

    # 1. Apex-suffix split.
    in_scope = []
    for name in candidates:
        if any(name == root or name.endswith("." + root) for root in roots):
            in_scope.append(name)
        else:
            _record_external(name)

    # 1b. The group's own rule.
    if scope is None:
        scope = injection_scope(result)
    if scope is not None:
        before = len(in_scope)
        if scope["mode"] == "exact":
            in_scope = []
        else:
            sr = scope["scan_root"]
            in_scope = [n for n in in_scope
                        if n.endswith("." + sr) or (n == sr and scope["include_root"])]
        if before != len(in_scope):
            print(f"[*][{source}] {before - len(in_scope)} name(s) not injected: outside "
                  f"this group's {scope['mode']} scope")

    # 2. RoE narrowing pass.
    from recon.helpers.roe_scope import _filter_roe_excluded
    in_scope = _filter_roe_excluded(in_scope, settings, label="SAN hostname")

    # 3. Syntax validation.
    in_scope = [n for n in in_scope if _is_valid_injected_hostname(n)]

    # Deterministic order so the cap truncates reproducibly.
    in_scope = sorted(set(in_scope))

    # 4. Cap BEFORE resolving. Each resolve is a blocking getaddrinfo, and this
    # runs in GROUP 3.6, ahead of the HTTP probe: resolving every SAN a scan
    # collected (one multi-SAN cert per host, unbounded) would put an unbounded
    # number of sequential DNS timeouts on the pipeline's critical path. Capping
    # first bounds that work to max_injected lookups. The cost is that a name
    # dropped in step 5 does not free a slot for the next candidate; bounding
    # the stall is worth more than filling the quota exactly.
    if max_injected is not None and max_injected >= 0 and len(in_scope) > max_injected:
        dropped = len(in_scope) - max_injected
        print(f"[*][{source}] injected-hostname cap: kept {max_injected}, dropped {dropped}")
        in_scope = in_scope[:max_injected]

    # 5. Resolve-and-check (SAN-derived names only, never the port-scan list).
    in_scope = [n for n in in_scope if _resolves_to_routable(n)]

    # 6. Wildcard DNS: these names arrive after puredns, so they get RedAmon's
    # own check. A name that answers only through its zone's wildcard is no
    # evidence of a host.
    if in_scope:
        from recon.helpers import wildcard_control
        control = wildcard_control.filter_late_names(in_scope, roots, settings, label=source)
        in_scope = control.kept
        if control.zones:
            result.setdefault("wildcard_zones", {}).update(control.zones)

    # Merge in-scope names into dns.subdomains (the DICT shape). Only in-scope
    # names reach here, so the eventual HAS_SUBDOMAIN edge cannot promote a
    # foreign host to a permanent target (Phase 0.5 rule 5).
    dns = result.setdefault("dns", {})
    subs = dns.get("subdomains")
    if not isinstance(subs, dict):
        subs = {}
        dns["subdomains"] = subs
    injected = 0
    for name in in_scope:
        entry = subs.get(name)
        if not isinstance(entry, dict):
            entry = {}
            subs[name] = entry
        entry["has_records"] = True
        entry.setdefault("source", source)
        injected += 1
    if injected:
        print(f"[*][{source}] merged {injected} in-scope hostname(s) into dns.subdomains")
    return result


def collect_certificate_sans(combined_result: dict) -> list:
    """Every hostname named by a certificate already captured in memory.

    Phase 0.6: httpx grabs the full SAN list on every HTTPS port it probes and
    the pipeline never looked at it again, so names the target itself advertised
    were thrown away. Reads BOTH sources so the feedback path does not depend on
    tlsx being enabled (the Phase 1.0 rule):

      - http_probe.by_url[*].tls.certificate.san
      - tlsx.by_target[*].san

    Returns raw names (wildcards included); scoping, validation and the cap are
    ``merge_discovered_hostnames``'s job, not this one's.
    """
    names: set = set()

    by_url = ((combined_result.get("http_probe") or {}).get("by_url")) or {}
    for info in by_url.values():
        if not isinstance(info, dict):
            continue
        cert = ((info.get("tls") or {}).get("certificate")) or {}
        for san in cert.get("san") or []:
            if isinstance(san, str) and san.strip():
                names.add(san.strip().lower())
        cn = cert.get("subject_cn")
        if isinstance(cn, str) and cn.strip():
            names.add(cn.strip().lower())

    by_target = ((combined_result.get("tlsx") or {}).get("by_target")) or {}
    for entry in by_target.values():
        if not isinstance(entry, dict):
            continue
        for san in entry.get("san") or []:
            if isinstance(san, str) and san.strip():
                names.add(san.strip().lower())

    return sorted(names)
