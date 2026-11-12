"""
RedAmon - FFuf Directory Fuzzer Helpers for Resource Enumeration
================================================================
Active endpoint/directory discovery using FFuf (Fuzz Faster U Fool).
Brute-forces common directory and file paths using wordlists to find
hidden content that crawlers cannot discover (admin panels, backups,
configs, undocumented API endpoints).

Compiled from source via multi-stage Docker build (pure Go, no CGO).
"""

import json
import os
import random
import shutil
import subprocess
import time

from recon.helpers.subprocess_helpers import run_with_heartbeat
from recon.helpers.resource_enum.classification import classify_endpoint
import tempfile
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlsplit, urlunsplit
from recon.helpers.target_helpers import http_url_rejection, admit_http_urls


def _fuzz_single_target(
    idx: int,
    fuzz_url: str,
    output_dir: str,
    wordlist: str,
    threads: int,
    timeout: int,
    max_time: int,
    rate: int,
    match_codes: List[int],
    filter_codes: List[int],
    filter_size: str,
    extensions: List[str],
    recursion: bool,
    recursion_depth: int,
    auto_calibrate: bool,
    custom_headers: List[str],
    follow_redirects: bool,
    allowed_hosts: set,
) -> Tuple[List[Dict], List[Dict]]:
    """Run FFuf against a single fuzz target URL. Returns (results, external_entries)."""
    results = []
    external_entries = []
    output_file = os.path.join(output_dir, f"ffuf_result_{idx}.json")

    cmd = ["ffuf"]
    cmd.extend(["-u", fuzz_url])
    cmd.extend(["-w", wordlist])
    cmd.extend(["-t", str(threads)])
    cmd.extend(["-timeout", str(timeout)])
    cmd.extend(["-maxtime", str(max_time)])

    if rate > 0:
        cmd.extend(["-rate", str(rate)])

    if match_codes:
        cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])

    if filter_codes:
        cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])

    if filter_size:
        cmd.extend(["-fs", filter_size])

    if extensions:
        cmd.extend(["-e", ",".join(extensions)])

    if recursion:
        cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])

    if auto_calibrate:
        cmd.append("-ac")

    if follow_redirects:
        cmd.append("-r")

    for header in custom_headers:
        cmd.extend(["-H", header])

    # HTTP traffic capture (Phase 1): route through the capture proxy when
    # enabled + reachable; tag added ONLY in this branch (§20.2 no-leak).
    from helpers.proxy_routing import get_capture_routing
    _cap_url, _cap_token = get_capture_routing("ffuf")
    if _cap_url and _cap_token:
        cmd.extend(["-x", _cap_url, "-H", f"X-Redamon-Ctx: {_cap_token}"])

    cmd.extend(["-of", "json", "-o", output_file])
    cmd.extend(["-s"])  # Silent mode (no banner/progress)

    from recon.helpers.resource_enum import tool_health
    started = time.time()
    try:
        # Heartbeat every 30s while FFuf fuzzes -- otherwise the drawer goes
        # silent during long wordlist runs (FFuf -s suppresses its own progress).
        result = run_with_heartbeat(
            cmd,
            label="FFuf",
            interval=30,
            timeout=max_time + 60,
        )

        # No output file at all is an FFuf that never got to write one, not a
        # target with nothing to find (that writes a file with no results).
        if not os.path.exists(output_file):
            tool_health.report_empty("ffuf", tool_health.FAILURE, return_code=result.returncode,
                                     seeds=1, elapsed_s=time.time() - started, stderr=result.stderr)
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                try:
                    ffuf_output = json.load(f)
                except json.JSONDecodeError:
                    print(f"[!][FFuf] Failed to parse JSON output for {fuzz_url}")
                    tool_health.report_empty("ffuf", tool_health.FAILURE,
                                             return_code=result.returncode, seeds=1,
                                             elapsed_s=time.time() - started, stderr=result.stderr)
                    return results, external_entries

            for entry in ffuf_output.get("results", []):
                url = entry.get("url", "")
                if not url:
                    continue

                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or ''
                    if host and allowed_hosts and host not in allowed_hosts:
                        external_entries.append({
                            "domain": host, "source": "ffuf", "url": url,
                        })
                        continue
                except Exception:
                    continue

                results.append({
                    "url": url,
                    # ffuf reports a status for every matched response; when the
                    # producer's JSON omits it we keep None so a reader can tell
                    # "not measured" from a fabricated 200.
                    "status": entry.get("status"),
                    "length": entry.get("length", 0),
                    "words": entry.get("words", 0),
                    "lines": entry.get("lines", 0),
                    "content_type": entry.get("content-type", ""),
                    "redirect_location": entry.get("redirectlocation", ""),
                    "duration": entry.get("duration", 0),
                    "input_fuzz": entry.get("input", {}).get("FUZZ", ""),
                })
            if not results and not external_entries:
                tool_health.check_empty("ffuf", seeds=1, return_code=result.returncode,
                                        stderr=result.stderr, elapsed_s=time.time() - started)

    except subprocess.TimeoutExpired:
        print(f"[!][FFuf] Timeout exceeded for {fuzz_url}")
        tool_health.report_empty("ffuf", tool_health.FAILURE, return_code=None, seeds=1,
                                 elapsed_s=time.time() - started)
    except Exception as e:
        print(f"[!][FFuf] Error fuzzing {fuzz_url}: {e}")
        tool_health.report_empty("ffuf", tool_health.FAILURE, return_code=None, seeds=1,
                                 elapsed_s=time.time() - started)

    return results, external_entries


def run_ffuf_discovery(
    target_urls: List[str],
    wordlist: str,
    threads: int,
    rate: int,
    timeout: int,
    max_time: int,
    match_codes: List[int],
    filter_codes: List[int],
    filter_size: str,
    extensions: List[str],
    recursion: bool,
    recursion_depth: int,
    auto_calibrate: bool,
    custom_headers: List[str],
    follow_redirects: bool,
    allowed_hosts: set,
    discovered_base_paths: Optional[List[str]] = None,
    parallelism: int = 3,
    origin_plan: Optional[Dict[str, List[str]]] = None,
    extensions_by_origin: Optional[Dict[str, List[str]]] = None,
) -> Tuple[List[Dict], Dict]:
    """
    Run FFuf directory fuzzer against target URLs.

    Fuzzes from root (target/FUZZ) and optionally under discovered base paths
    (target/api/v1/FUZZ, etc.) for targeted discovery.

    Args:
        target_urls: Base URLs to fuzz (e.g., https://example.com)
        wordlist: Path to wordlist file inside the container
        threads: Number of concurrent threads
        rate: Max requests per second (0 = unlimited)
        timeout: Per-request timeout in seconds
        max_time: Overall max execution time in seconds
        match_codes: HTTP status codes to match (include in results)
        filter_codes: HTTP status codes to filter out (exclude from results)
        filter_size: Response size filter (e.g., "0" to exclude empty responses)
        extensions: File extensions to append (e.g., [".php", ".bak"])
        recursion: Enable recursive fuzzing
        recursion_depth: Maximum recursion depth
        auto_calibrate: Enable auto-calibration to filter false positives
        custom_headers: Custom HTTP headers
        follow_redirects: Follow HTTP redirects
        allowed_hosts: Set of in-scope hostnames
        discovered_base_paths: Base paths discovered by crawlers to fuzz under

    Returns:
        Tuple of (results_list, {"external_domains": [...]})
    """
    print(f"\n[*][FFuf] Running FFuf directory fuzzer...")
    print(f"[*][FFuf] Wordlist: {wordlist}")
    print(f"[*][FFuf] Threads: {threads}")
    print(f"[*][FFuf] Rate limit: {rate} req/s" if rate > 0 else "[*][FFuf] Rate limit: unlimited")
    print(f"[*][FFuf] Timeout: {timeout}s per request, {max_time}s max total")
    print(f"[*][FFuf] Auto-calibrate: {auto_calibrate}")
    if match_codes:
        print(f"[*][FFuf] Match status codes: {','.join(str(c) for c in match_codes)}")
    if filter_codes:
        print(f"[*][FFuf] Filter status codes: {','.join(str(c) for c in filter_codes)}")
    if extensions:
        print(f"[*][FFuf] Extensions: {','.join(extensions)}")
    if recursion:
        print(f"[*][FFuf] Recursion: depth {recursion_depth}")
    print(f"[*][FFuf] Target URLs: {len(target_urls)}")
    print(f"[*][FFuf] Parallelism: {parallelism} concurrent targets")

    all_results = []
    external_domain_entries = []

    # F11: ``origin_plan`` is the ownership planner's per-origin base-path map.
    # When it is present the executor never applies one origin's base path to
    # another origin's target; when it is absent the legacy global set is used
    # (the ``off``/``shadow`` execution path, kept for rollback).
    if origin_plan is not None:
        fuzz_targets = _build_origin_fuzz_targets(target_urls, origin_plan)
        plan_kind = "origin_ownership"
    else:
        fuzz_targets = _build_fuzz_targets(target_urls, discovered_base_paths)
        plan_kind = "legacy_global"
    print(f"[*][FFuf] Fuzz targets (root + base paths): {len(fuzz_targets)}")

    # Skip a fuzz target whose host another module already found unreachable:
    # ffuf otherwise burns its per-target max_time against a dead host. The skip
    # is noted per host (gap 'resource_enum'), so the prune keeps every finding
    # on that host; Endpoints are assets, which the prune never touches.
    from recon.helpers import circuit_breaker as _cb
    _scope = _cb.scope((), label="FFuf", unit="target(s)")
    fuzz_targets_built = len(fuzz_targets)
    before_skip = len(fuzz_targets)
    fuzz_targets = [u for u in fuzz_targets if not _scope.skip_if_down(u)]
    fuzz_targets_skipped = before_skip - len(fuzz_targets)

    output_dir = tempfile.mkdtemp(prefix="redamon_ffuf_")

    try:
        effective_threads = max(threads // max(parallelism, 1), 5)
        max_workers = min(parallelism, len(fuzz_targets)) if fuzz_targets else 1

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for idx, fuzz_url in enumerate(fuzz_targets):
                # F11: extensions are per origin, so an AI pick made for one
                # target is never replayed against a different origin. A target
                # whose origin has no entry keeps the caller's global list.
                target_extensions = extensions
                if extensions_by_origin:
                    target_extensions = list(
                        extensions_by_origin.get(origin_key(fuzz_url), extensions))
                future = executor.submit(
                    _fuzz_single_target,
                    idx, fuzz_url, output_dir, wordlist, effective_threads,
                    timeout, max_time, rate, match_codes, filter_codes,
                    filter_size, target_extensions, recursion, recursion_depth,
                    auto_calibrate, custom_headers, follow_redirects,
                    allowed_hosts
                )
                futures[future] = fuzz_url

            for future in as_completed(futures):
                try:
                    results, externals = future.result()
                    all_results.extend(results)
                    external_domain_entries.extend(externals)
                except Exception as e:
                    print(f"[!][FFuf] Error: {e}")

    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
        _scope.finish("resource_enum", host_source="resource_enum")

    unique_results = _deduplicate_results(all_results)
    print(f"[+][FFuf] Discovered {len(unique_results)} unique endpoints")
    if external_domain_entries:
        print(f"[+][FFuf] Filtered {len(external_domain_entries)} out-of-scope URLs")

    # F08: the run's own accounting, so the caller can persist the raw metadata
    # AFTER this temp directory is gone rather than reconstructing it.
    return unique_results, {
        "external_domains": external_domain_entries,
        "plan_kind": plan_kind,
        "origin_plan_origins": len(origin_plan) if origin_plan else 0,
        "extensions_by_origin": len(extensions_by_origin) if extensions_by_origin else 0,
        "fuzz_targets_built": fuzz_targets_built,
        "fuzz_targets_skipped_unreachable": fuzz_targets_skipped,
        "fuzz_targets_run": len(fuzz_targets),
        "results_raw": len(all_results),
        "results_unique": len(unique_results),
        "temp_output_removed": True,
    }


def origin_key(url: str) -> str:
    """`scheme://netloc` with userinfo stripped; the port is kept.

    Non-default ports are different origins (``https://a.test:8443`` is not
    ``https://a.test``), and userinfo is dropped so a credential never becomes
    part of a plan key or a manifest. Empty when the URL is not http(s).
    """
    try:
        parts = urlsplit(url)
    except (ValueError, TypeError):
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    netloc = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, "", "", ""))


def base_paths_of(path: str) -> set:
    """First one and two segments of an endpoint path, encoding preserved.

    The same rule the caller always used (a one-segment and a two-segment
    prefix), kept here so the planner and the executor cannot drift. ``%2f``
    stays ``%2f``: a decoded slash would invent a directory the target never
    showed.
    """
    parts = (path or "").strip("/").split("/")
    out = set()
    if len(parts) >= 2:
        out.add("/".join(parts[:2]))
    if parts and parts[0]:
        out.add(parts[0])
    return out


def directory_target(base_url: str, prefix: str = "") -> str:
    """Insert the directory placeholder before any query, preserving the rest.

    Split path/query before inserting ``FUZZ`` so a query context is kept (P0
    contract), path case/escapes and matrix parameters survive, and a fragment
    (client-only, never part of an HTTP request target) is dropped.
    """
    parsed = urlsplit(base_url)
    path = parsed.path.rstrip("/")
    if prefix:
        path += "/" + prefix
    return urlunsplit(parsed._replace(path=path + "/FUZZ", fragment=""))


def _build_fuzz_targets(
    target_urls: List[str],
    discovered_base_paths: Optional[List[str]] = None,
) -> List[str]:
    """
    Build the list of fuzz target URLs.

    For each target URL, creates:
    - Root fuzz: https://target.com/FUZZ
    - Base path fuzz: https://target.com/api/v1/FUZZ (from crawlers)

    LEGACY (F11): ``discovered_base_paths`` is one global set, so every base
    path is applied to every target -- a cross-product. Kept verbatim as the
    ``off``/``shadow`` execution path; the ownership planner builds the
    per-origin map and calls ``_build_origin_fuzz_targets`` instead.
    """
    fuzz_targets = []
    target_urls = admit_http_urls(target_urls, "ffuf_seed")

    for base_url in target_urls:
        fuzz_targets.append(directory_target(base_url))

    if discovered_base_paths:
        for base_url in target_urls:
            for path in discovered_base_paths:
                if not isinstance(path, str) or '?' in path or '#' in path:
                    continue
                path = path.strip('/')
                if not path:
                    continue
                target = directory_target(base_url, path)
                if http_url_rejection(target) is None:
                    fuzz_targets.append(target)

    # Deduplicate identical generated tasks, never different query contexts.
    return list(dict.fromkeys(fuzz_targets))


def _build_origin_fuzz_targets(
    target_urls: List[str],
    base_paths_by_origin: Dict[str, List[str]],
) -> List[str]:
    """Build fuzz targets from a PER-ORIGIN base-path map (F11 ownership).

    Every target keeps its own root task; the base paths applied to it are the
    ones its OWN origin showed in the inventory. A base path observed on a
    different origin is never applied here -- that is the cross-origin
    hypothesis lane, which the planner records and only an explicit opt-in
    executes. Identical generated tasks are deduplicated; different query
    contexts are not.
    """
    fuzz_targets: List[str] = []
    target_urls = admit_http_urls(target_urls, "ffuf_seed")

    for base_url in target_urls:
        fuzz_targets.append(directory_target(base_url))
        for path in base_paths_by_origin.get(origin_key(base_url), []):
            if not isinstance(path, str) or '?' in path or '#' in path:
                continue
            path = path.strip('/')
            if not path:
                continue
            target = directory_target(base_url, path)
            if http_url_rejection(target) is None:
                fuzz_targets.append(target)

    return list(dict.fromkeys(fuzz_targets))


def select_base_paths(
    base_paths: Iterable[str],
    cap: int,
    *,
    rng: Optional[random.Random] = None,
    ranker: Optional[Callable[[List[str], int], Optional[List[str]]]] = None,
) -> List[str]:
    """Pick up to `cap` base paths to smart-fuzz under. The single seam.

    Without a `ranker` the pick is a RANDOM sample: unbiased, where the old
    alphabetical cut systematically favoured early-letter dirs. A `ranker`
    (the Jev base-path hook) is asked only when the cap actually cuts; it gets
    the sorted candidates and the cap and returns its order, or None to keep
    the random pick. Its answer is filtered to real candidates, and any slot it
    leaves is filled from the random pick, so the result has exactly as many
    paths either way: a ranker changes which survive, never how many.

    Never raises: the full-pipeline caller has no guard around this call, and in
    partial recon a raise would leave smart fuzz off for the whole run.

    The input is sorted first only to give it a canonical order: `base_paths`
    is usually a set of strings, whose iteration order changes with every
    process's hash seed, so without it a seeded `rng` would still pick a
    different sample on every run.
    """
    if cap <= 0:
        return []
    items = sorted(base_paths)
    if len(items) <= cap:
        return items
    picker = rng or random
    if ranker is not None:
        try:
            ranked = ranker(list(items), cap)
        except Exception as e:  # noqa: BLE001 - a ranker failure is the random pick
            print(f"[!][FFuf] Base-path ranker failed ({type(e).__name__}) - using the random pick")
            ranked = None
        if ranked:
            known = set(items)
            chosen: List[str] = []
            for path in ranked:
                if isinstance(path, str) and path in known and path not in chosen:
                    chosen.append(path)
                if len(chosen) == cap:
                    return chosen
            if chosen:
                rest = [p for p in items if p not in set(chosen)]
                return chosen + picker.sample(rest, cap - len(chosen))
    return picker.sample(items, cap)


def _deduplicate_results(results: List[Dict]) -> List[Dict]:
    """Deduplicate results by URL."""
    seen = set()
    unique = []
    for r in results:
        url = r.get("url", "")
        if url and url not in seen:
            seen.add(url)
            unique.append(r)
    return unique


def merge_ffuf_into_by_base_url(
    ffuf_results: List[Dict],
    existing_by_base_url: Dict,
) -> Tuple[Dict, Dict]:
    """
    Merge FFuf discovery results into the existing by_base_url structure.

    Deduplicates against existing endpoints and tracks overlap.

    Args:
        ffuf_results: List of FFuf result dicts with url, status, etc.
        existing_by_base_url: Existing by_base_url from crawlers/jsluice

    Returns:
        Tuple of (merged by_base_url, stats dict)
    """
    stats = {
        "ffuf_total": len(ffuf_results),
        "ffuf_new": 0,
        "ffuf_overlap": 0,
    }

    for result in ffuf_results:
        url = result.get("url", "")
        if not url:
            continue

        try:
            parsed = urlparse(url)
        except Exception:
            continue

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        if base_url in existing_by_base_url:
            existing_endpoints = existing_by_base_url[base_url].get('endpoints', {})
            if path in existing_endpoints:
                stats["ffuf_overlap"] += 1
                existing_ep = existing_endpoints[path]
                sources = existing_ep.get('sources', [])
                if 'ffuf' not in sources:
                    sources.append('ffuf')
                    existing_ep['sources'] = sources
                continue

        stats["ffuf_new"] += 1

        if base_url not in existing_by_base_url:
            existing_by_base_url[base_url] = {
                'base_url': base_url,
                'endpoints': {},
                'summary': {
                    'total_endpoints': 0,
                    'total_parameters': 0,
                    'methods': {},
                    'categories': {},
                }
            }

        # ffuf's own measured status, kept as None when the producer's record
        # carries none: an unmeasured response is not a 200.
        status = result.get("status")
        method = "GET"
        # The shared word in `category` (what every module writes); ffuf's own
        # label, which Route Exposure reads for its 403 hint, in `ffuf_category`.
        ffuf_category = _classify_ffuf_endpoint(path, status, result.get("content_type", ""))
        category = classify_endpoint(path, [method], {})

        endpoint = {
            'methods': [method],
            'sources': ['ffuf'],
            'category': category,
            'ffuf_category': ffuf_category,
            'parameters': {'query': [], 'body': [], 'path': []},
            'parameter_count': {'query': 0, 'body': 0, 'path': 0, 'total': 0},
            'urls_found': 1,
            'sample_urls': [url],
            'ffuf_metadata': {
                'status': status,
                'length': result.get("length", 0),
                'words': result.get("words", 0),
                'lines': result.get("lines", 0),
                'content_type': result.get("content_type", ""),
            },
        }

        existing_by_base_url[base_url]['endpoints'][path] = endpoint
        summary = existing_by_base_url[base_url]['summary']
        summary['total_endpoints'] = len(existing_by_base_url[base_url]['endpoints'])
        summary['methods'][method] = summary['methods'].get(method, 0) + 1
        summary['categories'][category] = summary['categories'].get(category, 0) + 1

    return existing_by_base_url, stats


def _classify_ffuf_endpoint(path: str, status: Optional[int], content_type: str) -> str:
    """Classify an FFuf-discovered endpoint by path and response characteristics.

    ``status`` is None when ffuf's record carried no status: the path still
    classifies, and no status-derived label is invented for it.
    """
    path_lower = path.lower()

    if status in (301, 302, 307, 308):
        return "redirect"
    if status == 403:
        return "forbidden"

    admin_indicators = ['/admin', '/dashboard', '/manager', '/cpanel', '/wp-admin',
                        '/console', '/panel', '/control', '/backend']
    if any(ind in path_lower for ind in admin_indicators):
        return "admin"

    config_indicators = ['.env', '.config', '.ini', '.yml', '.yaml', '.xml',
                         '.properties', '.conf', 'web.config', '.htaccess']
    if any(ind in path_lower for ind in config_indicators):
        return "config"

    backup_indicators = ['.bak', '.old', '.backup', '.orig', '.save', '.swp',
                         '.copy', '.tmp', '.dist']
    if any(ind in path_lower for ind in backup_indicators):
        return "backup"

    api_indicators = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/',
                      '/json/', '/xml/']
    if any(ind in path_lower for ind in api_indicators):
        return "api"

    if '/login' in path_lower or '/auth' in path_lower or '/signin' in path_lower:
        return "auth"

    if content_type and 'application/json' in content_type:
        return "api"

    return "directory"


def pull_ffuf_binary_check() -> bool:
    """Verify ffuf binary is available in PATH."""
    try:
        result = subprocess.run(
            ["ffuf", "-V"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False
