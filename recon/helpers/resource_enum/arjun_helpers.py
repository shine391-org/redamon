"""
RedAmon - Arjun Parameter Discovery Helpers for Resource Enumeration
=====================================================================
Active/passive HTTP parameter discovery using Arjun.
Tests common parameter names against endpoints to find hidden query/body
parameters (debug params, admin functionality, hidden API inputs).

Installed via pip (arjun>=2.2.7), runs as a subprocess.
"""

import json
import os
import signal
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Tuple
from urllib.parse import urlsplit

from .classification import classify_endpoint, classify_parameter, infer_parameter_type
from .arjun_contract import arjun_url_host, reconcile_arjun_schema
from recon.helpers.openapi.scope import _normalize_scope_host


def arjun_binary_check() -> bool:
    """Check if arjun binary is available on PATH."""
    if shutil.which('arjun'):
        print("[✓][Arjun] arjun binary found")
        return True
    print("[!][Arjun] arjun binary not found in PATH")
    return False


def _run_arjun_single_method(
    target_urls: List[str],
    method: str,
    threads: int,
    timeout: int,
    scan_timeout: int,
    chunk_size: int,
    rate_limit: int,
    stable: bool,
    passive: bool,
    disable_redirects: bool,
    custom_headers: List[str],
    allowed_hosts: Set[str],
    execution: Dict | None = None,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Run Arjun for a single HTTP method. Called in parallel by run_arjun_discovery().

    Returns:
        Tuple of (results_list, external_domains_list)
    """
    tmp_dir = tempfile.mkdtemp(prefix="redamon_arjun_")
    results = []
    external_domains = []
    execution = execution if execution is not None else {}
    execution.update(method=method, status='failed', input_count=len(target_urls),
                     timed_out=False, return_code=None, output_state='missing')

    from recon.helpers.resource_enum import tool_health
    started, stderr = time.time(), ""
    try:
        urls_file = os.path.join(tmp_dir, "urls.txt")
        output_file = os.path.join(tmp_dir, "results.json")

        with open(urls_file, 'w') as f:
            for url in target_urls:
                f.write(url + '\n')

        cmd = [
            'arjun',
            '-i', urls_file,
            '-oJ', output_file,
            '-m', method,
            '-t', str(threads),
            '-T', str(timeout),
            '-c', str(chunk_size),
        ]

        if rate_limit > 0:
            cmd.extend(['--rate-limit', str(rate_limit)])
        if stable:
            cmd.append('--stable')
        if passive:
            cmd.append('--passive')
        if disable_redirects:
            cmd.append('--disable-redirects')

        # HTTP traffic capture (Phase 1): arjun uses python-requests, so route it
        # via HTTP(S)_PROXY env + carry the tag in --headers. Both are set ONLY in
        # the routing branch (§20.2 no-leak).
        _cap_url, _cap_token = (None, None)
        try:
            from helpers.proxy_routing import get_capture_routing
            _cap_url, _cap_token = get_capture_routing("arjun")
        except Exception:
            pass
        _hdrs = [h.strip() for h in custom_headers if h.strip()]
        if _cap_url and _cap_token:
            _hdrs.append(f"X-Redamon-Ctx: {_cap_token}")
        headers_str = '\n'.join(_hdrs)
        if headers_str:
            cmd.extend(['--headers', headers_str])

        print(f"[*][Arjun/{method}] Scanning {len(target_urls)} URLs...")

        env = os.environ.copy()
        if _cap_url and _cap_token:
            env["HTTP_PROXY"] = _cap_url
            env["HTTPS_PROXY"] = _cap_url

        stdout, stderr = "", ""
        timed_out = False
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )

        try:
            stdout, stderr = proc.communicate(timeout=scan_timeout + 60)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Graceful shutdown: SIGTERM first, give Arjun time to flush output
            try:
                proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=10)
            except (subprocess.TimeoutExpired, ProcessLookupError, OSError):
                # Process didn't exit gracefully or already dead — force kill
                try:
                    proc.kill()
                except (ProcessLookupError, OSError):
                    pass
                proc.communicate()
            print(f"[!][Arjun/{method}] Timed out after {scan_timeout}s — collecting partial results")
        else:
            if proc.returncode != 0 and stderr:
                stderr_lines = stderr.strip().split('\n')
                for line in stderr_lines[-3:]:
                    print(f"[!][Arjun/{method}] {line}")

        execution.update(timed_out=timed_out, return_code=proc.returncode,
                         status='partial' if timed_out or proc.returncode != 0 else 'complete')
        # Parse output file (full results or partial after graceful shutdown)
        if not os.path.exists(output_file):
            if not timed_out:
                print(f"[-][Arjun/{method}] No parameters found")
            else:
                print(f"[-][Arjun/{method}] No partial results saved before timeout")
            # A crash also leaves no file: the exit code and stderr tell it apart.
            return [], []

        with open(output_file, 'r') as f:
            content = f.read().strip()
            if not content:
                if not timed_out:
                    print(f"[-][Arjun/{method}] No parameters found")
                else:
                    print(f"[-][Arjun/{method}] Output file empty after timeout")
                return [], []

        try:
            arjun_output = json.loads(content)
            execution['output_state'] = 'parsed'
        except json.JSONDecodeError:
            execution.update(status='partial', output_state='malformed')
            # Recover complete URL records only. Never invent a parameter name by
            # closing a truncated string/array. A kill can occur without TimeoutExpired.
            arjun_output = {}
            decoder = json.JSONDecoder()
            offset = 1 if content.startswith('{') else len(content)
            while offset < len(content):
                try:
                    while content[offset:offset + 1] in (' ', '\n', '\r', '\t', ','):
                        offset += 1
                    key, offset = decoder.raw_decode(content, offset)
                    while content[offset:offset + 1].isspace():
                        offset += 1
                    if content[offset:offset + 1] != ':':
                        break
                    offset += 1
                    while content[offset:offset + 1].isspace():
                        offset += 1
                    value, offset = decoder.raw_decode(content, offset)
                    arjun_output[key] = value
                except (ValueError, TypeError, IndexError):
                    break
            if arjun_output:
                execution['output_state'] = 'salvaged'

        if not isinstance(arjun_output, dict):
            execution.update(status='failed', output_state='invalid_schema')
            return [], []

        total_params = 0
        for url, url_data in arjun_output.items():
            if not isinstance(url_data, dict):
                execution['status'] = 'partial'
                continue
            params = url_data.get('params', [])
            if not isinstance(params, list) or any(not isinstance(p, str) or not p for p in params):
                execution['status'] = 'partial'
                continue
            params = list(dict.fromkeys(params))
            # The subprocess invocation, not untrusted output, proves the method.
            discovered_method = method
            if not params:
                continue
            host = arjun_url_host(url)
            if not host:
                execution['status'] = 'partial'
                continue

            if host not in {_normalize_scope_host(h) for h in allowed_hosts}:
                external_domains.append({
                    "domain": host,
                    "source": "arjun",
                    "url": url,
                })
                continue

            results.append({
                "url": url,
                "params": params,
                "method": discovered_method,
                "execution_status": execution["status"],
            })
            total_params += len(params)

        if timed_out and total_params > 0:
            print(f"[+][Arjun/{method}] Recovered {len(results)} URLs with params, {total_params} params from partial scan")
        elif timed_out:
            print(f"[-][Arjun/{method}] No parameters found before timeout")
        else:
            print(f"[+][Arjun/{method}] {len(results)} URLs with params, {total_params} params discovered")

    except Exception as e:
        execution.update(status="failed", error_class=type(e).__name__)
        print(f"[!][Arjun/{method}] Error: {e}")
    finally:
        if not results or execution['status'] != 'complete':
            verdict = tool_health.check_empty("arjun", seeds=len(target_urls),
                                              return_code=execution['return_code'], stderr=stderr,
                                              elapsed_s=time.time() - started,
                                              timed_out=execution['timed_out'],
                                              raised=execution['status'] != 'complete')
            if verdict in (tool_health.FAILURE, tool_health.UNDECIDED):
                execution['status'] = 'partial'
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass

    for result in results:
        result["execution_status"] = execution["status"]
    return results, external_domains


def run_arjun_discovery(
    target_urls: List[str],
    methods: List[str],
    threads: int,
    timeout: int,
    scan_timeout: int,
    chunk_size: int,
    rate_limit: int,
    stable: bool,
    passive: bool,
    disable_redirects: bool,
    custom_headers: List[str],
    allowed_hosts: Set[str],
) -> Tuple[List[Dict], Dict]:
    """
    Run Arjun parameter discovery against target URLs with multiple methods in parallel.

    Each method (GET, POST, JSON, XML) runs as a separate Arjun subprocess
    via ThreadPoolExecutor. Results from all methods are merged.

    Args:
        target_urls: Full endpoint URLs to test (e.g., https://example.com/api/users)
        methods: List of HTTP methods to test (GET, POST, JSON, XML)
        threads: Number of concurrent threads per Arjun process
        timeout: Per-request timeout in seconds
        scan_timeout: Overall scan timeout per method in seconds
        chunk_size: Number of parameters per request batch
        rate_limit: Max requests per second (0 = unlimited)
        stable: Enable stable mode (random delays for WAF evasion)
        passive: Use passive sources only (no active requests)
        disable_redirects: Do not follow HTTP redirects
        custom_headers: Custom HTTP headers to include
        allowed_hosts: Set of in-scope hostnames

    Returns:
        Tuple of (results_list, metadata_dict)
    """
    if not target_urls:
        print("[-][Arjun] No target URLs provided")
        return [], {"external_domains": []}

    normalized_hosts = {_normalize_scope_host(h) for h in allowed_hosts} - {''}
    supplied_count = len(target_urls)
    target_urls = [u for u in target_urls if arjun_url_host(u) and arjun_url_host(u) in normalized_hosts]
    rejected_inputs = supplied_count - len(target_urls)
    if not target_urls:
        return [], {"external_domains": [], "execution": [], "status": "not_executed",
                    "rejected_inputs": rejected_inputs, "coverage_scope": "selected_inputs"}
    if not methods:
        methods = ['GET']
    methods = list(dict.fromkeys(str(m).upper() for m in methods))
    if any(m not in ('GET', 'POST', 'JSON', 'XML') for m in methods):
        return [], {"external_domains": [], "execution": [], "status": "not_executed",
                    "reason": "unsupported_method", "coverage_scope": "selected_inputs"}

    print(f"\n[*][Arjun] Starting parameter discovery on {len(target_urls)} endpoints")
    print(f"[*][Arjun] Methods: {', '.join(methods)} ({'parallel' if len(methods) > 1 else 'single'})")
    if passive:
        print("[*][Arjun] Mode: PASSIVE (CommonCrawl/OTX/WaybackMachine only)")

    all_results = []
    all_external_domains = []
    executions = {method: {"method": method, "status": "failed"} for method in methods}

    if len(methods) == 1:
        # Single method — run directly, no thread overhead
        results, ext = _run_arjun_single_method(
            target_urls, methods[0], threads, timeout, scan_timeout,
            chunk_size, rate_limit, stable, passive, disable_redirects,
            custom_headers, allowed_hosts, executions[methods[0]],
        )
        all_results.extend(results)
        all_external_domains.extend(ext)
    else:
        # Multiple methods — run in parallel
        with ThreadPoolExecutor(max_workers=len(methods)) as executor:
            futures = {}
            for method in methods:
                futures[method] = executor.submit(
                    _run_arjun_single_method,
                    target_urls, method, threads, timeout, scan_timeout,
                    chunk_size, rate_limit, stable, passive, disable_redirects,
                    custom_headers, allowed_hosts, executions[method],
                )

            for method, future in futures.items():
                try:
                    results, ext = future.result(timeout=scan_timeout + 120)
                    all_results.extend(results)
                    all_external_domains.extend(ext)
                except Exception as e:
                    print(f"[!][Arjun/{method}] Failed: {e}")

    total_params = sum(len(r['params']) for r in all_results)
    print(f"[+][Arjun] Total: {len(all_results)} URLs with params, {total_params} params across {len(methods)} method(s)")
    if all_external_domains:
        print(f"[*][Arjun] Filtered {len(all_external_domains)} out-of-scope results")

    return all_results, {"external_domains": all_external_domains,
                         "execution": list(executions.values()),
                         "coverage_scope": "selected_inputs", "rejected_inputs": rejected_inputs,
                         "status": "complete" if not rejected_inputs and all(e['status'] == 'complete' for e in executions.values()) else "partial"}


def merge_arjun_into_by_base_url(
    arjun_results: List[Dict],
    by_base_url: Dict,
    allowed_hosts: Set[str] | None = None,
) -> Tuple[Dict, Dict[str, int]]:
    """
    Merge Arjun parameter discovery results into existing by_base_url structure.

    Unlike Kiterunner/FFuf which discover endpoints, Arjun discovers **parameters**
    on endpoints. It enriches existing endpoints with new params AND creates new
    endpoints when the URL wasn't previously known.

    Args:
        arjun_results: List of result dicts from run_arjun_discovery()
        by_base_url: Existing by_base_url structure from crawlers/fuzzers

    Returns:
        Tuple of (updated by_base_url, merge stats)
    """
    stats = {"arjun_total": len(arjun_results), "arjun_new_endpoints": 0,
             "arjun_existing_enriched": 0, "arjun_params_discovered": 0}
    for result in arjun_results:
        url = result.get('url', '')
        params = result.get('params', [])
        mode = str(result.get('method', 'GET')).upper()
        if not arjun_url_host(url) or not isinstance(params, list) or not params:
            continue
        if mode not in ('GET', 'POST', 'JSON', 'XML'):
            continue
        params = list(dict.fromkeys(p for p in params if isinstance(p, str) and p))
        if not params:
            continue
        if allowed_hosts is not None and arjun_url_host(url) not in {_normalize_scope_host(h) for h in allowed_hosts}:
            continue
        parsed = urlsplit(url)
        base, path = f"{parsed.scheme}://{parsed.netloc}", parsed.path or '/'
        position = 'body' if mode in ('POST', 'JSON', 'XML') else 'query'
        method = 'POST' if mode in ('JSON', 'XML') else mode
        base_data = by_base_url.setdefault(base, {'base_url': base, 'endpoints': {}})
        endpoints = base_data.setdefault('endpoints', {})
        is_new = path not in endpoints
        endpoint = endpoints.setdefault(path, {
            'methods': [], 'parameters': {'query': [], 'body': [], 'path': []},
            'sources': [],
        })
        sources = endpoint.setdefault('sources', [])
        old_source = endpoint.pop('source', None)
        if old_source and old_source not in sources:
            sources.append(old_source)
        if 'arjun' not in sources:
            sources.append('arjun')
        if method not in endpoint.setdefault('methods', []):
            endpoint['methods'].append(method)
        buckets = endpoint.setdefault('parameters', {})
        for key in ('query', 'body', 'path'):
            buckets.setdefault(key, [])
        existing = {p['name']: p for p in buckets[position]}
        added = 0
        for name in params:
            if name not in existing:
                info = {'name': name, 'arjun_only': True, 'type': infer_parameter_type(name, []),
                        'sample_values': [], 'category': classify_parameter(name)}
                buckets[position].append(info)
                existing[name] = info
                added += 1
            info = existing[name]
            # Location is the legacy bucket; method/mode are additive evidence,
            # never a claim that POST parameters were tested on the GET variant.
            for key, value in (('arjun_methods', method), ('arjun_modes', mode)):
                if value not in info.setdefault(key, []):
                    info[key].append(value)
        evidence = {'url': url, 'method': method, 'mode': mode,
                    'position': position, 'params': params,
                    'execution_status': result.get('execution_status', 'unknown')}
        if evidence not in endpoint.setdefault('arjun_evidence', []):
            endpoint['arjun_evidence'].append(evidence)
        endpoint.setdefault('category', classify_endpoint(path, endpoint['methods'], buckets))
        stats['arjun_params_discovered'] += added
        stats['arjun_new_endpoints'] += int(is_new)
        stats['arjun_existing_enriched'] += int(not is_new and added > 0)
    reconcile_arjun_schema(by_base_url)
    return by_base_url, stats
