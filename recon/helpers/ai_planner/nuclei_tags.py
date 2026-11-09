"""
Nuclei AI Tag Selector
======================
Replaces the static NUCLEI_TAGS list with a tech-aware tag set chosen by an
LLM based on the aggregated http_probe fingerprint (technologies + Server
headers).

The LLM call is delegated to the agent container's /llm/nuclei-tags endpoint
so the recon image stays free of LLM SDKs and per-user API keys live in one
place. Mirrors the FFuf AI extension planner.

All log lines use the `[symbol][Nuclei-AI]` format so they surface in the
recon drawer SSE stream.
"""

import json
import os
import re
from typing import Dict, List, Optional

import requests

from recon.helpers.ai_planner import agent_llm_gate, agent_jev_gate, internal_key_headers

TEMPLATES_STATS_PATH = '/opt/nuclei-templates-official/TEMPLATES-STATS.json'
MIN_TEMPLATE_COUNT = 50

TAG_REGEX = re.compile(r'^[a-z0-9-]{2,30}$')

HEAD_TIMEOUT = 5
HEAD_PROBE_LIMIT = 5
LLM_TIMEOUT = 30

_FALLBACK_CANDIDATES = (
    'cve', 'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'xxe', 'ssti',
    'oast', 'kev', 'exposure', 'misconfig', 'default-login',
    'unauth', 'auth-bypass', 'takeover',
    'wordpress', 'wp-plugin', 'joomla', 'drupal',
    'apache', 'nginx', 'iis', 'tomcat',
    'java', 'php', 'dotnet', 'nodejs',
    'aws', 'azure', 'gcp',
)

_candidates_cache: Optional[List[str]] = None


def _load_candidates() -> List[str]:
    global _candidates_cache
    if _candidates_cache is not None:
        return _candidates_cache
    try:
        with open(TEMPLATES_STATS_PATH) as f:
            stats = json.load(f)
        tags = [
            t['name']
            for t in stats.get('tags', [])
            if isinstance(t.get('name'), str)
            and t.get('count', 0) >= MIN_TEMPLATE_COUNT
            and TAG_REGEX.match(t['name'])
        ]
        _candidates_cache = sorted(set(tags))
        print(f"[*][Nuclei-AI] Loaded {len(_candidates_cache)} candidate tags from {TEMPLATES_STATS_PATH}")
    except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
        print(f"[!][Nuclei-AI] Could not load {TEMPLATES_STATS_PATH}: {e}. Using fallback list ({len(_FALLBACK_CANDIDATES)} tags).")
        _candidates_cache = list(_FALLBACK_CANDIDATES)
    return _candidates_cache


def _dedupe(items) -> List[str]:
    """Preserve first-occurrence order; skip non-strings and duplicates."""
    seen = set()
    out = []
    for t in items or []:
        if not isinstance(t, str) or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def policy_filtered_selection(current_tags, exclude_tags=None) -> List[str]:
    """The user selection after operator policy is applied.

    Dedupes (order-preserving) and drops every tag in ``exclude_tags``.
    This is the ONLY fallback shape and the universe the AI may prune
    within: pruning is a subset operation, never an expansion.
    """
    excluded = {t for t in (exclude_tags or []) if isinstance(t, str)}
    return [t for t in _dedupe(current_tags) if t not in excluded]


def _validate_tags(raw, candidates, allowed=None, excluded=None) -> List[str]:
    """Validate an AI-returned tag list as a PRUNING of the allowed set.

    A tag survives only if it is a string, matches TAG_REGEX, is in the
    candidate universe, AND -- when ``allowed`` is given -- is in
    ``allowed`` (the policy-filtered user selection). Tags in ``excluded``
    (operator NUCLEI_EXCLUDE_TAGS) are always dropped. Duplicates are
    coalesced, first occurrence wins. The result is therefore always a
    subset of ``allowed``: the model can remove tags, never add them.
    """
    candidate_set = set(candidates)
    allowed_set = set(allowed) if allowed is not None else None
    excluded_set = {t for t in (excluded or []) if isinstance(t, str)}
    out = []
    seen = set()
    for t in raw:
        if not isinstance(t, str) or t in seen:
            continue
        if t in excluded_set or not TAG_REGEX.match(t):
            continue
        if t not in candidate_set:
            continue
        if allowed_set is not None and t not in allowed_set:
            continue
        seen.add(t)
        out.append(t)
    return out


def selection_report(saved_tags, effective_tags, exclude_tags=None, ai_succeeded=False) -> dict:
    """Honest added/removed/effective accounting for one selection decision.

    ``effective_tags`` must already be clamped to a subset of the
    policy-filtered saved selection; ``added_tags`` is reported as
    whatever slipped through (callers assert it stays empty) so a future
    regression is visible in metadata instead of silently expanding.
    """
    saved = _dedupe(saved_tags)
    effective = _dedupe(effective_tags)
    policy_saved = policy_filtered_selection(saved, exclude_tags)
    effective_set = set(effective)
    saved_set = set(saved)
    removed = [t for t in saved if t not in effective_set]
    added = [t for t in effective if t not in saved_set]
    if added:
        reason = 'expansion_detected'
    elif effective == policy_saved and not ai_succeeded:
        reason = 'fallback_policy_filtered' if effective != saved else 'fallback_unchanged'
    elif effective_set <= set(policy_saved):
        reason = 'ai_pruned'
    else:
        reason = 'fallback_policy_filtered'
    return {
        'saved_tags': saved,
        'policy_saved_tags': policy_saved,
        'effective_tags': effective,
        'added_tags': added,
        'removed_tags': removed,
        'reason': reason,
        'exclude_tags': sorted({t for t in (exclude_tags or []) if isinstance(t, str)}),
    }


def get_ai_tags(
    tech_fingerprint: Dict[str, List[str]],
    current_tags: List[str],
    model: str,
    max_tags: int = 15,
    user_id: str = '',
    project_id: str = '',
    fallback_urls: Optional[List[str]] = None,
    engine: str = 'llm',
    settings: Optional[dict] = None,
    exclude_tags: Optional[List[str]] = None,
) -> List[str]:
    """
    Ask the agent to prune the Nuclei tag list to ones that match the detected
    tech stack. Never raises -- returns the policy-filtered ``current_tags``
    on any failure so the scan keeps running with the user's static list.

    PRUNING CONTRACT (F04): the returned list is always a subset of the
    policy-filtered user selection. Tags in ``exclude_tags`` (operator
    NUCLEI_EXCLUDE_TAGS) are removed after the AI decision, and any tag the
    model returns that the user did not already select is dropped -- the
    model may remove tags, never add them (no 'takeover', no tech tags, no
    out-of-whitelist tags). Empty/invalid AI output falls back to the
    policy-filtered user selection, never to a default-all list.

    Args:
        tech_fingerprint: Aggregated {"technologies": [...], "servers": [...]}
            from the http_probe (or from an opportunistic HEAD probe).
        current_tags: User's configured NUCLEI_TAGS, used as the safe fallback
            and as the upper bound for pruning.
        model: LLM model id (same format as agentOpenaiModel).
        max_tags: Cap on returned tags.
        user_id, project_id: Forwarded to the agent for per-user LLM key resolution.
        fallback_urls: Optional URL list to HEAD-probe when the fingerprint is
            empty (partial recon with bare user URLs).
        exclude_tags: Operator exclusion list applied to both the AI result
            and the fallback.

    Returns:
        Validated subset of the policy-filtered ``current_tags``, or that
        policy-filtered list itself if the AI was unhelpful.
    """
    _TAG = 'Nuclei-Jev' if engine == 'jev' else 'Nuclei-AI'
    # Operator policy is applied BEFORE the AI decision bounds the result:
    # the fallback and the pruning universe are the same policy-filtered list.
    policy_current = policy_filtered_selection(current_tags, exclude_tags)
    techs = list(tech_fingerprint.get('technologies') or [])
    servers = list(tech_fingerprint.get('servers') or [])

    if not techs and not servers and fallback_urls:
        probe_urls = fallback_urls[:HEAD_PROBE_LIMIT]
        print(f"[*][{_TAG}] No tech in fingerprint; probing {len(probe_urls)} URL(s) for headers...")
        for url in probe_urls:
            try:
                from recon.helpers.auth_profile import identity_header_dict, merge_identity_headers
                r = requests.head(url, allow_redirects=True, timeout=HEAD_TIMEOUT,
                                  headers=merge_identity_headers({}, identity_header_dict(settings)) or None)
                srv = (r.headers.get('Server') or '').lower().split('/')[0].strip()
                pwr = (r.headers.get('X-Powered-By') or '').lower().strip()
                if srv:
                    servers.append(srv)
                if pwr:
                    techs.append(pwr)
            except Exception as e:
                print(f"[!][{_TAG}] HEAD probe failed for {url}: {e}")
        if techs or servers:
            print(f"[*][{_TAG}] HEAD probe yielded servers={sorted(set(servers))} techs={sorted(set(techs))}")

    if not techs and not servers:
        print(f"[!][{_TAG}] No tech fingerprint available -- skipping AI call.")
        return policy_current

    candidates = _load_candidates()

    agent_api_url = os.environ.get('AGENT_API_URL', 'http://localhost:8090').rstrip('/')
    payload = {
        'technologies': sorted(set(techs)),
        'servers': sorted(set(servers)),
        'current_tags': policy_current,
        'candidates': candidates,
        'model': model,
        'max_tags': max_tags,
        'user_id': user_id,
        'project_id': project_id,
    }
    use_jev = engine == 'jev'
    route = 'jev' if use_jev else 'llm'
    endpoint = f"{agent_api_url}/{route}/nuclei-tags"
    print(f"[*][{_TAG}] Calling agent {endpoint} with model={model} ({len(payload['technologies'])} techs, {len(payload['servers'])} servers, {len(candidates)} candidates)")

    gate = agent_jev_gate() if use_jev else agent_llm_gate()
    if not gate.allowed:
        print(f"[!][{_TAG}] Agent LLM paused (breaker open) - using the fallback.")
        return policy_current
    try:
        resp = requests.post(endpoint, json=payload, headers=internal_key_headers(), timeout=LLM_TIMEOUT)
    except requests.RequestException as e:
        gate.record(exc=e)
        print(f"[!][{_TAG}] Agent request failed: {e}. Using policy-filtered tags as fallback.")
        return policy_current

    gate.record(resp=resp)
    if resp.status_code != 200:
        print(f"[!][{_TAG}] Agent returned HTTP {resp.status_code}: {resp.text[:200]}. Using policy-filtered tags as fallback.")
        return policy_current

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[!][{_TAG}] Agent returned non-JSON response: {e}. Using policy-filtered tags as fallback.")
        return policy_current

    raw = data.get('tags', None)
    if raw is None or not isinstance(raw, list):
        print(f"[!][{_TAG}] Agent response missing 'tags' list: {data}. Using policy-filtered tags as fallback.")
        return policy_current

    # Pruning, not selection: AI may only keep tags from the
    # policy-filtered user selection that are in the candidate universe.
    validated = _validate_tags(
        raw, candidates,
        allowed=policy_current,
        excluded=exclude_tags,
    )
    if len(validated) < len(raw):
        rejected = [t for t in raw if t not in validated]
        print(f"[!][{_TAG}] Rejected invalid/unselected/excluded tags: {rejected}")

    capped = validated[:max_tags]
    if not capped:
        print(f"[!][{_TAG}] Validation produced no usable tags. Using policy-filtered tags as fallback.")
        return policy_current

    return capped
