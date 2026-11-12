"""Planner consumers at the Nuclei dispatch boundary.

Only admitted legacy URLs are eligible. No consumer discovers targets or enables
DAST; shadow computes local evidence only and never invokes an AI/HTTP helper.
Unsupported request transports and incomplete plans retain legacy execution.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

from recon.helpers.planner_manifest import (
    consumer_enabled, resolve_mode, _job_context, MANIFEST_MAX_TASKS,
    maybe_write_pre_dispatch_manifest, publish_plan_pointer, KEY,
)
from recon.helpers.scan_planner import plan_for_settings, _endpoint_for, _endpoint_methods, _endpoint_body
from recon.helpers.template_classification import TemplateCategory


def enforcing(settings, consumer):
    return resolve_mode(settings) == 'enforce' and consumer_enabled(settings, consumer)


def routing_compatibility_reason(settings):
    """Conditions whose CLI selection/mount semantics must remain indivisible."""
    explicit = (settings.get('NUCLEI_TEMPLATES') or settings.get('NUCLEI_CUSTOM_TEMPLATES')
                or settings.get('NUCLEI_SELECTED_CUSTOM_TEMPLATES'))
    if settings.get('NUCLEI_CUSTOM_TEMPLATES') or settings.get('NUCLEI_SELECTED_CUSTOM_TEMPLATES'):
        return 'custom template mount mapping requires legacy builder'
    if explicit and settings.get('NUCLEI_TAGS'):
        return 'combined path/tag inclusion policy requires indivisible legacy selection'
    if settings.get('NUCLEI_NEW_TEMPLATES_ONLY'):
        return 'new-template loader selection requires legacy builder'
    return None


def exact_unique(urls):
    """Never normalize query encoding, ordering, method or auth variants."""
    return list(dict.fromkeys(urls))


def plan_dispatch(settings, target_urls, dast_urls, *, tags, templates,
                  custom_templates, selected_custom_templates, inventory=None):
    """Return detailed plans and conservative executable consumer decisions.

    Origin-safe routing only prunes to an origin already in the admitted list;
    it cannot manufacture a new URL. All other semantics, missing origins,
    body/raw/multi-step transports and bounded/oversize plans use compatibility.
    Two-pass admits method/body-compatible DAST inputs and removes exact
    duplicates only; checks are never removed across distinct template passes.
    """
    refs = list(templates or []) + list(custom_templates or []) + list(selected_custom_templates or [])
    refs += list(tags or [])
    # An absent selection is an explicit deferred task, not default-all.
    plan = plan_for_settings(settings, refs or [''], target_urls, inventory=inventory)
    dast_plan = plan_for_settings(settings, ['dast:engine-policy-selection'], dast_urls,
                                  inventory=inventory) if dast_urls else None
    targets = list(target_urls)
    dast = list(dast_urls)
    decisions = {}
    for consumer in ('ai_tags', 'target_selection', 'two_pass'):
        decisions[consumer] = {
            'enabled': consumer_enabled(settings, consumer),
            'executing': enforcing(settings, consumer),
            'reason': 'enforce opt-in' if enforcing(settings, consumer) else 'legacy execution (off, shadow or consumer disabled)',
        }
    if enforcing(settings, 'two_pass'):
        targets, dast = exact_unique(targets), exact_unique(dast)
    deferred_dast = []
    deferred_paths = set()
    if enforcing(settings, 'two_pass'):
        kept = []
        for url in dast:
            parsed = urlsplit(url)
            endpoint = _endpoint_for(f'{parsed.scheme}://{parsed.netloc}', parsed.path or '/', inventory)
            methods = _endpoint_methods(endpoint)
            # URL-list DAST cannot reproduce body-only/non-GET requests. Do
            # not invent a GET observation from their schema or mark clean.
            if (methods and 'GET' not in methods) or _endpoint_body(endpoint):
                deferred_paths.add((f'{parsed.scheme}://{parsed.netloc}', parsed.path or '/'))
                deferred_dast.append({'input_sha256': hashlib.sha256(url.encode()).hexdigest(),
                                      'reason': 'unsupported DAST URL transport: method/body evidence'})
            else:
                kept.append(url)
        dast = kept
    decisions['two_pass'].update({
        'detection_duplicates_removed': len(target_urls) - len(targets),
        'dast_duplicates_removed': len(dast_urls) - len(exact_unique(dast_urls)) if enforcing(settings, 'two_pass') else 0,
        'deferred': deferred_dast,
        'deferred_count': len(deferred_dast),
        'reason': 'method/body admission for the enabled DAST pass and exact duplicate removal; no cross-pass equivalence assumed',
    })
    # The plan tasks carry provenance/category. Build per-reference batches;
    # never interpret a truncated plan as proof that the omitted work is absent.
    routed = None
    if enforcing(settings, 'target_selection') and refs and not plan.oversize:
        categories = {}
        for task in plan.tasks:
            categories.setdefault(task.template, set()).add(
                task.template_category if task.disposition.value == 'planned' else 'unknown')
        origin_targets = []
        complete_origins = True
        for url in targets:
            parts = urlsplit(url)
            origin = f'{parts.scheme}://{parts.netloc}'
            # A trailing slash remains distinct. Choose only a present spelling.
            candidate = origin if origin in targets else origin + '/'
            if candidate not in targets:
                complete_origins = False
                break
            if candidate not in origin_targets:
                origin_targets.append(candidate)
        origin_refs = {ref for ref, cats in categories.items()
                       if cats == {TemplateCategory.ORIGIN_SAFE.value} and complete_origins
                       and (ref in ('ssl', 'tls', 'certificate') or ref.startswith(('ssl/', 'tls/', 'certificate/')))}
        by_category = {cat.value: [] for cat in TemplateCategory}
        for ref in refs:
            key = TemplateCategory.ORIGIN_SAFE.value if ref in origin_refs else TemplateCategory.UNKNOWN.value
            # Preserve how the operator selected the template; custom paths
            # are kept in compatibility by the caller until mount mapping is known.
            by_category[key].append(f'tag:{ref}' if ref in (tags or []) else ref)
        routed = {
            'by_category': by_category,
            'target_sets': {cat.value: origin_targets if cat == TemplateCategory.ORIGIN_SAFE else targets
                            for cat in TemplateCategory},
            'compatibility_templates': by_category['unknown'],
            'routing_metadata': {'source': 'scan_planner', 'origin_safe_references': len(origin_refs),
                                 'compatibility_references': len(by_category['unknown'])},
        }
        decisions['target_selection']['reason'] = 'planner origin-safe subset; all unproved semantics retain admitted legacy targets'
    elif enforcing(settings, 'target_selection'):
        decisions['target_selection']['reason'] = 'compatibility: absent selection or bounded plan; no pruning'
    compatibility_reason = routing_compatibility_reason(settings)
    if compatibility_reason or settings.get('AUTH_PROFILE'):
        routed = None
        decisions['target_selection']['reason'] = 'compatibility: ' + (compatibility_reason or 'authenticated transport requires legacy builder')
    summaries = [dict(task, pass_name='detection') for task in plan.manifest['tasks']]
    if dast_plan:
        for task in dast_plan.manifest['tasks']:
            summary = dict(task, pass_name='dast')
            if (task['origin'], task['path']) in deferred_paths:
                summary.update(disposition='deferred', reason='unsupported DAST URL transport: method/body evidence')
            summaries.append(summary)
    all_counts = {key: 0 for key in plan.disposition_counts()}
    dast_counts = {key: 0 for key in all_counts} if dast_plan else None
    for task in summaries:
        all_counts[task['disposition']] += 1
        if task['pass_name'] == 'dast':
            dast_counts[task['disposition']] += 1
    details = {
        'plan_id': plan.plan_id,
        'disposition_counts': all_counts,
        'input_count': plan.input_count,
        'template_count': plan.template_count,
        'task_count': len(summaries),
        'oversize': plan.oversize or bool(dast_plan and dast_plan.oversize) or len(summaries) > MANIFEST_MAX_TASKS,
        'consumers': decisions,
        'selection': {'detection_inputs': len(targets), 'dast_inputs': len(dast),
                      'effective_tags': list(tags or []),
                      'template_reference_count': len(refs),
                      'detection_disposition_counts': plan.disposition_counts(),
                      'dast_disposition_counts': dast_counts},
        'inventory': {'available': isinstance(inventory, dict),
                      'source': 'resource_enum' if isinstance(inventory, dict) else None,
                      'semantics': 'missing evidence is compatibility, not not-applicable'},
    }
    if deferred_dast:
        # Keep the originally planned inputs visible even when not dispatched.
        details['selection']['deferred_dast_count'] = len(deferred_dast)
    return targets, dast, routed, summaries, details


def persist_dispatch(settings, recon_data, output_file, summaries, details,
                     target_urls, dast_urls):
    """Write and index before dispatch; merge only pointer under artifact lock.

    Context is supplied by the actual job caller. Missing group context never
    invents a group and never writes a project-wide or random-run manifest.
    """
    if not settings.get('PLANNER_MANIFEST_ENABLED'):
        return None
    from recon.helpers.selection_coverage import ARTIFACT_SAVE_LOCK
    from recon.helpers.atomic_io import atomic_write_json
    # Hash actual built executable inputs, not upstream raw observations.
    inputs = json.dumps({'detection': target_urls, 'dast': dast_urls}, separators=(',', ':'))
    with ARTIFACT_SAVE_LOCK:
        pointer = maybe_write_pre_dispatch_manifest(
            settings, output_file, task_summaries=summaries,
            input_hashes={'dispatch_sha256': hashlib.sha256(inputs.encode()).hexdigest()},
            input_count=len(target_urls) + len(dast_urls),
            reason='actual Nuclei dispatch boundary', plan_details=details,
        )
        if pointer is None:
            return None
        recon_data[KEY] = copy.deepcopy(pointer)
        if output_file:
            try:
                path = Path(output_file)
                data = json.loads(path.read_text()) if path.exists() else {}
                if not isinstance(data, dict):
                    data = {}
                data[KEY] = pointer
                atomic_write_json(path, data)
            except Exception:
                # The manifest/index remain durable; a pointer merge is not a
                # reason to destroy evidence or fail a scan.
                pass
    publish_plan_pointer(pointer, settings,
                         kind='partial_recon' if _job_context(settings)['group_id'].startswith('partial:') else 'full_recon')
    return pointer
