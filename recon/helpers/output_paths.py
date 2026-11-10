"""
Where a recon run writes its JSON, and how a Domain batch merges its groups.

A single-domain or IP run keeps today's path exactly: `recon_<project_id>.json`.
A Domain batch writes one file per group and then rebuilds that canonical file as
the union of them, because everything downstream reads the canonical name and
nothing else knows about groups: the orchestrator's results and export endpoints,
the project export archive, and the GVM scanner, which refuses to start without it.

The merge runs after EVERY group, not once at the end. A batch that is stopped
half way then still leaves a canonical file that parses and describes the groups
that did finish, instead of whatever the last completed group happened to write.
"""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Optional

# The same charset the webapp and the orchestrator enforce. A group slug becomes a
# path component, so this is the last line of defence against a hostname that was
# edited straight into the database rather than through the form.
_SLUG_SAFE = re.compile(r'[^a-z0-9.-]')

#: Keys whose merge is not a generic dict/list fold. The Domain batch runs one
#: plan per group; the canonical artifact must describe the whole batch, so
#: these are combined explicitly instead of first-group-wins.
from recon.helpers.selection_coverage import KEY as SELECTION_KEY, merge_plans  # noqa: E402
_SPECIAL_MERGE_KEYS = (SELECTION_KEY,)

BATCH_SEPARATOR = '__'


def group_slug(root_domain: str) -> str:
    """Filesystem-safe name for one group's output file."""
    slug = _SLUG_SAFE.sub('_', (root_domain or '').strip().lower())
    slug = re.sub(r'\.\.+', '_', slug).strip('.-_')
    return slug if re.search(r'[a-z0-9]', slug) else 'group'


def canonical_output_file(output_dir: Path, project_id: str) -> Path:
    """The one path every downstream reader knows about."""
    return Path(output_dir) / f"recon_{project_id}.json"


def recon_output_file(output_dir: Path, project_id: str,
                      root_domain: Optional[str] = None) -> Path:
    """Where THIS run (or this batch group) writes.

    `root_domain` is None for a single-domain or IP run, which keeps the canonical
    path so nothing about those modes changes.
    """
    if not root_domain:
        return canonical_output_file(output_dir, project_id)
    return Path(output_dir) / f"recon_{project_id}{BATCH_SEPARATOR}{group_slug(root_domain)}.json"


def batch_output_files(output_dir: Path, project_id: str) -> list[Path]:
    """Every per-group file for this project, in a stable order.

    Matches by LITERAL PREFIX, never by glob. A project id is client-suppliable
    at creation, so a glob pattern built from it lets an id of `*` (or `[a-z]*`)
    match every OTHER project's group files - which this function feeds to both
    the merge (cross-project read) and the delete (cross-project destruction).
    startswith/endswith has no metacharacters to abuse.
    """
    prefix = f"recon_{project_id}{BATCH_SEPARATOR}"
    directory = Path(output_dir)
    try:
        names = list(directory.iterdir())
    except OSError:
        return []
    return sorted(
        p for p in names
        if p.name.startswith(prefix) and p.name.endswith(".json") and p.is_file()
    )


def clear_batch_outputs(output_dir: Path, project_id: str, keep_roots=None) -> int:
    """Drop the previous run's per-group files, except those of `keep_roots`.

    Without this a shrunk host list would resurrect a group the operator removed:
    the merge globs whatever is on disk, so a stale file keeps reappearing in the
    canonical output run after run. A run that skips discovery reads each
    group's previous file as its input, so it keeps the current roots' files.
    """
    keep = {recon_output_file(output_dir, project_id, r).name for r in keep_roots or ()}
    removed = 0
    for path in batch_output_files(output_dir, project_id):
        if path.name in keep:
            continue
        try:
            path.unlink()
            removed += 1
        except OSError as e:
            print(f"[!][batch] could not remove stale group output {path.name}: {e}")
    return removed


# Keys that describe ONE target and must never be folded across groups.
#
# `dns.domain` is a single dict (has_records / ips / records) for the run's root
# domain, and the top-level `domain` is that root's name. Merging them key-by-key
# across groups produced a chimera: domain1.com claiming domain2.it's A records,
# with has_records taken from whichever group merged first. Every consumer of the
# canonical file then read one domain's name attached to several domains' data.
#
# Instead each group's root is RE-FILED into dns.subdomains under its own
# hostname, which is a dict keyed by name and therefore merges losslessly, and
# the single-target keys are left empty in the merged file.
_SINGLE_TARGET_TOP_KEYS = ('domain',)


def _relocate_group_root(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of one group's result with its root-domain block moved into
    dns.subdomains, so the merge has no single-target key left to conflate."""
    out = dict(data)
    dns = out.get('dns')
    if not isinstance(dns, dict):
        return out

    dns = dict(dns)
    out['dns'] = dns
    root_block = dns.get('domain')
    root_name = (
        (out.get('metadata') or {}).get('root_domain')
        or out.get('domain')
        or ''
    )
    if isinstance(root_block, dict) and root_block and isinstance(root_name, str) and root_name:
        subs = dict(dns.get('subdomains') or {})
        # A group that already discovered its own root as a subdomain wins: that
        # entry came from the same scan and is at least as complete.
        subs.setdefault(root_name, root_block)
        dns['subdomains'] = subs
    dns['domain'] = {}

    for key in _SINGLE_TARGET_TOP_KEYS:
        if key in out:
            out[key] = ''
    return out


# Identical in every group's file (recon/main.py _stamp_project_roots).
_PROJECT_WIDE_KEYS = ('scope_groups', 'all_project_roots')
# One group's scope; dropped from the merged batch metadata.
_PER_GROUP_METADATA = ('include_root_domain', 'scope_mode', 'org_domain',
                       'filtered_mode', 'wildcard_mode', 'subdomain_filter')


def _merge_group_into(merged: dict[str, Any], group: dict[str, Any]) -> None:
    """Fold one group's result into the accumulating canonical structure.

    Deliberately shallow and defensive: recon results are nested dicts whose exact
    shape varies by which modules ran, so this merges dict keys and concatenates
    lists rather than assuming any particular schema. A group that produced an
    unexpected type never overwrites data another group already contributed.
    """
    for key, value in group.items():
        if key == SELECTION_KEY:
            existing = merged.get(key)
            merged[key] = merge_plans([existing, value] if isinstance(existing, dict) else [value])
            continue
        if key not in merged:
            merged[key] = value
            continue
        existing = merged[key]
        if isinstance(existing, dict) and isinstance(value, dict):
            _merge_group_into(existing, value)
        elif isinstance(existing, list) and isinstance(value, list):
            for item in value:
                # Dicts are unhashable, so dedupe only what can be compared cheaply.
                if isinstance(item, (str, int, float, bool)):
                    if item not in existing:
                        existing.append(item)
                else:
                    existing.append(item)
        # Scalars: first group wins. Metadata is rebuilt by the caller below.


def merge_batch_outputs(output_dir: Path, project_id: str) -> Optional[Path]:
    """Rebuild the canonical recon file from every per-group file on disk.

    Returns the canonical path, or None when there was nothing to merge. Never
    raises: a merge failure must not kill a scan whose results are already safely
    written per group.
    """
    files = batch_output_files(output_dir, project_id)
    if not files:
        return None

    merged: dict[str, Any] = {}
    groups_covered: list[str] = []
    org_domains: list[str] = []
    project_wide: dict[str, Any] = {}

    for path in files:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!][batch] skipping unreadable group output {path.name}: {e}")
            continue
        if not isinstance(data, dict):
            continue
        root = (data.get('metadata') or {}).get('root_domain') or path.stem
        groups_covered.append(str(root))
        org = (data.get('metadata') or {}).get('org_domain')
        if isinstance(org, str) and org and org not in org_domains:
            org_domains.append(org)
        for key in _PROJECT_WIDE_KEYS:
            if key in data and key not in project_wide:
                # A copy: the merge below extends the first group's lists in place.
                project_wide[key] = copy.deepcopy(data[key])
        _merge_group_into(merged, _relocate_group_root(data))

    if not merged:
        return None

    # The merged metadata must describe the BATCH, not whichever group happened to
    # be merged first, or a report would name one domain as the whole scope.
    metadata = merged.setdefault('metadata', {})
    metadata['domain_batch'] = True
    metadata['domain_batch_groups'] = groups_covered
    metadata['target'] = ', '.join(groups_covered)
    # root_domain names ONE domain by contract, and consumers use it that way:
    # gvm_scanner does `hostnames.add(metadata['root_domain'])`, so a joined
    # string became a literal scan target of "a.com, b.com". A batch has no single
    # root, so the field is emptied and every root lives in dns.subdomains
    # instead; the batch's scope is in domain_batch_groups.
    metadata['root_domain'] = ''
    # One group's scope means nothing for the whole batch (first-group-wins or
    # concatenated); the batch's scope is scope_groups.
    for key in _PER_GROUP_METADATA:
        metadata.pop(key, None)
    # Project-wide lists are the same in every group's file; the merge would
    # concatenate them, so they are assigned.
    merged.update(project_wide)
    if org_domains:
        metadata['org_domains'] = org_domains
    if 'scope_groups' in project_wide:
        metadata['scope_groups'] = project_wide['scope_groups']

    canonical = canonical_output_file(output_dir, project_id)
    try:
        canonical.parent.mkdir(parents=True, exist_ok=True)
        with open(canonical, 'w') as f:
            json.dump(merged, f, indent=2)
    except OSError as e:
        print(f"[!][batch] could not write merged recon file: {e}")
        return None

    return canonical


def initialize_batch_canonical(output_dir: Path, project_id: str,
                               roots: list[str]) -> Optional[Path]:
    """Overwrite the canonical file with an empty in-progress placeholder.

    Called right after the per-group files are cleared and BEFORE the first group
    runs. Without it the canonical file keeps describing the PREVIOUS run for the
    whole duration of group 1 - potentially an hour - while the graph has already
    been wiped. Anything that reads the file in that window (a GVM start only
    checks that it exists) would scan the previous run's target set.

    An empty dns block means "no live targets", which the downstream readers
    already handle, so the window fails closed instead of failing stale.
    """
    canonical = canonical_output_file(output_dir, project_id)
    payload = {
        "metadata": {
            "scan_type": "domain_batch",
            "domain_batch": True,
            "domain_batch_groups": list(roots),
            "domain_batch_in_progress": True,
            "target": ", ".join(roots),
            "root_domain": "",
            "project_id": project_id,
        },
        "domain": "",
        "dns": {"domain": {}, "subdomains": {}},
        "subdomains": [],
        "subdomain_count": 0,
    }
    try:
        canonical.parent.mkdir(parents=True, exist_ok=True)
        with open(canonical, 'w') as f:
            json.dump(payload, f, indent=2)
    except OSError as e:
        print(f"[!][batch] could not initialize the canonical recon file: {e}")
        return None
    return canonical
