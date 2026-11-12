"""Durable Phase A descriptor and conservative continuation validation.

Only budget-deferred, never-dispatched chunks are replayable. Ambiguous network
side effects are deliberately not a supported automatic retry policy.
"""
import os
from pathlib import Path
from recon.helpers.chunk_evidence import (
    EvidenceError, descriptor_name, safe_file, read_json, digest, continuation_work,
)
from recon.helpers.atomic_io import atomic_write_json


def register_group(base, project, run, tenant, revision, group, output, tools, settings):
    path = safe_file(base, descriptor_name(project, run))
    desc = read_json(path) if path.exists() else {
        "schema_version": 1, "project_id": project, "run_id": run, "tenant": tenant,
        "revision": revision, "groups": [],
        "project_revision": os.environ.get("RECON_PROJECT_REVISION", ""),
        "budget_per_group": settings.get("CHECKPOINT_BUDGET_PER_GROUP", 0),
        "budget_per_tool": settings.get("CHECKPOINT_BUDGET_PER_TOOL", 0),
    }
    if desc["revision"] != revision:
        raise EvidenceError("revision_mismatch")
    record = {"group_id": group, "output": Path(output).name,
              "tools": sorted(tools), "input_digest": digest(read_json(output))}
    old = next((g for g in desc["groups"] if g["group_id"] == group), None)
    if old:
        return desc
    desc["groups"].append(record)
    atomic_write_json(path, desc)
    return desc


def seal_group(base, project, run, group, output):
    path = safe_file(base, descriptor_name(project, run))
    desc = read_json(path)
    for record in desc["groups"]:
        if record["group_id"] == group:
            record["output_digest"] = digest(read_json(output))
    atomic_write_json(path, desc)


