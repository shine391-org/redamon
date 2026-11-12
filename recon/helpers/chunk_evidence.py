"""Bounded, allowlisted readback of durable recon evidence (no target text).

Also used by the recon worker. Keep this module stdlib-only: the orchestrator
must not import the scanner dependency tree to answer a status poll.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

TOOLS = frozenset({"vuln_scan", "graphql_scan", "subdomain_takeover", "vhost_sni",
                   "cache_scan", "origin_discovery", "route_exposure"})
STATUSES = frozenset({"pending", "running", "completed", "partial", "deferred", "failed"})
MAX_FILE = 32 * 1024 * 1024
MAX_GROUPS = 1000


class EvidenceError(ValueError):
    pass


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
        raise EvidenceError("invalid_context")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     default=str).encode()).hexdigest()


def project_revision(project):
    # Conservative: a changed scope, credential, authorization, or steering
    # setting refuses continuation. Only read-time bookkeeping is excluded.
    return digest({k: v for k, v in project.items()
                   if k not in {"updatedAt", "createdAt", "activationState",
                                "activationStartedAt", "activationVersionId"}})


def safe_file(base, name):
    base = Path(base)
    if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
        raise EvidenceError("invalid_path")
    path = base / name
    if path.is_symlink() or path.resolve().parent != base.resolve():
        raise EvidenceError("invalid_path")
    return path


def read_json(path, maximum=MAX_FILE):
    if path.is_symlink() or path.stat().st_size > maximum:
        raise EvidenceError("artifact_unreadable")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise EvidenceError("artifact_unreadable")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise EvidenceError("artifact_unreadable")
    return value


def descriptor_name(project, run):
    return f".recon_{identifier(project)}.json.{identifier(run)}.phase-a.json"


def journal_name(project, run):
    return f".recon_{identifier(project)}.json.{identifier(run)}.chunk-journal"


def read_journal(path, expected):
    """Strict readback: unlike crash recovery, diagnostics trusts no torn tail."""
    if path.is_symlink() or path.stat().st_size > MAX_FILE:
        raise EvidenceError("checkpoint_unreadable")
    chunks, revision, budget = {}, None, None
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise EvidenceError("checkpoint_unreadable")
    for line in raw.decode().splitlines():
        data = json.loads(line)
        if not isinstance(data, dict) or data.get("schema_version") != 1:
            raise EvidenceError("checkpoint_unreadable")
        kind = data.get("type")
        if kind == "revision":
            if revision is not None:
                raise EvidenceError("checkpoint_unreadable")
            revision = data
        elif kind in {"entry", "snapshot"}:
            for entry in ([data] if kind == "entry" else data.get("chunks", [])):
                blank = dict(entry, checksum="")
                checksum = hashlib.sha256(json.dumps(blank, sort_keys=True, ensure_ascii=True,
                    separators=(",", ":")).encode()).hexdigest()
                if entry.get("checksum") != checksum or entry.get("status") not in STATUSES:
                    raise EvidenceError("checkpoint_unreadable")
                if any(entry.get(k) != expected.get(k) for k in ("tenant", "project_id", "run_id")):
                    raise EvidenceError("context_mismatch")
                chunks[(entry["origin"], entry["chunk_index"])] = entry
        elif kind == "budget":
            budget = data.get("budget")
        else:
            raise EvidenceError("checkpoint_unreadable")
    if revision is None or any(revision.get(k) != v for k, v in expected.items()):
        raise EvidenceError("revision_mismatch")
    if len(chunks) > MAX_GROUPS * len(TOOLS):
        raise EvidenceError("checkpoint_unreadable")
    return chunks, budget


def load_checkpoint(base, project, run, tenant=None):
    desc = read_json(safe_file(base, descriptor_name(project, run)), 2 * 1024 * 1024)
    if (desc.get("schema_version") != 1 or desc.get("project_id") != project
            or desc.get("run_id") != run or (tenant is not None and desc.get("tenant") != tenant)):
        raise EvidenceError("context_mismatch")
    revision = desc["revision"]
    if any(revision.get(k) != desc.get(k) for k in ("tenant", "project_id", "run_id")):
        raise EvidenceError("context_mismatch")
    groups = desc["groups"]
    if not isinstance(groups, list) or not 0 < len(groups) <= MAX_GROUPS:
        raise EvidenceError("checkpoint_unreadable")
    seen = set()
    for group in groups:
        key = group["group_id"]
        if not isinstance(key, str) or not key or key in seen:
            raise EvidenceError("checkpoint_unreadable")
        seen.add(key)
        if not isinstance(group["tools"], list) or not set(group["tools"]) <= TOOLS:
            raise EvidenceError("unsupported_tool")
        file = safe_file(base, group["output"])
        if not file.name.startswith(f"recon_{project}") or not file.name.endswith(".json"):
            raise EvidenceError("invalid_path")
    chunks, budget = read_journal(safe_file(base, journal_name(project, run)), revision)
    allowed = {f"{g['group_id']}:{tool}" for g in groups for tool in g["tools"]}
    if any(origin not in allowed or index != 0 for origin, index in chunks):
        raise EvidenceError("unsupported_chunk")
    return desc, chunks, budget


def number(value):
    return value if type(value) is int and 0 <= value <= 10**9 else None


def numeric_fields(value, keys):
    if not isinstance(value, dict):
        return {}
    return {k: number(value[k]) for k in keys if k in value}


def summarize_inventory(data):
    inv = data.get("discovery_inventory")
    if not isinstance(inv, dict) or inv.get("schema_version") != 1 or not isinstance(inv.get("producers"), dict):
        return None
    # Never forward producer names or reason strings from untrusted artifacts.
    producers = []
    for raw in list(inv["producers"].values())[:32]:
        if isinstance(raw, dict):
            observations = raw.get("observations")
            producers.append({"observations": len(observations) if isinstance(observations, list) else None,
                              "observations_total": number(raw.get("observations_total")),
                              "rejected_count": sum(v for v in (raw.get("rejected") or {}).values()
                                                    if type(v) is int and 0 <= v <= 10**6)
                              if isinstance(raw.get("rejected", {}), dict) else None})
    return {"schema_version": 1, "producers": producers,
            "origins": len(inv["origins"]) if isinstance(inv.get("origins"), dict) else None,
            "reasons": ["durable_inventory_counts_only"]}


def summarize_selection(data):
    plans = data.get("selection_coverage")
    if not isinstance(plans, dict):
        return None
    modules = {}
    if plans.get("module") in TOOLS:
        plans = {plans["module"]: plans}
    for tool in sorted(TOOLS):
        plan = plans.get(tool)
        if not isinstance(plan, dict):
            continue
        status = plan.get("status")
        modules[tool] = {"status": status if status in {"planned", "complete", "partial", "failed"} else "unknown",
                         "exhaustive": plan.get("exhaustive") is True,
                         "targets": numeric_fields(plan.get("targets"), ["count"]),
                         "outcomes": numeric_fields(plan.get("outcomes"),
                             ["completed", "partial", "failed", "deferred", "unknown"]),
                         "reasons": ["selection_recorded"]}
    return {"modules": modules} if modules else None


def summarize_coverage(artifact):
    summary = {}
    for tool in ("js_recon", "vuln_scan"):
        data = artifact.get(tool)
        if not isinstance(data, dict):
            continue
        coverage = (data.get("scan_metadata") or {}).get("coverage") if tool == "vuln_scan" else data.get("coverage")
        if not isinstance(coverage, dict) or not isinstance(coverage.get("hosts"), dict):
            continue
        counts = {k: 0 for k in ("complete", "partial", "no_input", "failed", "not_scanned")}
        unknown = 0
        for row in coverage["hosts"].values():
            status = row.get("status") if isinstance(row, dict) else None
            if status in counts:
                counts[status] += 1
            else:
                unknown += 1
        # An empty host map proves no host coverage, not zero clean hosts.
        if coverage["hosts"]:
            summary[tool] = dict(counts, recorded=True, unknown=unknown)
    return summary or None


def diagnostics(base, project, run=None, tenant=None, active=False):
    unknown = {"status": "unknown", "reason": "artifact_unavailable", "run_id": None,
               "group_id": None, "inventory": None, "selection": None, "checkpoint": None,
               "is_history": False, "coverage_summary": None}
    try:
        identifier(project)
        artifact = read_json(safe_file(base, f"recon_{project}.json"))
        context = artifact.get("metadata", {}).get("checkpoint_context", {})
        current = context.get("run_id")
        if current is None:
            if run is not None:
                identifier(run)
                return dict(unknown, reason="run_context_unavailable", is_history=True)
            coverage = summarize_coverage(artifact)
            inventory, selection = summarize_inventory(artifact), summarize_selection(artifact)
            known = coverage is not None or inventory is not None or selection is not None
            return dict(unknown, status="ready" if known else "unknown",
                        reason="legacy_durable_evidence" if known else "run_context_unavailable",
                        inventory=inventory, selection=selection, coverage_summary=coverage,
                        is_history=True)
        current = identifier(current)
        if context.get("project_id") != project or (tenant is not None and context.get("tenant") != tenant):
            raise EvidenceError("context_mismatch")
        run = identifier(run) if run is not None else current
        historical = run != current
        out = dict(unknown, run_id=run, is_history=historical,
                   run_mode=context.get("mode") if context.get("mode") in {"full", "continuation"} else None,
                   coverage_summary=None if historical else summarize_coverage(artifact),
                   inventory=None if historical else summarize_inventory(artifact),
                   selection=None if historical else summarize_selection(artifact))
        try:
            desc, chunks, budget = load_checkpoint(base, project, run, tenant)
            entries, counts = [], {k: 0 for k in STATUSES}
            deferred = 0
            for entry in chunks.values():
                status = entry["status"]
                if status == "completed" and entry.get("coverage_durable") is not True:
                    status = "partial"
                counts[status] += 1
                safe_deferred = status == "deferred" and entry.get("reason") == "budget_exhausted"
                deferred += int(safe_deferred)
                if len(entries) < 100:
                    entries.append({"tool": next((t for t in entry.get("tool_ids", []) if t in TOOLS), "unknown"),
                                    "status": status, "coverage_durable": entry.get("coverage_durable") is True,
                                    "reason": "budget_exhausted" if safe_deferred else "durable_chunk_state"})
            planned = sum(len(g["tools"]) for g in desc["groups"])
            counts["not_tested"] = max(0, planned - len(chunks))
            eligible = not historical and not active and deferred > 0
            incompatibility = None
            if eligible:
                try:
                    continuation_work(base, project, run, desc["tenant"])
                except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
                    eligible = False
                    incompatibility = str(exc) if isinstance(exc, EvidenceError) else "checkpoint_unavailable"
            reason = (incompatibility if incompatibility else "historical_run" if historical else "scan_active" if active else
                      "no_safe_deferred_chunks" if not deferred else "explicit_human_invocation_required")
            out["checkpoint"] = {"scope": "group6_phase_a", "counts": counts,
                "planned": planned, "entries": entries, "entries_truncated": len(chunks) > len(entries),
                "budgets": {"per_group": number(desc.get("budget_per_group")),
                            "per_tool": number(desc.get("budget_per_tool")),
                            "unit": "tool_group_chunks", "renewal": "explicit_continuation",
                            "window": number(budget.get("window")) if isinstance(budget, dict) else None,
                            "lifetime_used": number(budget.get("lifetime_used")) if isinstance(budget, dict) else None},
                "continuation": {"supported": True, "eligible": eligible,
                                 "reason": reason, "run_id": run}}
            out["chunk_summary"] = {"scope": "group6_phase_a", "planned": planned,
                "completed": counts["completed"], "deferred": counts["deferred"],
                "failed": counts["failed"], "partial": counts["partial"],
                "not_tested": counts["not_tested"], "running": counts["running"]}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            out["checkpoint"] = {"scope": "group6_phase_a", "continuation": {
                "supported": False, "eligible": False, "reason": "checkpoint_unavailable"}}
        known = out["inventory"] is not None or out["selection"] is not None or out["coverage_summary"] is not None or out.get("chunk_summary") is not None
        out.update(status="ready" if known else "unknown", reason="historical_run" if historical else
                   "durable_evidence" if known else "evidence_unavailable")
        return out
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return unknown


def continuation_work(base, project, run, tenant, project_rev=None):
    desc, chunks, budget = load_checkpoint(base, project, run, tenant)
    if not desc.get("project_revision") or (project_rev is not None and desc["project_revision"] != project_rev):
        raise EvidenceError("project_revision_mismatch")
    artifact = read_json(safe_file(base, f"recon_{project}.json"))
    context = artifact.get("metadata", {}).get("checkpoint_context", {})
    if context.get("run_id") != run or context.get("project_id") != project or context.get("tenant") != tenant:
        raise EvidenceError("historical_run")
    # Batch fan-in and IP pre-PhaseA Nuclei have different dependencies. Do not
    # pretend a post-run subset can reproduce those phases safely.
    if len(desc["groups"]) != 1 or desc["groups"][0]["group_id"] == "ip":
        raise EvidenceError("unsupported_targeting_mode")
    group = desc["groups"][0]
    if group["output"] != f"recon_{project}.json":
        raise EvidenceError("unsupported_batch_continuation")
    if group.get("output_digest") != digest(artifact):
        raise EvidenceError("output_revision_mismatch")
    if any(e["status"] == "running" for e in chunks.values()):
        raise EvidenceError("ambiguous_execution")
    tools = [t for t in group["tools"]
             if (e := chunks.get((f"{group['group_id']}:{t}", 0)))
             and e["status"] == "deferred" and e.get("reason") == "budget_exhausted"]
    if not tools:
        raise EvidenceError("no_safe_deferred_chunks")
    return desc, group, tools, artifact, budget
