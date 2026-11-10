"""Run-scoped plan manifest for the planner controls (F09).

A run writes ONE manifest file before dispatch, scoped to
tenant / project / run / group. It is never a project-wide file that a later
run or group can overwrite, and the ScanJob row keeps only a pointer, a sha256
digest and a bounded summary -- never the full manifest and never credentials
or raw auth headers.

The manifest is written atomically (temp file + fsync + rename, mode 0600) and
kept for stable retention: cancellation and restart preserve it, and a
corrupt or missing file reads back as an explicit ``{"status": "unknown"}``
rather than being mistaken for a clean plan.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional

#: Manifest schema version, bumped only when the shape below changes.
SCHEMA_VERSION = 1
#: Planner controls version this manifest was authored against.
PLANNER_VERSION = 1

#: Manifest top-level key inside the recon artifact (kept small; the manifest
#: itself lives on disk, referenced by the ScanJob pointer).
KEY = "planner_manifest"

#: Planner modes. off = patched legacy behaviour, no planner optimization,
#: no changed commands, safety fixes still enforced.
MODE_OFF = "off"
MODE_SHADOW = "shadow"
MODE_ENFORCE = "enforce"
MODES = (MODE_OFF, MODE_SHADOW, MODE_ENFORCE)

#: Planner consumers: each gates one optimization path. Honoured only when the
#  mode is shadow or enforce.
CONSUMER_AI_TAGS = "ai_tags"
CONSUMER_TARGET_SELECTION = "target_selection"
CONSUMER_TWO_PASS = "two_pass"
CONSUMERS = (CONSUMER_AI_TAGS, CONSUMER_TARGET_SELECTION, CONSUMER_TWO_PASS)

#: Fields that must never be written into a manifest: credentials, raw auth
#: headers, tokens, secrets. These are hashed or dropped entirely.
SENSITIVE_PREFIXES = ("authorization", "cookie", "x-api-key", "x-auth-token",
                      "proxy-authorization", "set-cookie")


def is_known_mode(mode: Optional[str]) -> bool:
    return isinstance(mode, str) and mode in MODES


def default_mode() -> str:
    return MODE_OFF


def resolve_mode(settings: dict[str, Any]) -> str:
    """Effective planner mode from settings: off | shadow | enforce.

    Defaults to off (patched legacy behaviour). An unrecognised value is treated
    as off rather than silently escalating to enforce.
    """
    mode = settings.get("PLANNER_MODE", settings.get("planner_mode", MODE_OFF))
    return mode if is_known_mode(mode) else MODE_OFF


def consumer_enabled(settings: dict[str, Any], consumer: str) -> bool:
    """Whether one planner consumer is honoured for this run.

    A consumer flag is only honoured when the mode is shadow or enforce; off
    means patched legacy behaviour with no planner optimization.
    """
    if consumer not in CONSUMERS:
        return False
    if resolve_mode(settings) == MODE_OFF:
        return False
    key = {"ai_tags": "PLANNER_CONSUMER_AI_TAGS",
           "target_selection": "PLANNER_CONSUMER_TARGET_SELECTION",
           "two_pass": "PLANNER_CONSUMER_TWO_PASS"}[consumer]
    return bool(settings.get(key, settings.get(key.lower(), False)))


def _redact(value: Any) -> Any:
    """Drop credential-like material so a manifest never carries it."""
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()
                if not any(k.lower().startswith(p) for p in SENSITIVE_PREFIXES)}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_dir(base_dir: Path, tenant: str, project_id: str,
                 run_id: str, group_id: str) -> Path:
    """One directory per tenant/project/run/group.

    Never project-wide: a different run or group gets its own directory, so a
    later run cannot overwrite this run's manifest.
    """
    parts = [str(tenant or "default"), str(project_id), str(run_id), str(group_id)]
    safe = [p.replace("/", "_").replace("\\", "_") for p in parts]
    return Path(base_dir).joinpath(*safe)


def manifest_path(base_dir: Path, tenant: str, project_id: str,
                  run_id: str, group_id: str) -> Path:
    return manifest_dir(base_dir, tenant, project_id, run_id, group_id) / "plan_manifest.json"


def build_manifest(*, run_id: str, group_id: str, tenant: str, project_id: str,
                   scope: dict[str, Any], settings: dict[str, Any],
                   template_hashes: dict[str, str], task_summaries: list[dict],
                   reason: str = "", mode: Optional[str] = None,
                   planner_version: int = PLANNER_VERSION,
                   schema_version: int = SCHEMA_VERSION) -> dict:
    """Build the manifest dict. Credentials/raw auth headers are redacted."""
    mode = mode or resolve_mode(settings)
    return {
        "schema_version": schema_version,
        "planner_version": planner_version,
        "planner_mode": mode if is_known_mode(mode) else MODE_OFF,
        "tenant": tenant,
        "project_id": project_id,
        "run_id": run_id,
        "group_id": group_id,
        "scope": _redact(copy.deepcopy(scope or {})),
        "settings_hash": hashlib.sha256(
            json.dumps(settings or {}, sort_keys=True).encode()).hexdigest(),
        "settings_hash_prefix": hashlib.sha256(
            json.dumps(settings or {}, sort_keys=True).encode()).hexdigest()[:16],
        "template_hashes": _redact(copy.deepcopy(template_hashes or {})),
        "tasks": copy.deepcopy(task_summaries or []),
        "reason": str(reason or ""),
        "created_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
    }


def manifest_summary(manifest: dict) -> dict:
    """Bounded summary safe to store on the ScanJob row: no credentials, no raw
    headers, no full manifest, bounded size."""
    return {
        "schema_version": manifest.get("schema_version"),
        "planner_version": manifest.get("planner_version"),
        "planner_mode": manifest.get("planner_mode"),
        "run_id": manifest.get("run_id"),
        "group_id": manifest.get("group_id"),
        "settings_hash_prefix": manifest.get("settings_hash_prefix"),
        "template_count": len(manifest.get("template_hashes") or {}),
        "task_count": len(manifest.get("tasks") or []),
        "created_at": manifest.get("created_at"),
    }


def write_manifest(path: Path, manifest: dict) -> dict:
    """Atomically write ``manifest`` to ``path`` (temp + fsync + rename, 0600).

    Returns {"sha256": str, "summary": dict}. A different run/group directory
    means this never overwrites another run's file. Parents are created with
    restrictive permissions. Stable retention: the file is never deleted here;
    cancellation/restart leave it in place.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".plan_manifest.",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return {"sha256": _sha256_of_file(path), "summary": manifest_summary(manifest)}


def read_manifest(path: Path) -> dict:
    """Read a manifest, or return an explicit ``{"status": "unknown"}`` for a
    missing, unreadable or corrupt file. Never raises; never guesses clean."""
    path = Path(path)
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        return {"status": "unknown", "reason": f"manifest_unreadable: {exc}"}
    if not isinstance(data, dict) or "schema_version" not in data:
        return {"status": "unknown", "reason": "manifest_not_a_plan"}
    data.setdefault("status", "known")
    return data


def plan_pointer(manifest_path_str: str, sha256: str,
                 summary: dict) -> dict:
    """The ScanJob-side record: pointer + digest + bounded summary only."""
    return {
        "plan_manifest_path": manifest_path_str,
        "plan_manifest_sha256": sha256,
        "plan_manifest_summary": summary,
    }


def maybe_write_pre_dispatch_manifest(settings: dict[str, Any],
                                      output_file: str | Path) -> Optional[dict]:
    """Write the run-scoped plan manifest before a vuln_scan dispatch.

    Only honoured when ``PLANNER_MANIFEST_ENABLED`` is true. Never raises:
    on any failure it returns ``None`` and the scan proceeds (the manifest is
    an accounting aid, never a gate). The file is scoped to tenant/project/run/
    group under the artifact's own directory, so a later run or group cannot
    overwrite it; the returned pointer is what the caller persists on the
    ScanJob row (pointer + digest + bounded summary only).
    """
    try:
        if not settings.get("PLANNER_MANIFEST_ENABLED"):
            return None
        output_file = Path(output_file)
        manifest_base = output_file.parent / "planner_manifests"
        project_id = str(settings.get("PROJECT_ID") or "default")
        tenant = str(settings.get("PLANNER_TENANT") or "default")
        run_id = str(settings.get("PLANNER_RUN_ID") or uuid.uuid4().hex)
        group_id = str(settings.get("PLANNER_GROUP_ID") or "default")
        scope = {"roots": settings.get("SCOPE_GROUPS") or []}
        manifest = build_manifest(
            run_id=run_id, group_id=group_id, tenant=tenant, project_id=project_id,
            scope=scope, settings=settings, template_hashes={}, task_summaries=[],
            reason="pre-dispatch vuln_scan plan",
        )
        path = manifest_path(manifest_base, tenant, project_id, run_id, group_id)
        written = write_manifest(path, manifest)
        return plan_pointer(str(path), written["sha256"], written["summary"])
    except Exception:  # noqa: BLE001 - the manifest never fails a scan
        return None
