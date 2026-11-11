"""Run-scoped plan manifest for the planner controls (F09/G2-R3).

A run writes ONE manifest file before dispatch, scoped to
tenant / project / run / group. It is never a project-wide file that a later
run or group can overwrite, and the ScanJob row keeps only a pointer, a sha256
digest and a bounded summary -- never the full manifest and never credentials
or raw auth headers.

The manifest is written atomically (temp file + fsync + rename, mode 0600) and
kept for stable retention: cancellation and restart preserve it, and a
corrupt or missing file reads back as an explicit ``{"status": "unknown"}``
rather than being mistaken for a clean plan.

Security boundaries enforced here (G2 B4/B5):

* Canonical identifiers only. Tenant/project/run/group come from the job
  context -- never a fabricated random run id and never a hardcoded default
  tenant or group. Each path component is encoded injectively
  (``a/b`` and ``a_b`` can never collide) and ``.``/``..`` are rejected
  outright; the resolved path is containment-checked against the manifest base
  so no identifier can escape it.
* Redaction. Credentials and raw auth headers are dropped from every manifest
  payload field (task summaries, scope, template references). URL userinfo is
  stripped from any URL string. Settings are stored as a sha256 hash only,
  never wholesale.
* Bounding. Strings and collections are bounded with explicit markers --
  never silently truncated.
* Strict reader. ``read_manifest`` accepts only the complete, supported
  schema with valid context fields; ``read_manifest_in_context`` additionally
  requires the expected tenant/project/run/group and, optionally, the
  recorded sha256 digest. Incomplete, unsupported, tampered or cross-tenant
  / cross-run / cross-group reads return ``{"status": "unknown"}``.

The pre-dispatch helper writes the manifest before the vuln_scan tool launches
and returns the ScanJob-side pointer (path + digest + bounded summary only).
Missing or unwritable context means no manifest -- the scan still runs, the
manifest is an accounting aid, never a gate.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

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

#: Header/cookie-like keys that must never be written into a manifest.
SENSITIVE_PREFIXES = ("authorization", "cookie", "x-api-key", "x-auth-token",
                      "proxy-authorization", "set-cookie")

#: Top-level keys the reader accepts as a complete, supported manifest.
REQUIRED_MANIFEST_KEYS = (
    "schema_version", "planner_version", "planner_mode",
    "tenant", "project_id", "run_id", "group_id",
    "scope", "settings_hash", "settings_hash_prefix",
    "template_hashes", "tasks", "reason", "created_at",
)
#: Keys the reader treats as known (required plus explicitly allowed extras).
KNOWN_MANIFEST_KEYS = set(REQUIRED_MANIFEST_KEYS) | {"input_accounting", "status"}

#: Manifest bounding: explicit limits with observable markers, never silent truncation.
MANIFEST_MAX_STRING_CHARS = 2000
MANIFEST_MAX_COLLECTION_ITEMS = 100
MANIFEST_MAX_TASKS = 64

#: One path component that is safe to join verbatim.
_SAFE_COMPONENT = re.compile(r"\A[A-Za-z0-9._-]+\Z")
#: URL userinfo (``user:pass@``) -- stripped from any URL string before it can
#: reach the manifest.
_USERINFO_RE = re.compile(r"://[^@/?#]+@")
#: Bearer/token/secret-looking material as a string value.
_SECRET_VALUE_RE = re.compile(
    r"\b(Bearer|Basic|Token|API-?[Kk]ey|Secret|Pass(?:word)?)\s+[A-Za-z0-9._-]{8,}"
)
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


def is_known_mode(mode: Optional[str]) -> bool:
    return isinstance(mode, str) and mode in MODES


def default_mode() -> str:
    return MODE_OFF


def resolve_mode(settings: dict[str, Any]) -> str:
    """Effective planner mode from settings: off | shadow | enforce.

    Defaults to off (patched legacy behaviour). An unrecognised value is
    treated as off rather than silently escalating to enforce.
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


def _strip_userinfo(value: str) -> str:
    """Remove URL userinfo (``https://user:pass@host/``) so it never lands in
    the manifest as a string value."""
    return _USERINFO_RE.sub("://", value)


def _redact(value: Any) -> Any:
    """Drop credential-like material and bound strings/collections.

    Credentials are dropped or replaced with an explicit marker; nothing is
    silently truncated. A bounded collection that overflows keeps an explicit
    count marker so a reader can tell data was withheld.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and any(
                    k.lower().startswith(p) for p in SENSITIVE_PREFIXES):
                continue  # credentials never enter the manifest
            out[k] = _redact(v)
        if len(out) > MANIFEST_MAX_COLLECTION_ITEMS:
            kept = dict(list(out.items())[:MANIFEST_MAX_COLLECTION_ITEMS])
            kept["<redacted: collection truncated>"] = (
                f"{len(out) - MANIFEST_MAX_COLLECTION_ITEMS} more key(s)")
            return kept
        return out
    if isinstance(value, list):
        out = [_redact(v) for v in value[:MANIFEST_MAX_COLLECTION_ITEMS]]
        if len(value) > MANIFEST_MAX_COLLECTION_ITEMS:
            out.append(
                f"<redacted: collection truncated "
                f"{len(value) - MANIFEST_MAX_COLLECTION_ITEMS} item(s)>")
        return out
    if isinstance(value, str):
        value = _strip_userinfo(value)
        if len(value) > MANIFEST_MAX_STRING_CHARS:
            return f"<redacted: oversize {len(value)} chars>"
        if _SECRET_VALUE_RE.search(value):
            return "<redacted>"
        return value
    return value


def _encode_component(part: str) -> str:
    """Encode one manifest path component injectively.

    ``a/b`` and ``a_b`` can never collide; ``.`` and ``..`` are rejected
    outright (never encoded into something that could escape). The encoded
    component never contains ``/``, ``\\`` or a percent sequence that decodes
    back to one, so a joined path cannot escape the manifest base.
    """
    if not isinstance(part, str) or part == "" or part in (".", ".."):
        raise ValueError(f"invalid manifest id component: {part!r}")
    if "\x00" in part:
        raise ValueError(f"invalid manifest id component: {part!r}")
    if _SAFE_COMPONENT.match(part):
        return part
    return "".join(
        c if _SAFE_COMPONENT.match(c) else f"%{ord(c):02X}" for c in part
    )


def manifest_dir(base_dir: Path, tenant: str, project_id: str,
                 run_id: str, group_id: str) -> Path:
    """One directory per tenant/project/run/group.

    Never project-wide: a different run or group gets its own directory, so a
    later run cannot overwrite this run's manifest. Every component is encoded
    injectively and the resolved path is containment-checked against
    ``base_dir`` -- an identifier such as ``..`` or one containing ``/``
    raises ``ValueError`` instead of escaping.
    """
    base = Path(base_dir)
    encoded = [_encode_component(tenant), _encode_component(project_id),
               _encode_component(run_id), _encode_component(group_id)]
    dir_path = base.joinpath(*encoded)
    base_resolved = os.path.realpath(base)
    resolved = os.path.realpath(dir_path)
    if resolved != base_resolved and not resolved.startswith(
            base_resolved + os.sep):
        raise ValueError(f"manifest path escapes base directory: {dir_path}")
    return Path(dir_path)


def manifest_path(base_dir: Path, tenant: str, project_id: str,
                  run_id: str, group_id: str) -> Path:
    return manifest_dir(base_dir, tenant, project_id, run_id,
                        group_id) / "plan_manifest.json"


def _sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_digest(path: Path | str) -> str:
    """sha256 of the manifest file on disk, for the pointer/digest record."""
    return _sha256_of_file(Path(path))


def build_manifest(*, run_id: str, group_id: str, tenant: str,
                   project_id: str, scope: dict[str, Any],
                   settings: dict[str, Any],
                   template_hashes: dict[str, str], task_summaries: list[dict],
                   reason: str = "", mode: Optional[str] = None,
                   planner_version: int = PLANNER_VERSION,
                   schema_version: int = SCHEMA_VERSION,
                   input_hashes: Optional[dict[str, str]] = None,
                   input_count: Optional[int] = None) -> dict:
    """Build the manifest dict. Credentials/raw auth headers are redacted.

    ``input_hashes``/``input_count`` record honest input accounting
    (provenance of the planned inputs) when the caller has them; they are
    optional and omitted entirely when not provided.
    """
    mode = mode or resolve_mode(settings)
    tasks = copy.deepcopy(task_summaries or [])
    task_truncated = 0
    if len(tasks) > MANIFEST_MAX_TASKS:
        task_truncated = len(tasks) - MANIFEST_MAX_TASKS
        tasks = tasks[:MANIFEST_MAX_TASKS]
    manifest: dict[str, Any] = {
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
        "tasks": _redact(tasks),
        "reason": str(reason or ""),
        "created_at": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(),
    }
    if task_truncated:
        manifest["tasks"].append(
            {"<redacted: collection truncated>":
             f"{task_truncated} more task summary(ies)"})
    if input_hashes is not None or input_count is not None:
        manifest["input_accounting"] = {
            "input_count": input_count,
            "input_hashes": _redact(copy.deepcopy(input_hashes or {})),
        }
    return manifest


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
    cancellation and restart leave it in place.
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
    return {"sha256": manifest_digest(path), "summary": manifest_summary(manifest)}


def _validate_manifest(data: Any) -> dict:
    """Accept only a complete, supported manifest schema; anything else is
    ``{"status": "unknown"}`` -- never a guessed clean plan."""
    if not isinstance(data, dict):
        return {"status": "unknown", "reason": "manifest_not_a_plan"}
    for key in REQUIRED_MANIFEST_KEYS:
        if key not in data:
            return {"status": "unknown",
                    "reason": f"manifest_missing_key: {key}"}
    extra = set(data) - KNOWN_MANIFEST_KEYS
    if extra:
        return {"status": "unknown",
                "reason": f"manifest_unsupported_keys: {sorted(extra)}"}
    if data.get("schema_version") != SCHEMA_VERSION:
        return {"status": "unknown",
                "reason": f"manifest_unsupported_schema: {data.get('schema_version')!r}"}
    if data.get("planner_mode") not in MODES:
        return {"status": "unknown",
                "reason": f"manifest_invalid_planner_mode: {data.get('planner_mode')!r}"}
    for key in ("tenant", "project_id", "run_id", "group_id"):
        value = data.get(key)
        if not isinstance(value, str) or not value:
            return {"status": "unknown",
                    "reason": f"manifest_invalid_{key}"}
    if not isinstance(data.get("tasks"), list):
        return {"status": "unknown", "reason": "manifest_invalid_tasks"}
    if not isinstance(data.get("template_hashes"), dict):
        return {"status": "unknown", "reason": "manifest_invalid_template_hashes"}
    settings_hash = data.get("settings_hash")
    if not isinstance(settings_hash, str) or not _HEX64.match(settings_hash):
        return {"status": "unknown",
                "reason": "manifest_invalid_settings_hash"}
    data["status"] = "known"
    return data


def read_manifest(path: Path | str) -> dict:
    """Read a manifest, or return an explicit ``{"status": "unknown"}`` for a
    missing, unreadable, corrupt, incomplete, unsupported or tampered file.
    Never raises; never guesses clean. Only the complete supported schema with
    valid context fields reads back as ``known``.
    """
    path = Path(path)
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        return {"status": "unknown", "reason": f"manifest_unreadable: {exc}"}
    return _validate_manifest(data)


def read_manifest_in_context(path: Path | str,
                             expected_context: dict[str, str],
                             expected_sha256: Optional[str] = None) -> dict:
    """Read a manifest and require it to match the expected job context
    (tenant/project/run/group) and, when given, the recorded sha256 digest.

    Incomplete, unsupported, tampered or cross-tenant / cross-project /
    cross-run / cross-group reads return ``{"status": "unknown"}`` with a
    reason. This is the reader half of the lifecycle: a status/API reader
    validates the manifest before presenting it as evidence of a run's plan.
    """
    data = read_manifest(path)
    if data.get("status") != "known":
        return data
    for key in ("tenant", "project_id", "run_id", "group_id"):
        if data.get(key) != expected_context.get(key):
            return {"status": "unknown",
                    "reason": f"manifest_context_mismatch: {key}"}
    if expected_sha256 is not None:
        try:
            actual = manifest_digest(path)
        except OSError as exc:
            return {"status": "unknown",
                    "reason": f"manifest_digest_unreadable: {exc}"}
        if actual != expected_sha256:
            return {"status": "unknown",
                    "reason": "manifest_digest_mismatch"}
    return data


def plan_pointer(manifest_path_str: str, sha256: str,
                 summary: dict) -> dict:
    """The ScanJob-side record: pointer + digest + bounded summary only."""
    return {
        "plan_manifest_path": manifest_path_str,
        "plan_manifest_sha256": sha256,
        "plan_manifest_summary": summary,
    }


def _job_context(settings: dict[str, Any]) -> dict[str, str]:
    """Canonical tenant/project/run/group for this run, from job context only.

    Sources: explicit planner settings keys (set by the caller from the job),
    then the run's own environment (PROJECT_ID, RECON_RUN_ID,
    PARTIAL_RECON_RUN_ID). Nothing here is fabricated: a missing component
    stays empty and the caller must treat the context as incomplete.
    """
    return {
        "tenant": str(settings.get("PLANNER_TENANT") or ""),
        "project_id": str(
            settings.get("PLANNER_PROJECT_ID")
            or settings.get("PROJECT_ID")
            or ""),
        "run_id": str(
            settings.get("PLANNER_RUN_ID")
            or os.environ.get("RECON_RUN_ID")
            or os.environ.get("PARTIAL_RECON_RUN_ID")
            or ""),
        "group_id": str(settings.get("PLANNER_GROUP_ID") or ""),
    }


def maybe_write_pre_dispatch_manifest(settings: dict[str, Any],
                                      output_file: Optional[str | Path] = None
                                      ) -> Optional[dict]:
    """Write the run-scoped plan manifest before a vuln_scan dispatch.

    Only honoured when ``PLANNER_MANIFEST_ENABLED`` is true **and** the job
    context is complete (tenant/project/run/group all present from job
    context -- no fabricated defaults, no fresh random run id per call).
    Never raises: on any failure it returns ``None`` and the scan proceeds
    (the manifest is an accounting aid, never a gate). The file is scoped to
    tenant/project/run/group under ``<output_file parent>/planner_manifests``
    (or a scratch ``planner_manifests`` base when there is no output file), so
    a later run or group cannot overwrite it; the returned pointer is what the
    caller persists (pointer + digest + bounded summary only).
    """
    try:
        if not settings.get("PLANNER_MANIFEST_ENABLED"):
            return None
        ctx = _job_context(settings)
        missing = [key for key, value in ctx.items() if not value]
        if missing:
            logger.info(
                "planner manifest skipped: incomplete job context %s", missing)
            return None
        output_path = Path(output_file) if output_file else None
        manifest_base = (
            output_path.parent / "planner_manifests"
            if output_path is not None
            else Path(tempfile.gettempdir()) / "redamon" / "planner_manifests"
        )
        settings_for_manifest = dict(settings)
        settings_for_manifest.update(
            {f"PLANNER_{key.upper()}": value for key, value in ctx.items()})
        scope = {"roots": settings.get("SCOPE_GROUPS") or []}
        manifest = build_manifest(
            run_id=ctx["run_id"], group_id=ctx["group_id"],
            tenant=ctx["tenant"], project_id=ctx["project_id"],
            scope=scope, settings=settings_for_manifest,
            template_hashes={}, task_summaries=[],
            reason="pre-dispatch vuln_scan plan",
        )
        path = manifest_path(manifest_base, ctx["tenant"], ctx["project_id"],
                             ctx["run_id"], ctx["group_id"])
        written = write_manifest(path, manifest)
        return plan_pointer(str(path), written["sha256"],
                            written["summary"])
    except Exception:  # noqa: BLE001 - the manifest never fails a scan
        logger.exception("planner manifest write failed; scan continues")
        return None
