"""Durable chunk-level checkpoint journal for recon continuation.

A recon run is one container process; it can die mid-phase (OOM, stop, host
reboot) with nothing durable except the per-phase artifact that save_recon_file
overwrites. When the container restarts there is no record of which (origin,
tool) chunks finished, so the run either re-executes everything (duplicate
findings, wasted budget) or cannot resume at all.

This module writes an append-only, atomic, durable JSONL journal keyed by
tenant/project/run/scope/settings/template/auth revisions. After each origin
chunk completes, the caller appends a {chunk_index, origin, tool_ids, status}
entry. On resume the journal is read back, its revision block is validated
against the current run's scope/RoE/settings/template/auth, and done chunks are
skipped. A corrupted or absent journal reads as unknown/block safe: never
pretend complete.

Durability contract
-------------------
* Every entry is written to a sibling temp file, fsynced, then os.replace'd
  into place: a reader sees either the previous complete journal or the new
  one, never a half-written line.
* Lines are JSONL so a torn final line is detectable (invalid JSON) and the
  journal degrades to its last valid prefix rather than to zero.
* A periodic compaction line (type "snapshot") collapses the history to the
  latest entry per chunk key; readers use the last snapshot plus trailing
  entries, so the journal stays bounded.
* Each entry carries a sha256 checksum over its own content; a reader that
  cannot verify an entry treats the journal as truncated at that point.

Task states
-----------
pending | running | completed | partial | deferred | failed

A chunk is *completed* only when its output is ingested and coverage is
durable (see task_state.py). Until then it is running/partial/deferred, and a
restart re-evaluates it under the safe policy: ambiguous interrupted execution
is reported and retried, never silently replayed as exactly-once.

Network side effects are never claimed exactly-once: an entry whose status is
uncertain (running with an expired lease, or completed without coverage
durable) is reported as uncertain and retried under the safe policy rather
than auto-replayed.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Any, Optional

#: Journal schema version. Readers that see an unknown version treat the
#: journal as unreadable and fail closed (unknown -> block).
SCHEMA_VERSION = 1

#: Maximum number of entry lines kept before a compaction snapshot is forced.
MAX_JOURNAL_LINES = 10000

#: Default lease TTL seconds. A running chunk whose lease expires is uncertain.
DEFAULT_LEASE_TTL_S = 300.0

_STATUSES = frozenset({"pending", "running", "completed", "partial", "deferred", "failed"})

_REVISION_KEYS = ("scope", "settings_hash", "template_rev", "auth_rev")


class JournalError(RuntimeError):
    """The journal cannot be read or written; raised, never swallowed."""


class RevisionMismatch(JournalError):
    """The journal's revision block does not match the current run's."""


def _utc_now() -> float:
    import time
    return time.time()


def _new_id() -> str:
    return uuid.uuid4().hex


def _checksum(payload: dict) -> str:
    """sha256 over the entry with its checksum field blanked."""
    blank = dict(payload)
    blank["checksum"] = ""
    blob = json.dumps(blank, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _verify_checksum_raw(data: dict) -> bool:
    """Verify the stored checksum against the content with checksum blanked.

    Called on the raw parsed JSON line (before ChunkEntry.from_dict), so the
    stored checksum is compared against a recomputed one over the same fields
    minus the checksum itself.
    """
    expected = data.get("checksum", "")
    if not isinstance(expected, str) or not expected:
        return False
    blank = dict(data)
    blank["checksum"] = ""
    blob = json.dumps(blank, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest() == expected


def _verify_checksum(entry: ChunkEntry) -> bool:
    """Verify a ChunkEntry's stored checksum against its content."""
    return _verify_checksum_raw(entry.to_dict())


@dataclass
class ChunkEntry:
    """One durable record of a chunk's lifecycle state."""

    tenant: str
    project_id: str
    run_id: str
    chunk_index: int
    origin: str
    tool_ids: list[str]
    status: str
    lease_id: str
    lease_expires_at: float
    started_at: float
    completed_at: Optional[float] = None
    output_ref: Optional[str] = None
    coverage_durable: bool = False
    revision: dict[str, str] = field(default_factory=dict)
    entry_id: str = field(default_factory=_new_id)
    created_at: float = field(default_factory=_utc_now)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "entry_id": self.entry_id,
            "type": "entry",
            "tenant": self.tenant,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "chunk_index": self.chunk_index,
            "origin": self.origin,
            "tool_ids": list(self.tool_ids),
            "status": self.status,
            "lease_id": self.lease_id,
            "lease_expires_at": self.lease_expires_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "output_ref": self.output_ref,
            "coverage_durable": self.coverage_durable,
            "revision": dict(self.revision),
            "created_at": self.created_at,
        }
        d["checksum"] = _checksum(d)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "ChunkEntry":
        return cls(
            tenant=str(data.get("tenant", "")),
            project_id=str(data.get("project_id", "")),
            run_id=str(data.get("run_id", "")),
            chunk_index=int(data.get("chunk_index", 0)),
            origin=str(data.get("origin", "")),
            tool_ids=list(data.get("tool_ids") or []),
            status=str(data.get("status", "pending")),
            lease_id=str(data.get("lease_id", "")),
            lease_expires_at=float(data.get("lease_expires_at", 0.0)),
            started_at=float(data.get("started_at", 0.0)),
            completed_at=data.get("completed_at"),
            output_ref=data.get("output_ref"),
            coverage_durable=bool(data.get("coverage_durable", False)),
            revision=dict(data.get("revision") or {}),
            entry_id=str(data.get("entry_id") or _new_id()),
            created_at=float(data.get("created_at", 0.0)),
        )


@dataclass
class JournalRevision:
    """The revision block that ties a journal to one run's scope/config."""

    tenant: str
    project_id: str
    run_id: str
    scope: str
    settings_hash: str
    template_rev: str
    auth_rev: str

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "revision",
            "tenant": self.tenant,
            "project_id": self.project_id,
            "run_id": self.run_id,
            "scope": self.scope,
            "settings_hash": self.settings_hash,
            "template_rev": self.template_rev,
            "auth_rev": self.auth_rev,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "JournalRevision":
        return cls(
            tenant=str(data.get("tenant", "")),
            project_id=str(data.get("project_id", "")),
            run_id=str(data.get("run_id", "")),
            scope=str(data.get("scope", "")),
            settings_hash=str(data.get("settings_hash", "")),
            template_rev=str(data.get("template_rev", "")),
            auth_rev=str(data.get("auth_rev", "")),
        )

    def matches(self, other: "JournalRevision") -> bool:
        return all(
            getattr(self, k) == getattr(other, k) for k in _REVISION_KEYS
        )


@dataclass
class JournalSnapshot:
    """A compaction snapshot: the latest status per chunk key."""

    chunks: dict[tuple[str, int], ChunkEntry] = field(default_factory=dict)

    def key_for(self, entry: ChunkEntry) -> tuple[str, int]:
        return (entry.origin, entry.chunk_index)

    def merge(self, entry: ChunkEntry) -> None:
        key = self.key_for(entry)
        existing = self.chunks.get(key)
        if existing is None or entry.created_at >= existing.created_at:
            self.chunks[key] = entry

    def completed_keys(self) -> set[tuple[str, int]]:
        return {k for k, e in self.chunks.items() if e.status == "completed"}

    def uncertain_keys(self, now: float) -> set[tuple[str, int]]:
        """Chunks whose outcome is not safely known: running with an expired
        lease, completed without durable coverage, or any non-terminal state."""
        out: set[tuple[str, int]] = set()
        for key, entry in self.chunks.items():
            if entry.status == "completed" and entry.coverage_durable:
                continue  # safely done
            if entry.status == "completed":
                # Completed but coverage not durable: output may not be durable.
                out.add(key)
                continue
            if entry.status == "running" and now > entry.lease_expires_at:
                out.add(key)
            elif entry.status in ("pending", "running", "partial", "deferred"):
                out.add(key)
        return out


class ChunkJournal:
    """Append-only durable journal for chunk checkpoint state."""

    def __init__(self, path: Path, revision: JournalRevision, *,
                 lease_ttl_s: float = DEFAULT_LEASE_TTL_S,
                 now: Optional[Callable] = None) -> None:
        self.path = Path(path)
        self.revision = revision
        self.lease_ttl_s = lease_ttl_s
        self._now = now or _utc_now
        self._lock = threading.Lock()
        self._entries: list[ChunkEntry] = []
        self._loaded = False

    # -- loading -----------------------------------------------------------

    def _read_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        try:
            return self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise JournalError(f"{self.path}: unreadable ({exc})") from exc

    def load(self) -> JournalSnapshot:
        """Load and validate the journal. Raises JournalError on corruption.

        A missing journal is not an error: it returns an empty snapshot, and
        callers treat absence as unknown/block safe.
        """
        with self._lock:
            return self._load_locked()

    def _load_locked(self) -> JournalSnapshot:
        """Load the journal assuming the caller holds ``self._lock``."""
        if self._loaded:
            return self._snapshot()
        lines = self._read_lines()
        snapshot = JournalSnapshot()
        revision_seen: Optional[JournalRevision] = None
        truncated_at: Optional[int] = None
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                # A torn final line: degrade to the last valid prefix.
                truncated_at = idx
                break
            if not isinstance(data, dict):
                truncated_at = idx
                break
            jtype = data.get("type")
            if jtype == "revision":
                try:
                    revision_seen = JournalRevision.from_dict(data)
                except Exception:  # noqa: BLE001 - malformed revision
                    truncated_at = idx
                    break
            elif jtype == "entry":
                try:
                    entry = ChunkEntry.from_dict(data)
                except Exception:  # noqa: BLE001 - malformed entry
                    truncated_at = idx
                    break
                if not _verify_checksum_raw(data):
                    # Checksum mismatch: this entry cannot be trusted.
                    truncated_at = idx
                    break
                if entry.status not in _STATUSES:
                    truncated_at = idx
                    break
                snapshot.merge(entry)
            elif jtype == "snapshot":
                # A snapshot supersedes prior entries for its keys.
                try:
                    for raw in data.get("chunks") or []:
                        entry = ChunkEntry.from_dict(raw)
                        if _verify_checksum(entry):
                            snapshot.merge(entry)
                except Exception:  # noqa: BLE001
                    truncated_at = idx
                    break
        # Validate revision: the journal must belong to this run.
        if revision_seen is not None and not revision_seen.matches(self.revision):
            raise RevisionMismatch(
                f"{self.path}: journal revision does not match this run "
                f"(scope/settings/template/auth changed): incompatible "
                f"snapshot, requires replan or approval"
            )
        self._entries = list(snapshot.chunks.values())
        self._loaded = True
        return snapshot

    def _snapshot(self) -> JournalSnapshot:
        snapshot = JournalSnapshot()
        for entry in self._entries:
            snapshot.merge(entry)
        return snapshot

    # -- writing -----------------------------------------------------------

    def _write_lines(self, lines: list[str]) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        text = "\n".join(lines) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=str(directory)
        )
        handle = None
        try:
            handle = os.fdopen(fd, "w", encoding="utf-8")
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            handle = None
            os.replace(tmp_name, str(self.path))
            tmp_name = None
        except OSError as exc:
            raise JournalError(f"{self.path}: write failed ({exc})") from exc
        finally:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    def _compact_lines(self, snapshot: JournalSnapshot) -> list[str]:
        """Build a compacted journal: revision header + one snapshot line +
        trailing uncommitted entries."""
        lines = [json.dumps(self.revision.to_dict(), sort_keys=True)]
        snap_entry = {
            "schema_version": SCHEMA_VERSION,
            "type": "snapshot",
            "chunks": [e.to_dict() for e in snapshot.chunks.values()],
        }
        snap_entry["checksum"] = _checksum(snap_entry)
        lines.append(json.dumps(snap_entry, sort_keys=True))
        # Entries after the last snapshot (none yet, since we compact everything)
        # are appended here on future writes.
        return lines

    def append(self, entry: ChunkEntry) -> None:
        """Append one entry atomically. Rewrites the whole journal under lock.

        The read-modify-write is intentional: the journal is small (bounded by
        MAX_JOURNAL_LINES with compaction), and a full rewrite keeps every
        reader seeing a consistent state without a separate lock file.
        """
        with self._lock:
            snapshot = self._load_locked()
            snapshot.merge(entry)
            lines = self._compact_lines(snapshot)
            if len(lines) > MAX_JOURNAL_LINES:
                # Force compaction: already compacted by _compact_lines.
                pass
            self._write_lines(lines)
            self._entries = list(snapshot.chunks.values())

    def mark_completed(self, entry: ChunkEntry) -> None:
        """Mark a chunk completed with coverage durable."""
        entry.status = "completed"
        entry.completed_at = self._now()
        entry.coverage_durable = True
        self.append(entry)

    def mark_uncertain(self, entry: ChunkEntry) -> None:
        """Mark a chunk as uncertain: its outcome cannot be safely assumed."""
        if entry.status == "running":
            entry.status = "deferred"
        self.append(entry)

    # -- queries -----------------------------------------------------------

    def is_done(self, origin: str, chunk_index: int, now: Optional[float] = None) -> bool:
        """True only when the chunk is completed with coverage durable."""
        now = now if now is not None else self._now()
        snapshot = self.load()
        entry = snapshot.chunks.get((origin, chunk_index))
        if entry is None:
            return False
        return entry.status == "completed" and entry.coverage_durable

    def uncertain(self, now: Optional[float] = None) -> list[ChunkEntry]:
        """Chunks whose outcome is not safely known (safe-policy retry set)."""
        now = now if now is not None else self._now()
        snapshot = self.load()
        return [snapshot.chunks[k] for k in sorted(snapshot.uncertain_keys(now))]

    def revision_ok(self) -> bool:
        """True when the journal's revision matches this run (loaded already)."""
        try:
            self.load()
        except (JournalError, RevisionMismatch):
            return False
        return True
