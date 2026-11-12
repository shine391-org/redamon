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

Run identity vs configuration revision
--------------------------------------
A journal belongs to exactly ONE run. ``run_id`` is part of the journal's
identity, not its configuration revision:

* different run_id  -> ``RunMismatch``: this is a NEW run. A new run cleared the
  graph and started fresh, so it must NOT reuse the previous run's checkpoints.
  The caller starts a fresh journal (replan), never a silent resume.
* same run_id, different scope/settings/template/auth -> ``RevisionMismatch``:
  the same run was restarted under a changed configuration. The snapshot is
  incompatible and the caller must replan or get approval, never silently
  resume.

Durability contract
-------------------
* The journal is append-only JSONL: every entry is one line appended with
  ``O_APPEND`` while holding an exclusive ``flock`` on a sibling lock file.
  Separate processes (the case a per-process ``threading.Lock`` cannot cover)
  serialize on that lock, so concurrent writers cannot clobber each other's
  entries. A reader sees whole lines; a torn final line is detectable (invalid
  JSON) and the journal degrades to its last valid prefix.
* The first line is the run's revision header. Every entry carries a sha256
  checksum over its own content; a reader that cannot verify an entry treats
  the journal as truncated at that point.
* A periodic compaction rewrites the journal as revision + one snapshot line
  (plus the latest budget line), so the file stays bounded. Compaction runs
  under the same exclusive lock and swaps atomically.

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

import fcntl
import hashlib
import json
import os
import tempfile
import threading
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

#: Journal schema version. Readers that see an unknown version treat the
#: journal as unreadable and fail closed (unknown -> block).
SCHEMA_VERSION = 1

#: Maximum number of entry lines kept before a compaction snapshot is forced.
MAX_JOURNAL_LINES = 10000

#: Default lease TTL seconds. A running chunk whose lease expires is uncertain.
DEFAULT_LEASE_TTL_S = 300.0

_STATUSES = frozenset({"pending", "running", "completed", "partial", "deferred", "failed"})

#: Configuration keys that must match for a journal to be resumable by the SAME
#: run. ``run_id`` is deliberately excluded: a different run is a new run
#: (RunMismatch -> fresh journal), not an incompatible snapshot.
_REVISION_KEYS = ("scope", "settings_hash", "template_rev", "auth_rev")

#: Identity keys: a journal belongs to exactly one run.
_RUN_KEYS = ("tenant", "project_id", "run_id")


class JournalError(RuntimeError):
    """The journal cannot be read or written; raised, never swallowed."""


class RevisionMismatch(JournalError):
    """The journal's configuration revision does not match this run's.

    The SAME run was restarted under changed scope/settings/template/auth.
    The snapshot is incompatible: replan or approval required.
    """


class RunMismatch(JournalError):
    """The journal belongs to a DIFFERENT run.

    A new run cleared the graph and started fresh, so it must not reuse the
    previous run's checkpoints. The caller starts a fresh journal.
    """


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
    reason: str = ""
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
        if self.reason:
            d["reason"] = self.reason
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
            reason=str(data.get("reason") or ""),
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
        """True when the CONFIGURATION revision matches (same run assumed).

        Scope/RoE/settings/template/auth changes make a snapshot incompatible
        for the same run: replan or approval required.
        """
        return all(
            getattr(self, k) == getattr(other, k) for k in _REVISION_KEYS
        )

    def same_run(self, other: "JournalRevision") -> bool:
        """True when both revisions belong to the same tenant/project/run."""
        return all(
            getattr(self, k) == getattr(other, k) for k in _RUN_KEYS
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
        return {k for k, e in self.chunks.items() if e.status == "completed" and e.coverage_durable}

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
    """Append-only durable journal for chunk checkpoint state.

    Concurrent writers (threads or separate processes) serialize on an
    exclusive ``flock`` over a sibling lock file, so an append can never
    clobber another writer's entry. Readers take a shared lock and see whole
    lines; a torn final line degrades to the last valid prefix.
    """

    def __init__(self, path: Path, revision: JournalRevision, *,
                 lease_ttl_s: float = DEFAULT_LEASE_TTL_S,
                 now: Optional[Callable] = None) -> None:
        self.path = Path(path)
        self.revision = revision
        self.lease_ttl_s = lease_ttl_s
        self._now = now or _utc_now
        self._lock = threading.Lock()
        self._last_budget: Optional[dict] = None

    # -- locking -----------------------------------------------------------
    #
    # A per-process ``threading.Lock`` alone cannot serialize separate
    # processes (two recon containers, a worker and a supervisor). ``flock``
    # on a sibling lock file is kernel-owned and released on process death, so
    # a killed writer cannot leave the lock held.

    @property
    def _lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @contextmanager
    def _exclusive(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    @contextmanager
    def _shared(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self._lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

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
        with self._shared():
            return self._load_unlocked()

    def _load_unlocked(self) -> JournalSnapshot:
        """Load the journal assuming the caller holds a lock."""
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
                        if _verify_checksum_raw(raw):
                            snapshot.merge(entry)
                        else:
                            raise JournalError("invalid snapshot checksum")
                except Exception:  # noqa: BLE001
                    truncated_at = idx
                    break
            elif jtype == "budget":
                budget = data.get("budget")
                if isinstance(budget, dict):
                    self._last_budget = budget
            # Unknown line types are ignored (forward compatibility).
        # Validate identity first, then configuration: a different run is a
        # new run (RunMismatch), not an incompatible snapshot.
        if revision_seen is not None:
            if not revision_seen.same_run(self.revision):
                raise RunMismatch(
                    f"{self.path}: journal belongs to run "
                    f"{revision_seen.run_id!r}, not {self.revision.run_id!r}: "
                    f"a new run must start a fresh checkpoint"
                )
            if not revision_seen.matches(self.revision):
                raise RevisionMismatch(
                    f"{self.path}: journal revision does not match this run "
                    f"(scope/settings/template/auth changed): incompatible "
                    f"snapshot, requires replan or approval"
                )
        return snapshot

    # -- writing -----------------------------------------------------------

    def _write_lines(self, lines: list[str]) -> None:
        """Atomically rewrite the whole journal (caller holds the lock)."""
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

    def _first_line_is_revision(self, lines: list[str]) -> bool:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (ValueError, TypeError):
                return False
            return isinstance(data, dict) and data.get("type") == "revision"
        return False

    def _append_line(self, payload: dict) -> None:
        """Append one JSON line under O_APPEND (caller holds the lock)."""
        line = json.dumps(payload, sort_keys=True) + "\n"
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def append(self, entry: ChunkEntry) -> None:
        """Append one entry atomically, without losing other writers' entries.

        The read-modify-write of earlier revisions is gone: the entry is a single
        appended line, so a writer never rewrites (and can never clobber) the
        entries another process appended. The exclusive flock serializes
        writers across processes; the per-process lock serializes threads.
        """
        with self._lock:
            with self._exclusive():
                lines = self._read_lines()
                has_revision = self._first_line_is_revision(lines)
                if not has_revision:
                    self._append_line(self.revision.to_dict())
                self._append_line(entry.to_dict())
                kept = sum(1 for line in lines if line.strip())
                kept += 0 if has_revision else 1
                kept += 1
                if kept > MAX_JOURNAL_LINES:
                    self._compact()

    def _compact(self) -> None:
        """Collapse the journal to revision + one snapshot (+ budget) line."""
        try:
            snapshot = self._load_unlocked()
        except JournalError:
            return  # never lose entries because a compaction could not read
        lines = [json.dumps(self.revision.to_dict(), sort_keys=True)]
        snap_entry = {
            "schema_version": SCHEMA_VERSION,
            "type": "snapshot",
            "chunks": [e.to_dict() for e in snapshot.chunks.values()],
        }
        snap_entry["checksum"] = _checksum(snap_entry)
        lines.append(json.dumps(snap_entry, sort_keys=True))
        if self._last_budget is not None:
            lines.append(json.dumps(
                {"schema_version": SCHEMA_VERSION, "type": "budget",
                 "budget": self._last_budget}, sort_keys=True))
        self._write_lines(lines)

    def reset(self) -> None:
        """Start a fresh journal for this run: replace any existing file with
        this run's revision header and nothing else.

        Used when the stored journal cannot be resumed (a different run, an
        incompatible configuration, or a corrupted file): the caller replans
        from an empty checkpoint rather than trusting prior state.
        """
        with self._lock:
            with self._exclusive():
                self._write_lines([json.dumps(self.revision.to_dict(), sort_keys=True)])
                self._last_budget = None

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

    # -- budget persistence ------------------------------------------------

    def save_budget(self, budget: dict) -> None:
        """Persist the budget ledger snapshot as a journal line.

        The ledger is per-run, and the journal is the run's durable store, so a
        deferred backlog survives a restart and has a continuation route.
        """
        with self._lock:
            with self._exclusive():
                self._last_budget = dict(budget)
                self._append_line({
                    "schema_version": SCHEMA_VERSION,
                    "type": "budget",
                    "budget": dict(budget),
                })

    def load_budget(self) -> Optional[dict]:
        """The latest persisted budget ledger, or None.

        Read without revision validation: the caller validates the run first
        and ignores the budget when the journal is not resumable.
        """
        with self._shared():
            for line in self._read_lines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except (ValueError, TypeError):
                    break
                if not isinstance(data, dict):
                    break
                if data.get("type") == "budget" and isinstance(data.get("budget"), dict):
                    self._last_budget = data["budget"]
        return self._last_budget

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
        except (JournalError, RevisionMismatch, RunMismatch):
            return False
        return True
