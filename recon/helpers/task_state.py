"""Task state machine with lease/recovery rules for recon continuation.

A recon chunk (one origin + its tool set) moves through:

    pending -> running -> completed
              -> partial   (some tools finished, others skipped/failed)
              -> deferred  (interrupted, outcome uncertain)
              -> failed    (hard failure, no safe retry)

Completion rule: a chunk is *completed* only when its output is ingested and
coverage is durable. Nothing is marked complete before that. A chunk left in
running/partial when its lease expires is *uncertain*: the safe policy reports
it and retries it, never auto-replays a potentially-unsafe network request.

The lease is a wall-clock TTL held by whoever runs the chunk. When the process
dies, the lease expires and a restart sees the chunk as uncertain. The restart
then re-checks scope/RoE/time window/auth/template revision before deciding:
compatible -> retry under safe policy; incompatible -> replan or approval,
never silent resume.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from collections.abc import Callable
from typing import Any, Optional

DEFAULT_LEASE_TTL_S = 300.0

STATUSES = frozenset({
    "pending", "running", "completed", "partial", "deferred", "failed",
})

# Statuses that are not terminal: a restart may re-evaluate them.
_RETRIABLE = frozenset({"pending", "running", "partial", "deferred"})


@dataclass
class TaskState:
    """The durable state of one chunk (one origin, one tool set)."""

    chunk_key: str                      # "origin:chunk_index"
    status: str = "pending"
    lease_id: str = ""
    lease_expires_at: float = 0.0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    coverage_durable: bool = False
    attempts: int = 0
    last_reason: str = ""
    revision: dict[str, str] = field(default_factory=dict)

    def is_terminal(self) -> bool:
        return self.status in ("completed", "failed")

    def is_completed(self) -> bool:
        return self.status == "completed" and self.coverage_durable

    def is_uncertain(self, now: float) -> bool:
        """True when the outcome cannot be safely assumed: running with an
        expired lease, or any non-terminal state that is not cleanly completed.

        A running chunk with an active lease is actively being worked on and
        is NOT uncertain; only an expired lease makes it uncertain.
        """
        if self.is_completed():
            return False
        if self.status == "failed":
            return False
        if self.status == "running":
            return now > self.lease_expires_at
        if self.status in _RETRIABLE:
            return True
        return False

    def lease_active(self, now: float) -> bool:
        return now <= self.lease_expires_at


@dataclass
class RecoveryDecision:
    """What a restart should do with an uncertain chunk."""

    action: str                         # "retry" | "replan" | "approve" | "block"
    reason: str
    chunk_key: str
    previous_status: str
    lease_expired: bool


class TaskStateMachine:
    """In-memory state machine; the journal persists it.

    Callers own persistence (ChunkJournal.append). This class enforces the
    transition rules and the lease/recovery policy.
    """

    def __init__(self, now: Optional[Callable] = None,
                 lease_ttl_s: float = DEFAULT_LEASE_TTL_S) -> None:
        self._now = now or time.time
        self.lease_ttl_s = lease_ttl_s
        self._lock = threading.Lock()
        self._tasks: dict[str, TaskState] = {}

    def _task(self, chunk_key: str) -> TaskState:
        task = self._tasks.get(chunk_key)
        if task is None:
            task = TaskState(chunk_key=chunk_key)
            self._tasks[chunk_key] = task
        return task

    def claim(self, chunk_key: str, lease_id: str, *,
              revision: dict[str, str]) -> TaskState:
        """Attempt to claim a chunk for execution.

        Returns the task state and whether the claim succeeded. A claim fails
        (returns the existing state with status != running) when another holder
        has an active lease, or when the chunk is already completed.
        """
        now = self._now()
        with self._lock:
            task = self._task(chunk_key)
            if task.is_completed():
                return task
            if task.status == "running" and task.lease_active(now):
                # Another holder has an active lease: do not steal.
                return task
            # Lease expired or no holder: take it.
            task.status = "running"
            task.lease_id = lease_id
            task.lease_expires_at = now + self.lease_ttl_s
            task.started_at = now
            task.attempts += 1
            task.revision = dict(revision or {})
            return task

    def release(self, chunk_key: str, status: str, *,
                coverage_durable: bool = False,
                reason: str = "") -> TaskState:
        """Record a chunk's terminal or intermediate outcome."""
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        now = self._now()
        with self._lock:
            task = self._task(chunk_key)
            task.status = status
            task.coverage_durable = bool(coverage_durable)
            task.last_reason = reason or ""
            if status == "completed":
                task.completed_at = now
            if status in ("failed", "completed", "partial"):
                # Clear the lease on any terminal-ish outcome.
                task.lease_id = ""
                task.lease_expires_at = 0.0
            return task

    def heartbeat(self, chunk_key: str, lease_id: str, *,
                  ttl_s: Optional[float] = None) -> bool:
        """Extend the lease for a running chunk. Returns False if not the holder."""
        now = self._now()
        ttl = ttl_s if ttl_s is not None else self.lease_ttl_s
        with self._lock:
            task = self._task(chunk_key)
            if task.status != "running" or task.lease_id != lease_id:
                return False
            task.lease_expires_at = now + ttl
            return True

    def get(self, chunk_key: str) -> Optional[TaskState]:
        with self._lock:
            return self._tasks.get(chunk_key)

    def restore(self, task: TaskState) -> None:
        """Load a durable task state (rebuilt from the journal) into the machine.

        A restart rebuilds the in-memory machine from the journal so the lease
        and recovery rules apply to chunks the previous process left behind.
        """
        with self._lock:
            self._tasks[task.chunk_key] = task

    def snapshot(self) -> dict[str, TaskState]:
        with self._lock:
            return dict(self._tasks)

    # -- recovery ----------------------------------------------------------

    def recover_uncertain(self, now=None,
                          revision_ok: bool = True) -> list[RecoveryDecision]:
        """Return recovery decisions for every uncertain chunk.

        When revision_ok is False the snapshot is incompatible: every uncertain
        chunk requires replan or approval, never silent resume.
        """
        if now is None:
            now = self._now()
        elif callable(now):
            now = now()
        decisions: list[RecoveryDecision] = []
        with self._lock:
            for key in sorted(self._tasks):
                task = self._tasks[key]
                if not task.is_uncertain(now):
                    continue
                lease_expired = (
                    task.status == "running" and now > task.lease_expires_at
                )
                if not revision_ok:
                    decisions.append(RecoveryDecision(
                        action="replan",
                        reason=(
                            "journal revision incompatible with this run: "
                            "scope/RoE/settings/template/auth changed"
                        ),
                        chunk_key=key,
                        previous_status=task.status,
                        lease_expired=lease_expired,
                    ))
                elif task.status == "deferred":
                    decisions.append(RecoveryDecision(
                        action="retry",
                        reason="deferred chunk re-evaluated under safe policy",
                        chunk_key=key,
                        previous_status=task.status,
                        lease_expired=lease_expired,
                    ))
                else:
                    decisions.append(RecoveryDecision(
                        action="retry",
                        reason=(
                            "uncertain interrupted execution: reported and "
                            "retried under safe policy, not auto-replayed"
                        ),
                        chunk_key=key,
                        previous_status=task.status,
                        lease_expired=lease_expired,
                    ))
        return decisions
