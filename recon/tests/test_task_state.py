"""recon/helpers/task_state.py — task state machine with lease/recovery.

Hermetic: injects a fake clock, no I/O, no network.
"""
from __future__ import annotations

import time
from unittest import mock

import pytest

from recon.helpers.task_state import (
    TaskState,
    TaskStateMachine,
    RecoveryDecision,
    DEFAULT_LEASE_TTL_S,
    STATUSES,
)


# --------------------------------------------------------------------------- #
# fake clock
# --------------------------------------------------------------------------- #

class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t
        self.slept = []

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


# --------------------------------------------------------------------------- #
# TaskState
# --------------------------------------------------------------------------- #

def test_task_state_defaults():
    ts = TaskState(chunk_key="k1")
    assert ts.status == "pending"
    assert ts.is_terminal() is False
    assert ts.is_completed() is False


def test_task_state_completed_requires_coverage_durable():
    ts = TaskState(chunk_key="k1", status="completed", coverage_durable=False)
    assert ts.is_terminal() is True
    assert ts.is_completed() is False

    ts.coverage_durable = True
    assert ts.is_completed() is True


def test_task_state_uncertain_running_expired_lease():
    clock = FakeClock()
    ts = TaskState(chunk_key="k1", status="running",
                   lease_expires_at=clock.t - 10)  # expired
    assert ts.is_uncertain(clock.now()) is True


def test_task_state_uncertain_running_active_lease():
    clock = FakeClock()
    ts = TaskState(chunk_key="k1", status="running",
                   lease_expires_at=clock.t + 100)  # active
    assert ts.is_uncertain(clock.now()) is False


def test_task_state_uncertain_pending_partial_deferred():
    clock = FakeClock()
    for status in ("pending", "partial", "deferred"):
        ts = TaskState(chunk_key="k1", status=status)
        assert ts.is_uncertain(clock.now()) is True, status


def test_task_state_uncertain_failed_is_not_uncertain():
    clock = FakeClock()
    ts = TaskState(chunk_key="k1", status="failed")
    assert ts.is_uncertain(clock.now()) is False


# --------------------------------------------------------------------------- #
# TaskStateMachine claim / release / heartbeat
# --------------------------------------------------------------------------- #

def test_claim_sets_running_and_lease():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    ts = sm.claim("k1", "lease-1", revision={"scope": "s"})
    assert ts.status == "running"
    assert ts.lease_id == "lease-1"
    assert ts.lease_expires_at == clock.t + 300
    assert ts.attempts == 1


def test_claim_returns_existing_when_completed():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    sm.release("k1", "completed", coverage_durable=True)
    ts = sm.claim("k1", "lease-2", revision={"scope": "s"})
    assert ts.status == "completed"
    assert ts.lease_id == ""


def test_claim_rejects_when_active_lease_held():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    # Active lease: second claim should not take over
    ts = sm.claim("k1", "lease-2", revision={"scope": "s"})
    assert ts.lease_id == "lease-1"
    assert ts.status == "running"


def test_claim_takes_over_after_lease_expires():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    clock.advance(301)  # lease expired
    ts = sm.claim("k1", "lease-2", revision={"scope": "s"})
    assert ts.lease_id == "lease-2"
    assert ts.attempts == 2


def test_release_completed_clears_lease():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    sm.release("k1", "completed", coverage_durable=True)
    ts = sm.get("k1")
    assert ts.status == "completed"
    assert ts.lease_id == ""
    assert ts.coverage_durable is True


def test_heartbeat_extends_lease_only_for_holder():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    assert sm.heartbeat("k1", "lease-1", ttl_s=600) is True
    ts = sm.get("k1")
    assert ts.lease_expires_at == clock.t + 600
    assert sm.heartbeat("k1", "lease-2") is False  # wrong holder


# --------------------------------------------------------------------------- #
# Recovery
# --------------------------------------------------------------------------- #

def test_recover_uncertain_running_expired():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    clock.advance(301)  # expire lease
    decisions = sm.recover_uncertain(now=clock.now, revision_ok=True)
    assert len(decisions) == 1
    assert decisions[0].action == "retry"
    assert decisions[0].chunk_key == "k1"
    assert decisions[0].lease_expired is True


def test_recover_uncertain_deferred():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    sm.release("k1", "deferred", reason="interrupted")
    decisions = sm.recover_uncertain(now=clock.now, revision_ok=True)
    assert len(decisions) == 1
    assert decisions[0].action == "retry"
    assert decisions[0].previous_status == "deferred"


def test_recover_incompatible_revision_requires_replan():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    clock.advance(301)
    decisions = sm.recover_uncertain(now=clock.now, revision_ok=False)
    assert len(decisions) == 1
    assert decisions[0].action == "replan"
    assert "revision" in decisions[0].reason


def test_recover_no_uncertain_when_all_completed():
    clock = FakeClock()
    sm = TaskStateMachine(now=clock.now, lease_ttl_s=300)
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    sm.release("k1", "completed", coverage_durable=True)
    decisions = sm.recover_uncertain(now=clock.now, revision_ok=True)
    assert decisions == []


# --------------------------------------------------------------------------- #
# snapshot
# --------------------------------------------------------------------------- #

def test_snapshot_returns_copy():
    sm = TaskStateMachine()
    sm.claim("k1", "lease-1", revision={"scope": "s"})
    snap = sm.snapshot()
    assert "k1" in snap
    snap.pop("k1")  # mutating the copy must not affect the machine
    assert sm.get("k1") is not None
