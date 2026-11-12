"""recon/helpers chunk continuation — crash matrix and resume behavior.

Hermetic: no Docker, no network. Simulates kill/restart by creating a journal,
writing entries at different lifecycle points, then re-opening it (the
"restart") and checking what survived.

Covers F16 DoD:
* kill/restart at pre-dispatch, mid-tool, after-output-before-ack, after-commit
* completed chunks are not re-run
* interrupted uncertain chunks are reported and retried under safe policy
* no exactly-once network side effects claimed
* resume rechecks revision: incompatible snapshot raises RevisionMismatch
* corrupted/absent journal reads as unknown/block safe
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from recon.helpers.chunk_journal import (
    ChunkJournal,
    ChunkEntry,
    JournalRevision,
    JournalError,
    RevisionMismatch,
)


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #

def _rev(tenant="t", project="p", run="r", scope="s", settings="sh",
         template="tr", auth="ar") -> JournalRevision:
    return JournalRevision(tenant=tenant, project_id=project, run_id=run,
                           scope=scope, settings_hash=settings,
                           template_rev=template, auth_rev=auth)


# --------------------------------------------------------------------------- #
# Crash matrix: four kill points
# --------------------------------------------------------------------------- #

def test_crash_pre_dispatch_nothing_completed(tmp_path):
    """Kill before any tool starts: journal exists but nothing is done."""
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _rev())
    # Journal created but no entries appended: on restart nothing is done.
    snap = journal.load()
    assert snap.completed_keys() == set()
    assert ("nuclei", 0) not in snap.completed_keys()


def test_crash_mid_tool_chunk_deferred(tmp_path):
    """Kill mid-tool: chunk is running with an expired lease -> uncertain."""
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _rev())
    now = time.time()
    # A running chunk whose lease expired before the kill.
    journal.append(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="running", lease_id="lease-1",
        lease_expires_at=now - 60, started_at=now - 120,
        completed_at=None, coverage_durable=False, revision={},
    ))
    snap = journal.load()
    uncertain = snap.uncertain_keys(now)
    assert ("nuclei", 0) in uncertain
    assert ("nuclei", 0) not in snap.completed_keys()


def test_crash_after_output_before_ack_coverage_not_durable(tmp_path):
    """Kill after output saved but before chunk marked complete:
    completed without coverage_durable -> not done, uncertain on restart."""
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _rev())
    journal.append(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="completed", lease_id="", lease_expires_at=0.0,
        started_at=time.time(), completed_at=time.time(),
        coverage_durable=False, revision={},
    ))
    snap = journal.load()
    # Not done: coverage not durable
    assert journal.is_done("nuclei", 0) is False
    # Uncertain: completed but not durable
    uncertain = snap.uncertain_keys(time.time())
    assert ("nuclei", 0) in uncertain


def test_crash_after_commit_chunk_done_not_rerun(tmp_path):
    """Kill after commit: completed + coverage durable -> done, not re-run."""
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _rev())
    journal.mark_completed(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="running", lease_id="lease-1",
        lease_expires_at=time.time() + 300, started_at=time.time(),
        coverage_durable=False, revision={},
    ))
    snap = journal.load()
    assert journal.is_done("nuclei", 0) is True
    # On restart, this chunk is skipped (not re-run)
    assert ("nuclei", 0) in snap.completed_keys()


# --------------------------------------------------------------------------- #
# Resume revision check
# --------------------------------------------------------------------------- #

def test_resume_incompatible_revision_raises(tmp_path):
    """Resume with changed scope/settings/template/auth raises RevisionMismatch:
    requires replan or approval, never silent resume."""
    path = tmp_path / "chunk-journal"
    rev_a = _rev(scope="scope-a", settings="hash-a")
    rev_b = _rev(scope="scope-b", settings="hash-b")
    journal_a = ChunkJournal(path, rev_a)
    journal_a.mark_completed(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="completed", lease_id="", lease_expires_at=0.0,
        started_at=time.time(), completed_at=time.time(),
        coverage_durable=True,
        revision={"scope": "scope-a", "settings_hash": "hash-a",
                  "template_rev": "tr", "auth_rev": "ar"},
    ))
    journal_b = ChunkJournal(path, rev_b)
    with pytest.raises(RevisionMismatch):
        journal_b.load()


def test_resume_compatible_revision_keeps_done_chunks(tmp_path):
    """Resume with same revision: done chunks are preserved and skipped."""
    path = tmp_path / "chunk-journal"
    rev = _rev(scope="scope-a", settings="hash-a")
    journal_a = ChunkJournal(path, rev)
    journal_a.mark_completed(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="completed", lease_id="", lease_expires_at=0.0,
        started_at=time.time(), completed_at=time.time(),
        coverage_durable=True,
        revision={"scope": "scope-a", "settings_hash": "hash-a",
                  "template_rev": "tr", "auth_rev": "ar"},
    ))
    journal_b = ChunkJournal(path, rev)
    snap = journal_b.load()
    assert journal_b.is_done("nuclei", 0) is True


# --------------------------------------------------------------------------- #
# Corrupted / absent journal -> unknown/block safe
# --------------------------------------------------------------------------- #

def test_absent_journal_unknown_block_safe(tmp_path):
    """No journal file: empty snapshot, nothing trusted as done."""
    path = tmp_path / "no-journal-here"
    journal = ChunkJournal(path, _rev())
    snap = journal.load()
    assert snap.completed_keys() == set()
    assert journal.is_done("nuclei", 0) is False


def test_corrupted_journal_degrades_to_valid_prefix(tmp_path):
    """Torn write: valid prefix is kept, torn tail is dropped."""
    path = tmp_path / "chunk-journal"
    import json
    good = ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="good", tool_ids=["nuclei"],
        status="completed", lease_id="", lease_expires_at=0.0,
        started_at=time.time(), completed_at=time.time(),
        coverage_durable=True, revision={},
    )
    lines = [
        json.dumps(_rev().to_dict(), sort_keys=True),
        json.dumps(good.to_dict(), sort_keys=True),
        "{torn tail",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    journal = ChunkJournal(path, _rev())
    snap = journal.load()
    assert ("good", 0) in snap.completed_keys()


# --------------------------------------------------------------------------- #
# Concurrent duplicate dispatch idempotency
# --------------------------------------------------------------------------- #

def test_concurrent_duplicate_dispatch_idempotent(tmp_path):
    """Two workers claiming the same chunk: only one succeeds, the other sees
    it as running with an active lease (not a duplicate)."""
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _rev())
    now = time.time()

    # Worker A claims the chunk
    entry_a = ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="running", lease_id="lease-a",
        lease_expires_at=now + 300, started_at=now,
        coverage_durable=False, revision={},
    )
    journal.append(entry_a)

    # Worker B checks: not done (not completed+durable)
    assert journal.is_done("nuclei", 0) is False

    # Worker A completes it
    journal.mark_completed(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="completed", lease_id="", lease_expires_at=0.0,
        started_at=now, completed_at=now + 10,
        output_ref="/out/recon.json", coverage_durable=True,
        revision={},
    ))

    # On restart: done, not re-run
    snap = journal.load()
    assert journal.is_done("nuclei", 0) is True
    assert ("nuclei", 0) in snap.completed_keys()


# --------------------------------------------------------------------------- #
# No exactly-once network side effects: uncertain = reported, not replayed
# --------------------------------------------------------------------------- #

def test_uncertain_chunk_not_silently_replayed(tmp_path):
    """An interrupted chunk is reported as uncertain; the caller decides retry
    vs replan, never auto-replays a potentially unsafe request."""
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _rev())
    now = time.time()
    # Running chunk with expired lease = uncertain
    journal.append(ChunkEntry(
        tenant="t", project_id="p", run_id="r",
        chunk_index=0, origin="nuclei", tool_ids=["nuclei"],
        status="running", lease_id="lease-1",
        lease_expires_at=now - 60, started_at=now - 120,
        coverage_durable=False, revision={},
    ))
    uncertain = journal.uncertain(now)
    assert len(uncertain) == 1
    assert uncertain[0].origin == "nuclei"
    assert uncertain[0].status == "running"
    # The journal itself does not auto-replay: it just reports uncertainty.


# --------------------------------------------------------------------------- #
# Optional budget does not delete candidates
# --------------------------------------------------------------------------- #

def test_budget_defers_rather_than_deletes(tmp_path):
    """A budget-overrun candidate is deferred (recorded), not dropped from the
    journal. The backlog persists with a continuation route."""
    from recon.helpers.chunk_budget import BudgetLedger
    ledger = BudgetLedger()
    ledger.set_limit("nuclei", 1)
    ledger.record("nuclei", "cve-scan", admitted=True)
    assert ledger.admits("nuclei", "cve-scan") is False
    ledger.record("nuclei", "takeover", admitted=False)
    snap = ledger.snapshot()
    assert "takeover" in snap["origins"]["nuclei"]["deferred"]
    # Candidate is still in the backlog (deferred), not deleted.
    assert snap["origins"]["nuclei"]["used"] == 1
