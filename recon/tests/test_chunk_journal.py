"""recon/helpers/chunk_journal.py — durable chunk checkpoint journal.

Hermetic: no Docker, no network, no graph. Uses tmp_path for the journal file
and an injected clock where the module accepts one (time-based lease expiry
is driven by time.monotonic via a patched now function).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers.chunk_journal import (
    ChunkJournal,
    ChunkEntry,
    JournalRevision,
    JournalError,
    RunMismatch,
    RevisionMismatch,
    SCHEMA_VERSION,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _revision(tenant="t", project="p", run="r", scope="s", settings="sh",
              template="tr", auth="ar") -> JournalRevision:
    return JournalRevision(tenant=tenant, project_id=project, run_id=run,
                           scope=scope, settings_hash=settings,
                           template_rev=template, auth_rev=auth)


def _entry(origin="origin-a", chunk_index=0, status="completed",
           coverage_durable=True, revision=None, lease_expires_at=None,
           run_id="r") -> ChunkEntry:
    rev = revision or {}
    if lease_expires_at is None:
        lease_expires_at = time.time() + 300
    return ChunkEntry(
        tenant="t", project_id="p", run_id=run_id,
        chunk_index=chunk_index, origin=origin,
        tool_ids=["nuclei"], status=status,
        lease_id="lease-1", lease_expires_at=lease_expires_at,
        started_at=time.time(), completed_at=time.time(),
        output_ref=None, coverage_durable=coverage_durable,
        revision=rev,
    )


def _write_journal(tmp_path: Path, lines: list[str]) -> Path:
    path = tmp_path / "chunk-journal"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# ChunkEntry roundtrip
# --------------------------------------------------------------------------- #

def test_entry_roundtrip_preserves_checksum():
    e = _entry()
    d = e.to_dict()
    assert d["checksum"] != ""
    e2 = ChunkEntry.from_dict(d)
    assert e2.entry_id == e.entry_id
    assert e2.origin == e.origin
    assert e2.status == e.status
    assert e2.coverage_durable == e.coverage_durable


def test_entry_checksum_changes_with_content():
    e1 = _entry(status="completed")
    e2 = _entry(status="running")
    assert e1.to_dict()["checksum"] != e2.to_dict()["checksum"]


# --------------------------------------------------------------------------- #
# Journal load: missing / empty / corrupted
# --------------------------------------------------------------------------- #

def test_missing_journal_returns_empty_snapshot(tmp_path):
    path = tmp_path / "does-not-exist"
    journal = ChunkJournal(path, _revision())
    snap = journal.load()
    assert snap.completed_keys() == set()
    assert snap.uncertain_keys(time.time()) == set()


def test_empty_journal_returns_empty_snapshot(tmp_path):
    path = _write_journal(tmp_path, [])
    journal = ChunkJournal(path, _revision())
    snap = journal.load()
    assert snap.completed_keys() == set()


def test_corrupted_line_degrades_to_last_valid_prefix(tmp_path):
    good = _entry(origin="a", chunk_index=0, status="completed",
                  coverage_durable=True)
    lines = [json.dumps(_revision().to_dict(), sort_keys=True),
             json.dumps(good.to_dict(), sort_keys=True),
             "{this is not json}"]
    path = _write_journal(tmp_path, lines)
    journal = ChunkJournal(path, _revision())
    snap = journal.load()
    assert ("a", 0) in snap.completed_keys()


def test_checksum_mismatch_truncates_journal(tmp_path):
    good = _entry(origin="a", chunk_index=0, status="completed",
                  coverage_durable=True)
    bad = _entry(origin="b", chunk_index=1, status="completed",
                 coverage_durable=True)
    bad_dict = bad.to_dict()
    bad_dict["checksum"] = "0000000000000000000000000000000000000000000000000000000000000000"
    lines = [json.dumps(_revision().to_dict(), sort_keys=True),
             json.dumps(good.to_dict(), sort_keys=True),
             json.dumps(bad_dict, sort_keys=True)]
    path = _write_journal(tmp_path, lines)
    journal = ChunkJournal(path, _revision())
    snap = journal.load()
    # 'a' completed, 'b' rejected due to bad checksum
    assert ("a", 0) in snap.completed_keys()
    assert ("b", 1) not in snap.completed_keys()


# --------------------------------------------------------------------------- #
# Revision validation
# --------------------------------------------------------------------------- #

def test_revision_mismatch_raises(tmp_path):
    path = _write_journal(tmp_path, [
        json.dumps(_revision(scope="old").to_dict(), sort_keys=True),
    ])
    journal = ChunkJournal(path, _revision(scope="new"))
    with pytest.raises(RevisionMismatch):
        journal.load()


def test_revision_match_passes(tmp_path):
    rev = _revision(scope="s1")
    path = _write_journal(tmp_path, [json.dumps(rev.to_dict(), sort_keys=True)])
    journal = ChunkJournal(path, rev)
    snap = journal.load()
    assert snap.completed_keys() == set()


# --------------------------------------------------------------------------- #
# Append + read back
# --------------------------------------------------------------------------- #

def test_append_entry_is_readable(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision())
    e = _entry(origin="o1", chunk_index=3, status="completed",
               coverage_durable=True)
    journal.append(e)
    snap = journal.load()
    assert ("o1", 3) in snap.completed_keys()


def test_append_overwrites_older_entry_for_same_chunk(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision())
    journal.append(_entry(origin="o1", chunk_index=0, status="running"))
    journal.append(_entry(origin="o1", chunk_index=0, status="completed",
                          coverage_durable=True))
    snap = journal.load()
    assert ("o1", 0) in snap.completed_keys()


def test_mark_completed_sets_coverage_durable(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision())
    e = _entry(origin="o1", chunk_index=0, status="running",
               coverage_durable=False)
    journal.mark_completed(e)
    snap = journal.load()
    entry = snap.chunks[("o1", 0)]
    assert entry.status == "completed"
    assert entry.coverage_durable is True


def test_mark_uncertain_sets_deferred(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision())
    e = _entry(origin="o1", chunk_index=0, status="running")
    journal.mark_uncertain(e)
    snap = journal.load()
    entry = snap.chunks[("o1", 0)]
    assert entry.status == "deferred"


# --------------------------------------------------------------------------- #
# Done / uncertain queries
# --------------------------------------------------------------------------- #

def test_is_done_only_true_when_completed_and_durable(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision())
    # completed without coverage durable -> not done
    journal.append(_entry(origin="o1", chunk_index=0, status="completed",
                          coverage_durable=False))
    assert journal.is_done("o1", 0) is False
    # completed with coverage durable -> done
    journal.append(_entry(origin="o1", chunk_index=0, status="completed",
                          coverage_durable=True))
    assert journal.is_done("o1", 0) is True
    # running -> not done
    journal.append(_entry(origin="o2", chunk_index=0, status="running"))
    assert journal.is_done("o2", 0) is False


def test_uncertain_returns_running_with_expired_lease(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision())
    now = time.time()
    # running with expired lease -> uncertain
    e = _entry(origin="o1", chunk_index=0, status="running",
               lease_expires_at=now - 10)
    journal.append(e)
    uncertain = journal.uncertain(now)
    assert any(e.origin == "o1" and e.chunk_index == 0 for e in uncertain)
    # completed+durable -> not uncertain
    journal.append(_entry(origin="o2", chunk_index=0, status="completed",
                          coverage_durable=True))
    uncertain = journal.uncertain(now)
    assert all(not (e.origin == "o2" and e.chunk_index == 0)
               for e in uncertain)


# --------------------------------------------------------------------------- #
# Atomic write: concurrent writers don't corrupt
# --------------------------------------------------------------------------- #

def test_concurrent_appends_do_not_corrupt(tmp_path):
    """Concurrent writers must not corrupt the journal AND must not lose any
    entry: a lost 'completed' entry makes the chunk re-run (duplicate work)."""
    path = tmp_path / "chunk-journal"
    import threading

    def writer(origin_prefix):
        journal = ChunkJournal(path, _revision())
        for i in range(5):
            journal.append(_entry(origin=f"{origin_prefix}-{i}",
                                  chunk_index=i, status="completed",
                                  coverage_durable=True))

    threads = [threading.Thread(target=writer, args=(f"t{n}",)) for n in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Journal must still load cleanly: no corruption from concurrent writers.
    journal = ChunkJournal(path, _revision())
    snap = journal.load()
    # EVERY writer's entries survived: 3 writers x 5 chunks.
    assert len(snap.completed_keys()) == 15
    for key in snap.completed_keys():
        entry = snap.chunks[key]
        assert entry.status == "completed"
        assert entry.coverage_durable is True


# --------------------------------------------------------------------------- #
# RevisionMismatch blocks incompatible resume
# --------------------------------------------------------------------------- #

def test_incompatible_snapshot_requires_replan(tmp_path):
    """A journal written under one scope cannot be silently resumed under another."""
    path = tmp_path / "chunk-journal"
    rev_a = _revision(scope="scope-a", settings="hash-a")
    rev_b = _revision(scope="scope-b", settings="hash-b")
    journal_a = ChunkJournal(path, rev_a)
    journal_a.append(_entry(origin="o1", chunk_index=0,
                            status="completed", coverage_durable=True,
                            revision={"scope": "scope-a", "settings_hash": "hash-a",
                                      "template_rev": "tr", "auth_rev": "ar"}))
    # Resume with different scope: must raise
    journal_b = ChunkJournal(path, rev_b)
    with pytest.raises(RevisionMismatch):
        journal_b.load()


# ---------------------------------------------------------------------------
# Run identity: a new run never reuses another run's checkpoints
# ---------------------------------------------------------------------------

def test_different_run_same_path_raises_run_mismatch(tmp_path):
    """A journal written under run-1 cannot be read as run-2: a new run cleared
    the graph and must start a fresh checkpoint, never silently resume."""
    path = tmp_path / "chunk-journal"
    journal_a = ChunkJournal(path, _revision(run="run-1"))
    journal_a.append(_entry(origin="o1", chunk_index=0, status="completed",
                            coverage_durable=True, run_id="run-1"))
    journal_b = ChunkJournal(path, _revision(run="run-2"))
    with pytest.raises(RunMismatch):
        journal_b.load()


def test_run_mismatch_is_not_a_revision_mismatch(tmp_path):
    """RunMismatch is a distinct failure: the caller starts fresh rather than
    treating it as an incompatible snapshot needing approval."""
    path = tmp_path / "chunk-journal"
    ChunkJournal(path, _revision(run="run-1")).append(
        _entry(origin="o1", chunk_index=0, status="completed",
               coverage_durable=True, run_id="run-1"))
    with pytest.raises(RunMismatch):
        ChunkJournal(path, _revision(run="run-2")).load()


def test_same_run_config_change_raises_revision_mismatch(tmp_path):
    """Same run, changed scope -> RevisionMismatch (replan/approval), not a
    silent fresh start."""
    path = tmp_path / "chunk-journal"
    ChunkJournal(path, _revision(run="run-1", scope="scope-a")).append(
        _entry(origin="o1", chunk_index=0, status="completed",
               coverage_durable=True, run_id="run-1"))
    with pytest.raises(RevisionMismatch):
        ChunkJournal(path, _revision(run="run-1", scope="scope-b")).load()


def test_same_run_same_config_resumes(tmp_path):
    path = tmp_path / "chunk-journal"
    rev = _revision(run="run-1", scope="scope-a")
    ChunkJournal(path, rev).append(_entry(origin="o1", chunk_index=0,
                                          status="completed",
                                          coverage_durable=True, run_id="run-1"))
    journal = ChunkJournal(path, rev)
    assert journal.is_done("o1", 0) is True


# ---------------------------------------------------------------------------
# Cross-process concurrent appends: no lost entries
# ---------------------------------------------------------------------------

def _mp_append_chunk(args):
    path, prefix, index, revision = args
    journal = ChunkJournal(path, revision)
    journal.append(_entry(origin=f"{prefix}-{index}", chunk_index=index,
                          status="completed", coverage_durable=True,
                          run_id=revision.run_id))


def test_concurrent_process_appends_do_not_lose_entries(tmp_path):
    """Separate PROCESSES appending concurrently must all survive: a per-process
    lock cannot serialize them, so the journal uses a cross-process flock."""
    import multiprocessing
    path = tmp_path / "chunk-journal"
    rev = _revision(run="run-1")
    procs = [multiprocessing.Process(target=_mp_append_chunk,
                                     args=((path, f"p{n}", i, rev),))
             for n in range(4) for i in range(5)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join()
    journal = ChunkJournal(path, rev)
    snap = journal.load()
    assert len(snap.completed_keys()) == 20


# ---------------------------------------------------------------------------
# Budget persistence
# ---------------------------------------------------------------------------

def test_budget_roundtrip_through_journal(tmp_path):
    """The optional budget ledger persists with the run's journal, so a
    deferred backlog survives a restart."""
    from recon.helpers.chunk_budget import BudgetLedger
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision(run="run-1"))
    ledger = BudgetLedger()
    ledger.set_limit("o1", 1)
    ledger.record("o1", "fam-a", admitted=True)
    ledger.record("o1", "fam-b", admitted=False)
    journal.save_budget(ledger.snapshot())

    restored = BudgetLedger.from_snapshot(journal.load_budget())
    assert restored.admits("o1", "fam-a") is False
    assert "fam-b" in restored.snapshot()["origins"]["o1"]["deferred"]


def test_no_budget_line_means_no_ledger(tmp_path):
    path = tmp_path / "chunk-journal"
    journal = ChunkJournal(path, _revision(run="run-1"))
    assert journal.load_budget() is None
