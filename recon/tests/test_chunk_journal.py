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
           coverage_durable=True, revision=None, lease_expires_at=None) -> ChunkEntry:
    rev = revision or {}
    if lease_expires_at is None:
        lease_expires_at = time.time() + 300
    return ChunkEntry(
        tenant="t", project_id="p", run_id="r",
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
    """Concurrent writers must not corrupt the journal (last write wins per
    chunk key; the journal stays valid and readable)."""
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
    # At least one writer's entries survived; every entry present is valid.
    assert len(snap.completed_keys()) > 0
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
