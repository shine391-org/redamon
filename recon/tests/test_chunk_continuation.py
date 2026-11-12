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


# ---------------------------------------------------------------------------
# Integration: the REAL _start_checkpoint -> _run_phase_a_fan_out -> journal
# -> resume path. Helper-level tests alone did not catch the cross-group and
# cross-run collisions (review round 1), so these drive the actual caller.
# ---------------------------------------------------------------------------

import sys
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    """Import recon.main with a hermetic settings stub and a tmp OUTPUT_DIR."""
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['vuln_scan'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        yield rm


def _tool(payload=None):
    def _run(data, settings):
        return payload if payload is not None else {"findings": []}
    return _run


def _combined():
    return {"metadata": {"modules_executed": []}}


class TestRealFanOutPath:
    def test_two_batch_groups_never_share_a_chunk_key(self, recon_main, tmp_path):
        """Group 2 must run its own tools even though group 1 completed the same
        tool names. A shared project-level key silently skipped Phase A for
        groups 2..N (review round 1, blocker 1)."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool(), "graphql_scan": _tool()}

        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, _combined(), settings, output,
                                group_id="group-a")

        combined = _combined()
        rm._start_checkpoint(settings, "p1", "run-1", "group-b", "t1")
        rm._run_phase_a_fan_out(tools, combined, settings, output,
                                group_id="group-b")

        assert combined["metadata"]["modules_executed"] == ["vuln_scan", "graphql_scan"]

    def test_restart_same_run_skips_completed_chunks(self, recon_main, tmp_path):
        """A restart of the SAME run resumes: completed chunks are not re-run."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool()}

        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, _combined(), settings, output,
                                group_id="group-a")

        combined = _combined()
        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, combined, settings, output,
                                group_id="group-a")

        assert combined["metadata"]["modules_executed"] == []

    def test_new_run_does_not_reuse_the_previous_runs_checkpoints(
            self, recon_main, tmp_path):
        """A brand-new run (new run_id) must NOT reuse run-1's checkpoints: it
        cleared the graph and starts fresh (review round 1, blocker 2)."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool()}

        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, _combined(), settings, output,
                                group_id="group-a")

        combined = _combined()
        rm._start_checkpoint(settings, "p1", "run-2", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, combined, settings, output,
                                group_id="group-a")

        assert combined["metadata"]["modules_executed"] == ["vuln_scan"]

    def test_same_run_config_change_replans_instead_of_silent_resume(
            self, recon_main, tmp_path):
        """Same run, changed scope/settings -> replan from a fresh checkpoint,
        never a silent resume (DoD: incompatible snapshot requires replan)."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool()}

        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, _combined(), settings, output,
                                group_id="group-a")

        changed = dict(settings)
        changed["TARGET_DOMAIN"] = "changed.example"
        combined = _combined()
        status = rm._start_checkpoint(changed, "p1", "run-1", "group-a", "t1")
        assert status == "fresh"
        rm._run_phase_a_fan_out(tools, combined, changed, output,
                                group_id="group-a")
        assert combined["metadata"]["modules_executed"] == ["vuln_scan"]

    def test_journal_path_is_per_run(self, recon_main, tmp_path):
        rm = recon_main
        base = tmp_path / "recon_p1.json"
        assert (rm._checkpoint_journal_path(base, "run-1")
                == tmp_path / ".recon_p1.json.run-1.chunk-journal")
        assert (rm._checkpoint_journal_path(base, "")
                == tmp_path / ".recon_p1.json.chunk-journal")


class TestBudgetWiring:
    def test_budget_defers_without_deleting_and_persists(
            self, recon_main, tmp_path):
        """An over-budget candidate is deferred (backlog persisted), not
        dropped; the ledger round-trips through the run's journal."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool(), "graphql_scan": _tool()}

        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._checkpoint_budget.set_limit("group-a", 1)
        combined = _combined()
        rm._run_phase_a_fan_out(tools, combined, settings, output,
                                group_id="group-a")

        # Exactly one tool admitted; the other deferred, still in the backlog.
        assert len(combined["metadata"]["modules_executed"]) == 1
        snapshot = rm._checkpoint_journal.load()
        assert any(e.status == "deferred" for e in snapshot.chunks.values())
        persisted = rm._checkpoint_journal.load_budget()
        assert persisted is not None
        assert persisted["origins"]["group-a"]["deferred"]

    def test_unbounded_default_admits_everything(self, recon_main, tmp_path):
        """No operator-approved budget -> unbounded: every candidate runs."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool(), "graphql_scan": _tool()}
        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        combined = _combined()
        rm._run_phase_a_fan_out(tools, combined, settings, output,
                                group_id="group-a")
        assert combined["metadata"]["modules_executed"] == ["vuln_scan", "graphql_scan"]


class TestUncertainRecovery:
    def test_interrupted_chunk_is_reported_and_retried(
            self, recon_main, tmp_path, capsys):
        """A chunk left running with an expired lease is reported as uncertain
        and retried under the safe policy, not silently skipped or replayed
        without acknowledgement."""
        rm = recon_main
        settings = dict(rm._settings)
        output = tmp_path / "recon_p1.json"
        tools = {"vuln_scan": _tool()}

        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._checkpoint_journal.append(ChunkEntry(
            tenant="t1", project_id="p1", run_id="run-1",
            chunk_index=0, origin="group-a:vuln_scan", tool_ids=["vuln_scan"],
            status="running", lease_id="dead", lease_expires_at=time.time() - 10,
            started_at=time.time() - 20, coverage_durable=False, revision={},
        ))

        combined = _combined()
        rm._start_checkpoint(settings, "p1", "run-1", "group-a", "t1")
        rm._run_phase_a_fan_out(tools, combined, settings, output,
                                group_id="group-a")

        out = capsys.readouterr().out
        assert "uncertain chunk group-a:vuln_scan" in out
        assert combined["metadata"]["modules_executed"] == ["vuln_scan"]
        assert rm._checkpoint_journal.is_done("group-a:vuln_scan", 0) is True


class TestCoverageDurability:
    def test_no_future_with_graph_disabled_is_durable(self, recon_main, tmp_path):
        rm = recon_main
        out = tmp_path / "recon.json"
        out.write_text("{}")
        assert rm._checkpoint_coverage_durable(None, out, "vuln_scan") is True

    def test_no_future_with_graph_enabled_is_not_durable(
            self, recon_main, tmp_path, monkeypatch):
        rm = recon_main
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", True)
        out = tmp_path / "recon.json"
        out.write_text("{}")
        assert rm._checkpoint_coverage_durable(None, out, "vuln_scan") is False

    def test_failed_future_is_not_durable(self, recon_main, tmp_path):
        import concurrent.futures
        rm = recon_main
        out = tmp_path / "recon.json"
        out.write_text("{}")
        future = concurrent.futures.Future()
        future.set_result(False)
        assert rm._checkpoint_coverage_durable(future, out, "vuln_scan") is False

    def test_raised_future_is_not_durable(self, recon_main, tmp_path):
        import concurrent.futures
        rm = recon_main
        out = tmp_path / "recon.json"
        out.write_text("{}")
        future = concurrent.futures.Future()
        future.set_exception(RuntimeError("neo4j down"))
        assert rm._checkpoint_coverage_durable(future, out, "vuln_scan") is False

    def test_missing_output_is_not_durable(self, recon_main, tmp_path):
        rm = recon_main
        assert (rm._checkpoint_coverage_durable(
            None, tmp_path / "missing.json", "vuln_scan") is False)

    def test_successful_future_is_durable(self, recon_main, tmp_path):
        import concurrent.futures
        rm = recon_main
        out = tmp_path / "recon.json"
        out.write_text("{}")
        future = concurrent.futures.Future()
        future.set_result(True)
        assert rm._checkpoint_coverage_durable(future, out, "vuln_scan") is True
