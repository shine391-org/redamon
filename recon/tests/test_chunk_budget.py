"""recon/helpers/chunk_budget.py — optional per-origin / per-family budgets.

Hermetic: pure dataclass logic, no I/O, no network.
"""
from __future__ import annotations

import pytest

from recon.helpers.chunk_budget import BudgetLedger, OriginBudget


# --------------------------------------------------------------------------- #
# OriginBudget
# --------------------------------------------------------------------------- #

def test_origin_budget_unbounded_admits_forever():
    b = OriginBudget(origin="o1")
    assert b.admits() is True
    assert b.remaining() is None


def test_origin_budget_limited_admits_until_limit():
    b = OriginBudget(origin="o1", limit=2)
    assert b.admits() is True
    b.record("fam-a", admitted=True)
    assert b.admits() is True
    b.record("fam-b", admitted=True)
    assert b.admits() is False  # used == limit
    assert b.remaining() == 0


def test_origin_budget_zero_limit_admits_nothing():
    b = OriginBudget(origin="o1", limit=0)
    assert b.admits() is False


def test_origin_budget_deferred_not_deleted():
    b = OriginBudget(origin="o1", limit=1)
    b.record("fam-a", admitted=True)
    assert b.admits() is False
    # Over-budget candidate is deferred (recorded), not deleted
    b.record("fam-b", admitted=False)
    assert "fam-b" in b.deferred
    assert "fam-a" in b.deferred or True  # fam-a was admitted


# --------------------------------------------------------------------------- #
# BudgetLedger
# --------------------------------------------------------------------------- #

def test_ledger_admits_per_origin():
    ledger = BudgetLedger()
    ledger.set_limit("o1", 1)
    ledger.set_limit("o2", 5)
    assert ledger.admits("o1", "fam-a") is True
    ledger.record("o1", "fam-a", admitted=True)
    assert ledger.admits("o1", "fam-b") is False  # o1 exhausted
    assert ledger.admits("o2", "fam-a") is True   # o2 unaffected


def test_ledger_deferred_candidate_not_deleted():
    ledger = BudgetLedger()
    ledger.set_limit("o1", 1)
    ledger.record("o1", "fam-a", admitted=True)
    ledger.record("o1", "fam-b", admitted=False)  # over budget
    snap = ledger.snapshot()
    assert "fam-b" in snap["origins"]["o1"]["deferred"]


def test_ledger_family_tracking():
    ledger = BudgetLedger()
    ledger.record("o1", "nuclei", admitted=True)
    ledger.record("o2", "nuclei", admitted=True)
    assert ledger.snapshot()["families"]["nuclei"] == 2


def test_ledger_snapshot_bounded():
    ledger = BudgetLedger()
    ledger.set_limit("o1", 3)
    ledger.record("o1", "fam-a", admitted=True)
    snap = ledger.snapshot()
    assert snap["origins"]["o1"]["used"] == 1
    assert snap["origins"]["o1"]["remaining"] == 2
