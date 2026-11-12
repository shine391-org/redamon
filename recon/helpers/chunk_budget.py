"""Optional per-origin / per-check-family budgets for recon continuation.

Budgets are optional and unbounded by default: a run that has not had its
trade-off approved uses no budget at all. When a budget is set it is fair per
origin and per check family, never deletes a candidate, and the backlog is
persisted with a supported continuation route.

Design rules (from the F16 DoD):
* Optional: no budget unless the operator sets one. Unbounded default.
* Fair: each origin and each check family gets its own counter; no origin can
  starve another, and no family can consume a whole origin's budget.
* No deletion: a candidate that exceeds its budget is deferred, not dropped.
  The backlog stays persisted and resumable.
* Persisted backlog: deferred candidates survive a restart and have a supported
  continuation route (the checkpoint journal + resume).

The ledger is serialized into the run's chunk journal (see
``ChunkJournal.save_budget`` / ``load_budget``), so a restart rebuilds the same
counters and a deferred backlog is not lost.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class _BudgetCounter:
    """One counter: a limit (None = unbounded), used, and deferred families."""

    limit: Optional[int] = None
    used: int = 0
    deferred: list[str] = field(default_factory=list)

    def remaining(self) -> Optional[int]:
        if self.limit is None:
            return None
        return max(0, self.limit - self.used)

    def admits(self) -> bool:
        """True when another candidate under this counter may run."""
        if self.limit is None:
            return True
        return self.used < self.limit

    def record(self, admitted: bool, check_family: str = "") -> None:
        if admitted:
            self.used += 1
        elif check_family and check_family not in self.deferred:
            self.deferred.append(check_family)


@dataclass
class OriginBudget:
    """One origin's remaining budget and deferred backlog."""

    origin: str
    limit: Optional[int] = None          # None = unbounded
    used: int = 0
    deferred: list[str] = field(default_factory=list)  # check family names

    def remaining(self) -> Optional[int]:
        if self.limit is None:
            return None
        return max(0, self.limit - self.used)

    def admits(self) -> bool:
        """True when another candidate of this origin may run."""
        if self.limit is None:
            return True
        return self.used < self.limit

    def record(self, check_family: str, *, admitted: bool) -> None:
        if admitted:
            self.used += 1
        else:
            if check_family not in self.deferred:
                self.deferred.append(check_family)


@dataclass
class BudgetLedger:
    """Per-origin, per-check-family budget accounting for one run."""

    #: origin -> OriginBudget
    origins: dict[str, OriginBudget] = field(default_factory=dict)
    #: check family -> counter (fairness across origins)
    family_budgets: dict[str, _BudgetCounter] = field(default_factory=dict)
    #: check family -> total used across origins (reporting; the legacy shape)
    families: dict[str, int] = field(default_factory=dict)

    def origin_for(self, origin: str) -> OriginBudget:
        budget = self.origins.get(origin)
        if budget is None:
            budget = OriginBudget(origin=origin)
            self.origins[origin] = budget
        return budget

    def family_for(self, check_family: str) -> _BudgetCounter:
        counter = self.family_budgets.get(check_family)
        if counter is None:
            counter = _BudgetCounter()
            self.family_budgets[check_family] = counter
        return counter

    def admits(self, origin: str, check_family: str) -> bool:
        """True when this (origin, family) candidate may run under budget."""
        if not self.origin_for(origin).admits():
            return False
        if not self.family_for(check_family).admits():
            return False
        return True

    def record(self, origin: str, check_family: str, *, admitted: bool) -> None:
        budget = self.origin_for(origin)
        budget.record(check_family, admitted=admitted)
        counter = self.family_for(check_family)
        counter.record(admitted, check_family=check_family)
        if admitted:
            self.families[check_family] = self.families.get(check_family, 0) + 1

    def set_limit(self, origin: str, limit: int, *,
                  check_family: Optional[str] = None) -> None:
        """Set an origin limit, or a per-family limit when ``check_family``."""
        if check_family is None:
            self.origin_for(origin).limit = max(0, int(limit))
        else:
            self.family_for(check_family).limit = max(0, int(limit))

    def snapshot(self) -> dict:
        return {
            "origins": {
                origin: {
                    "limit": b.limit,
                    "used": b.used,
                    "remaining": b.remaining(),
                    "deferred": list(b.deferred),
                }
                for origin, b in self.origins.items()
            },
            "families": dict(self.families),
            "family_budgets": {
                name: {
                    "limit": c.limit,
                    "used": c.used,
                    "remaining": c.remaining(),
                    "deferred": list(c.deferred),
                }
                for name, c in self.family_budgets.items()
            },
        }

    @classmethod
    def from_snapshot(cls, data: dict) -> "BudgetLedger":
        """Rebuild a ledger from ``snapshot()`` (a persisted journal line)."""
        ledger = cls()
        for origin, raw in (data.get("origins") or {}).items():
            budget = OriginBudget(
                origin=origin,
                limit=raw.get("limit"),
                used=int(raw.get("used") or 0),
                deferred=list(raw.get("deferred") or []),
            )
            ledger.origins[origin] = budget
        for name, raw in (data.get("family_budgets") or {}).items():
            counter = _BudgetCounter(
                limit=raw.get("limit"),
                used=int(raw.get("used") or 0),
                deferred=list(raw.get("deferred") or []),
            )
            ledger.family_budgets[name] = counter
        # Legacy shape: families was a flat {name: used} map.
        legacy_families = data.get("families")
        if isinstance(legacy_families, dict):
            for name, value in legacy_families.items():
                if isinstance(value, int):
                    ledger.families[str(name)] = value
        ledger.families.update({
            str(k): int(v) for k, v in (data.get("family_used") or {}).items()
        })
        return ledger
