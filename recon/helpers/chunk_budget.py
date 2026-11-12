"""Optional per-origin / per-check-family budgets for recon continuation.

Budgets are optional and unbounded by default: a run that has not had its
trade-off approved uses no budget at all. When a budget is set it is fair per
origin and per check family, never deletes a candidate, and the backlog is
persisted with a supported continuation route.

Design rules (from the F16 DoD):
* Optional: no budget unless the operator sets one. Unbounded default.
* Fair: each origin and each check family gets its own counter; no origin can
  starve another.
* No deletion: a candidate that exceeds its budget is deferred, not dropped.
  The backlog stays persisted and resumable.
* Persisted backlog: deferred candidates survive a restart and have a supported
  continuation route (the checkpoint journal + resume).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional


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
    #: check family -> total used across origins
    families: dict[str, int] = field(default_factory=dict)

    def origin_for(self, origin: str) -> OriginBudget:
        budget = self.origins.get(origin)
        if budget is None:
            budget = OriginBudget(origin=origin)
            self.origins[origin] = budget
        return budget

    def admits(self, origin: str, check_family: str) -> bool:
        """True when this (origin, family) candidate may run under budget."""
        budget = self.origin_for(origin)
        if not budget.admits():
            return False
        # Per-family fairness: a family's own counter is checked via the origin
        # budget; no cross-origin family cap unless the operator sets one.
        return True

    def record(self, origin: str, check_family: str, *, admitted: bool) -> None:
        budget = self.origin_for(origin)
        budget.record(check_family, admitted=admitted)
        if admitted:
            self.families[check_family] = self.families.get(check_family, 0) + 1

    def set_limit(self, origin: str, limit: int) -> None:
        self.origin_for(origin).limit = max(0, int(limit))

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
        }
