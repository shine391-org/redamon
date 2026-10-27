"""
Scan Queue — the queue dispatcher worker (plan Phase 2).

Mirrors scan_scheduler.py: the orchestrator owns admission + the spawn, so it owns
the TICK; the webapp owns the version freeze + history, so it owns the RUN. Each
tick:

  1. disk pre-check (C-9): defer the whole tick when free space on the scan-output
     filesystem is below JOB_QUEUE_MIN_FREE_DISK. A scan with no disk cannot run.
  2. peek candidates (GET /api/internal/job-queue/candidates) — NON-RESERVING (R1).
  3. walk them in order with a head-of-line reserve against the ledger: for each
     job take its OWN envelope; if it exceeds the remaining budget, BREAK rather
     than skip ahead, so a big job (2.5 GB GVM) is never starved by a stream of
     small ones. Also stop at the JOB_QUEUE_MAX_CONCURRENT ceiling (C-9).
  4. ask the webapp to dispatch each that fits (POST .../{id}/dispatch), which runs
     the identical start path a manual scan uses. try_admit inside that start path
     is still the ONLY thing that reserves (R1); this peek can at worst waste one
     start attempt, never cause an OOM.

Never raises into the event loop.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import resource_governor as rg
from webapp_client import internal_key, request_json, webapp_base

logger = logging.getLogger(__name__)

DEFAULT_TICK_SECONDS = 20.0
MIN_TICK_SECONDS = 5.0
_FALLBACK_MAX_CONCURRENT = 4
_FALLBACK_MIN_FREE_DISK = 10 * 1024 ** 3  # 10 GB


def dispatcher_enabled() -> bool:
    raw = (os.environ.get("JOB_QUEUE_DISPATCHER_ENABLED", "true") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def tick_seconds() -> float:
    try:
        value = float(os.environ.get("JOB_QUEUE_TICK_SECONDS", "") or DEFAULT_TICK_SECONDS)
    except (TypeError, ValueError):
        return DEFAULT_TICK_SECONDS
    return max(MIN_TICK_SECONDS, value)


def max_concurrent() -> int:
    """The dispatcher's OWN hard ceiling (C-9). The ledger's count cap is None when
    RECON_MAX_CONCURRENT_GLOBAL is unset, so do not rely on it; this is the real one."""
    raw = os.environ.get("JOB_QUEUE_MAX_CONCURRENT")
    if raw is None or raw.strip() == "":
        return _FALLBACK_MAX_CONCURRENT
    try:
        return max(0, int(float(raw)))
    except (TypeError, ValueError):
        return _FALLBACK_MAX_CONCURRENT


def min_free_disk() -> int:
    raw = os.environ.get("JOB_QUEUE_MIN_FREE_DISK")
    if raw is None or raw.strip() == "":
        return _FALLBACK_MIN_FREE_DISK
    try:
        return max(0, int(float(raw)))
    except (TypeError, ValueError):
        return _FALLBACK_MIN_FREE_DISK


def _free_disk_bytes() -> Optional[int]:
    stats = rg.disk_stats()
    return stats[1] if stats else None


def run_dispatcher_tick(container_manager) -> dict:
    """One pass. Blocking (called via asyncio.to_thread). Returns a small summary."""
    base, key = webapp_base(), internal_key()
    summary = {"candidates": 0, "dispatched": 0, "deferred": 0, "failed": 0, "disk_blocked": False}
    if not key:
        return summary

    # 1. Disk floor (C-9): a scan needs somewhere to write its output.
    free = _free_disk_bytes()
    floor = min_free_disk()
    if free is not None and free < floor:
        summary["disk_blocked"] = True
        logger.info(
            "[jobDispatcher] disk below floor (%s MB free < %s MB) - deferring tick",
            free // (1024 ** 2), floor // (1024 ** 2),
        )
        return summary

    data = request_json(f"{base}/api/internal/job-queue/candidates", key, tag="jobDispatcher")
    if not data:
        return summary

    candidates = data.get("candidates") or []
    active = int(data.get("activeCount") or 0)
    summary["candidates"] = len(candidates)

    ledger = getattr(container_manager, "ledger", None)
    cap = max_concurrent()

    def budget() -> Optional[int]:
        if ledger is None:
            return None
        try:
            return ledger.remaining_for_new()
        except Exception:  # noqa: BLE001
            return None

    remaining = budget()
    # Projects we have already dispatched THIS tick. The candidates endpoint already
    # excludes projects busy from a PRIOR tick, but two queued jobs for one project
    # can both arrive in the same list; once we dispatch one, the other cannot run
    # (one-per-project), so skip it BEFORE the head-of-line RAM break, or it would
    # starve everyone behind it (Finding 2).
    dispatched_projects: set = set()

    for job in candidates:
        if active >= cap:
            break
        pid = job.get("projectId")
        if pid in dispatched_projects:
            continue  # already dispatched a job for this project this tick
        kind = job.get("kind", "")
        # This job's OWN envelope; do not hardcode full_recon's.
        env = 0
        if ledger is not None:
            try:
                env = ledger.envelope_for(kind)
            except Exception:  # noqa: BLE001
                env = int(job.get("envelopeBytes") or 0)
        else:
            env = int(job.get("envelopeBytes") or 0)

        # Head-of-line reserve: if the head job does not fit, do NOT skip ahead.
        if remaining is not None and env > remaining:
            break

        res = request_json(
            f"{base}/api/internal/job-queue/{job.get('id')}/dispatch", key, "POST", {}, tag="jobDispatcher",
        )
        if res is None:
            summary["failed"] += 1
            continue
        if res.get("ok"):
            summary["dispatched"] += 1
            active += 1
            dispatched_projects.add(pid)
            remaining = budget()
            continue

        # Not dispatched. A capacity-bound block (RAM / hard cap / disk) means every
        # later job is also capacity-bound, so stop; so does a transient refusal (an
        # orchestrator-wide 5xx), which would otherwise spend one attempt of every
        # candidate in a single tick. Any OTHER outcome (busy, agent, needs_review,
        # permanent failure) is per-project/per-job, so try other projects - but mark
        # THIS project handled so a sibling of it cannot trip the head-of-line RAM
        # break below and starve everyone (Finding 2).
        summary["deferred"] += 1
        blocked = res.get("blocked")
        if blocked in ("ram", "hard", "disk", "transient"):
            break
        dispatched_projects.add(pid)

    return summary


# Both the periodic loop AND the reaper's "capacity just freed" trigger want to
# dispatch. They must not run concurrently, or both fetch the same candidates and
# race on the per-row claim (the loser gets a benign 409 that looks like a
# failure). asyncio is single-threaded, so the check-and-set below is atomic (no
# await between them); a tick already in flight makes the other a no-op.
_tick_in_progress = False


async def _guarded_tick(container_manager) -> Optional[dict]:
    global _tick_in_progress
    if _tick_in_progress:
        return None
    _tick_in_progress = True
    try:
        return await asyncio.to_thread(run_dispatcher_tick, container_manager)
    finally:
        _tick_in_progress = False


async def job_dispatcher_loop(get_container_manager) -> None:
    """Background task: tick forever. `get_container_manager` is a callable so the
    loop picks up the manager once lifespan startup has created it."""
    if not dispatcher_enabled():
        logger.info("[jobDispatcher] disabled (JOB_QUEUE_DISPATCHER_ENABLED=false)")
        return
    interval = tick_seconds()
    logger.info("[jobDispatcher] started (tick=%ss, max_concurrent=%s)", interval, max_concurrent())
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                cm = get_container_manager()
                if cm is None:
                    continue
                summary = await _guarded_tick(cm)
                if summary and summary["candidates"]:
                    logger.info(
                        "[jobDispatcher] tick: %s candidates, %s dispatched, %s deferred, %s failed",
                        summary["candidates"], summary["dispatched"],
                        summary["deferred"], summary["failed"],
                    )
            except Exception as e:  # noqa: BLE001 - never let one tick kill the loop
                logger.warning("[jobDispatcher] tick failed: %s", e)
    except asyncio.CancelledError:
        pass


async def run_one_dispatch_tick(container_manager) -> dict:
    """Single tick, for the 'capacity just freed' trigger fired from the reaper
    after reconcile_reservations. Safe to call even when the loop is disabled."""
    if not dispatcher_enabled() or container_manager is None:
        return {"candidates": 0, "dispatched": 0, "deferred": 0, "failed": 0, "disk_blocked": False}
    try:
        # Serialized against the periodic loop; a no-op if a tick is already running.
        return await _guarded_tick(container_manager) or {
            "candidates": 0, "dispatched": 0, "deferred": 0, "failed": 0, "disk_blocked": False}
    except Exception as e:  # noqa: BLE001
        logger.warning("[jobDispatcher] one-shot tick failed: %s", e)
        return {"candidates": 0, "dispatched": 0, "deferred": 0, "failed": 0, "disk_blocked": False}
