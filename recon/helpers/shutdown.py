"""What a recon or partial-recon container does when it is told to stop.

Python is PID 1 in these containers (the entrypoint execs it), and Linux does
not deliver a signal from outside the PID namespace to a PID 1 that installed
no handler. Python installs one only for SIGINT, so a `docker stop` used to be
ignored until the SIGKILL: no queued graph write landed and the node-filter
sweep (the operator's mute rules) never ran.

The handler raises nothing. Raising SystemExit would unwind through the
pipeline's `with ThreadPoolExecutor` blocks, which wait for every running AND
queued task, and partial recon catches SystemExit per root and moves on to the
next one, so the grace would run out with the scan still going. Instead the
handler sets a flag and wakes a stopper thread, which:

  1. sends SIGTERM to every descendant (an attached `docker run` CLI forwards
     it to its tool container; the orchestrator removes those containers too);
  2. waits for the registered drains (the background graph writer) until a
     deadline inside the orchestrator's grace (RECON_STOP_GRACE_S);
  3. runs the node-filter sweep, once;
  4. exits 143. When PID 1 exits, the kernel kills every other process in the
     container.

While the flag is set, no new process starts (`subprocess.Popen` refuses), and
the pipeline drops new graph writes and refuses the prune. In-process Python
traffic already in flight (security checks, OSINT calls, JS downloads) is not
killed: refusing new work keeps it to what is in flight, and the deadline
bounds it.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from typing import Callable, Optional

DEFAULT_GRACE_S = 45.0
# The part of the grace kept back from the graph drain for the sweep and the
# exit, so the orchestrator's SIGKILL at the end of the grace lands after both.
MAX_SWEEP_MARGIN_S = 10.0
EXIT_CODE = 143  # 128 + SIGTERM, what a process killed by SIGTERM reports

_STOP = threading.Event()
_drains: list = []
_sweep: Optional[Callable[[], None]] = None
_sweep_lock = threading.Lock()
_sweep_done = False
_stopper: Optional[threading.Thread] = None


class ToolLaunchRefused(OSError):
    """A process start refused because the run is stopping."""


def stop_requested() -> bool:
    return _STOP.is_set()


def grace_seconds() -> float:
    """RECON_STOP_GRACE_S from the environment; blank or invalid means 45."""
    raw = (os.environ.get("RECON_STOP_GRACE_S") or "").strip()
    try:
        value = float(raw) if raw else DEFAULT_GRACE_S
    except ValueError:
        value = DEFAULT_GRACE_S
    return value if value > 0 else DEFAULT_GRACE_S


def drain_deadline(started: float, grace: float) -> float:
    """When the drains must give up (time.monotonic() clock)."""
    return started + grace - min(MAX_SWEEP_MARGIN_S, grace / 4)


def register_drain(fn: Callable[[float], None]) -> None:
    """`fn(deadline)` waits for this module's pending writes, at most until deadline."""
    if fn not in _drains:
        _drains.append(fn)


def set_sweep(fn: Callable[[], None]) -> None:
    """The node-filter sweep of the run starting now; it has not run yet."""
    global _sweep, _sweep_done
    with _sweep_lock:
        _sweep = fn
        _sweep_done = False


def sweep_once() -> bool:
    """Run the registered sweep unless it already ran. The end of a run and the
    stopper both call this; the second waits for the first, then skips."""
    global _sweep_done
    with _sweep_lock:
        if _sweep_done or _sweep is None:
            return False
        _sweep_done = True
        _sweep()
        return True


def park() -> None:
    """Block the calling thread for good: the stopper ends the process."""
    if _STOP.is_set():
        threading.Event().wait()


def install() -> None:
    """Install the SIGTERM handler and the process-start guard. Main thread only."""
    global _stopper
    if _stopper is not None:
        return
    _guard_popen()
    # Started now and parked on the flag: the handler only sets an Event,
    # because starting a thread inside a signal handler can deadlock on a lock
    # the interrupted main thread holds.
    _stopper = threading.Thread(target=_stop_when_asked, name="recon-stopper", daemon=True)
    _stopper.start()
    signal.signal(signal.SIGTERM, _on_sigterm)


def _on_sigterm(_signum, _frame) -> None:
    if _STOP.is_set():
        return
    # os.write, not print: a print here can raise "reentrant call" when the
    # signal lands while the main thread is inside a print.
    os.write(2, b"\n[!][Pipeline] Stop requested: ending this run's tools, landing the "
                b"queued graph writes, then applying the mute rules\n")
    _STOP.set()


def _say(line: str) -> None:
    print(line, flush=True)


def _stop_when_asked() -> None:
    _STOP.wait()
    started = time.monotonic()
    deadline = drain_deadline(started, grace_seconds())
    signal_descendants(signal.SIGTERM)
    for drain in list(_drains):
        try:
            drain(deadline)
        except Exception as e:  # noqa: BLE001 - a failed drain must not skip the sweep
            _say(f"[!][Pipeline] Stop: a drain failed: {e}")
    _say("[*][Pipeline] Stop: applying the mute rules (node-filter sweep)")
    try:
        sweep_once()
    except Exception as e:  # noqa: BLE001
        _say(f"[!][Pipeline] Stop: the node-filter sweep failed: {e}")
    _say(f"[!][Pipeline] Stopped after {time.monotonic() - started:.1f}s (exit {EXIT_CODE})")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # noqa: BLE001
            pass
    os._exit(EXIT_CODE)


def signal_descendants(sig) -> None:
    """Send `sig` to every process this one started, directly or not."""
    if os.getpid() == 1:
        # Every process in the container's namespace but PID 1 itself. Only as
        # PID 1: anywhere else (a test, a CLI run) -1 means every process the
        # user owns.
        try:
            os.kill(-1, sig)
        except (ProcessLookupError, PermissionError):
            pass
        return
    for pid in descendants(os.getpid()):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass


def descendants(root: int, proc: str = "/proc") -> list:
    """Descendant pids of `root`, read from /proc (the image has no procps)."""
    children: dict = {}
    try:
        entries = os.listdir(proc)
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, "stat"), encoding="latin1") as f:
                stat = f.read()
            # The command name may hold spaces and parentheses: read after the last ')'.
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
        except (OSError, IndexError, ValueError):
            continue
        children.setdefault(ppid, []).append(int(entry))
    found, todo = [], [root]
    while todo:
        for child in children.get(todo.pop(), []):
            found.append(child)
            todo.append(child)
    return found


def _guard_popen() -> None:
    """Make every process start refuse while the run is stopping.

    The pipeline starts its tools (the docker CLI, nmap, masscan, ffuf) through
    some thirty separate subprocess calls; every one of them goes through
    subprocess.Popen, so the refusal lives there.
    """
    if getattr(subprocess.Popen, "_redamon_stop_guard", False):
        return

    class _StopGuardedPopen(subprocess.Popen):
        _redamon_stop_guard = True

        def __init__(self, *args, **kwargs):
            if _STOP.is_set():
                raise ToolLaunchRefused("the run is stopping: no new tool is started")
            super().__init__(*args, **kwargs)

    subprocess.Popen = _StopGuardedPopen
