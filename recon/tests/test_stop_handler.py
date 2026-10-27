"""A stopped recon container runs its end-of-run steps (plan 12.3).

Python is PID 1 in the recon container and installed no SIGTERM handler, so a
stop was ignored until Docker's SIGKILL: no queued graph write landed and the
node-filter sweep (the mute rules) never ran. recon/helpers/shutdown.py now
handles SIGTERM without raising: it ends the run's processes, drains, sweeps
once, and exits 143.

The end-to-end case runs in a child process, with its tool started by Popen:
subprocess.run in the main thread kills its child on any exception, which would
prove nothing about the handler.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import shutdown  # noqa: E402

CHILD = textwrap.dedent("""
    import os, subprocess, sys, time
    sys.path.insert(0, {root!r}); sys.path.insert(0, {recon!r})
    from recon.helpers import shutdown
    shutdown.install()
    shutdown.register_drain(lambda deadline: open({drain!r}, "a").write("drained\\n"))
    shutdown.set_sweep(lambda: open({marker!r}, "a").write("swept\\n"))
    tool = subprocess.Popen(["sleep", "60"])
    print(tool.pid, flush=True)
    time.sleep(120)
    print("the main thread ran on", flush=True)
""")


def _gone(pid: int) -> bool:
    """Exited, or a zombie nobody reaped yet (the test container's PID 1 may not)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except FileNotFoundError:
        return True


@pytest.fixture
def child(tmp_path):
    marker, drain = tmp_path / "swept", tmp_path / "drained"
    script = CHILD.format(root=str(PROJECT_ROOT), recon=str(PROJECT_ROOT / "recon"),
                          marker=str(marker), drain=str(drain))
    env = dict(os.environ, RECON_STOP_GRACE_S="8")
    proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, env=env)
    tool_pid = int(proc.stdout.readline())
    yield proc, tool_pid, marker, drain
    if proc.poll() is None:
        proc.kill()
    try:
        os.kill(tool_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


class TestTheStoppedProcess:
    def test_sigterm_sweeps_ends_the_tool_and_exits_143(self, child):
        proc, tool_pid, marker, drain = child
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        code = proc.wait(timeout=5)
        assert time.monotonic() - started < 5
        assert code == 143
        assert marker.read_text() == "swept\n"
        assert drain.read_text() == "drained\n"
        deadline = time.monotonic() + 2
        while not _gone(tool_pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _gone(tool_pid)
        out, err = proc.communicate()
        assert "the main thread ran on" not in out
        assert "Stop requested" in err
        assert "node-filter sweep" in out

    def test_a_second_sigterm_changes_nothing(self, child):
        proc, _tool, marker, _drain = child
        proc.send_signal(signal.SIGTERM)
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=5) == 143
        _out, err = proc.communicate()
        assert err.count("Stop requested") == 1
        assert marker.read_text() == "swept\n"


class TestSignalDescendants:
    def test_as_pid_1_it_signals_the_whole_namespace(self, monkeypatch):
        sent = []
        monkeypatch.setattr(shutdown.os, "getpid", lambda: 1)
        monkeypatch.setattr(shutdown.os, "kill", lambda pid, sig: sent.append((pid, sig)))
        monkeypatch.setattr(shutdown, "descendants", lambda root: pytest.fail("not read as PID 1"))
        shutdown.signal_descendants(signal.SIGTERM)
        assert sent == [(-1, signal.SIGTERM)]

    def test_anywhere_else_it_never_sends_to_minus_one(self, monkeypatch):
        sent = []
        monkeypatch.setattr(shutdown.os, "getpid", lambda: 4321)
        monkeypatch.setattr(shutdown.os, "kill", lambda pid, sig: sent.append((pid, sig)))
        monkeypatch.setattr(shutdown, "descendants", lambda root: [4400, 4401])
        shutdown.signal_descendants(signal.SIGTERM)
        assert sent == [(4400, signal.SIGTERM), (4401, signal.SIGTERM)]

    def test_descendants_walks_the_proc_tree(self, tmp_path):
        def stat(pid, ppid, comm="sh"):
            (tmp_path / str(pid)).mkdir()
            (tmp_path / str(pid) / "stat").write_text(f"{pid} ({comm}) S {ppid} 1 1 0\n")
        stat(10, 1)
        stat(11, 10, "docker run (x)")   # a name with spaces and parentheses
        stat(12, 11)
        stat(13, 1)                       # not ours
        (tmp_path / "self").mkdir()
        assert sorted(shutdown.descendants(10, proc=str(tmp_path))) == [11, 12]


class TestNoNewProcess:
    @pytest.fixture
    def guarded(self, monkeypatch):
        original = subprocess.Popen
        shutdown._guard_popen()
        yield
        shutdown._STOP.clear()
        subprocess.Popen = original

    def test_a_start_is_refused_once_the_stop_is_requested(self, guarded):
        assert subprocess.run(["true"]).returncode == 0
        shutdown._STOP.set()
        with pytest.raises(shutdown.ToolLaunchRefused):
            subprocess.run(["true"])

    def test_the_refusal_is_an_oserror_tools_already_handle(self):
        assert issubclass(shutdown.ToolLaunchRefused, OSError)


class TestTheGrace:
    @pytest.mark.parametrize("raw, expected", [("", 45.0), ("  ", 45.0), ("30", 30.0),
                                               ("abc", 45.0), ("0", 45.0), ("-5", 45.0)])
    def test_blank_or_invalid_means_45(self, monkeypatch, raw, expected):
        monkeypatch.setenv("RECON_STOP_GRACE_S", raw)
        assert shutdown.grace_seconds() == expected

    def test_the_drain_leaves_room_for_the_sweep(self):
        assert shutdown.drain_deadline(100.0, 45.0) == 135.0
        assert shutdown.drain_deadline(100.0, 8.0) == 106.0


class TestSweepOnce:
    def test_the_second_caller_skips(self, monkeypatch):
        calls = []
        monkeypatch.setattr(shutdown, "_sweep_done", False)
        monkeypatch.setattr(shutdown, "_sweep", lambda: calls.append(1))
        assert shutdown.sweep_once() is True
        assert shutdown.sweep_once() is False
        assert calls == [1]
