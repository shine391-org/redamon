"""Kiterunner capture routing: use the patched binary, never a silent direct run."""
from pathlib import Path
from unittest import mock

from recon.helpers.resource_enum import kiterunner_helpers as kh


def _run(tmp_path, monkeypatch, *, patched_exists, routing):
    binary = tmp_path / "kr"
    binary.write_text("#!/bin/sh\n")
    wordlist = tmp_path / "routes.kite"
    wordlist.write_text("x")
    seen = {}

    def exists(self):
        if self.name == "kr-capture":
            return patched_exists
        return True

    def heartbeat(cmd, **kwargs):
        seen["cmd"] = cmd
        return mock.Mock(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(kh.os, "access", lambda path, mode: True)
    monkeypatch.setattr(kh, "run_with_heartbeat", heartbeat)
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda tool: routing)
    out = kh.run_kiterunner_discovery(
        ["http://app.example.test"], str(binary), str(wordlist), "routes",
        rate_limit=0, connections=1, timeout=1, scan_timeout=1, threads=1,
        ignore_status=[], match_status=[], min_content_length=0, headers=[])
    return out, seen.get("cmd")


def test_capture_route_selects_patched_binary_and_passes_context(tmp_path, monkeypatch):
    out, cmd = _run(tmp_path, monkeypatch, patched_exists=True,
                    routing=("http://127.0.0.1:18888", "fixture-context"))
    assert cmd is not None
    assert cmd[0].endswith("kr-capture")
    assert "--proxy" in cmd and "http://127.0.0.1:18888" in cmd
    assert "X-Redamon-Ctx: fixture-context" in cmd


def test_capture_route_without_patched_binary_does_not_run_direct(tmp_path, monkeypatch):
    out, cmd = _run(tmp_path, monkeypatch, patched_exists=False,
                    routing=("http://127.0.0.1:18888", "fixture-context"))
    assert out == [] and cmd is None


def test_no_capture_route_keeps_stock_binary_and_no_context_header(tmp_path, monkeypatch):
    out, cmd = _run(tmp_path, monkeypatch, patched_exists=True, routing=(None, None))
    assert cmd is not None
    assert cmd[0].endswith("/kr")
    assert "--proxy" not in cmd
    assert not any("X-Redamon-Ctx" in str(x) for x in cmd)
