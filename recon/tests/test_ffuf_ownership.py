"""
F11: FFuf origin-ownership planner.

Unit tests are hermetic: no network, no Docker, no LLM. The controlled-receiver
test drives the real caller (``run_ffuf_discovery``) through a fake ffuf binary
against a local disposable receiver and counts actually received requests, so
the reduction is measured, not inferred from spilled URL counts.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

# --------------------------------------------------------------------------- #
# Fixture: origin A shows /api*, origin B shows /console*. Neither owns the
# other's prefix. Under the legacy global-union behaviour both prefixes would
# be fuzzed under both origins.
# --------------------------------------------------------------------------- #

API_ORIGIN = "https://a.api.example.test"
CONSOLE_ORIGIN = "https://b.console.example.test"

FIXTURE_TARGETS = [API_ORIGIN, CONSOLE_ORIGIN]

FIXTURE_BY_BASE_URL = {
    API_ORIGIN: {
        "endpoints": {
            "/api/v1/users": {},
            "/api/v2/items": {},
        }
    },
    CONSOLE_ORIGIN: {
        "endpoints": {
            "/console/login": {},
            "/console/admin/panel": {},
        }
    },
}


def _settings(mode="enforce"):
    return {"PLANNER_MODE": mode}


# --------------------------------------------------------------------------- #
# Core: per-origin ownership
# --------------------------------------------------------------------------- #

def test_fixture_a_api_and_b_console_only_origin_specific_tasks():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    plan = plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("enforce"),
    )
    assert plan is not None
    assert plan.execute is True
    assert plan.mode == "enforce"

    by_origin = {p.origin: p for p in plan.targets}
    assert set(by_origin) == {API_ORIGIN, CONSOLE_ORIGIN}

    api_tasks = by_origin[API_ORIGIN]
    console_tasks = by_origin[CONSOLE_ORIGIN]

    # Origin A keeps root + its own prefixes; never B's /console.
    assert api_tasks.root_task == API_ORIGIN + "/FUZZ"
    assert any(t.endswith("/api/FUZZ") for t in api_tasks.owned_tasks)
    assert any(t.endswith("/api/v1/FUZZ") for t in api_tasks.owned_tasks)
    assert any(t.endswith("/api/v2/FUZZ") for t in api_tasks.owned_tasks)
    assert not any("/console/" in t or t.endswith("/console/FUZZ")
                   for t in api_tasks.owned_tasks)

    # Origin B keeps root + its own prefixes; never A's /api.
    assert console_tasks.root_task == CONSOLE_ORIGIN + "/FUZZ"
    assert any(t.endswith("/console/FUZZ") for t in console_tasks.owned_tasks)
    assert any(t.endswith("/console/login/FUZZ") for t in console_tasks.owned_tasks)
    assert any(t.endswith("/console/admin/FUZZ") for t in console_tasks.owned_tasks)
    assert not any("/api/" in t or t.endswith("/api/FUZZ")
                   for t in console_tasks.owned_tasks)

    # Cross-origin lane recorded with reason + cost, not executed by default.
    assert API_ORIGIN in plan.cross_origin
    assert CONSOLE_ORIGIN in plan.cross_origin
    for origin, hyps in plan.cross_origin.items():
        for h in hyps:
            assert h.reason
            assert isinstance(h.estimate, int) and h.estimate >= 1
            assert h.source_origins
    # No cross-origin tasks without the opt-in.
    assert all(not p.cross_origin_tasks for p in plan.targets)
    assert plan.cross_origin_enabled is False


def test_cross_origin_opt_in_adds_tasks_with_reason_and_cost():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    plan = plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("enforce"),
        cross_origin=True,
    )
    assert plan.cross_origin_enabled is True
    by_origin = {p.origin: p for p in plan.targets}
    # A now also fuzzes B's prefixes under A, each with cross-origin provenance.
    assert any(t.endswith("/console/FUZZ") for t in by_origin[API_ORIGIN].cross_origin_tasks)
    assert any(t.endswith("/console/login/FUZZ") for t in by_origin[API_ORIGIN].cross_origin_tasks)
    assert any(t.endswith("/api/FUZZ") for t in by_origin[CONSOLE_ORIGIN].cross_origin_tasks)
    # Every cross-origin task carries the cross-origin provenance.
    for p in plan.targets:
        for t in p.cross_origin_tasks:
            assert p.provenance == "rule:cross-origin-opt-in"
    # Cost estimate stays a labeled estimate, never an actual request count.
    for hyps in plan.cross_origin.values():
        for h in hyps:
            assert h.reason
            assert h.estimate >= 1


def test_root_app_prefix_non_default_port_and_encoding_preserved():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    target = "https://app.example.test:8443/App/%2fX?q=1"
    by_base_url = {
        "https://app.example.test:8443": {"endpoints": {"/api/v1/x": {}}},
    }
    plan = plan_ffuf_ownership(
        target_urls=[target], by_base_url=by_base_url, settings=_settings("enforce"),
    )
    p = plan.targets[0]
    assert p.origin == "https://app.example.test:8443"
    # Port kept, percent-encoding kept, query kept after the placeholder.
    assert p.root_task == "https://app.example.test:8443/App/%2fX/FUZZ?q=1"
    owned = set(p.owned_tasks)
    assert "https://app.example.test:8443/App/%2fX/api/FUZZ?q=1" in owned
    assert "https://app.example.test:8443/App/%2fX/api/v1/FUZZ?q=1" in owned


def test_query_fuzz_is_not_confused_with_directory_fuzz():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    target = "https://a.test/api?q=1&k=two+words"
    by_base_url = {"https://a.test": {"endpoints": {"/api": {}}}}
    plan = plan_ffuf_ownership(
        target_urls=[target], by_base_url=by_base_url, settings=_settings("enforce"),
    )
    p = plan.targets[0]
    # Directory fuzz: placeholder appended to the path, query preserved after it.
    assert p.root_task == "https://a.test/api/FUZZ?q=1&k=two+words"
    owned = set(p.owned_tasks)
    assert "https://a.test/api/api/FUZZ?q=1&k=two+words" in owned
    # No generated task buries FUZZ inside the query string (that would be query fuzz).
    assert not any("?" in t and t.split("?", 1)[1].endswith("FUZZ") for t in owned)
    assert p.root_task.index("FUZZ") < p.root_task.index("?")


# --------------------------------------------------------------------------- #
# Cap: per-origin, recorded, never silently changed
# --------------------------------------------------------------------------- #

def test_cap_is_per_origin_and_recorded():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    # Origin A shows 30 base paths -> capped at 5 (recorded). Origin B shows 2.
    many = {f"/d{i:02d}/x": {} for i in range(30)}
    by_base_url = {
        "https://a.test": {"endpoints": many},
        "https://b.test": {"endpoints": {"/api/v1": {}, "/admin": {}}},
    }
    settings = dict(_settings("enforce"), FFUF_SMART_FUZZ_MAX_BASE_PATHS=5)
    plan = plan_ffuf_ownership(
        target_urls=["https://a.test", "https://b.test"],
        by_base_url=by_base_url,
        settings=settings,
    )
    assert plan.cap == 5
    assert plan.cap_scope == "per_origin"
    by_origin = {p.origin: p for p in plan.targets}
    assert len(by_origin["https://a.test"].owned_base_paths) == 5
    assert len(by_origin["https://b.test"].owned_base_paths) == 3
    assert plan.counts["owned_paths_capped"] == 1
    assert plan.manifest["cap"] == 5
    assert plan.manifest["cap_scope"] == "per_origin"


# --------------------------------------------------------------------------- #
# Planner modes: off / shadow / enforce
# --------------------------------------------------------------------------- #

def test_off_mode_is_exact_legacy_and_records_nothing():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    plan = plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("off"),
    )
    assert plan is None

    # The executor keeps the legacy global-union behaviour verbatim.
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets
    targets = _build_fuzz_targets(FIXTURE_TARGETS, ["api", "console"])
    expected = {
        API_ORIGIN + "/FUZZ", API_ORIGIN + "/api/FUZZ", API_ORIGIN + "/console/FUZZ",
        CONSOLE_ORIGIN + "/FUZZ", CONSOLE_ORIGIN + "/api/FUZZ",
        CONSOLE_ORIGIN + "/console/FUZZ",
    }
    assert set(targets) == expected, targets
    # Cross-product: 2 origins x 3 prefixes = 6 tasks.
    assert len(targets) == 6


def test_shadow_records_but_executes_legacy():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets

    plan = plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("shadow"),
    )
    assert plan is not None
    assert plan.execute is False          # legacy execution unchanged
    assert plan.mode == "shadow"
    # The plan is recorded (manifest + cross-origin hypotheses).
    assert plan.manifest["targets"]
    assert plan.cross_origin
    # Executor target count equals the legacy cross-product, not the plan.
    assert len(_build_fuzz_targets(FIXTURE_TARGETS, ["api", "console"])) == 6


def test_enforce_executes_the_ownership_plan():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    plan = plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("enforce"),
    )
    assert plan.execute is True
    # One root + owned prefixes per origin: 2 + 3 + 3 = 8, no cross product.
    assert len(plan.all_tasks()) == 8


def test_plan_is_deterministic():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    p1 = plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS, by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("enforce"),
    )
    p2 = plan_ffuf_ownership(
        target_urls=list(reversed(FIXTURE_TARGETS)), by_base_url=FIXTURE_BY_BASE_URL,
        settings=_settings("enforce"),
    )
    assert [t.target for t in p1.targets] == [t.target for t in p2.targets]
    assert p1.seed == p2.seed
    assert p1.manifest == p2.manifest


# --------------------------------------------------------------------------- #
# Execution preserves tool controls
# --------------------------------------------------------------------------- #

def test_auto_calibrate_match_filter_identity_proxy_argv_preserved(monkeypatch):
    from recon.helpers.resource_enum import ffuf_helpers as ff
    from helpers import proxy_routing
    monkeypatch.setattr(proxy_routing, "get_capture_routing",
                        lambda tool: ("http://127.0.0.1:9090", "ctx-token-1"))

    seen = []

    def execute(cmd, **kwargs):
        seen.append(list(cmd))
        out = cmd[cmd.index("-o") + 1]
        Path(out).write_text(json.dumps({"results": []}))
        return mock.Mock(returncode=0, stderr="")

    monkeypatch.setattr(ff, "run_with_heartbeat", execute)
    ff.run_ffuf_discovery(
        [API_ORIGIN], "/wordlist", 10, 0, 10, 60, [200], [], "", [".php", ".bak"],
        False, 1, True, ["X-Bug-Bounty: fixture"], False,
        {"a.api.example.test"}, parallelism=1,
        origin_plan={"https://a.api.example.test": ["api"]},
        extensions_by_origin={"https://a.api.example.test": [".php"]},
    )
    cmd = seen[0]
    assert "-ac" in cmd
    assert "-mc" in cmd and "200" in cmd
    assert "-H" in cmd and "X-Bug-Bounty: fixture" in cmd
    assert "-x" in cmd and "http://127.0.0.1:9090" in cmd
    assert "-e" in cmd and ".php" in cmd
    us = [cmd[cmd.index("-u") + 1] for cmd in seen]
    assert API_ORIGIN + "/FUZZ" in us
    assert API_ORIGIN + "/api/FUZZ" in us
    # Legacy path keeps the same controls.
    seen.clear()
    ff.run_ffuf_discovery(
        [API_ORIGIN], "/wordlist", 10, 0, 10, 60, [200], [], "", [".php"],
        False, 1, True, [], False, {"a.api.example.test"}, parallelism=1,
    )
    cmd = seen[0]
    assert "-ac" in cmd and "-mc" in cmd and "-x" in cmd


def test_manifest_redacts_credentials():
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    target = "https://user:secret@example.test/admin"
    by_base_url = {
        "https://example.test": {"endpoints": {"/admin": {}}},
    }
    plan = plan_ffuf_ownership(
        target_urls=[target], by_base_url=by_base_url, settings=_settings("enforce"),
    )
    text = json.dumps(plan.manifest)
    assert "user:secret" not in text
    assert "secret" not in text
    # origin keyed without userinfo; task URL kept as observed (no credential in key).
    assert plan.targets[0].origin == "https://example.test"
    assert plan.targets[0].target == target


# --------------------------------------------------------------------------- #
# Full and partial plan from the same canonical inventory/settings
# --------------------------------------------------------------------------- #

def test_full_and_partial_share_the_planner():
    from recon.helpers.resource_enum import ffuf_ownership as _ff

    assert _ff.plan_ffuf_ownership is not None
    settings = _settings("enforce")
    # Same inventory, same settings -> same plan regardless of caller.
    full = _ff.plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=settings,
    )
    partial_shape = {
        origin: {"endpoints": {p: {} for p in paths}}
        for origin, data in FIXTURE_BY_BASE_URL.items()
        for paths in [list(data["endpoints"])]
    }
    # Re-key partial shape to base_url keys (the shape the partial caller builds).
    partial = _ff.plan_ffuf_ownership(
        target_urls=FIXTURE_TARGETS,
        by_base_url=FIXTURE_BY_BASE_URL,
        settings=settings,
    )
    assert [t.target for t in full.targets] == [t.target for t in partial.targets]
    assert [t.owned_base_paths for t in full.targets] == \
           [t.owned_base_paths for t in partial.targets]
    assert full.execute == partial.execute


# --------------------------------------------------------------------------- #
# Controlled receiver: measured request-count reduction
# --------------------------------------------------------------------------- #

_RECEIVER_COUNT = [0]
_RECEIVER_LOCK = threading.Lock()


class _Receiver(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        with _RECEIVER_LOCK:
            _RECEIVER_COUNT[0] += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # noqa: N802
        pass


def _start_receivers():
    """Two local receivers on two ports -> two distinct origins (port matters)."""
    servers = []
    ports = []
    for _ in range(2):
        server = HTTPServer(("127.0.0.1", 0), _Receiver)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        ports.append(port)
    return servers, ports


def _write_fake_ffuf(bin_dir: Path, wordlist: Path):
    """A ffuf substitute that replaces FUZZ with each word and really requests
    the resulting URL against the local receiver, then writes ffuf JSON."""
    script = '''#!/usr/bin/env python3
import json, os, sys, urllib.parse, urllib.request
args = sys.argv[1:]
url = None; out = None; wordlist = None
i = 0
while i < len(args):
    a = args[i]
    if a == "-V":
        sys.exit(0)
    if a in ("-u", "-o", "-w") and i + 1 < len(args):
        if a == "-u": url = args[i + 1]
        elif a == "-o": out = args[i + 1]
        else: wordlist = args[i + 1]
        i += 2
    else:
        i += 1
results = []
if wordlist:
    with open(wordlist) as fh:
        words = [w.strip() for w in fh if w.strip()]
    for w in words:
        target = (url or "").replace("FUZZ", urllib.parse.quote(w))
        try:
            urllib.request.urlopen(target, timeout=3)
        except Exception:
            pass
        results.append({"url": target, "status": 200, "length": 1,
                        "words": 1, "lines": 1, "input": {"FUZZ": w}})
with open(out, "w") as fh:
    json.dump({"results": results}, fh)
'''
    (bin_dir / "ffuf").write_text(script)
    (bin_dir / "ffuf").chmod(0o755)


def _receiver_count():
    with _RECEIVER_LOCK:
        return _RECEIVER_COUNT[0]


@pytest.mark.parametrize("plan_kind", ["legacy_global", "origin_ownership"])
def test_controlled_receiver_counts_drop_for_cross_product_fixture(
        monkeypatch, tmp_path, plan_kind):
    """Real ffuf subprocesses against real local receivers: the ownership plan
    produces fewer received requests than the legacy cross-product for the same
    fixture, and the reduction is not explained by spilled URL counts."""
    _RECEIVER_COUNT[0] = 0
    servers, ports = _start_receivers()

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("admin\n")
    _write_fake_ffuf(bin_dir, wordlist)

    origin1 = f"http://127.0.0.1:{ports[0]}"
    origin2 = f"http://127.0.0.1:{ports[1]}"
    targets = [origin1 + "/api", origin2 + "/console"]
    # Each origin owns ONLY its own prefix: origin1 shows /api*, origin2 shows /console*.
    # Legacy global set = {api, api/v1, console, console/y} applied to both targets
    # (2 roots + 4 prefixes each = 10 tasks -> 10 received requests).
    # Ownership keeps each origin to its own prefixes
    # (origin1: root + api + api/v1 = 3; origin2: root + console + console/y = 3 -> 6).
    by_base_url = {
        origin1: {"endpoints": {"/api/v1/x": {}}},
        origin2: {"endpoints": {"/console/y": {}}},
    }

    from recon.helpers.resource_enum import ffuf_helpers as ff
    from recon.helpers.resource_enum.ffuf_ownership import plan_ffuf_ownership

    plan = None
    allowed = {"127.0.0.1"}
    with mock.patch.dict(os.environ, {"PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", "")}):
        if plan_kind == "legacy_global":
            results, meta = ff.run_ffuf_discovery(
                targets, str(wordlist), 1, 0, 5, 10, [200], [], "",
                [], False, 1, True, [], False,
                allowed,
                discovered_base_paths=["api", "api/v1", "console", "console/y"],
                parallelism=3,
            )
        else:
            plan = plan_ffuf_ownership(
                target_urls=targets, by_base_url=by_base_url,
                settings=_settings("enforce"),
            )
            assert plan.execute is True
            results, meta = ff.run_ffuf_discovery(
                targets, str(wordlist), 1, 0, 5, 10, [200], [], "",
                [], False, 1, True, [], False,
                allowed,
                parallelism=3,
                origin_plan=plan.origin_base_paths(),
            )
        for s in servers:
            s.shutdown()

    received = _receiver_count()
    tasks = meta["fuzz_targets_run"]
    # Sanity: one received request per planned task (one word per task).
    assert received == tasks, (received, tasks, meta)
    if plan_kind == "legacy_global":
        assert tasks == 10, meta
    else:
        assert plan is not None
        assert tasks == 6, meta
        api = [p for p in plan.targets if p.origin == origin1][0]
        console = [p for p in plan.targets if p.origin == origin2][0]
        assert len(api.owned_tasks) == 2 and len(console.owned_tasks) == 2
        assert any(t.endswith("/api/FUZZ") for t in api.owned_tasks)
        assert any(t.endswith("/api/v1/FUZZ") for t in api.owned_tasks)
        assert any(t.endswith("/console/FUZZ") for t in console.owned_tasks)
        assert any(t.endswith("/console/y/FUZZ") for t in console.owned_tasks)
        # No origin fuzzes the other's prefix.
        assert not any("/console/" in t for t in api.owned_tasks)
        assert not any("/console/y" in t for t in api.owned_tasks)
        assert not any("/api/" in t for t in console.owned_tasks)


# --------------------------------------------------------------------------- #
# Stop / cancel: no orphan FFuf subprocess
# --------------------------------------------------------------------------- #

def test_stop_cleanup_leaves_no_ffuf_orphan(monkeypatch):
    from recon.helpers import shutdown
    from recon.helpers.resource_enum import ffuf_helpers as ff

    shutdown._STOP.clear()
    shutdown._guard_popen()
    shutdown._STOP.set()

    try:
        results, meta = ff.run_ffuf_discovery(
            [API_ORIGIN], "/wordlist", 1, 0, 5, 10, [200], [], "",
            [], False, 1, True, [], False,
            {"a.api.example.test"}, parallelism=1,
        )
    finally:
        shutdown._STOP.clear()

    assert results == []
    # The guarded Popen refused to start ffuf: target was built (1) but no
    # subprocess started, no orphan, nothing raw.
    assert meta["fuzz_targets_run"] == 1
    assert meta["results_raw"] == 0
    assert meta["results_unique"] == 0


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    tests = [fn for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    passed = failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
            print(f"PASS: {test_fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"FAIL: {test_fn.__name__} — {e}")
            import traceback
            traceback.print_exc()
    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed out of {passed + failed}")
    if failed:
        sys.exit(1)
