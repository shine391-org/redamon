"""One case per ROUTE_EXPOSURE_* setting, proving its effect on a real run (plan §15.1)."""

from __future__ import annotations

import json
import threading
import time

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.route_exposure import generators, prober, run_route_exposure_isolated, seeds
from recon.tests.route_exposure_fakeapp import BEARER, FakeApp, corpus, json_answer, settings

USERS = json.dumps([{"id": i, "email": f"user{i}@lab.invalid"} for i in range(6)]).encode()
APP = {
    "/internal/users/export": json_answer(200, USERS),
    "/api/v2/items/1": json_answer(401, b'{"error":"auth"}'),
    "/api/v1/items/1": json_answer(200, USERS),
    "/.git/HEAD": (200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n"),
    "/backup.zip": (200, {"Content-Type": "application/zip"}, b"PK\x03\x04" + b"\x00" * 64),
}
ENDPOINTS = {"/internal/users/export": {"methods": ["GET"]}, "/api/v2/items/1": {"methods": ["GET"]},
             "/config.php": {"methods": ["GET"]}}
ALL_ON = dict(ROUTE_EXPOSURE_SEED_PATHS=True, ROUTE_EXPOSURE_VCS_FILES=True,
              ROUTE_EXPOSURE_BACKUP_FILES=True, ROUTE_EXPOSURE_VERSION_VARIANTS=True,
              AUTH_PROFILE=BEARER)


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()


def _run(routes=None, endpoints=None, **overrides):
    with FakeApp(routes or APP) as app:
        out = run_route_exposure_isolated(corpus(app.base, endpoints=endpoints or ENDPOINTS),
                                          settings(**{**ALL_ON, **overrides}))
    return out["route_exposure"], app.hits


def _kinds(result):
    return {(f["path"], f["exposure_kind"]) for f in result["findings"]}


def test_enabled_off_requests_nothing():
    result, hits = _run(ROUTE_EXPOSURE_ENABLED=False)
    assert result == {} and hits == []


_SEEDS = set(generators.seed_paths({"/api", "/api/v2"}))
_BACKUPS = {p for p, _ in generators.backup_paths([generators._route("", "/config.php", "found")])}


@pytest.mark.parametrize("key,gone", [
    ("ROUTE_EXPOSURE_SEED_PATHS", lambda p: p in _SEEDS),
    ("ROUTE_EXPOSURE_VCS_FILES", lambda p: p.endswith(seeds.VCS_FILES)),
    ("ROUTE_EXPOSURE_BACKUP_FILES", lambda p: p in _BACKUPS),
    ("ROUTE_EXPOSURE_VERSION_VARIANTS", lambda p: p in ("/api/v1/items/1", "/api/items/1")),
])
def test_each_generator_off_removes_exactly_its_requests(key, gone):
    on_result, on_hits = _run()
    off_result, off_hits = _run(**{key: False})
    on_paths = {h.path for h in on_hits if "/rdm-" not in h.path}
    off_paths = {h.path for h in off_hits if "/rdm-" not in h.path}
    removed = on_paths - off_paths
    assert removed and all(gone(p) for p in removed), sorted(removed)
    assert not [p for p in off_paths if gone(p)]
    # nothing else changed: the other findings are still there
    kept = {k for k in _kinds(on_result) if not gone(k[0])}
    assert kept <= _kinds(off_result)


def test_compare_off_sends_no_logged_in_request():
    result, hits = _run(ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False)
    assert hits and not [h for h in hits if h.authed]
    assert result["summary"]["logged_in_compared"] == 0
    assert all("authed_status" not in f for f in result["findings"])


def test_pii_off_empties_pii_while_candidates_remain():
    result, _ = _run(ROUTE_EXPOSURE_PII_DETECTION=False)
    anon = [f for f in result["findings"] if f["exposure_kind"] == "anonymous_access"]
    assert anon and all(f["pii_types"] == [] and f["pii_record_estimate"] == 0 for f in result["findings"])


def test_max_rps_paces_every_request():
    routes = {f"/internal/r{i}": json_answer(200, USERS) for i in range(16)}
    endpoints = {p: {"methods": ["GET"]} for p in routes}
    _, hits = _run(routes, endpoints, ROUTE_EXPOSURE_MAX_RPS=8, ROUTE_EXPOSURE_WORKERS=8,
                   ROUTE_EXPOSURE_SEED_PATHS=False, ROUTE_EXPOSURE_VCS_FILES=False,
                   ROUTE_EXPOSURE_BACKUP_FILES=False, ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False)
    stamps = sorted(h.at for h in hits)
    rate = (len(stamps) - 1) / (stamps[-1] - stamps[0])
    assert len(stamps) >= 16 and rate <= 8 * 1.1


def test_workers_bound_concurrency():
    live, peak, lock = [0], [0], threading.Lock()

    def tracked(_hit):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.15)
        with lock:
            live[0] -= 1
        return json_answer(200, USERS)
    routes = {f"/internal/w{i}": tracked for i in range(8)}
    _run(routes, {p: {"methods": ["GET"]} for p in routes}, ROUTE_EXPOSURE_WORKERS=2,
         ROUTE_EXPOSURE_SEED_PATHS=False, ROUTE_EXPOSURE_VCS_FILES=False,
         ROUTE_EXPOSURE_BACKUP_FILES=False, ROUTE_EXPOSURE_VERSION_VARIANTS=False,
         ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False)
    assert peak[0] == 2


def test_timeout_reaches_every_request(monkeypatch):
    seen = []
    real = requests.Session.request

    def spy(self, method, url, **kw):
        seen.append(kw.get("timeout"))
        return real(self, method, url, **kw)
    monkeypatch.setattr(requests.Session, "request", spy)
    _run(ROUTE_EXPOSURE_TIMEOUT=7)
    assert seen and set(seen) == {7}


@pytest.mark.parametrize("key,value,requested", [
    ("ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST", 10, 10),
    ("ROUTE_EXPOSURE_MAX_ROUTES_TOTAL", 50, 50),
])
def test_each_budget_key_cuts(key, value, requested):
    endpoints = {f"/api/x{i}": {"methods": ["GET"]} for i in range(120)}
    result, _ = _run({}, endpoints, ROUTE_EXPOSURE_SEED_PATHS=False, ROUTE_EXPOSURE_VCS_FILES=False,
                     ROUTE_EXPOSURE_BACKUP_FILES=False, ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False,
                     **{key: value})
    assert result["summary"]["routes_requested"] == requested
    assert result["summary"]["budget_cut"] == 120 - requested


def test_numeric_out_of_bounds_values_are_clamped():
    """fetch_project_settings never clamps; the scanner does, so a hand-edited
    row can never run out of bounds."""
    endpoints = {f"/api/x{i}": {"methods": ["GET"]} for i in range(20)}
    result, _ = _run({}, endpoints, ROUTE_EXPOSURE_SEED_PATHS=False, ROUTE_EXPOSURE_VCS_FILES=False,
                     ROUTE_EXPOSURE_BACKUP_FILES=False, ROUTE_EXPOSURE_COMPARE_LOGGED_IN=False,
                     ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST=1, ROUTE_EXPOSURE_MAX_RPS=10_000,
                     ROUTE_EXPOSURE_WORKERS=500, ROUTE_EXPOSURE_TIMEOUT=0)
    assert result["summary"]["routes_requested"] == 10   # the per-host floor of the bounds


def test_every_route_exposure_setting_has_an_effect_case():
    """A new ROUTE_EXPOSURE_* default ships with a test proving its effect, here or in
    test_route_exposure_v2.py (the v2 generators and riders)."""
    from pathlib import Path

    from recon.project_settings import DEFAULT_SETTINGS
    here = Path(__file__).parent
    text = (here / "test_route_exposure_settings_effect.py").read_text() + \
        (here / "test_route_exposure_v2.py").read_text()
    keys = [k for k in DEFAULT_SETTINGS if k.startswith("ROUTE_EXPOSURE_") and "_JEV_" not in k]
    assert keys
    missing = [k for k in keys if k != "ROUTE_EXPOSURE_ENABLED" and f"{k}=" not in text and f'"{k}"' not in text]
    assert not missing, f"no effect test names {missing}"
