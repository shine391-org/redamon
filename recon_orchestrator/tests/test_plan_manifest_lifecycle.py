"""G2-R3 — orchestrator plan-manifest persistence and reader.

Tests the pointer index the recon container writes to the shared output
volume and the reader endpoint that validates a persisted pointer against
the manifest file on disk (context + sha256).
"""
import os
import json
import asyncio
import tempfile
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Stub `docker` so api.py / container_manager import without a daemon.
_docker = MagicMock()
class _DockerError(Exception):
    pass
_docker.errors = MagicMock()
_docker.errors.NotFound = _DockerError
_docker.errors.APIError = _DockerError
sys.modules.setdefault("docker", _docker)
sys.modules.setdefault("docker.errors", _docker.errors)

# Stub `dns` (dnspython) so `recon.helpers` can import in this local run.
import types as _types
_dns = _types.ModuleType("dns")
_dns.__path__ = []
_dns.resolver = _types.ModuleType("dns.resolver")
_dns.zone = _types.ModuleType("dns.zone")
_dns.query = _types.ModuleType("dns.query")
_dns.exception = _types.ModuleType("dns.exception")
_dns.rdatatype = _types.ModuleType("dns.rdatatype")
_dns.rdataclass = _types.ModuleType("dns.rdataclass")
_dns.name = _types.ModuleType("dns.name")
sys.modules.setdefault("dns", _dns)
for _sub in ("resolver", "zone", "query", "exception", "rdatatype", "rdataclass", "name"):
    sys.modules.setdefault(f"dns.{_sub}", getattr(_dns, _sub))

import pytest

# Make sibling packages importable from this test root, as they are in the
# orchestrator container layout: recon_orchestrator/ (api, container_manager,
# models) and the repo root (recon_settings, recon, graph_db).
_sys_here = Path(__file__).resolve()
sys.path.insert(0, str(_sys_here.parent.parent))        # recon_orchestrator/
sys.path.insert(0, str(_sys_here.parent.parent.parent)) # repo root

os.environ.setdefault("ORCHESTRATOR_API_KEY", "test-key")
_tmp = tempfile.mkdtemp()
for _var in ("RECON_PATH", "GVM_SCAN_PATH", "GITHUB_HUNT_PATH", "TRUFFLEHOG_PATH",
             "SUPPLY_CHAIN_PATH", "GRAPH_DB_PATH", "RECON_SETTINGS_PATH",
             "AI_ATTACK_SURFACE_PATH"):
    os.environ.setdefault(_var, _tmp)

import api  # noqa: E402  (env must be set before import)
from container_manager import ContainerManager  # noqa: E402
from models import ReconState, ReconStatus  # noqa: E402


@pytest.fixture
def mock_docker_client():
    client = MagicMock()
    client.containers = MagicMock()
    client.images = MagicMock()
    return client


@pytest.fixture
def wired_manager(mock_docker_client):
    with patch("container_manager.docker") as mock_docker_mod:
        mock_docker_mod.from_env.return_value = mock_docker_client
        mgr = ContainerManager()
        mgr.client = mock_docker_client
        mgr.recon_host_path = os.environ["RECON_PATH"]
    prev = api.container_manager
    api.container_manager = mgr
    try:
        yield mgr
    finally:
        api.container_manager = prev


def _write_manifest(tenant: str, project_id: str,
                    run_id: str, group_id: str, body: dict) -> Path:
    host_base = Path(os.environ["RECON_PATH"])
    m = host_base / "output" / "planner_manifests" / tenant / project_id / run_id / group_id / "plan_manifest.json"
    m.parent.mkdir(parents=True, exist_ok=True)
    m.write_text(json.dumps(body, sort_keys=True))
    return m


def _digest(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestPlanManifestPointers:
    def test_reads_pointer_index_for_project(self, wired_manager):
        mgr = wired_manager
        base = Path(os.environ["RECON_PATH"]) / "output" / "planner_manifests"
        idx = base / "p1" / "r1" / "pointers.json"
        idx.parent.mkdir(parents=True, exist_ok=True)
        idx.write_text(json.dumps({"pointers": [
            {"plan_manifest_path": "/app/recon/output/planner_manifests/t1/p1/r1/g1/plan_manifest.json",
             "plan_manifest_sha256": "a" * 64,
             "plan_manifest_summary": {"run_id": "r1", "group_id": "g1"}},
        ]}))
        ptrs = mgr._plan_manifest_pointers("p1")
        assert len(ptrs) == 1
        assert ptrs[0]["plan_manifest_sha256"] == "a" * 64

    def test_missing_index_is_empty_not_an_error(self, wired_manager):
        mgr = wired_manager
        assert mgr._plan_manifest_pointers("nope") == []

    def test_corrupt_index_is_empty(self, wired_manager):
        mgr = wired_manager
        base = Path(os.environ["RECON_PATH"]) / "output" / "planner_manifests"
        idx = base / "p1" / "r1" / "pointers.json"
        idx.parent.mkdir(parents=True, exist_ok=True)
        idx.write_text("{not json")
        assert mgr._plan_manifest_pointers("p1") == []


class TestGetReconPlanManifestEndpoint:
    def _call(self, **params):
        return asyncio.get_event_loop().run_until_complete(
            api.get_recon_plan_manifest(project_id="p1", **params))

    def test_known_when_context_and_digest_match(self, wired_manager):
        wired_manager
        manifest = {"schema_version": 1, "planner_version": 1, "planner_mode": "off",
                    "tenant": "t1", "project_id": "p1", "run_id": "run9",
                    "group_id": "g1", "scope": {"roots": []},
                    "settings_hash": "0" * 64, "settings_hash_prefix": "0" * 16,
                    "template_hashes": {}, "tasks": [], "reason": "plan", "created_at": "2026-01-01T00:00:00+00:00"}
        path = _write_manifest("t1", "p1", "run9", "g1", manifest)
        digest = _digest(path)
        container_path = "/app/recon/output/planner_manifests/t1/p1/run9/g1/plan_manifest.json"
        out = self._call(path=container_path, sha256=digest,
                         tenant="t1", run_id="run9", group_id="g1")
        assert out["status"] == "known"
        assert out["tenant"] == "t1"

    def test_unknown_when_digest_mismatches(self, wired_manager):
        wired_manager
        manifest = {"schema_version": 1, "planner_version": 1, "planner_mode": "off",
                    "tenant": "t1", "project_id": "p1", "run_id": "run9",
                    "group_id": "g1", "scope": {"roots": []},
                    "settings_hash": "0" * 64, "settings_hash_prefix": "0" * 16,
                    "template_hashes": {}, "tasks": [], "reason": "plan", "created_at": "2026-01-01T00:00:00+00:00"}
        path = _write_manifest("t1", "p1", "run9", "g1", manifest)
        container_path = "/app/recon/output/planner_manifests/t1/p1/run9/g1/plan_manifest.json"
        out = self._call(path=container_path, sha256="f" * 64,
                         tenant="t1", run_id="run9", group_id="g1")
        assert out["status"] == "unknown"
        assert out["reason"] == "manifest_digest_mismatch"

    def test_unknown_when_cross_context(self, wired_manager):
        wired_manager
        manifest = {"schema_version": 1, "planner_version": 1, "planner_mode": "off",
                    "tenant": "t1", "project_id": "p1", "run_id": "run9",
                    "group_id": "g1", "scope": {"roots": []},
                    "settings_hash": "0" * 64, "settings_hash_prefix": "0" * 16,
                    "template_hashes": {}, "tasks": [], "reason": "plan", "created_at": "2026-01-01T00:00:00+00:00"}
        path = _write_manifest("t1", "p1", "run9", "g1", manifest)
        digest = _digest(path)
        container_path = "/app/recon/output/planner_manifests/t1/p1/run9/g1/plan_manifest.json"
        out = self._call(path=container_path, sha256=digest,
                         tenant="t1", run_id="run9", group_id="other")
        assert out["status"] == "unknown"
        assert out["reason"] == "manifest_context_mismatch: group_id"

    def test_unknown_when_path_escapes_prefix(self, wired_manager):
        out = self._call(path="/etc/passwd", sha256="a" * 64, tenant="t1",
                         run_id="r1", group_id="g1")
        assert out["status"] == "unknown"
        assert out["reason"] == "manifest_path_outside_prefix"

    def test_unknown_when_digest_missing(self, wired_manager):
        out = self._call(path="/app/recon/output/planner_manifests/t1/p1/r1/g1/plan_manifest.json",
                         sha256="", tenant="t1", run_id="r1", group_id="g1")
        assert out["status"] == "unknown"
        assert out["reason"] == "manifest_digest_missing"
