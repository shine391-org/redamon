"""Regression coverage for local evidence readback without scanner imports."""
import asyncio
import hashlib
import importlib.abc
import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "recon_orchestrator"))
for key in ("RECON_PATH", "GVM_SCAN_PATH", "GITHUB_HUNT_PATH", "TRUFFLEHOG_PATH",
            "SUPPLY_CHAIN_PATH", "AI_ATTACK_SURFACE_PATH"):
    os.environ.setdefault(key, "/host-only/not-mounted/recon")
os.environ.setdefault("ORCHESTRATOR_API_KEY", "fixture-only")

import api
import container_manager
import recon_evidence
from models import ReconState, ReconStatus
from fastapi.testclient import TestClient


@pytest.fixture
def local_tree(tmp_path, monkeypatch):
    output = tmp_path / "local-recon" / "output"
    output.mkdir(parents=True)
    monkeypatch.setattr(api, "RECON_PATH", "/host-only/not-mounted/recon")
    monkeypatch.setattr(recon_evidence, "recon_output_path", lambda: output, raising=False)
    monkeypatch.setattr(container_manager, "recon_output_path", lambda: output, raising=False)
    monkeypatch.setattr(api, "ORCHESTRATOR_API_KEY", "fixture-only")
    return output


def write_artifact(output):
    artifact = {
        "metadata": {"checkpoint_context": {
            "project_id": "p1", "run_id": "r1", "tenant": "t1", "mode": "full"}},
        "js_recon": {"coverage": {"hosts": {"fixture.invalid": {"status": "complete"}}}},
    }
    (output / "recon_p1.json").write_text(json.dumps(artifact))


def write_manifest(output):
    path = output / "planner_manifests" / "t1" / "p1" / "r1" / "g1" / "plan_manifest.json"
    path.parent.mkdir(parents=True)
    value = {
        "schema_version": 1, "planner_version": 1, "planner_mode": "enforce",
        "tenant": "t1", "project_id": "p1", "run_id": "r1", "group_id": "g1",
        "scope": {"roots": []}, "settings_hash": "0" * 64,
        "settings_hash_prefix": "0" * 16, "template_hashes": {}, "tasks": [],
        "reason": "fixture", "created_at": "2026-01-01T00:00:00+00:00",
    }
    path.write_text(json.dumps(value))
    return {
        "path": "/app/recon/output/planner_manifests/t1/p1/r1/g1/plan_manifest.json",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "tenant": "t1", "run_id": "r1", "group_id": "g1",
    }


def test_http_diagnostics_reads_local_artifact(local_tree, monkeypatch):
    write_artifact(local_tree)
    state = ReconState(project_id="p1", status=ReconStatus.RUNNING, run_id="r1")
    manager = SimpleNamespace(get_status=AsyncMock(return_value=state))
    monkeypatch.setattr(api, "container_manager", manager)
    client = TestClient(api.app)  # no lifespan: no Docker/reconciler side effects
    response = client.get("/recon/p1/diagnostics", headers={"X-Orchestrator-Key": "fixture-only"})
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "ready"
    assert result["run_id"] == "r1"
    assert result["coverage_summary"]["js_recon"]["complete"] == 1
    assert api.RECON_PATH == "/host-only/not-mounted/recon"


def test_status_evidence_reads_local_artifact(local_tree):
    write_artifact(local_tree)
    manager = container_manager.ContainerManager.__new__(container_manager.ContainerManager)
    manager.recon_host_path = "/host-only/not-mounted/recon"
    state = ReconState(project_id="p1", status=ReconStatus.RUNNING, run_id="r1")
    manager._get_status_sync = lambda project_id: state
    with ThreadPoolExecutor(max_workers=1) as pool:
        manager._docker_op_executor = pool
        out = asyncio.run(manager.get_status("p1"))
    assert out.run_id == "r1"
    assert out.coverage_summary is not None
    assert out.coverage_summary["js_recon"]["complete"] == 1
    assert manager.recon_host_path == "/host-only/not-mounted/recon"


def test_pointer_index_reads_local_not_host(local_tree):
    pointer = write_manifest(local_tree)
    index = local_tree / "planner_manifests" / "p1" / "r1" / "pointers.json"
    index.parent.mkdir(parents=True)
    index.write_text(json.dumps({"pointers": [{"plan_manifest_path": pointer["path"]}]}))
    manager = container_manager.ContainerManager.__new__(container_manager.ContainerManager)
    manager.recon_host_path = "/host-only/not-mounted/recon"
    assert manager._plan_manifest_pointers("p1") == [{"plan_manifest_path": pointer["path"]}]


def test_http_manifest_reads_local_without_scanner_imports(local_tree):
    pointer = write_manifest(local_tree)
    class BlockScannerImports(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "dns" or fullname.startswith("dns.") or fullname.startswith("recon.helpers"):
                raise AssertionError("scanner import forbidden: " + fullname)
    guard = BlockScannerImports()
    sys.meta_path.insert(0, guard)
    try:
        response = TestClient(api.app).get("/recon/p1/plan-manifest", params=pointer,
                                         headers={"X-Orchestrator-Key": "fixture-only"})
    finally:
        sys.meta_path.remove(guard)
    assert response.status_code == 200
    assert response.json()["status"] == "known"
    assert response.json()["run_id"] == "r1"


@pytest.mark.parametrize("change,reason", [
    ({"sha256": "f" * 64}, "manifest_digest_mismatch"),
    ({"tenant": "foreign"}, "manifest_context_mismatch: tenant"),
    ({"run_id": "old"}, "manifest_context_mismatch: run_id"),
    ({"group_id": "other"}, "manifest_context_mismatch: group_id"),
    ({"path": "/etc/passwd"}, "manifest_path_outside_prefix"),
    ({"path": "/app/recon/output/planner_manifests/../secret"}, "manifest_path_outside_prefix"),
])
def test_manifest_still_fails_closed(local_tree, change, reason):
    pointer = write_manifest(local_tree)
    pointer.update(change)
    result = asyncio.run(api.get_recon_plan_manifest("p1", **pointer))
    assert result == {"status": "unknown", "reason": reason}


def test_manifest_symlink_escape_refused(local_tree, tmp_path):
    base = local_tree / "planner_manifests"
    base.mkdir()
    (base / "escape").symlink_to(tmp_path, target_is_directory=True)
    assert api._host_manifest_path("/app/recon/output/planner_manifests/escape/out.json") is None


def test_unknown_missing_artifact_is_not_clean(local_tree, monkeypatch):
    state = ReconState(project_id="p1", status=ReconStatus.RUNNING, run_id="r1")
    monkeypatch.setattr(api, "container_manager", SimpleNamespace(get_status=AsyncMock(return_value=state)))
    out = asyncio.run(api.get_recon_diagnostics("p1"))
    assert out["status"] == "unknown"
    assert out["reason"] == "artifact_unavailable"


def test_helper_import_is_independent_of_host_env_and_scanner_packages():
    code = '''
import importlib.abc, os, sys
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'dns' or fullname.startswith('dns.') or fullname.startswith('recon.helpers'):
            raise AssertionError('scanner dependency imported: ' + fullname)
sys.meta_path.insert(0, Guard())
os.environ['RECON_PATH'] = '/host-only/not-mounted/recon'
import recon_evidence
assert recon_evidence.recon_local_path().is_dir()
assert str(recon_evidence.recon_local_path()) != os.environ['RECON_PATH']
result = recon_evidence.read_manifest_in_context('/nonexistent/fixture.json', {})
assert result['status'] == 'unknown'
assert not any(k == 'dns' or k.startswith('recon.helpers') for k in sys.modules)
'''
    env = dict(os.environ, PYTHONPATH=str(ROOT / "recon_orchestrator") + os.pathsep + str(ROOT))
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
