"""F09 — run-scoped plan manifest: atomic write, retention, redaction, isolation.

Neo4j / Docker / network are faked; only the real manifest module is exercised.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.planner_manifest import (  # noqa: E402
    MODE_ENFORCE, MODE_OFF, MODE_SHADOW, CONSUMER_AI_TAGS,
    build_manifest, manifest_path, manifest_summary, plan_pointer,
    read_manifest, resolve_mode, consumer_enabled, write_manifest,
    maybe_write_pre_dispatch_manifest,
)


def _tmp() -> Path:
    import tempfile
    return Path(tempfile.mkdtemp(prefix="planner-manifest-"))


def test_manifest_contains_required_fields_and_redacts_credentials():
    m = build_manifest(
        run_id="run1", group_id="g1", tenant="t1", project_id="p1",
        scope={"roots": ["example.com"]},
        settings={"PLANNER_MODE": "shadow", "Authorization": "Bearer secret",
                  "Cookie": "sess=abc", "NUCLEI_RATE_LIMIT": 2},
        template_hashes={"t1.yaml": "sha256:aaa"},
        task_summaries=[{"task": "nuclei", "reason": "cvss>=high"}],
        reason="draft plan",
    )
    assert m["schema_version"] == 1
    assert m["planner_version"] == 1
    assert m["planner_mode"] == "shadow"
    assert m["run_id"] == "run1" and m["group_id"] == "g1"
    assert m["tenant"] == "t1" and m["project_id"] == "p1"
    assert "settings_hash" in m and "settings_hash_prefix" in m
    assert m["template_hashes"] == {"t1.yaml": "sha256:aaa"}
    assert m["tasks"] == [{"task": "nuclei", "reason": "cvss>=high"}]
    assert m["reason"] == "draft plan"
    # No credentials or raw auth headers anywhere in the manifest.
    text = json.dumps(m)
    assert "Bearer secret" not in text and "sess=abc" not in text
    # settings is hashed, not stored wholesale; no credential keys present.
    assert "settings" not in m
    assert "Authorization" not in text and "Cookie" not in text


def test_write_manifest_is_atomic_mode_0600_and_digest_matches():
    base = _tmp()
    path = manifest_path(base, "t1", "p1", "run1", "g1")
    m = build_manifest(run_id="run1", group_id="g1", tenant="t1", project_id="p1",
                       scope={}, settings={}, template_hashes={}, task_summaries=[])
    result = write_manifest(path, m)
    assert path.exists()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, mode
    assert result["sha256"] and len(result["sha256"]) == 64
    # Digest equals an independent sha256 of the file.
    import hashlib
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == result["sha256"]
    # Summary is bounded and has no credentials/full manifest.
    s = result["summary"]
    assert set(s) <= {"schema_version", "planner_version", "planner_mode", "run_id",
                      "group_id", "settings_hash_prefix", "template_count",
                      "task_count", "created_at"}
    assert "settings_hash" not in s and "tasks" not in s


def test_read_manifest_missing_and_corrupt_return_explicit_unknown():
    base = _tmp()
    path = manifest_path(base, "t1", "p1", "run1", "g1")
    assert read_manifest(path)["status"] == "unknown"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not valid json")
    assert read_manifest(path)["status"] == "unknown"
    path.write_text(json.dumps({"schema_version": 1}))
    assert read_manifest(path)["status"] == "known"


def test_run_and_group_isolation_no_overwrite():
    base = _tmp()
    m1 = build_manifest(run_id="run1", group_id="g1", tenant="t", project_id="p",
                        scope={}, settings={}, template_hashes={}, task_summaries=[])
    m2 = build_manifest(run_id="run2", group_id="g1", tenant="t", project_id="p",
                        scope={}, settings={}, template_hashes={}, task_summaries=[])
    m3 = build_manifest(run_id="run1", group_id="g2", tenant="t", project_id="p",
                        scope={}, settings={}, template_hashes={}, task_summaries=[])
    write_manifest(manifest_path(base, "t", "p", "run1", "g1"), m1)
    write_manifest(manifest_path(base, "t", "p", "run2", "g1"), m2)
    write_manifest(manifest_path(base, "t", "p", "run1", "g2"), m3)
    # Each file is distinct and none overwrote another.
    assert read_manifest(manifest_path(base, "t", "p", "run1", "g1"))["run_id"] == "run1"
    assert read_manifest(manifest_path(base, "t", "p", "run2", "g1"))["run_id"] == "run2"
    assert read_manifest(manifest_path(base, "t", "p", "run1", "g2"))["group_id"] == "g2"


def test_concurrent_writes_do_not_corrupt():
    base = _tmp()
    errors = []

    def worker(i: int) -> None:
        try:
            path = manifest_path(base, "t", "p", "run-shared", f"g{i}")
            m = build_manifest(run_id="run-shared", group_id=f"g{i}", tenant="t",
                               project_id="p", scope={}, settings={},
                               template_hashes={}, task_summaries=[])
            write_manifest(path, m)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    # Every group's manifest parses and keeps its own group id.
    for i in range(8):
        m = read_manifest(manifest_path(base, "t", "p", "run-shared", f"g{i}"))
        assert m["status"] == "known", m
        assert m["group_id"] == f"g{i}"


def test_plan_pointer_is_pointer_only():
    summary = {"schema_version": 1, "planner_mode": "shadow"}
    ptr = plan_pointer("/x/plan_manifest.json", "a" * 64, summary)
    assert ptr["plan_manifest_path"] == "/x/plan_manifest.json"
    assert ptr["plan_manifest_sha256"] == "a" * 64
    assert ptr["plan_manifest_summary"] == summary
    # Pointer carries no full manifest and no credentials.
    assert set(ptr) == {"plan_manifest_path", "plan_manifest_sha256",
                        "plan_manifest_summary"}


def test_resolve_mode_defaults_off_and_rejects_unknown():
    assert resolve_mode({}) == MODE_OFF
    assert resolve_mode({"PLANNER_MODE": MODE_OFF}) == MODE_OFF
    assert resolve_mode({"planner_mode": MODE_SHADOW}) == MODE_SHADOW
    assert resolve_mode({"PLANNER_MODE": MODE_ENFORCE}) == MODE_ENFORCE
    assert resolve_mode({"PLANNER_MODE": "bogus"}) == MODE_OFF
    assert resolve_mode({"PLANNER_MODE": ""}) == MODE_OFF


def test_consumer_enabled_only_honoured_in_shadow_enforce():
    base = {"PLANNER_CONSUMER_AI_TAGS": True}
    assert not consumer_enabled(dict(base, PLANNER_MODE=MODE_OFF), CONSUMER_AI_TAGS)
    assert consumer_enabled(dict(base, PLANNER_MODE=MODE_SHADOW), CONSUMER_AI_TAGS)
    assert consumer_enabled(dict(base, PLANNER_MODE=MODE_ENFORCE), CONSUMER_AI_TAGS)
    assert not consumer_enabled({}, CONSUMER_AI_TAGS)
    assert not consumer_enabled({}, "not_a_consumer")


def test_manifest_summary_bounded():
    m = build_manifest(run_id="r", group_id="g", tenant="t", project_id="p",
                       scope={"a": "b" * 1000},
                       settings={"PLANNER_MODE": "shadow", "NUCLEI_RATE_LIMIT": 1},
                       template_hashes={f"t{i}": "h" for i in range(50)},
                       task_summaries=[{"task": "x"}] * 20)
    s = manifest_summary(m)
    assert s["template_count"] == 50
    assert s["task_count"] == 20
    # summary does not embed scope or settings wholesale: the long scope value
    # and the settings key are absent from the summary.
    assert "b" * 1000 not in json.dumps(s)
    assert "NUCLEI_RATE_LIMIT" not in json.dumps(s)


def test_maybe_write_pre_dispatch_manifest_off_returns_none():
    assert maybe_write_pre_dispatch_manifest({}, "/tmp/x.json") is None
    assert maybe_write_pre_dispatch_manifest(
        {"PLANNER_MANIFEST_ENABLED": False}, "/tmp/x.json") is None


def test_maybe_write_pre_dispatch_manifest_writes_and_never_raises(tmp_path):
    out = tmp_path / "recon_p1.json"
    out.write_text("{}")
    settings = {"PROJECT_ID": "p1", "PLANNER_MANIFEST_ENABLED": True,
                "PLANNER_RUN_ID": "run9", "PLANNER_GROUP_ID": "g1",
                "PLANNER_TENANT": "t1", "SCOPE_GROUPS": []}
    ptr = maybe_write_pre_dispatch_manifest(settings, out)
    assert ptr is not None
    assert ptr["plan_manifest_sha256"] and len(ptr["plan_manifest_sha256"]) == 64
    assert str(tmp_path / "planner_manifests" / "t1" / "p1" / "run9" / "g1" /
               "plan_manifest.json") == ptr["plan_manifest_path"]
    # The manifest file parses and is known; no credentials stored.
    m = read_manifest(Path(ptr["plan_manifest_path"]))
    assert m["status"] == "known"
    assert m["project_id"] == "p1" and m["run_id"] == "run9" and m["group_id"] == "g1"
    assert "Authorization" not in json.dumps(m) and "Cookie" not in json.dumps(m)
    # Pointer is bounded: path + digest + summary only.
    assert set(ptr) == {"plan_manifest_path", "plan_manifest_sha256",
                        "plan_manifest_summary"}


def test_maybe_write_pre_dispatch_manifest_bad_output_never_raises():
    # Nonexistent/unwritable output: manifest is an aid, never a gate.
    assert maybe_write_pre_dispatch_manifest(
        {"PLANNER_MANIFEST_ENABLED": True}, "/nonexistent-dir/x.json") is None
