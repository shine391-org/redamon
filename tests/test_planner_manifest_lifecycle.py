"""G2-R3 — manifest lifecycle: isolation, redaction, reader contract, dispatch wiring.

Synthetic offline inputs only. Neo4j / Docker / network are faked; only the real
manifest module and the real main.py wiring helpers are exercised.

Each counterexample below reproduces a G2 review defect (B4: manifest not wired
through the dispatch paths with canonical job context; B5: helper isolation and
redaction holes). They must FAIL on the rejected base 98b68a93 and PASS on this
candidate; none of them is skipped or xfailed to buy acceptance.
"""
from __future__ import annotations

import json
import hashlib
import os
import stat
import sys
import tempfile
import types as _types
from pathlib import Path
from unittest.mock import patch

# Stub `dns` (dnspython) so `recon.helpers` imports without the package locally.
_dns = _types.ModuleType("dns")
_dns.__path__ = []
for _sub in ("resolver", "zone", "query", "exception", "rdatatype", "rdataclass", "name", "reversename", "rcode", "ttl", "tokenizer"):
    _mod = _types.ModuleType(f"dns.{_sub}")
    setattr(_dns, _sub, _mod)
    sys.modules[f"dns.{_sub}"] = _mod
sys.modules["dns"] = _dns

for _missing in ("whois", "neo4j", "graph_db"):
    if _missing not in sys.modules:
        sys.modules[_missing] = _types.ModuleType(_missing)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import planner_manifest as pm  # noqa: E402
from recon.helpers.planner_manifest import (  # noqa: E402
    MODE_OFF, build_manifest, manifest_digest, manifest_path,
    read_manifest, read_manifest_in_context, write_manifest,
    maybe_write_pre_dispatch_manifest,
)

import recon.main as main_mod  # noqa: E402  (real main.py wiring helpers)

EXPECTED_CTX = {"tenant": "t1", "project_id": "p1", "run_id": "run9",
                "group_id": "g1"}


def _tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="g2r3-manifest-"))


# ---------------------------------------------------------------------------
# B5 — path isolation and injective safe identifiers
# ---------------------------------------------------------------------------

def test_manifest_path_rejects_traversal_and_dot_components():
    base = _tmp()
    for bad in ("", ".", "..", "\x00x", "a\x00b"):
        try:
            manifest_path(base, bad, "p", "r", "g")
        except ValueError:
            continue
        else:
            raise AssertionError(f"invalid component accepted: {bad!r}")
    # A missing base is fine: containment is checked on resolution, not existence.
    path = manifest_path(base, "t1", "p1", "run9", "g1")
    assert str(path).endswith("t1/p1/run9/g1/plan_manifest.json")


def test_tenant_ids_are_injective_a_b_vs_a_slash_b_cannot_collide():
    base = _tmp()
    # "a/b" is a legal identifier: it is encoded injectively, never rejected
    # as invalid, and can never collide with "a_b".
    slash = manifest_path(base, "a/b", "p", "r", "g")
    under = manifest_path(base, "a_b", "p", "r", "g")
    assert slash != under
    assert slash.name == "plan_manifest.json"
    for p in (slash, under):
        resolved = os.path.realpath(p)
        base_resolved = os.path.realpath(base)
        assert resolved == base_resolved or resolved.startswith(
            base_resolved + os.sep), p
    # Percent-encoding is injective: a literal "a%2Fb" is not "a/b".
    lit = manifest_path(base, "a%2Fb", "p", "r", "g")
    assert lit != slash and lit != under


def test_manifest_dir_contained_even_for_non_existent_base():
    base = _tmp() / "does-not-exist-yet"
    path = manifest_path(base, "t1", "p1", "run9", "g1")
    assert os.path.realpath(path).startswith(os.path.realpath(base) + os.sep)


# ---------------------------------------------------------------------------
# B5 — redaction of payload/task-summary/URL fields, bounding without silence
# ---------------------------------------------------------------------------

def test_build_manifest_redacts_auth_canary_userinfo_and_settings():
    manifest = build_manifest(
        run_id="run9", group_id="g1", tenant="t1", project_id="p1",
        scope={"roots": ["https://synthetic.test/a"]},
        settings={"PLANNER_MODE": "shadow", "NUCLEI_RATE_LIMIT": 2,
                  "API_KEY": "sk-live-SECRET"},
        template_hashes={"t.yaml": "sha256:aaa"},
        task_summaries=[{"Authorization": "Bearer SYNTHETIC-CANARY",
                         "url": "https://user:pass@synthetic.test/a?x=1",
                         "reason": "cvss>=high"}],
        reason="draft plan",
    )
    text = json.dumps(manifest)
    assert "SYNTHETIC-CANARY" not in text
    assert "sk-live-SECRET" not in text
    assert "user:pass@" not in text
    # Settings are hashed wholesale, never stored, never credential-bearing.
    assert "settings" not in manifest
    assert "API_KEY" not in text
    assert manifest["settings_hash"] and len(manifest["settings_hash"]) == 64


def test_build_manifest_bounds_strings_and_collections_explicitly():
    long_root = "https://" + "synthetic.test." * 300 + "/a"
    manifest = build_manifest(
        run_id="run9", group_id="g1", tenant="t1", project_id="p1",
        scope={"roots": [long_root]},
        settings={}, template_hashes={}, task_summaries=[
            {"reason": "x" * 5000} for _ in range(250)
        ],
    )
    text = json.dumps(manifest)
    assert "x" * 5000 not in text  # no silent oversize string
    assert "<redacted: oversize" in text
    assert len(manifest["tasks"]) <= 65  # bound plus the truncation marker
    assert any("<redacted: collection truncated" in str(t) for t in manifest["tasks"])
    # Oversize string in scope is an explicit marker, not silent truncation.
    assert long_root not in text
    assert "<redacted: oversize" in text


# ---------------------------------------------------------------------------
# B5 — strict reader: complete schema + expected context + digest
# ---------------------------------------------------------------------------

def _write_valid(base: Path) -> Path:
    path = manifest_path(base, "t1", "p1", "run9", "g1")
    manifest = build_manifest(run_id="run9", group_id="g1", tenant="t1",
                              project_id="p1", scope={}, settings={},
                              template_hashes={}, task_summaries=[],
                              reason="draft plan")
    write_manifest(path, manifest)
    return path


def test_read_manifest_accepts_complete_known_manifest():
    base = _tmp()
    path = _write_valid(base)
    assert read_manifest(path)["status"] == "known"


def test_read_manifest_rejects_incomplete_and_unsupported():
    base = _tmp()
    path = manifest_path(base, "t1", "p1", "run9", "g1")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Only schema_version: previously classed known, now unknown.
    path.write_text(json.dumps({"schema_version": 1}))
    assert read_manifest(path)["status"] == "unknown"
    # Unsupported schema version.
    base_manifest = build_manifest(
        run_id="run9", group_id="g1", tenant="t1", project_id="p1",
        scope={}, settings={}, template_hashes={}, task_summaries=[])
    bad = dict(base_manifest); bad["schema_version"] = 2
    path.write_text(json.dumps(bad))
    assert read_manifest(path)["status"] == "unknown"
    # Missing required key.
    bad = dict(base_manifest); del bad["run_id"]
    path.write_text(json.dumps(bad))
    assert read_manifest(path)["status"] == "unknown"
    # Invalid planner mode / empty context field.
    bad = dict(base_manifest); bad["planner_mode"] = "bogus"
    path.write_text(json.dumps(bad))
    assert read_manifest(path)["status"] == "unknown"
    bad = dict(base_manifest); bad["tenant"] = ""
    path.write_text(json.dumps(bad))
    assert read_manifest(path)["status"] == "unknown"


def test_read_manifest_rejects_tampered_digest_and_missing_file():
    base = _tmp()
    path = _write_valid(base)
    digest = manifest_digest(path)
    # Context matches, digest matches -> known.
    assert read_manifest_in_context(path, EXPECTED_CTX,
                                    expected_sha256=digest)["status"] == "known"
    # Tamper: flip a byte, digest no longer matches -> unknown.
    data = path.read_bytes()
    path.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))
    assert read_manifest_in_context(path, EXPECTED_CTX,
                                    expected_sha256=digest)["status"] == "unknown"
    # Missing file -> unknown.
    missing = manifest_path(base, "t1", "p1", "run9", "gone")
    assert read_manifest(missing)["status"] == "unknown"


def test_read_manifest_rejects_cross_context():
    base = _tmp()
    path = _write_valid(base)
    for key in ("tenant", "project_id", "run_id", "group_id"):
        wrong = dict(EXPECTED_CTX)
        wrong[key] = "not-the-run"
        assert read_manifest_in_context(path, wrong)["status"] == "unknown", key


# ---------------------------------------------------------------------------
# maybe_write_pre_dispatch_manifest: job context only, never fabricated
# ---------------------------------------------------------------------------

def test_maybe_write_disabled_returns_none():
    assert maybe_write_pre_dispatch_manifest({}, "/tmp/x.json") is None
    assert maybe_write_pre_dispatch_manifest(
        {"PLANNER_MANIFEST_ENABLED": False}, "/tmp/x.json") is None


def test_maybe_write_requires_complete_job_context_no_defaults():
    base = _tmp()
    out = base / "recon_p1.json"
    out.write_text("{}")
    # Manifest enabled but no tenant/project/run/group from job context:
    # nothing is fabricated, nothing is written, scan still proceeds.
    assert maybe_write_pre_dispatch_manifest(
        {"PLANNER_MANIFEST_ENABLED": True}, out) is None
    assert not list((base / "planner_manifests").rglob("*")) \
        if (base / "planner_manifests").exists() else True

    # Invalid identifier (traversal) is rejected, never written.
    assert maybe_write_pre_dispatch_manifest({
        "PLANNER_MANIFEST_ENABLED": True,
        "PLANNER_TENANT": "..", "PLANNER_PROJECT_ID": "p",
        "PLANNER_RUN_ID": "r", "PLANNER_GROUP_ID": "g",
    }, out) is None


def test_maybe_write_persists_before_readback_with_exact_context():
    base = _tmp()
    out = base / "recon_p1.json"
    out.write_text("{}")
    settings = {
        "PLANNER_MANIFEST_ENABLED": True,
        "PROJECT_ID": "p1", "USER_ID": "u1",
        "PLANNER_TENANT": "t1", "PLANNER_RUN_ID": "run9",
        "PLANNER_GROUP_ID": "g1", "SCOPE_GROUPS": [],
    }
    ptr = maybe_write_pre_dispatch_manifest(settings, out)
    assert ptr is not None
    assert set(ptr) == {"plan_manifest_path", "plan_manifest_sha256",
                        "plan_manifest_summary"}
    path = Path(ptr["plan_manifest_path"])
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # Digest on the pointer equals the live file digest.
    assert ptr["plan_manifest_sha256"] == manifest_digest(path)
    # Read back with the exact job context -> known; any other context -> unknown.
    m = read_manifest_in_context(path, EXPECTED_CTX,
                                 expected_sha256=ptr["plan_manifest_sha256"])
    assert m["status"] == "known"
    assert m["tenant"] == "t1" and m["project_id"] == "p1"
    assert m["run_id"] == "run9" and m["group_id"] == "g1"
    # No credentials survived into the manifest or the pointer summary.
    assert "SECRET" not in json.dumps(ptr) and "Bearer" not in json.dumps(m)


def test_maybe_write_does_not_mutate_caller_settings(tmp_path):
    out = tmp_path / "recon.json"
    out.write_text("{}")
    settings = {"PLANNER_MANIFEST_ENABLED": True,
                "PLANNER_TENANT": "t", "PLANNER_PROJECT_ID": "p",
                "PLANNER_RUN_ID": "r", "PLANNER_GROUP_ID": "g",
                "NUCLEI_RATE_LIMIT": 1}
    before = dict(settings)
    ptr = maybe_write_pre_dispatch_manifest(settings, out)
    assert ptr is not None
    assert settings == before  # caller's dict is never mutated
    # The on-disk manifest kept none of the caller's settings wholesale.
    m = read_manifest(Path(ptr["plan_manifest_path"]))
    assert m["status"] == "known"
    assert "NUCLEI_RATE_LIMIT" not in json.dumps(m)


def test_maybe_write_unwritable_output_never_raises():
    assert maybe_write_pre_dispatch_manifest(
        {"PLANNER_MANIFEST_ENABLED": True,
         "PLANNER_TENANT": "t", "PLANNER_PROJECT_ID": "p",
         "PLANNER_RUN_ID": "r", "PLANNER_GROUP_ID": "g"},
        "/nonexistent-dir-deep/no/such/file.json") is None


# ---------------------------------------------------------------------------
# B4 — manifest is written before vuln_scan launches, in every targeting mode
# ---------------------------------------------------------------------------

def _enabled_settings(group_id: str) -> dict:
    return {"PLANNER_MANIFEST_ENABLED": True,
            "PROJECT_ID": "p1", "USER_ID": "u1",
            "PLANNER_TENANT": "t1", "PLANNER_GROUP_ID": group_id,
            "SCOPE_GROUPS": []}


def test_manifest_persisted_before_launch_in_off_mode_is_none(monkeypatch, tmp_path):
    monkeypatch.setenv("RECON_RUN_ID", "run9")
    out = tmp_path / "recon.json"
    out.write_text("{}")
    combined = {"metadata": {}}
    settings = dict(_enabled_settings("g1"))
    settings["PLANNER_MANIFEST_ENABLED"] = False
    ptr = main_mod._write_pre_dispatch_plan_manifest(settings, out, combined,
                                                     group_id="g1")
    assert ptr is None
    assert "planner_manifest_pointers" not in combined.get("metadata", {})


def test_manifest_persisted_before_launch_writes_pointer_and_file(monkeypatch, tmp_path):
    monkeypatch.setenv("RECON_RUN_ID", "run9")
    out = tmp_path / "recon.json"
    out.write_text("{}")
    combined = {"metadata": {}}
    settings = _enabled_settings("g1")
    ptr = main_mod._write_pre_dispatch_plan_manifest(settings, out, combined,
                                                     group_id="g1")
    assert ptr is not None
    assert combined["metadata"]["planner_manifest_pointers"] == [ptr]
    path = Path(ptr["plan_manifest_path"])
    assert path.exists()  # durable on disk before any tool launch
    m = read_manifest_in_context(path, EXPECTED_CTX,
                                 expected_sha256=ptr["plan_manifest_sha256"])
    assert m["status"] == "known"


def test_manifest_group_isolation_across_modes(monkeypatch, tmp_path):
    """Domain single / domain batch group / IP modes land in distinct dirs."""
    monkeypatch.setenv("RECON_RUN_ID", "run9")
    base = tmp_path
    written = []
    for group_id in ("domain:synthetic.test", "domain:other.test", "ip",
                     "partial:nuclei"):
        out = base / f"recon-{group_id}.json"
        out.write_text("{}")
        combined = {"metadata": {}}
        settings = _enabled_settings(group_id)
        ptr = main_mod._write_pre_dispatch_plan_manifest(settings, out,
                                                         combined, group_id=group_id)
        assert ptr is not None
        written.append(ptr)
    paths = {Path(p["plan_manifest_path"]).parent for p in written}
    assert len(paths) == 4  # no two modes share a manifest file


# ---------------------------------------------------------------------------
# Partial dispatch ordering: manifest writer runs before run_vuln_scan
# ---------------------------------------------------------------------------

def test_partial_run_nuclei_manifest_before_vuln_scan(monkeypatch):
    """Mirror of the review's probe_callers.py harness: real caller, real
    settings dispatch, graph input and tool dispatch faked. Asserts the
    manifest helper is invoked BEFORE run_vuln_scan and receives the canonical
    partial job context."""
    from recon.partial_recon_modules import vulnerability_scanning as caller
    from recon.main_recon_modules import vuln_scan
    from recon.helpers import planner_manifest as pm

    captured = {"order": [], "manifest_settings": None}

    class Halt(BaseException):
        pass

    def fake_write(s, output_file=None, **kwargs):
        captured["order"].append("manifest")
        captured["manifest_settings"] = dict(s)
        return {"plan_manifest_path": "/x.json",
                "plan_manifest_sha256": "a" * 64,
                "plan_manifest_summary": {}}

    def fake_run_vuln_scan(data, settings=None, **kwargs):
        captured["order"].append("vuln_scan")
        assert captured["order"] == ["manifest", "vuln_scan"], \
            f"manifest must precede vuln_scan, got {captured['order']}"
        raise Halt()

    settings = {"PLANNER_MODE": "shadow", "NUCLEI_RATE_LIMIT": 1}
    synthetic = {"domain": "synthetic.test",
                 "dns": {"domain": {"has_records": False}, "subdomains": {}},
                 "http_probe": {"by_url": {"https://synthetic.test/a":
                                           {"host": "synthetic.test"}}},
                 "resource_enum": {"by_base_url": {},
                                   "discovered_urls": []}}
    with patch.object(caller, "partial_settings", return_value=settings), \
         patch.object(caller, "_build_vuln_scan_data_from_graph",
                      return_value=dict(synthetic)), \
         patch.object(pm, "maybe_write_pre_dispatch_manifest",
                      side_effect=fake_write), \
         patch.object(vuln_scan, "run_vuln_scan", side_effect=fake_run_vuln_scan), \
         patch.object(sys, "exit", side_effect=Halt()):
        try:
            caller.run_nuclei({"graph_inputs": {"domains": ["synthetic.test"]},
                               "settings_overrides": {}})
        except Halt:
            pass
    assert captured["order"] == ["manifest", "vuln_scan"]
    ms = captured["manifest_settings"]
    assert ms.get("PLANNER_GROUP_ID") == "partial:nuclei"
    for key in ("PLANNER_TENANT", "PLANNER_PROJECT_ID", "PLANNER_RUN_ID"):
        assert key in ms

# ---------------------------------------------------------------------------
# B4/B5 — honest accounting provenance (real scope roots, hashed templates,
# hashed observed inputs) and the run pointer index
# ---------------------------------------------------------------------------

def test_scope_roots_from_settings_batch_first():
    settings = {"SCOPE_GROUPS": [{"scanRoot": "synthetic.test"}, {"root_domain": "other.test"}]}
    assert pm.scope_roots_from_settings(settings) == ["synthetic.test", "other.test"]

def test_scope_roots_from_settings_legacy_fallback():
    settings = {"TARGET_DOMAIN": "synthetic.test", "TARGET_IPS": ["1.2.3.4", "5.6.7.8"]}
    assert pm.scope_roots_from_settings(settings) == ["synthetic.test", "1.2.3.4", "5.6.7.8"]
    assert pm.scope_roots_from_settings({}) == []

def test_template_hashes_from_settings():
    settings = {"NUCLEI_TEMPLATES": ["cves/2024.yaml", "cves/2024.yaml"],
                "NUCLEI_TAGS": ["cve", "xss"], "NUCLEI_CUSTOM_TEMPLATES": []}
    hashes = pm.template_hashes_from_settings(settings)
    assert "cves/2024.yaml" in hashes
    assert len(hashes["cves/2024.yaml"]) == 64
    assert "cve" in hashes and "xss" in hashes
    assert hashes["cves/2024.yaml"] == hashlib.sha256("cves/2024.yaml".encode()).hexdigest()
    assert pm.template_hashes_from_settings({}) == {}

def test_input_accounting_from_recon_data():
    recon_data = {"http_probe": {"by_url": {"https://synthetic.test/a": {},
                                             "https://synthetic.test/b": {}}},
                  "resource_enum": {"discovered_urls": ["https://synthetic.test/c"]},
                  "subdomains": ["synthetic.test"]}
    hashes, count = pm.input_accounting_from_recon_data(recon_data)
    assert count == 4
    assert set(hashes) == {"https://synthetic.test/a", "https://synthetic.test/b",
                           "https://synthetic.test/c", "synthetic.test"}
    assert all(len(h) == 64 for h in hashes.values())
    assert pm.input_accounting_from_recon_data({}) == ({}, 0)
    assert pm.input_accounting_from_recon_data(None) == ({}, 0)

def test_pointer_index_roundtrip(tmp_path):
    base = tmp_path / "manifests"
    ptr1 = {"plan_manifest_path": "x/p1.json", "plan_manifest_sha256": "a" * 64,
            "plan_manifest_summary": {"run_id": "r", "group_id": "g"}}
    pm.write_pointer_index(base, "p1", "r1", ptr1)
    got = pm.read_pointer_index(base, "p1", "r1")
    assert got == [ptr1]
    pm.write_pointer_index(base, "p1", "r1", ptr1)
    assert pm.read_pointer_index(base, "p1", "r1") == [ptr1]
    assert pm.read_pointer_index(base, "p1", "r2") == []
    bad = base / "p1" / "r1" / "pointers.json"
    bad.write_text("{not json")
    assert pm.read_pointer_index(base, "p1", "r1") == []

def test_maybe_write_writes_real_accounting_and_index(monkeypatch, tmp_path):
    monkeypatch.setenv("RECON_RUN_ID", "run9")
    monkeypatch.setenv("PROJECT_ID", "p1")
    monkeypatch.setenv("USER_ID", "u1")
    out = tmp_path / "recon_p1.json"
    out.write_text("{}")
    combined = {"metadata": {}, "http_probe": {"by_url": {"https://synthetic.test/a": {}}},
                "resource_enum": {"discovered_urls": []}, "subdomains": ["synthetic.test"]}
    settings = {"PLANNER_MANIFEST_ENABLED": True, "PLANNER_TENANT": "t1",
                "PLANNER_PROJECT_ID": "p1", "PLANNER_GROUP_ID": "g1",
                "SCOPE_GROUPS": [], "NUCLEI_TEMPLATES": ["cves/2024.yaml"]}
    ptr = main_mod._write_pre_dispatch_plan_manifest(settings, out, combined, group_id="g1")
    assert ptr is not None
    manifest = pm.read_manifest(Path(ptr["plan_manifest_path"]))
    assert manifest["status"] == "known"
    assert manifest["scope"] == {"roots": []}
    assert manifest["template_hashes"] == {"cves/2024.yaml": hashlib.sha256("cves/2024.yaml".encode()).hexdigest()}
    assert manifest["input_accounting"]["input_count"] == 2
    assert set(manifest["input_accounting"]["input_hashes"]) == {
        "https://synthetic.test/a", "synthetic.test"}
    base = pm.manifest_base_dir(out)
    idx = pm.read_pointer_index(base, "p1", "run9")
    assert any(p["plan_manifest_path"] == ptr["plan_manifest_path"] for p in idx)
    assert manifest["run_id"] == "run9"
    assert manifest["group_id"] == "g1"

def test_maybe_write_does_not_fabricate_run_id_or_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("RECON_RUN_ID", raising=False)
    monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)
    out = tmp_path / "recon.json"
    out.write_text("{}")
    settings = {"PLANNER_MANIFEST_ENABLED": True, "PLANNER_TENANT": "t",
                "PLANNER_PROJECT_ID": "p", "PLANNER_GROUP_ID": "g"}
    assert main_mod._write_pre_dispatch_plan_manifest(settings, out, {}, group_id="g") is None
    assert not list((tmp_path / "planner_manifests").rglob("*")) \
        if (tmp_path / "planner_manifests").exists() else True
