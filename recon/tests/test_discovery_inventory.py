"""F08 — discovery inventory: versioned observations, producer evidence,
consumer disposition, and reconciled counts.

These tests import only the pure inventory/adapters modules and real producer
helpers. No Neo4j, no scanner binary, no network.
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from recon.helpers import discovery_inventory as di
from recon.helpers import discovery_adapters as da
from recon.helpers import atomic_io


# ---------------------------------------------------------------------------
# Observation identity
# ---------------------------------------------------------------------------


def test_observation_keeps_raw_ref_and_path_fidelity():
    raw = {"url": "https://A.test/API/V1/Users?q=1", "status": 200}
    obs = di.observation(
        source="ffuf", raw=raw, origin="https://A.test", path="/API/V1/Users",
        method="GET",
        query=[{"name": "q", "type": "string", "position": "query",
                "sample_values": ["1"], "sample_values_encoding": "decoded-observation"}],
        validation={"status": "observed", "status_code": 200},
        disposition="merged_new",
    )
    assert obs["raw_ref"] == hashlib.sha256(
        json.dumps(raw, sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    # Raw itself is never stored.
    assert "url" not in obs and "status" not in obs
    # Case, slash and encoding are kept exactly as observed.
    assert obs["origin"] == "https://A.test"
    assert obs["path"] == "/API/V1/Users"
    assert obs["method"] == "GET"
    assert obs["validation"]["status_code"] == 200


def test_unknown_is_not_fabricated_200():
    obs = di.observation(
        source="ffuf", raw={"url": "https://a.test/x"}, origin="https://a.test",
        path="/x", method="GET", validation={"status": "unknown"})
    assert obs["validation"]["status"] == "unknown"
    assert obs["validation"].get("status_code") is None


def test_observation_adds_raw_ref_only():
    inv = di.new_inventory()
    obs = di.observation(source="katana", raw={"url": "https://a.test/"},
                         origin="https://a.test", path="/", disposition="merged_new")
    di.add_observation(inv, obs)
    assert inv["producers"]["katana"]["observations"][0]["raw_ref"]
    assert "raw_locator" not in inv["producers"]["katana"]["observations"][0]


# ---------------------------------------------------------------------------
# Bounded retention
# ---------------------------------------------------------------------------


def test_add_observation_bounds_retention_and_names_dropped():
    inv = di.new_inventory()
    limit = di.MAX_OBSERVATIONS_PER_SOURCE
    for i in range(limit + 3):
        di.add_observation(inv, di.observation(
            source="ffuf", raw={"url": f"https://a.test/{i}"},
            origin="https://a.test", path=f"/{i}", disposition="merged_new"))
    prod = inv["producers"]["ffuf"]
    assert len(prod["observations"]) == limit
    assert prod["truncated"]["limit"] == limit
    assert prod["truncated"]["dropped"] == 3
    assert inv["truncated"]["ffuf"]["dropped"] == 3


# ---------------------------------------------------------------------------
# Raw evidence survives temp cleanup
# ---------------------------------------------------------------------------


def test_record_raw_evidence_persists_metadata_only():
    inv = di.new_inventory()
    long_body = "x" * (di.MAX_STRING * 3)
    di.record_raw_evidence(inv, "ffuf", record={
        "targets": 40, "results": 12, "wordlist": "/wordlists/common.txt",
        "response_body_like": long_body,
    })
    rec = inv["producers"]["ffuf"]["raw_evidence"]
    assert rec["targets"] == 40
    assert rec["results"] == 12
    assert rec["wordlist"] == "/wordlists/common.txt"
    # A body-like value is clipped, never stored in full.
    assert rec["response_body_like"] == long_body[:di.MAX_STRING]


def test_atomic_write_swap_and_oversized_refusal():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "art.json"
        atomic_io.atomic_write_json(p, {"a": 1})
        assert json.loads(p.read_text()) == {"a": 1}
        atomic_io.atomic_write_json(p, {"b": 2})
        assert json.loads(p.read_text()) == {"b": 2}
        try:
            atomic_io.atomic_write_json(p, {"x": "y" * 10}, max_bytes=5)
        except atomic_io.ArtifactTooLarge:
            pass
        else:
            raise AssertionError("expected ArtifactTooLarge")
        assert json.loads(p.read_text()) == {"b": 2}


# ---------------------------------------------------------------------------
# Slash / case / encoding fidelity: variants stay distinct
# ---------------------------------------------------------------------------


def test_family_key_is_a_label_never_a_merge_key():
    inv = di.new_inventory()
    for variant in ("/API/Users", "/api/users", "/API/Users/"):
        di.add_observation(inv, di.observation(
            source="katana", raw={"url": f"https://a.test{variant}"},
            origin="https://a.test", path=variant, disposition="merged_new"))
    bucket = inv["origins"]["https://a.test"]
    assert bucket["observations"] == 3
    assert bucket["family_keys"]["https://a.test|GET|/API/Users"] == 1
    assert bucket["family_keys"]["https://a.test|GET|/api/users"] == 1
    assert bucket["family_keys"]["https://a.test|GET|/API/Users/"] == 1


# ---------------------------------------------------------------------------
# FFuf observations: status is the producer's, never fabricated
# ---------------------------------------------------------------------------


def test_observe_ffuf_merged_new_and_overlap():
    inv = di.new_inventory()
    existing = {("https://a.test", "/admin")}
    results = [
        {"url": "https://a.test/admin", "status": 200, "length": 500},
        {"url": "https://a.test/.env", "status": 403, "length": 12},
    ]
    da.observe_ffuf(inv, results=results, existing_keys=existing)
    obs = inv["producers"]["ffuf"]["observations"]
    assert len(obs) == 2
    statuses = {o["path"]: o["validation"]["status_code"] for o in obs}
    assert statuses["/admin"] == 200
    assert statuses["/.env"] == 403
    assert obs[0]["disposition"] == "overlap_existing"
    assert obs[1]["disposition"] == "merged_new"


def test_observe_ffuf_missing_status_is_unknown_not_200():
    inv = di.new_inventory()
    da.observe_ffuf(inv, results=[{"url": "https://a.test/x"}], existing_keys=set())
    obs = inv["producers"]["ffuf"]["observations"][0]
    assert obs["validation"]["status"] == "unknown"
    assert obs["validation"].get("status_code") is None


# ---------------------------------------------------------------------------
# OpenAPI: a declaration is never an observed executable URL
# ---------------------------------------------------------------------------


def test_openapi_template_path_is_declared_only():
    inv = di.new_inventory()
    existing = set()
    payload = {
        "operations": [{
            "baseurl": "https://api.test", "path": "/users/{id}", "method": "GET",
            "operation": {"parameters": [{"in": "path", "name": "id",
                                         "schema": {"type": "string"}}]},
        }],
        "documents": [],
    }
    da.observe_openapi(inv, payload=payload, existing_keys=existing)
    paths = [o["path"] for o in inv["producers"]["openapi"]["observations"]]
    assert "/users/{id}" in paths  # the template, marked declared_only_template
    assert "/users/1" in paths     # the filled example
    by_disp = {}
    for o in inv["producers"]["openapi"]["observations"]:
        by_disp.setdefault(o["disposition"], []).append(o["path"])
    assert "/users/{id}" in by_disp["declared_only_template"]
    assert "/users/1" in by_disp["declared_only_new"]
    for o in inv["producers"]["openapi"]["observations"]:
        if o["disposition"] == "declared_only_new":
            assert o["validation"]["status"] == "declared"


# ---------------------------------------------------------------------------
# Reconciliation: counts recompute from members; mismatch is reported
# ---------------------------------------------------------------------------


def test_reconcile_recomputes_summary_from_members():
    inv = di.new_inventory()
    by_base_url = {
        "https://a.test": {
            "base_url": "https://a.test",
            "endpoints": {
                "/x": {"methods": ["GET", "POST"],
                       "parameters": {"query": [{"name": "q"}], "body": [], "path": []}},
                "/y": {"methods": ["GET"], "parameters": {"query": [], "body": [], "path": []}},
            },
        },
    }
    summary = {"total_endpoints": 1, "total_parameters": 0}  # drifted: 1 endpoint, 1 param
    di.reconcile(inv, by_base_url, summary)
    rec = inv["reconciliation"]
    assert rec["match"] is False
    assert any(m["field"] == "total_endpoints" for m in rec["mismatches"])
    assert rec["inventory_distinct_endpoints"] == 3
    assert rec["inventory_distinct_parameters"] == 1


def test_recompute_counts_fixes_ffuf_parameter_drift():
    by_base_url = {
        "https://a.test": {
            "endpoints": {"/x": {"parameters": {"query": [{"name": "q"}], "body": [], "path": []},
                                 "summary": {"total_parameters": 0}}},
            "summary": {"total_endpoints": 1, "total_parameters": 0},
        },
    }
    fixed = di.recompute_counts(by_base_url)
    assert fixed["total_parameters"] == 1
    assert by_base_url["https://a.test"]["endpoints"]["/x"]["parameter_count"]["total"] == 1


# ---------------------------------------------------------------------------
# Serialization roundtrip
# ---------------------------------------------------------------------------


def test_serialize_deserialize_roundtrip_is_byte_stable():
    inv = di.new_inventory()
    di.add_observation(inv, di.observation(
        source="kiterunner", raw={"url": "https://a.test/admin", "method": "POST"},
        origin="https://a.test", path="/admin", method="POST",
        validation={"status": "observed", "status_code": 201},
        disposition="merged_new"))
    first = di.serialize(inv)
    back = di.deserialize(first)
    assert di.serialize(back) == first
    assert back["producers"]["kiterunner"]["observations"][0]["validation"]["status_code"] == 201


# ---------------------------------------------------------------------------
# Merging two group inventories dedupes by raw_ref only
# ---------------------------------------------------------------------------


def test_merge_inventories_dedupes_by_raw_ref():
    older = di.new_inventory()
    obs = di.observation(source="gau", raw={"url": "https://a.test/x"},
                         origin="https://a.test", path="/x", disposition="merged_new")
    di.add_observation(older, obs)
    newer = di.new_inventory()
    di.add_observation(newer, obs)  # same raw record
    di.add_observation(newer, di.observation(
        source="gau", raw={"url": "https://a.test/x?q=1"}, origin="https://a.test",
        path="/x", method="GET", disposition="merged_new"))  # same path, different record
    merged = di.merge_inventories(older, newer)
    refs = [o["raw_ref"] for o in merged["producers"]["gau"]["observations"]]
    assert len(refs) == len(set(refs))
    assert len(refs) == 2


# ---------------------------------------------------------------------------
# Consumer adapters name absent sources instead of hiding them
# ---------------------------------------------------------------------------


def test_consumer_nuclei_dast_names_kiterunner_and_openapi_absent():
    inv = di.new_inventory()
    da.consumer_nuclei_dast(
        inv, dast_count=0,
        discovered_url_sources={"katana": 5, "ffuf": 3},
        sources_absent=["kiterunner", "openapi"],
        note="DAST reads discovered_urls which omits late merges.",
    )
    c = inv["consumers"]["nuclei_dast"]
    assert c["admitted"] == 0
    assert c["not_admitted"]["kiterunner"]["reason"] == "not_in_discovered_urls"
    assert c["not_admitted"]["openapi"]["reason"] == "not_in_discovered_urls"
    assert c["notes"][0].endswith("omits late merges.")


def test_consumer_arjun_names_late_producers_not_yet_merged():
    inv = di.new_inventory()
    da.consumer_arjun(
        inv, targets=200, unexecuted=5,
        sources_present=["katana", "ffuf"],
        sources_absent=["gau", "openapi", "kiterunner"],
    )
    c = inv["consumers"]["arjun_full"]
    assert c["not_admitted"]["gau"]["reason"] == "not_yet_merged"
    assert c["not_admitted"]["unexecuted_by_cap"]["count"] == 5


# ---------------------------------------------------------------------------
# Endpoint writer test scaffolding (RecordingGraph contracts live elsewhere;
# this guards the new additive properties are passed through)
# ---------------------------------------------------------------------------


def test_resource_mixin_accepts_ffuf_metadata_fields():
    """The writer path reads ffuf_metadata and projects ffuf_status/length/content_type."""
    import inspect
    from graph_db.mixins.recon.resource_mixin import ResourceMixin
    source = inspect.getsource(ResourceMixin.update_graph_from_resource_enum)
    # The SET clause must carry each new additive property from its parameter.
    for field, param in (("ffuf_status", "ffuf_status"),
                         ("ffuf_length", "ffuf_length"),
                         ("ffuf_content_type", "ffuf_content_type")):
        assert f"e.{field} = coalesce(${param}" in source, f"{field} must be projected by the writer"
        assert f"{field}={field}," in source or f"{field}={field}\n" in source or f"{field}={field}," in source, \
            f"{field} must be passed to session.run"
    # The parameter is read from ffuf_metadata.
    assert 'ffuf_metadata = endpoint_info.get("ffuf_metadata")' in source
    assert "ffuf_status = ffuf_metadata.get(\"status\")" in source
    assert "ffuf_length = ffuf_metadata.get(\"length\")" in source
    assert "ffuf_content_type = ffuf_metadata.get(\"content_type\")" in source


def test_ffuf_producer_records_raw_before_temp_removal():
    inv = di.new_inventory()
    da.observe_ffuf(inv, results=[
        {"url": "https://a.test/.env", "status": 200, "length": 123,
         "content_type": "text/plain"},
    ], existing_keys=set())
    di.record_raw_evidence(inv, "ffuf", record={
        "targets": 1, "results": 1, "temp_output_removed": True,
    })
    assert inv["producers"]["ffuf"]["observations"][0]["evidence"]["content_type"] == "text/plain"
    assert inv["producers"]["ffuf"]["raw_evidence"]["temp_output_removed"] is True
