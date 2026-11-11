"""G2-R1 — inventory identities and full/partial retention.

These tests import only the pure inventory/adapters modules and the real
atomic writer. No Neo4j, no scanner binary, no network. One process per file.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from recon.helpers import atomic_io
from recon.helpers import discovery_inventory as di
from recon.helpers import discovery_adapters as da

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _obs(source, url, origin, path, method="GET", auth="anon", rev="",
         query=None, disposition="merged_new"):
    return di.observation(
        source=source, raw={"url": url}, origin=origin, path=path, method=method,
        query=query or [],
        auth_profile_ref=auth, auth_profile_revision=rev,
        validation={"status": "observed"},
        disposition=disposition,
        raw_locator=f"{source}:{origin}{path}",
    )


# ---------------------------------------------------------------------------
# B1 — observation identity: distinct from raw_ref, context-aware
# ---------------------------------------------------------------------------

def test_identity_is_distinct_from_raw_ref():
    obs = _obs("ffuf", "https://a.test/x", "https://a.test", "/x")
    assert obs["observation_id"] != obs["raw_ref"]
    assert obs["observation_id"].startswith("obs_v1:")


def test_same_raw_different_contexts_are_distinct_identities():
    raw = {"url": "https://synthetic.test/a"}
    a = _obs("katana", "https://synthetic.test/a", "https://synthetic.test",
             "/a", method="GET", auth="auth-A")
    b = _obs("katana", "https://synthetic.test/a", "https://synthetic.test",
             "/a", method="POST", auth="auth-B")
    di_obs_a = di.observation(raw=raw, source="katana", origin="https://synthetic.test",
                              path="/a", method="GET",
                              auth_profile_ref="auth-A",
                              validation={"status": "observed"},
                              disposition="merged_new")
    di_obs_b = di.observation(raw=raw, source="katana", origin="https://synthetic.test",
                              path="/a", method="POST",
                              auth_profile_ref="auth-B",
                              validation={"status": "observed"},
                              disposition="merged_new")
    assert di_obs_a["raw_ref"] == di_obs_b["raw_ref"]          # same raw record
    assert di_obs_a["observation_id"] != di_obs_b["observation_id"]   # different context


def test_identity_includes_parameter_schema_and_encoding():
    q1 = [{"name": "q", "type": "string", "position": "query",
           "sample_values": ["1"], "sample_values_encoding": "decoded-observation"}]
    q2 = [{"name": "q", "type": "string", "position": "query",
           "sample_values": ["2"], "sample_values_encoding": "decoded-observation"}]
    q3 = [{"name": "r", "type": "string", "position": "query",
           "sample_values": ["1"], "sample_values_encoding": "decoded-observation"}]
    common = dict(source="arjun", origin="https://a.test", path="/x",
                  auth_profile_ref="anon")
    same = di.observation(raw={"url": "https://a.test/x?q=1"}, **common,
                          validation={"status": "observed"},
                          disposition="merged_new", query=q1)
    # Raw values are NOT part of the identity: different sample values, same context.
    assert di.observation(raw={"url": "https://a.test/x?q=2"}, **common,
                          validation={"status": "observed"},
                          disposition="merged_new", query=q2)[
        "observation_id"] == same["observation_id"]
    # Different parameter name IS a different context.
    assert di.observation(raw={"url": "https://a.test/x?r=1"}, **common,
                          validation={"status": "observed"},
                          disposition="merged_new", query=q3)[
        "observation_id"] != same["observation_id"]


def test_identity_includes_auth_profile_revision():
    common = dict(source="gau", origin="https://a.test", path="/x",
                  auth_profile_ref="prof-1")
    r1 = di.observation(raw={"url": "https://a.test/x"}, **common,
                        auth_profile_revision="r1",
                        validation={"status": "observed"},
                        disposition="merged_new")
    r2 = di.observation(raw={"url": "https://a.test/x"}, **common,
                        auth_profile_revision="r2",
                        validation={"status": "observed"},
                        disposition="merged_new")
    assert r1["observation_id"] != r2["observation_id"]
    assert di.observation(raw={"url": "https://a.test/x"}, **common,
                          auth_profile_revision="r1",
                          validation={"status": "observed"},
                          disposition="merged_new")[
        "observation_id"] == r1["observation_id"]


def test_identity_excludes_raw_values_no_credential_leak():
    secret = "eyJhbGciOiJIUzI1NiJ9.secret"
    obs = di.observation(
        source="katana", raw={"url": f"https://a.test/x?token={secret}"},
        origin="https://a.test", path="/x", auth_profile_ref="anon",
        validation={"status": "observed"}, disposition="merged_new",
    )
    blob = json.dumps(obs, sort_keys=True)
    assert secret not in blob
    assert secret not in obs["observation_id"]


# ---------------------------------------------------------------------------
# B1 — group merge keeps distinct contexts, dedupes genuinely identical ones
# ---------------------------------------------------------------------------

def test_merge_keeps_auth_and_method_contexts():
    older = di.new_inventory()
    newer = di.new_inventory()
    for inv, auth, method in ((older, "auth-A", "GET"), (newer, "auth-B", "POST")):
        di.add_observation(inv, _obs("katana", "https://synthetic.test/a",
                                     "https://synthetic.test", "/a",
                                     method=method, auth=auth))
    merged = di.merge_inventories(older, newer)
    obs = merged["producers"]["katana"]["observations"]
    assert len(obs) == 2
    contexts = sorted((o["auth_profile_ref"], o["method"]) for o in obs)
    assert contexts == [("auth-A", "GET"), ("auth-B", "POST")]


def test_merge_dedupes_genuinely_identical_observation():
    older = di.new_inventory()
    obs = _obs("gau", "https://a.test/x", "https://a.test", "/x")
    di.add_observation(older, obs)
    newer = di.new_inventory()
    di.add_observation(newer, obs)  # same record, same context
    di.add_observation(newer, _obs("gau", "https://a.test/x?q=1",
                                   "https://a.test", "/x"))  # different raw record
    merged = di.merge_inventories(older, newer)
    obs_list = merged["producers"]["gau"]["observations"]
    # Same context + same raw record collapses; a different raw record is kept
    # even though its identity (request context) matches the first one.
    assert len(obs_list) == 2
    assert len({o["observation_id"] for o in obs_list}) == 1


def test_slash_case_encoding_variants_stay_distinct_through_merge():
    older = di.new_inventory()
    newer = di.new_inventory()
    for inv, variant in ((older, "/API/Users"), (newer, "/api/users/")):
        di.add_observation(inv, _obs("katana", f"https://a.test{variant}",
                                     "https://a.test", variant))
    merged = di.merge_inventories(older, newer)
    assert len(merged["producers"]["katana"]["observations"]) == 2


# ---------------------------------------------------------------------------
# B2 — every malformed/rejected input is accounted by stable safe identity
# ---------------------------------------------------------------------------

def test_malformed_inputs_are_recorded_not_silent():
    inv = di.new_inventory()
    da.observe_crawl(inv, source="katana", urls=[None, "", 42, "not-a-url",
                                                 "ftp://a.test/x"])
    prod = inv["producers"]["katana"]
    assert prod["rejected"]["non_string_or_empty_url"] == 3
    assert prod["rejected"]["non_http_url"] == 2
    ledger = prod["input_ledger"]
    assert ledger["total"] == 5
    refs = [e["ref"] for e in ledger["entries"]]
    assert refs == ["katana:input:0", "katana:input:1", "katana:input:2",
                    "katana:input:3", "katana:input:4"]
    # No target text is echoed into a ref or identity.
    for e in ledger["entries"]:
        assert e["ref"].startswith("katana:input:")
        assert "ftp://" not in e["ref"] and "42" not in e["ref"]
        assert e["disposition"] == "rejected"
        assert e["identity"].startswith("rej_v1:")
        assert e["ref"] not in e["identity"]


def test_reject_input_keeps_reason_and_identity():
    inv = di.new_inventory()
    di.reject_input(inv, "ffuf", "malformed_result", "ffuf:input:7")
    prod = inv["producers"]["ffuf"]
    assert prod["rejected"]["malformed_result"] == 1
    entry = prod["input_ledger"]["entries"][0]
    assert entry["ref"] == "ffuf:input:7"
    assert entry["identity"] == di.rejected_identity("ffuf", "ffuf:input:7",
                                                     "malformed_result")


def test_ledger_bounded_with_observable_backpressure():
    inv = di.new_inventory()
    limit = di.MAX_INPUT_LEDGER_PER_SOURCE
    for i in range(limit + 4):
        da.observe_crawl(inv, source="ffuf",
                         urls=[f"https://a.test/{i}"])
    prod = inv["producers"]["ffuf"]
    ledger = prod["input_ledger"]
    assert ledger["total"] == limit + 4
    assert len(ledger["entries"]) == limit
    assert ledger["truncated"]["dropped"] == 4
    assert ledger["truncated"]["reason"] == "input_ledger_cap_evidence_only"


# ---------------------------------------------------------------------------
# B2 — reconciliation compares ledger vs retained/rejected identities
# ---------------------------------------------------------------------------

def test_reconcile_detects_lost_observation_by_identity():
    inv = di.new_inventory()
    da.observe_crawl(inv, source="katana", urls=["https://synthetic.test/lost"])
    structure = {
        "https://synthetic.test": {
            "base_url": "https://synthetic.test",
            "endpoints": {"/different": {"methods": ["GET"],
                                         "parameters": {"query": [], "body": [], "path": []}}},
        },
    }
    di.reconcile(inv, structure,
                 {"total_endpoints": 1, "total_parameters": 0, "total_base_urls": 1})
    rec = inv["reconciliation"]
    assert rec["match"] is False
    assert rec["inventory_distinct_endpoints"] == 1
    assert any(m["reason"] == "merged_disposition_but_absent_from_by_base_url"
               for m in rec["mismatches"])


def test_reconcile_unaccounted_ledger_retained_entry():
    inv = di.new_inventory()
    obs = _obs("ffuf", "https://a.test/x", "https://a.test", "/x")
    di.add_observation(inv, obs)
    inv["producers"]["ffuf"]["observations"].pop()
    structure = {"https://a.test": {"base_url": "https://a.test", "endpoints": {}}}
    di.reconcile(inv, structure, {"total_endpoints": 0, "total_parameters": 0,
                                  "total_base_urls": 1})
    rec = inv["reconciliation"]
    assert rec["identity_match"] is False
    assert rec["unaccounted_identities"] == [obs["observation_id"]]


def test_reconcile_phantom_observation_without_input_entry():
    inv = di.new_inventory()
    di._producer(inv, "ffuf")  # create the block without recording an input
    obs = _obs("ffuf", "https://a.test/x", "https://a.test", "/x")
    inv["producers"]["ffuf"]["observations"].append(obs)
    structure = {"https://a.test": {"base_url": "https://a.test",
                                    "endpoints": {"/x": {"methods": ["GET"],
                                                         "parameters": {"query": [],
                                                                        "body": [],
                                                                        "path": []}}}}}
    di.reconcile(inv, structure, {"total_endpoints": 1, "total_parameters": 0,
                                  "total_base_urls": 1})
    rec = inv["reconciliation"]
    assert rec["identity_match"] is False
    assert any(m["reason"] == "observation_without_input_ledger_entry"
               for m in rec["mismatches"])


def test_reconcile_count_match_is_not_identity_match():
    inv = di.new_inventory()
    da.observe_crawl(inv, source="gau", urls=["https://a.test/lost"])
    da.observe_crawl(inv, source="gau", urls=["https://a.test/kept"])
    structure = {
        "https://a.test": {
            "base_url": "https://a.test",
            "endpoints": {"/kept": {"methods": ["GET"],
                                    "parameters": {"query": [], "body": [], "path": []}}},
        },
    }
    di.reconcile(inv, structure, {"total_endpoints": 1, "total_parameters": 0,
                                  "total_base_urls": 1})
    rec = inv["reconciliation"]
    assert rec["inventory_distinct_endpoints"] == 1
    assert rec["observed_distinct_endpoints"] == 2
    assert rec["match"] is False


# ---------------------------------------------------------------------------
# Full roundtrip: producer -> deepcopy -> batch merge -> atomic save -> API read
# ---------------------------------------------------------------------------

def test_identities_survive_deepcopy_merge_atomic_save_api_read(tmp_path):
    inv_a = di.new_inventory()
    da.observe_crawl(inv_a, source="katana", urls=["https://synthetic.test/a"],
                     auth_ref="auth-A", auth_revision="r1",
                     existing_keys=set(),
                     merged_keys={("https://synthetic.test", "/a")})
    da.observe_crawl(inv_a, source="katana", urls=["https://synthetic.test/a"],
                     auth_ref="auth-B", auth_revision="r2",
                     existing_keys=set(),
                     merged_keys={("https://synthetic.test", "/a")})
    da.observe_crawl(inv_a, source="katana", urls=[None])

    inv_b = di.new_inventory()
    da.observe_crawl(inv_b, source="katana", urls=["https://synthetic.test/a"],
                     auth_ref="auth-A", auth_revision="r1",
                     existing_keys=set(),
                     merged_keys={("https://synthetic.test", "/a")})

    a_copy = copy.deepcopy(inv_a)
    b_copy = copy.deepcopy(inv_b)

    merged = di.merge_inventories(a_copy, b_copy)
    katana = merged["producers"]["katana"]
    assert len(katana["observations"]) == 2
    assert {o["auth_profile_ref"] for o in katana["observations"]} == {"auth-A", "auth-B"}
    # Two distinct contexts survive; the duplicate collapses; the malformed input
    # is accounted in the ledger (3 from A, 1 from B).
    assert katana["input_ledger"]["total"] == 4
    assert katana["rejected"]["non_string_or_empty_url"] == 1

    artifact = {"metadata": {"project_id": "p1"}, di.KEY: merged}
    out = tmp_path / "recon_p1.json"
    atomic_io.atomic_write_json(out, artifact)

    on_disk = json.loads(out.read_text())
    read = di.read_persisted_inventory(on_disk)
    assert read["status"] == "known"
    proj = read["inventory"]["producers"]["katana"]
    identities = {o["observation_id"] for o in proj["observations"]}
    assert len(identities) == 2
    auths = {o["auth_profile_ref"] for o in proj["observations"]}
    assert auths == {"auth-A", "auth-B"}
    assert proj["input_ledger"]["total"] == 4
    assert proj["input_ledger"]["entries"][0]["disposition"] == "retained"

    assert di.read_persisted_inventory(on_disk) == read
    assert di.select_persisted_fields(merged)["producers"]["katana"] == proj


def test_unknown_status_for_unpersisted_or_tampered_artifact():
    assert di.read_persisted_inventory({"metadata": {}})["status"] == "unknown"
    assert di.read_persisted_inventory({"discovery_inventory": "not-a-dict"})[
        "status"] == "unknown"
    bad = {"discovery_inventory": {"schema_version": 99, "producers": {}}}
    assert di.read_persisted_inventory(bad)["status"] == "unknown"
    assert di.read_persisted_inventory(None)["status"] == "unknown"


# ---------------------------------------------------------------------------
# Partial run: build_partial_inventory wired and identity-correct
# ---------------------------------------------------------------------------

def test_build_partial_inventory_keeps_identities_and_rejections():
    inv = da.build_partial_inventory(
        source="ffuf",
        observations=[
            _obs("ffuf", "https://synthetic.test/a", "https://synthetic.test", "/a"),
            _obs("ffuf", "https://synthetic.test/a", "https://synthetic.test", "/a",
                 method="POST"),
        ],
        rejected={"non_http_url": 1},
        by_base_url={"https://synthetic.test": {"base_url": "https://synthetic.test",
                                                "endpoints": {}}},
        summary={"total_endpoints": 0, "total_parameters": 0,
                 "total_base_urls": 1},
    )
    prod = inv["producers"]["ffuf"]
    assert len(prod["observations"]) == 2
    assert len({o["observation_id"] for o in prod["observations"]}) == 2
    assert prod["rejected"]["non_http_url"] == 1
    rec = inv["reconciliation"]
    assert rec["observed_distinct_endpoints"] == 2
    assert rec["inventory_distinct_endpoints"] == 0
    assert rec["match"] is False
