"""P0 executable baseline, not an endorsement of legacy lossy projections.

Only tool/driver boundaries are mocked. No target or Docker socket is used.
Future changed-behavior requirements live in negative-contracts.json, not xfails.
"""
import copy
import json
from pathlib import Path
from unittest.mock import MagicMock
from urllib.parse import parse_qsl, urlsplit

import pytest

from recon.helpers import target_helpers as th
from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets
from recon.main_recon_modules import vuln_scan as vs
from recon.tests.test_coverage_prune import recon_main, graph  # noqa: F401 fixtures
from recon.tests.test_nuclei_cve_findings_reach_graph import _Client, _vuln_props

FIXTURES = Path(__file__).parent / "fixtures" / "recon_quality"
CORPUS = json.loads((FIXTURES / "corpus.json").read_text())
CASES = {r["id"]: r for r in CORPUS["cases"]}


def native_resource(rows):
    """Explicit TEST adapter, not a new engine inventory or producer merge."""
    by_base = {}
    for row in rows:
        by_base.setdefault(row["origin"], {"endpoints": {}})["endpoints"][row["path"]] = {
            "methods": [row["method"]], "parameters": copy.deepcopy(row["parameters"]),
            "declared_only": row["declared_only"], "sources": row["provenance"],
            "status_code": row["validation"]["status_code"],
        }
    return {"by_base_url": by_base, "discovered_urls": [r["raw_url"] for r in rows]}


def test_corpus_identity_and_roundtrip():
    rows = CORPUS["cases"]
    assert CORPUS["synthetic"] is True and CORPUS["seed"] == 0
    assert len(CASES) == len(rows)
    assert json.loads(json.dumps(rows)) == rows
    assert CASES["post-body-auth"]["auth_ref"] == "synthetic-session-A"
    assert CASES["post-body-auth"]["method"] == "POST"
    assert CASES["timeout-unknown"]["validation"]["state"] == "unknown"
    assert CASES["challenge-unknown"]["validation"]["challenge"] is True
    assert parse_qsl(urlsplit(CASES["duplicate-keys"]["raw_url"]).query, keep_blank_values=True) == [
        ("k", "1"), ("k", "2"), ("empty", ""), ("K", "3")]
    assert {401, 403, 404, 405} <= {r["validation"]["status_code"] for r in rows}
    assert {"kiterunner", "openapi", "jsluice"} <= {p for r in rows for p in r["provenance"]}


@pytest.mark.parametrize("case_id", [r["id"] for r in CORPUS["cases"] if "origin" in r])
def test_characterize_native_builder_projection(case_id):
    row = CASES[case_id]
    bases, urls = th.build_target_urls_from_resource_enum(native_resource([row]))
    assert bases == [row["origin"]]
    # Literal expectations keep this independent of the URL helper under test.
    if row["id"] in {"declared-post", "declared-template"}:
        assert urls == []  # not executable GET targets; declaration still in corpus
    elif row["id"] == "query-encoding":
        # F01 rejects the malformed raw-whitespace URI produced by the legacy
        # interpolation. Raw observation survives; F02 owns correct encoding.
        assert urls == []
    elif row["id"] == "duplicate-keys":
        assert urls == ["https://a.example.test/api/dup?k=1&empty=&K=3"]
    else:
        assert urls == [row["raw_url"]]
    # This captures admission only, not method/auth/validation fidelity or coverage.


def test_negative_probe_query_fidelity_is_not_approved_baseline():
    row = CASES["query-encoding"]
    rebuilt = th._endpoint_url(row["origin"], row["path"], {"parameters": row["parameters"]})
    desired_pairs = parse_qsl(urlsplit(row["raw_url"]).query, keep_blank_values=True)
    assert desired_pairs == [("q", "a&b=# %+雪")]
    assert parse_qsl(urlsplit(rebuilt).query, keep_blank_values=True) != desired_pairs
    # F02 must replace this defect probe with equality against the desired contract.


def test_ffuf_seed_path_meets_f01_contract():
    contract = json.loads((FIXTURES / "negative-contracts.json").read_text())["cases"][0]
    assert _build_fuzz_targets([contract["input"]]) == [contract["required"]]
    assert contract["legacy"] != contract["required"]


def test_negative_fixture_inputs_remain_raw_not_validated():
    invalid = [r for r in CORPUS["cases"] if r.get("http_eligible") is False]
    assert len(invalid) == 7
    assert {r["id"] for r in invalid} == {"tel", "mailto", "javascript", "hostless", "bad-port", "bad-bracket", "control"}
    assert all(r["validation"]["state"] == "unknown" for r in invalid)
    # Deliberately do not send these through the legacy caller: F01 owns fail-closed
    # HTTP validation across every source. Fixture membership is not that fix.


def test_actual_two_pass_parse_merge_artifact_graph_and_prune(monkeypatch, tmp_path, recon_main, graph):
    from helpers import proxy_routing
    rows = [CASES[k] for k in ("app-prefix-a", "app-prefix-b", "duplicate-keys")]
    resource = native_resource(rows)
    data = {"domain": "example.test", "subdomains": ["a.example.test", "b.example.test"],
            "resource_enum": resource,
            "http_probe": {"by_url": {}}, "metadata": {"modules_executed": []}}
    original = copy.deepcopy(data)
    generated = []
    for name in ("is_docker_installed", "is_docker_running", "pull_nuclei_docker_image", "ensure_templates_volume"):
        monkeypatch.setattr(vs, name, lambda *args: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd: ([], ["a.example.test", "b.example.test"], {}))
    monkeypatch.setattr(proxy_routing, "get_capture_routing", lambda tool: (None, None))

    def fake_popen(cmd, **kwargs):
        # Read the actual target file through the generated bind/argv contract.
        host_dir = next(arg.rsplit(":/targets:ro", 1)[0] for arg in cmd if arg.endswith(":/targets:ro"))
        target_file = Path(host_dir) / Path(cmd[cmd.index("-l") + 1]).name
        output = Path(host_dir) / Path(cmd[cmd.index("-o") + 1]).name
        urls = target_file.read_text().splitlines()
        is_dast = "-dast" in cmd
        generated.append({"dast": is_dast, "urls": urls, "cmd": cmd})
        assert "X-Synthetic-Identity: p0" in cmd
        raw = {"template-id": "synthetic-dast" if is_dast else "synthetic-detection",
               "info": {"name": "Synthetic P0", "severity": "low", "tags": ["p0"]},
               "type": "http", "host": urlsplit(urls[0]).hostname, "matched-at": urls[0]}
        output.write_text(json.dumps(raw) + "\n")
        proc = MagicMock()
        proc.stdout = iter([])
        proc.returncode = 0
        return proc

    monkeypatch.setattr(vs.subprocess, "Popen", fake_popen)
    settings = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_DAST_MODE": True,
                "NUCLEI_AUTO_UPDATE_TEMPLATES": False, "NUCLEI_MAX_RUNTIME": 0,
                "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False,
                "ENGAGEMENT_IDENTITY_HEADER": "X-Synthetic-Identity: p0"}
    returned = vs.run_vuln_scan_isolated(data, settings)
    assert data == original  # real isolated deep-copy contract
    recon_main._merge_isolated_result(data, "vuln_scan", returned)
    artifact = tmp_path / "recon_synthetic.json"
    recon_main.save_recon_file(data, artifact)
    saved = json.loads(artifact.read_text())
    assert [p["dast"] for p in generated] == [False, True]
    assert generated[1]["urls"] == [CASES["duplicate-keys"]["raw_url"]]
    expected = set(th.build_target_urls(["a.example.test", "b.example.test"], [], original))
    assert set(generated[0]["urls"]) == expected
    assert saved["vuln_scan"]["summary"]["total_findings"] == 2
    assert set(saved["vuln_scan"]["by_template"]) == {"synthetic-detection", "synthetic-dast"}
    assert saved["vuln_scan"]["scan_metadata"]["coverage"]["hosts"]
    client = _Client()  # real writer + strict recording driver, not real Neo4j
    stats = client.update_graph_from_vuln_scan(saved, "synthetic-user", "synthetic-project")
    assert stats["errors"] == []
    assert len(_vuln_props(client)) == 2
    stamps = [params for q, params in client.writes if "bu.nuclei_status = row.status" in q]
    assert len(stamps) == 1
    assert stamps[0]["uid"] == "synthetic-user" and stamps[0]["pid"] == "synthetic-project"
    assert len(stamps[0]["rows"]) == 2
    # Real run-level coverage/prune guards with a recording client. A failed
    # coverage write must prevent prune, regardless of successful tool rc.
    graph.matched = 0
    assert recon_main._write_coverage_record("example.test") is False
    recon_main._prune_recon_findings()
    assert graph.prunes == []
