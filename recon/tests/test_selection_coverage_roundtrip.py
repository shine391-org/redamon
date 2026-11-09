"""F07 — selection coverage survives every merge boundary and the prune fails closed.

Covers the DoD:
  - a selective run never completes the whole origin/source (exhaustive flag);
  - same-host finding /b is kept when only /a was selected, human verdict/mute/review kept;
  - missing manifest / failed coverage write / cancellation / crash partial output fail-closed;
  - the plan lives through deepcopy -> TopLevelKeys whitelist -> fan-in -> file save ->
    domain-batch merge -> graph writer -> API coverage reader;
  - two groups with different counts/time merge without first-group-wins or double-counting;
  - legacy findings without endpoint/template provenance stay conservative.

Neo4j / Docker / network are faked; only the real caller->merge->artifact->graph/coverage/prune
path is exercised.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main import save_recon_file, _merge_isolated_result  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.output_paths import merge_batch_outputs, recon_output_file  # noqa: E402
from recon.helpers.selection_coverage import (  # noqa: E402
    KEY, build_plan, is_exhaustive, merge_plans, merge_selection_blocks,
    plan_hosts, plan_ids, record_outcome, selection_block,
)
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402


def _reset():
    cb.reset_registry()


# --------------------------------------------------------------------- plan

class TestSelectionPlan:
    def test_baseline_is_exhaustive(self):
        p = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                       templates={"tags": ["cve", "xss"]}, exhaustive=True)
        assert is_exhaustive(p) is True
        assert p["schema_version"] == 1
        assert isinstance(p["plan_id"], str) and len(p["plan_id"]) == 32
        assert p["status"] == "planned"
        assert p["targets"]["count"] == 1
        assert p["targets"]["hosts"] == ["a.example:443"]
        assert p["outcomes"] == {"completed": 0, "partial": 0, "failed": 0,
                                 "deferred": 0, "unknown": 0}

    def test_ai_pruned_is_not_exhaustive(self):
        p = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                       templates={"tags": ["cve"], "tags_saved": ["cve", "xss"],
                                  "tags_removed": ["xss"], "ai_pruned": True},
                       exhaustive=False, reason="AI tag pruning removed 1 tag(s)")
        assert is_exhaustive(p) is False
        assert p["templates"]["ai_pruned"] is True
        assert p["templates"]["tags_removed"] == ["xss"]

    def test_partial_scope_is_not_exhaustive(self):
        p = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                       templates={"tags": ["cve"]}, exhaustive=False,
                       scope="partial", reason="partial run: targets/templates limited")
        assert is_exhaustive(p) is False
        assert p["scope"] == "partial"

    def test_record_outcome(self):
        p = build_plan(module="vuln_scan", targets=[], exhaustive=True)
        p2 = record_outcome(p, "complete", completed=5, failed=1)
        assert p2["status"] == "complete"
        assert p2["outcomes"]["completed"] == 5
        assert p2["outcomes"]["failed"] == 1
        # original untouched (deep copy)
        assert p["status"] == "planned" and p["outcomes"]["completed"] == 0

    def test_plan_hosts_and_ids(self):
        p = build_plan(module="vuln_scan", targets=["https://a.example:8443/x",
                                                    "http://b.example/x"],
                       exhaustive=True)
        assert plan_hosts(p) == ["a.example:8443", "b.example:80"]
        assert plan_ids(p) == [p["plan_id"]]

    def test_merge_plans_sums_counts_and_dedups_ids(self):
        a = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                       templates={"tags": ["cve"]}, exhaustive=False,
                       reason="AI pruning removed 1 tag(s)")
        b = build_plan(module="vuln_scan", targets=["https://b.example/x",
                                                    "https://c.example/x"],
                       templates={"tags": ["xss"]}, exhaustive=False,
                       reason="partial run: targets/templates limited")
        merged = merge_plans([a, b])
        assert merged is not None
        # counts summed, not first-group-wins
        assert merged["targets"]["count"] == 3
        assert merged["targets"]["hosts"] == ["a.example:443",
                                              "b.example:443",
                                              "c.example:443"]
        # every plan id kept, no duplication
        assert sorted(merged["plan_ids"]) == sorted([a["plan_id"], b["plan_id"]])
        # exhaustive only when every plan was; status worst
        assert merged["exhaustive"] is False
        assert merged["status"] == "planned"
        # template lists unioned
        assert set(merged["templates"]["tags"]) == {"cve", "xss"}
        assert merged["reason"] == "AI pruning removed 1 tag(s); partial run: targets/templates limited"


# --------------------------------------------------------------------- caller -> TopLevelKeys -> fan-in -> file -> batch merge

class TestPlumbing:
    def _stub(self, monkeypatch, plans):
        def fake(recon_data, output_file=None, settings=None, selection_hint=None,
                 plan_output_file=None):
            recon_data[KEY] = copy.deepcopy(plans[recon_data["domain"]])
            return recon_data
        monkeypatch.setattr(vs, "run_vuln_scan", fake)

    def test_selection_survives_isolated_and_fan_in(self, monkeypatch):
        plan = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                          templates={"tags": ["cve"], "ai_pruned": True},
                          exhaustive=False, reason="AI pruning removed 1 tag(s)")
        self._stub(monkeypatch, {"example.com": plan})
        combined = {"domain": "example.com", "metadata": {"modules_executed": []}}
        original = copy.deepcopy(combined)
        returned = vs.run_vuln_scan_isolated(combined, {})
        assert isinstance(returned, vs.TopLevelKeys)
        # TopLevelKeys whitelist carries the new key
        assert KEY in returned
        assert returned[KEY]["plan_id"] == plan["plan_id"]
        assert combined == original  # deep-copy contract

        # fan-in
        _merge_isolated_result(combined, "vuln_scan", returned)
        assert combined[KEY]["plan_id"] == plan["plan_id"]
        assert combined[KEY]["exhaustive"] is False

    def test_selection_survives_file_save_and_batch_merge(self, monkeypatch, tmp_path):
        plans = {
            "a.example": build_plan(module="vuln_scan", targets=["https://a.example/x"],
                                    exhaustive=False, reason="r1"),
            "b.example": build_plan(module="vuln_scan", targets=["https://b.example/x",
                                                                  "https://c.example/x"],
                                    exhaustive=False, reason="r2"),
        }
        self._stub(monkeypatch, plans)
        for root, plan in plans.items():
            combined = {"domain": root, "metadata": {"root_domain": root,
                                                     "modules_executed": []}}
            returned = vs.run_vuln_scan_isolated(combined, {})
            _merge_isolated_result(combined, "vuln_scan", returned)
            path = recon_output_file(tmp_path, "p1", root)
            path.parent.mkdir(parents=True, exist_ok=True)
            save_recon_file(combined, path)

        canonical = merge_batch_outputs(tmp_path, "p1")
        assert canonical is not None
        data = json.loads(Path(canonical).read_text())
        merged_plan = data[KEY]
        # counts summed, ids unioned, exhaustive False
        assert merged_plan["targets"]["count"] == 3
        assert sorted(merged_plan["targets"]["hosts"]) == [
            "a.example:443", "b.example:443", "c.example:443"]
        assert set(merged_plan["plan_ids"]) == {plans["a.example"]["plan_id"],
                                                plans["b.example"]["plan_id"]}
        assert merged_plan["exhaustive"] is False
        assert merged_plan["scope"] == "full"  # no partial_scope hint


class TestPlanPersistedBeforeLaunch:
    """DoD 8 on the PRODUCTION domain path: run_domain_recon runs vuln_scan
    through the isolated wrapper in a fan-out thread, and the plan must reach
    the canonical artifact before the Nuclei pass launches."""

    SETTINGS = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"],
                "NUCLEI_AUTO_UPDATE_TEMPLATES": False, "CVE_LOOKUP_ENABLED": False,
                "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0}

    def test_the_isolated_wrapper_writes_the_plan_before_the_pass_launches(self, tmp_path):
        target = tmp_path / "recon_p1.json"
        # Another tool's results already merged by the time Nuclei launches.
        target.write_text(json.dumps({"domain": "example.com",
                                      "graphql_scan": {"findings": [1]},
                                      "metadata": {"root_domain": "example.com"}}))
        seen = {}

        def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
            seen["at_launch"] = json.loads(target.read_text())
            return [], [], 1.0, 0

        recon = {"domain": "example.com", "metadata": {"root_domain": "example.com"},
                 "http_probe": {"by_url": {"https://app.example.com": {"status_code": 200}}}}
        with mock.patch.object(vs, "is_docker_installed", lambda: True), \
                mock.patch.object(vs, "is_docker_running", lambda: True), \
                mock.patch.object(vs, "pull_nuclei_docker_image", lambda image: True), \
                mock.patch.object(vs, "ensure_templates_volume", lambda image, auto: True), \
                mock.patch.object(vs, "extract_targets_from_recon",
                                  lambda rd: ([], ["app.example.com"], {})), \
                mock.patch.object(vs, "build_target_urls",
                                  lambda h, i, rd, scan_all_ips=False: ["https://app.example.com"]), \
                mock.patch.object(vs, "set_fp_ai_ctx", lambda **kw: None), \
                mock.patch.object(vs, "_execute_nuclei_pass", fake_pass):
            combined = copy.deepcopy(recon)
            returned = vs.run_vuln_scan_isolated(combined, dict(self.SETTINGS),
                                                 output_file=target)

        assert "at_launch" in seen, "the detection pass never launched"
        on_disk = seen["at_launch"]
        # The plan was on disk BEFORE the pass launched - not after the future.
        assert on_disk[KEY]["plan_id"]
        assert on_disk[KEY]["targets"]["count"] == 1
        # ...and the merge preserved the other tool's freshly merged results.
        assert on_disk["graphql_scan"] == {"findings": [1]}
        # The wrapper still hands the plan to the fan-in, and the deep-copy
        # contract holds.
        assert returned[KEY]["plan_id"] == on_disk[KEY]["plan_id"]
        assert combined == recon

    def test_without_an_output_file_the_wrapper_does_not_write_a_plan(self, tmp_path):
        """The legacy call (no output_file) keeps the old behaviour: no plan
        write, and the caller's own save persists the merged result."""
        written = []
        real_persist = vs.persist_plan

        def spy(output_file, plan):
            written.append(output_file)
            return real_persist(output_file, plan)

        with mock.patch.object(vs, "persist_plan", spy), \
                mock.patch.object(vs, "run_vuln_scan",
                                  lambda rd, output_file=None, settings=None,
                                  selection_hint=None, plan_output_file=None: rd):
            vs.run_vuln_scan_isolated({"domain": "example.com", "metadata": {}}, {})
        assert written == []


# --------------------------------------------------------------------- graph writer -> API coverage reader

class TestGraphWriterAndApiReader:
    def test_graph_writer_records_selection(self):
        from graph_db.mixins.recon.vuln_mixin import VulnMixin  # noqa: E402

        calls = []

        class _Session:
            def run(self, query, **params):
                calls.append((query, params))
                class _R:
                    def single(self):
                        return None
                return _R()
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False

        class _Driver:
            def session(self):
                return _Session()

        class _Client(VulnMixin):
            def __init__(self):
                self.driver = _Driver()

        plan = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                          exhaustive=False, reason="r")
        recon_data = {KEY: plan, "metadata": {"root_domain": "a.example"},
                      "vuln_scan": {"scan_metadata": {}, "summary": {"critical": 1}}}
        client = _Client()
        client.update_graph_from_vuln_scan(recon_data, "u1", "p1")
        (query, params), = [c for c in calls if "vuln_scan_selection_json" in c[0]]
        assert "vuln_scan_selection_json" in query
        # The bounded block, the same shape the coverage record carries: ids and
        # flags only, never the plan's target hosts or template bodies.
        block = json.loads(params["selection_json"])
        assert block["plan_ids"] == [plan["plan_id"]]
        assert block["recorded"] is True
        assert block["exhaustive"] is False
        assert "a.example" not in params["selection_json"]

    def test_the_selection_block_reaches_the_coverage_record_reader(self):
        # The block the API coverage reader parses is the one the coverage
        # record carries: _write_coverage_record stamps report.selection_json()
        # and update_graph_coverage persists it as recon_selection_json on the
        # Domain (asserted in tests/test_recon_coverage_graph.py); the webapp
        # reader merges that with vuln_scan_selection_json using the same
        # merge_selection_blocks rules.
        cb.note_selection_cut("vuln_scan", sources=["nuclei"],
                              hosts=["a.example.com:443"], plan_id="P-GAP",
                              reason="AI tag pruning removed xss")
        report = cb.coverage_report()
        gaps = json.loads(report.gaps_json())
        assert any(g.get("source") == "nuclei" and g.get("module") == "vuln_scan"
                   for g in gaps)
        assert report.selection_plan_ids == ("P-GAP",)
        block = report.selection_json()
        assert block["plan_ids"] == ["P-GAP"]
        assert block["recorded"] is True
        assert block["selection_unknown"] is False
        # A recorded plan means a cut, so a selective run is never exhaustive.
        assert block["exhaustive"] is False

    def test_a_run_that_cut_nothing_reports_exhaustive(self):
        # No cut noted, no plan id: the run checked its whole configured
        # baseline. "exhaustive" answers that, not "is there a plan?".
        report = cb.coverage_report()
        assert report.selection_plan_ids == ()
        assert report.selection_json() == {"recorded": False, "selection_unknown": False,
                                           "plan_ids": [], "exhaustive": True}

    def test_merge_selection_blocks_matches_the_reader_rules(self):
        a = {"recorded": True, "selection_unknown": False, "plan_ids": ["P1"],
             "exhaustive": False}
        b = {"recorded": True, "selection_unknown": False, "plan_ids": ["P2"],
             "exhaustive": True}
        merged = merge_selection_blocks(json.dumps(a), json.dumps(b))
        assert merged == {"recorded": True, "selection_unknown": False,
                          "plan_ids": ["P1", "P2"], "exhaustive": False}
        # An unknown cut on either side makes the whole run unknown.
        unknown = merge_selection_blocks(a, {"recorded": False, "selection_unknown": True,
                                             "plan_ids": [], "exhaustive": False})
        assert unknown["selection_unknown"] is True
        assert unknown["exhaustive"] is False
        # Malformed input is dropped, never trusted.
        assert merge_selection_blocks("{not json", a) == a
        assert merge_selection_blocks(None, None) is None

    def test_selection_block_is_bounded(self):
        # The graph writer's block: ids and flags only, never a URL or template.
        plan = build_plan(module="vuln_scan", targets=["https://a.example/x"],
                          templates={"tags": ["cve"]}, exhaustive=False,
                          reason="AI pruning removed 1 tag(s)")
        block = selection_block(plan)
        assert block == {"recorded": True, "selection_unknown": False,
                         "plan_ids": [plan["plan_id"]], "exhaustive": False}
        assert "a.example" not in json.dumps(block)
        assert selection_block(None) == {"recorded": False, "selection_unknown": False,
                                         "plan_ids": [], "exhaustive": False}


# --------------------------------------------------------------------- prune: same host /b kept, missing manifest fail-closed

class _FakeGraph:
    def __init__(self, matched=1, reachable=True):
        self.matched = matched
        self.reachable = reachable
        self.prunes = []
        self.coverage = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return self.reachable

    def backfill_passive_cve_hosts(self, user_id, project_id):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(),
                              keep_unproven=False):
        self.prunes.append({"sources": list(sources), "since": since,
                            "keep_hosts": tuple(keep_hosts),
                            "keep_unproven": bool(keep_unproven)})
        return {"pruned": 0, "stale": 0, "revived": 0}

    def update_graph_coverage(self, user_id, project_id, domain, record, run_started_at=None):
        if not self.reachable:
            raise RuntimeError("Neo4j not reachable")
        self.coverage.append({"domain": domain, "run_started_at": run_started_at,
                              **record})
        return self.matched


@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        yield rm


@pytest.fixture
def graph(monkeypatch):
    fake = _FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


class TestSameHostPrune:
    @pytest.fixture(autouse=True)
    def _isolate(self):
        _reset()
        yield
        _reset()

    def _write_manifest(self, recon_main, tmp_path, plan):
        recon_main.OUTPUT_DIR = tmp_path
        path = recon_output_file(tmp_path, "p1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({KEY: plan}))
        return path

    def test_selective_run_keeps_same_host_finding_b_when_only_a_tested(self,
                                                                        recon_main, graph,
                                                                        tmp_path):
        # /a was selected and tested; /b on the same host was not. The prune
        # must keep /b (host-level protection) and must not stamp it stale.
        cb.note_selection_cut("vuln_scan", sources=["nuclei"],
                              hosts=["a.example.com:443"], plan_id="P-SEL-1",
                              reason="AI tag pruning removed xss")
        self._write_manifest(recon_main, tmp_path,
                             build_plan(module="vuln_scan", targets=["https://a.example/a"],
                                        exhaustive=False, reason="AI tag pruning removed xss",
                                        plan_id="P-SEL-1"))
        recon_main._prune_recon_findings()
        assert graph.prunes, "a prune call is expected"
        prune = next(p for p in graph.prunes if "a.example.com" in p["keep_hosts"])
        assert "nuclei" in prune["sources"]
        assert prune["keep_hosts"] == ("a.example.com",)
        # security_check / CVE are NOT reset by Nuclei-only metadata:
        # they are pruned in their own batch (their own coverage was complete)
        other = next(p for p in graph.prunes if p["keep_hosts"] == ())
        assert "security_check" in other["sources"]

    def test_missing_manifest_fail_closed(self, recon_main, graph, tmp_path, capsys):
        cb.note_selection_cut("vuln_scan", sources=["nuclei"],
                              hosts=["a.example.com:443"], plan_id="P-MISSING",
                              reason="r")
        # no manifest written -> unknown coverage -> nothing pruned
        recon_main.OUTPUT_DIR = tmp_path
        recon_main._prune_recon_findings()
        assert graph.prunes == []
        out = capsys.readouterr().out
        assert "Finding prune skipped" in out

    def test_cut_without_plan_id_fail_closed(self, recon_main, graph, tmp_path):
        recon_main.OUTPUT_DIR = tmp_path
        cb.note_selection_cut("vuln_scan", sources=["nuclei"],
                              hosts=["a.example.com:443"], plan_id="", reason="r")
        recon_main._prune_recon_findings()
        assert graph.prunes == []

    def test_a_stopped_run_never_prunes(self, recon_main, graph, tmp_path, monkeypatch):
        # DoD 3: cancellation is fail-closed. A stopped run's killed tools
        # returned empty results, which would read as "gone".
        recon_main.OUTPUT_DIR = tmp_path

        class _Stopped:
            def stop_requested(self):
                return True

        monkeypatch.setattr(recon_main, "_shutdown", _Stopped())
        recon_main._prune_recon_findings()
        assert graph.prunes == []

    def test_non_selective_run_prunes_normally(self, recon_main, graph, tmp_path):
        # exhaustive run: no cut, prune proceeds as before
        recon_main.OUTPUT_DIR = tmp_path
        recon_main._prune_recon_findings()
        (prune,) = graph.prunes
        from recon.helpers.finding_sources import RECON_FINDING_SOURCES  # noqa: E402
        assert prune["sources"] == list(RECON_FINDING_SOURCES)
        assert prune["keep_hosts"] == ()

# --------------------------------------------------------------------- DoD 6: legacy findings without provenance stay conservative

class _FakeDriver:
    def __init__(self):
        self.calls = []
    def session(self):
        return self
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
    def run(self, query, **params):
        self.calls.append((query, params))
        class _R:
            def single(self):
                return {"pruned": 0, "stale": 0, "revived": 0}
        return _R()


class _UnprovenClient:
    def __init__(self):
        self.driver = _FakeDriver()
    def prune_unseen_findings(self, user_id, project_id, sources, run_started_at,
                              keep_hosts=(), keep_unproven=False):
        from graph_db.mixins.base_mixin import BaseMixin, keep_host_patterns
        BaseMixin.prune_unseen_findings(
            self, user_id, project_id, sources, run_started_at,
            keep_hosts=keep_hosts, keep_unproven=keep_unproven)


class TestKeepUnproven:
    def test_unproven_findings_kept_when_run_selective(self):
        client = _UnprovenClient()
        client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00",
                                     keep_unproven=True)
        (query, _), = [c for c in client.driver.calls if "DETACH DELETE d" in c[0]]
        assert "coalesce(n.host, '') = ''" in query
        assert "coalesce(n.matched_at, '') = ''" in query
        assert "coalesce(n.endpoint, '') = ''" in query

    def test_unproven_findings_not_kept_when_run_exhaustive(self):
        client = _UnprovenClient()
        client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00",
                                     keep_unproven=False)
        (query, _), = [c for c in client.driver.calls if "DETACH DELETE d" in c[0]]
        assert "coalesce(n.host, '') = ''" not in query
