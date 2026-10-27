"""BaseURL coverage stamps: who stamps what, and what stays untouched (plan 09.1).

The js_recon and nuclei writers stamp every BaseURL their module considered
with ``<module>_at`` / ``_status`` / ``_inputs`` / ``_outputs`` / ``_reason``,
by MATCH (never MERGE), tenant-scoped. A BaseURL the module never considered
keeps no stamp: that absence is what a reader reads as "not scanned".

The fake session below applies the stamp statement to an in-memory set of
BaseURLs, so the test asserts which nodes changed rather than which string was
sent. tests/test_coverage_stamps_graph_live.py runs the same Cypher on Neo4j.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.coverage_stamps import (  # noqa: E402
    COVERAGE_MODULES,
    COVERAGE_PROPERTIES,
    COVERAGE_STATUSES,
    COVERAGE_SUMMARY_CYPHER,
    base_url_variants,
    coverage_summary,
    coverage_summary_lines,
    stamp_base_url_coverage,
)
from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402
from graph_db.mixins.recon.vuln_mixin import VulnMixin  # noqa: E402

AT = "2026-10-25T08:00:00+00:00"


class FakeResult:
    def __init__(self, record=None, records=()):
        self.record, self.records = record, list(records)

    def single(self):
        return self.record

    def __iter__(self):
        return iter(self.records)


class FakeGraph:
    """BaseURL nodes of one tenant, keyed by url, and a session over them."""

    def __init__(self, urls, tenant=("u1", "p1")):
        self.nodes = {url: {} for url in urls}
        self.tenant = tenant
        self.stamp_calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kw):
        if "UNWIND $rows AS row" in query and "_status" in query:
            self.stamp_calls.append((query, kw))
            if (kw.get("uid"), kw.get("pid")) != self.tenant:
                return FakeResult({"stamped": 0})
            module = next(m for m in COVERAGE_MODULES if f"bu.{m}_status" in query)
            assert "MERGE" not in query
            stamped = 0
            for row in kw["rows"]:
                for url in row["urls"]:
                    if url in self.nodes:
                        node = self.nodes[url]
                        node.update({f"{module}_at": kw["at"], f"{module}_status": row["status"],
                                     f"{module}_inputs": row["inputs"], f"{module}_outputs": row["outputs"]})
                        if row["reason"] is None:
                            node.pop(f"{module}_reason", None)
                        else:
                            node[f"{module}_reason"] = row["reason"]
                        stamped += 1
            return FakeResult({"stamped": stamped})
        return FakeResult({"linked": 0, "created": False, "enriched": 0})


def _hosts(**rows):
    return {"at": AT, "hosts": rows}


def _row(status, inputs=0, outputs=0, reason=None):
    return {"status": status, "inputs": inputs, "outputs": outputs, "reason": reason}


class TestStampWriter(unittest.TestCase):
    def test_the_considered_baseurls_get_the_stamp_and_the_rest_nothing(self):
        graph = FakeGraph(["https://app.example.com", "https://www.example.com", "https://old.example.com"])
        n = stamp_base_url_coverage(graph, "js_recon", {"at": AT, "hosts": {
            "https://app.example.com:443": _row("complete", 12, 1),
            "https://www.example.com:443": _row("no_input"),
        }}, "u1", "p1")
        self.assertEqual(n, 2)
        self.assertEqual(graph.nodes["https://app.example.com"], {
            "js_recon_at": AT, "js_recon_status": "complete", "js_recon_inputs": 12, "js_recon_outputs": 1})
        self.assertEqual(graph.nodes["https://www.example.com"]["js_recon_status"], "no_input")
        self.assertEqual(graph.nodes["https://old.example.com"], {})

    def test_the_reason_is_written_when_set_and_cleared_when_complete(self):
        graph = FakeGraph(["https://app.example.com"])
        stamp_base_url_coverage(graph, "js_recon", _hosts(**{
            "https://app.example.com:443": _row("partial", 2, 0, "file cap")}), "u1", "p1")
        self.assertEqual(graph.nodes["https://app.example.com"]["js_recon_reason"], "file cap")
        stamp_base_url_coverage(graph, "js_recon", _hosts(**{
            "https://app.example.com:443": _row("complete", 4, 0)}), "u1", "p1")
        self.assertNotIn("js_recon_reason", graph.nodes["https://app.example.com"])

    def test_both_spellings_of_a_default_port_match(self):
        self.assertEqual(base_url_variants("https://app.example.com:443"),
                         ["https://app.example.com:443", "https://app.example.com"])
        self.assertEqual(base_url_variants("http://app.example.com"),
                         ["http://app.example.com", "http://app.example.com:80"])
        self.assertEqual(base_url_variants("http://app.example.com:8080"), ["http://app.example.com:8080"])
        self.assertEqual(base_url_variants("https://[2001:db8::1]:443"),
                         ["https://[2001:db8::1]:443", "https://[2001:db8::1]"])

    def test_an_unknown_status_or_a_non_web_url_is_dropped(self):
        graph = FakeGraph(["https://app.example.com"])
        n = stamp_base_url_coverage(graph, "js_recon", _hosts(**{
            "https://app.example.com:443": _row("clean"), "upload://x.js": _row("complete")}), "u1", "p1")
        self.assertEqual(n, 0)
        self.assertEqual(graph.stamp_calls, [])

    def test_the_module_name_is_never_taken_from_input(self):
        with self.assertRaises(ValueError):
            stamp_base_url_coverage(FakeGraph([]), "js_recon_at = 1 SET bu", _hosts(), "u1", "p1")

    def test_an_out_of_scope_host_is_not_stamped(self):
        graph = FakeGraph(["https://app.example.com", "https://cdn.example.org"])
        stamp_base_url_coverage(graph, "nuclei", _hosts(**{
            "https://app.example.com:443": _row("complete", 3),
            "https://cdn.example.org:443": _row("complete", 1)}),
            "u1", "p1", in_scope=lambda host: host.endswith("example.com"))
        self.assertIn("nuclei_status", graph.nodes["https://app.example.com"])
        self.assertEqual(graph.nodes["https://cdn.example.org"], {})

    def test_another_tenant_is_untouched(self):
        graph = FakeGraph(["https://app.example.com"], tenant=("u2", "p2"))
        stamp_base_url_coverage(graph, "js_recon", _hosts(**{
            "https://app.example.com:443": _row("complete")}), "u1", "p1")
        self.assertEqual(graph.nodes["https://app.example.com"], {})
        _query, kw = graph.stamp_calls[0]
        self.assertEqual((kw["uid"], kw["pid"]), ("u1", "p1"))

    def test_every_written_property_is_declared(self):
        self.assertEqual(COVERAGE_PROPERTIES, tuple(
            f"{m}_{f}" for m in COVERAGE_MODULES for f in ("at", "status", "inputs", "outputs", "reason")))


class TestCoverageSummary(unittest.TestCase):
    """The per-module host counts graph_summary reports (plan 09.2)."""

    def _row(self, **counts):
        row = {f"{m}_{s}": 0 for m in COVERAGE_MODULES for s in (*COVERAGE_STATUSES, "not_scanned")}
        row.update(counts)
        return row

    def test_a_stamped_module_reports_every_bucket(self):
        summary = coverage_summary(self._row(js_recon_complete=3, js_recon_partial=1, js_recon_no_input=2,
                                             js_recon_not_scanned=4))
        self.assertEqual(summary["js_recon"], {"recorded": True, "complete": 3, "partial": 1, "no_input": 2,
                                               "failed": 0, "not_scanned": 4})

    def test_a_module_with_no_stamp_anywhere_is_not_recorded_and_claims_no_count(self):
        # Its hosts are not "not scanned": the project predates the stamps, or
        # never ran the module.
        summary = coverage_summary(self._row(nuclei_not_scanned=9))
        self.assertEqual(summary["nuclei"], {"recorded": False})

    def test_no_row_means_nothing_is_recorded(self):
        self.assertEqual(coverage_summary(None), {m: {"recorded": False} for m in COVERAGE_MODULES})

    def test_the_text_tells_the_three_answers_apart(self):
        lines = "\n".join(coverage_summary_lines(coverage_summary(self._row(
            js_recon_complete=3, js_recon_failed=1, js_recon_not_scanned=2))))
        self.assertIn("JS Recon: 3 complete, 0 partial, 0 no input, 1 failed; 2 live hosts not scanned", lines)
        self.assertIn("Nuclei: coverage not recorded", lines)

    def test_the_cypher_is_tenant_scoped_and_projects_counts_only(self):
        self.assertIn("user_id: $tenant_user_id", COVERAGE_SUMMARY_CYPHER)
        self.assertIn("project_id: $tenant_project_id", COVERAGE_SUMMARY_CYPHER)
        self.assertNotIn("bu.url", COVERAGE_SUMMARY_CYPHER)
        for module in COVERAGE_MODULES:
            for bucket in (*COVERAGE_STATUSES, "not_scanned"):
                self.assertIn(f"AS {module}_{bucket}", COVERAGE_SUMMARY_CYPHER)


class Client(JsReconMixin, VulnMixin):
    def __init__(self, session):
        driver = MagicMock()
        driver.session.return_value = session
        self.driver = driver


class TestModuleWriters(unittest.TestCase):
    def test_the_js_recon_writer_stamps_its_coverage(self):
        graph = FakeGraph(["https://app.example.com", "https://www.example.com"])
        Client(graph).update_graph_from_js_recon({
            "domain": "example.com", "subdomains": ["app.example.com", "www.example.com"],
            "js_recon": {"scan_metadata": {"coverage": _hosts(**{
                "https://app.example.com:443": _row("complete", 2, 1)})},
                "secrets": [], "endpoints": []},
        }, "u1", "p1")
        self.assertEqual(graph.nodes["https://app.example.com"]["js_recon_status"], "complete")
        self.assertEqual(graph.nodes["https://www.example.com"], {})

    def test_the_js_recon_writer_keeps_a_host_outside_the_run_scope_unstamped(self):
        graph = FakeGraph(["https://app.example.com", "https://cdn.example.org"])
        Client(graph).update_graph_from_js_recon({
            "domain": "example.com", "subdomains": ["app.example.com"],
            "js_recon": {"scan_metadata": {"coverage": _hosts(**{
                "https://app.example.com:443": _row("complete"),
                "https://cdn.example.org:443": _row("complete")})},
                "secrets": [], "endpoints": []},
        }, "u1", "p1")
        self.assertEqual(graph.nodes["https://cdn.example.org"], {})

    def test_the_vuln_writer_stamps_the_nuclei_coverage(self):
        graph = FakeGraph(["https://app.example.com"])
        Client(graph).update_graph_from_vuln_scan({
            "domain": "example.com", "subdomains": ["app.example.com"],
            "vuln_scan": {"scan_metadata": {"coverage": _hosts(**{
                "https://app.example.com:443": _row("partial", 5, 0, "runtime cap")})}},
        }, "u1", "p1")
        node = graph.nodes["https://app.example.com"]
        self.assertEqual((node["nuclei_status"], node["nuclei_inputs"], node["nuclei_reason"]),
                         ("partial", 5, "runtime cap"))

    def test_a_security_checks_only_write_stamps_no_nuclei_coverage(self):
        graph = FakeGraph(["https://app.example.com"])
        Client(graph).update_graph_from_vuln_scan({
            "domain": "example.com", "subdomains": ["app.example.com"],
            "vuln_scan": {"security_checks": {}},
        }, "u1", "p1")
        self.assertEqual(graph.stamp_calls, [])


if __name__ == "__main__":
    unittest.main()
