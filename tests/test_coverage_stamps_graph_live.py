"""LIVE-Neo4j proof of the BaseURL coverage stamps (plan 09.1).

tests/test_coverage_stamps.py proves which rows are sent; only a real database
proves the Cypher is valid on Neo4j 5.x and that the stamp:

  * lands on the BaseURL whatever spelling of its default port it was stored
    under, and on no other BaseURL;
  * never creates a BaseURL (MATCH, not MERGE);
  * stays inside its tenant;
  * clears the reason when a later run completes, and stores `_at` as a
    datetime.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_coverage_stamps_graph_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
"""
import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "Neo4j not reachable")
class TestCoverageStampsLive(unittest.TestCase):
    def setUp(self):
        from graph_db.coverage_stamps import stamp_base_url_coverage
        self.stamp = stamp_base_url_coverage
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.uid = f"cov-live-{uuid.uuid4().hex[:8]}"
        self.pid, self.other = f"{self.uid}-p", f"{self.uid}-q"
        with self.driver.session() as s:
            for pid in (self.pid, self.other):
                for url in ("https://app.example.com", "https://www.example.com:443",
                            "http://old.example.com"):
                    s.run("CREATE (:BaseURL {url: $url, user_id: $uid, project_id: $pid})",
                          url=url, uid=self.uid, pid=pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        self.driver.close()

    def _props(self, url, pid=None):
        with self.driver.session() as s:
            rec = s.run("MATCH (b:BaseURL {url: $url, user_id: $uid, project_id: $pid}) "
                        "RETURN properties(b) AS p, b.js_recon_at IS :: ZONED DATETIME AS dt",
                        url=url, uid=self.uid, pid=pid or self.pid).single()
        return dict(rec["p"]), rec["dt"]

    def _run(self, hosts, module="js_recon"):
        with self.driver.session() as s:
            return self.stamp(s, module, {"at": "2026-10-25T08:00:00+00:00", "hosts": hosts},
                              self.uid, self.pid)

    def test_stamps_land_on_both_spellings_and_nowhere_else(self):
        n = self._run({
            "https://app.example.com:443": {"status": "partial", "inputs": 3, "outputs": 1, "reason": "file cap"},
            "https://www.example.com:443": {"status": "no_input", "inputs": 0, "outputs": 0, "reason": None},
            "https://ghost.example.com:443": {"status": "complete", "inputs": 1, "outputs": 0, "reason": None},
        })
        self.assertEqual(n, 2)
        app, is_dt = self._props("https://app.example.com")
        self.assertTrue(is_dt)
        self.assertEqual((app["js_recon_status"], app["js_recon_inputs"], app["js_recon_outputs"],
                          app["js_recon_reason"]), ("partial", 3, 1, "file cap"))
        self.assertEqual(self._props("https://www.example.com:443")[0]["js_recon_status"], "no_input")
        self.assertNotIn("js_recon_status", self._props("http://old.example.com")[0])
        self.assertNotIn("js_recon_status", self._props("https://app.example.com", self.other)[0])
        with self.driver.session() as s:
            ghost = s.run("MATCH (b:BaseURL {user_id: $uid}) WHERE b.url CONTAINS 'ghost' RETURN count(b) AS c",
                          uid=self.uid).single()["c"]
        self.assertEqual(ghost, 0)

    def test_the_summary_counts_this_tenant_only(self):
        from graph_db.coverage_stamps import COVERAGE_SUMMARY_CYPHER, coverage_summary
        with self.driver.session() as s:
            s.run("MATCH (b:BaseURL {user_id: $uid}) SET b.source = 'http_probe'", uid=self.uid)
        self._run({"https://app.example.com:443": {"status": "complete", "inputs": 2, "outputs": 0,
                                                   "reason": None}})
        with self.driver.session() as s:
            row = s.run(COVERAGE_SUMMARY_CYPHER, tenant_user_id=self.uid, tenant_project_id=self.pid).single()
            other = s.run(COVERAGE_SUMMARY_CYPHER, tenant_user_id=self.uid,
                          tenant_project_id=self.other).single()
        summary = coverage_summary(dict(row))
        self.assertEqual(summary["js_recon"], {"recorded": True, "complete": 1, "partial": 0, "no_input": 0,
                                               "failed": 0, "not_scanned": 2})
        self.assertEqual(summary["nuclei"], {"recorded": False})
        self.assertEqual(coverage_summary(dict(other))["js_recon"], {"recorded": False})

    def test_a_later_complete_run_clears_the_reason(self):
        self._run({"https://app.example.com:443": {"status": "failed", "inputs": 0, "outputs": 0,
                                                   "reason": "host unreachable"}}, module="nuclei")
        self._run({"https://app.example.com:443": {"status": "complete", "inputs": 4, "outputs": 0,
                                                   "reason": None}}, module="nuclei")
        props = self._props("https://app.example.com")[0]
        self.assertEqual(props["nuclei_status"], "complete")
        self.assertNotIn("nuclei_reason", props)


if __name__ == "__main__":
    unittest.main()
