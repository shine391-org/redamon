"""LIVE-Neo4j proof of the shared-body cluster pass (shared_body_cluster).

The unit test checks the Cypher text; only a real database proves it groups
the right Endpoints, that a partial run removes the mark from an Endpoint that
left its cluster, and that another project's identical page never counts.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_http_shared_body_cluster_graph_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (_REPO, os.path.join(_REPO, "agentic")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

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

DENY = "d" * 64
OTHER = "e" * 64


def _probe_data(pages):
    """pages: {host: (status, body_sha256)} -> an http_probe recon payload."""
    by_url, by_host = {}, {}
    for host, (status, digest) in pages.items():
        url = f"https://{host}"
        by_url[url] = {"url": url, "host": host, "status_code": status,
                       "body_hash": {"body_sha256": digest}}
        by_host[host] = {"urls": [url], "status_codes": [status]}
    return {"domain": "cluster-itest.test", "subdomains": list(pages), "metadata": {},
            "http_probe": {"scan_metadata": {}, "by_url": by_url, "by_host": by_host}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestSharedBodyClusterLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.uid = "u-cluster-itest"
        self.pid = f"p-cluster-itest-{uuid.uuid4().hex[:8]}"
        self.other_pid = f"{self.pid}-other"

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.project_id IN [$a, $b] DETACH DELETE n", a=self.pid, b=self.other_pid)

    def _marks(self, pid):
        with self.client.driver.session() as s:
            rows = s.run("""MATCH (e:Endpoint {user_id: $u, project_id: $p, path: '/'})
                            RETURN e.baseurl AS b, e.shared_body_cluster AS n""", u=self.uid, p=pid)
            return {r["b"]: r["n"] for r in rows}

    def test_three_hosts_sharing_a_deny_page_form_a_cluster(self):
        self.client.update_graph_from_http_probe(_probe_data({
            "a.cluster-itest.test": (403, DENY), "b.cluster-itest.test": (403, DENY),
            "c.cluster-itest.test": (200, DENY), "d.cluster-itest.test": (500, DENY),
            "e.cluster-itest.test": (200, OTHER),
        }), self.uid, self.pid)
        marks = self._marks(self.pid)
        self.assertEqual({b: n for b, n in marks.items() if n is not None}, {
            "https://a.cluster-itest.test": 3, "https://b.cluster-itest.test": 3,
            "https://c.cluster-itest.test": 3})
        self.assertIsNone(marks["https://d.cluster-itest.test"])   # a 500 is not a deny page
        self.assertIsNone(marks["https://e.cluster-itest.test"])

    def test_a_partial_run_removes_the_mark_from_an_endpoint_that_left(self):
        self.client.update_graph_from_http_probe(_probe_data({
            "a.cluster-itest.test": (403, DENY), "b.cluster-itest.test": (403, DENY),
            "c.cluster-itest.test": (403, DENY)}), self.uid, self.pid)
        self.assertEqual(set(self._marks(self.pid).values()), {3})
        # A partial re-probe of one host: it now serves its own page.
        self.client.update_graph_from_http_probe(_probe_data({
            "c.cluster-itest.test": (200, OTHER)}), self.uid, self.pid)
        self.assertEqual(set(self._marks(self.pid).values()), {None})

    def test_another_projects_identical_page_never_counts(self):
        self.client.update_graph_from_http_probe(_probe_data({
            "a.cluster-itest.test": (403, DENY), "b.cluster-itest.test": (403, DENY)}), self.uid, self.pid)
        self.client.update_graph_from_http_probe(_probe_data({
            "x.cluster-itest.test": (403, DENY), "y.cluster-itest.test": (403, DENY)}),
            self.uid, self.other_pid)
        self.assertEqual(set(self._marks(self.pid).values()), {None})
        self.assertEqual(set(self._marks(self.other_pid).values()), {None})


if __name__ == "__main__":
    unittest.main()
