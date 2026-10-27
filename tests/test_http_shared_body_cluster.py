"""One deny page shared across many hosts: shared_body_cluster on root Endpoints.

http_probe stores each probed page's body_sha256 on its Endpoint, and nothing
read it. A WAF or gateway deny page served by many hosts is one page, not many
findings' worth of evidence: every http_probe write, full or partial, groups the
project's root Endpoints by body hash and marks those whose hash 3 or more
distinct BaseURLs serve (status 200 or 403) with the cluster's size, and
removes the mark from Endpoints that left a cluster.

Hermetic: a fake driver records every query; the live proof is
test_http_shared_body_cluster_graph_live.py.
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

from graph_db.mixins.recon import http_mixin  # noqa: E402
from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402


class _Result:
    def __init__(self, record=None):
        self.record = record

    def single(self):
        return self.record

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self, queries, fail_on=None):
        self.queries = queries
        self.fail_on = fail_on

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        if self.fail_on and self.fail_on in query:
            raise RuntimeError("neo4j down")
        if "shared_body_cluster = size(bases)" in query:
            return _Result({"clustered": ["4:x:1", "4:x:2", "4:x:3"]})
        return _Result()


class _Driver:
    def __init__(self, queries, fail_on=None):
        self.queries, self.fail_on = queries, fail_on

    def session(self):
        return _Session(self.queries, self.fail_on)


class _Client(HttpMixin):
    def __init__(self, fail_on=None):
        self.queries = []
        self.driver = _Driver(self.queries, fail_on)


def _recon():
    url = "https://a.example.com"
    return {
        "domain": "example.com", "subdomains": ["a.example.com"], "metadata": {},
        "http_probe": {"scan_metadata": {}, "by_url": {url: {
            "url": url, "host": "a.example.com", "status_code": 403,
            "body_hash": {"body_sha256": "d" * 64}}},
            "by_host": {"a.example.com": {"urls": [url], "status_codes": [403]}}},
    }


def _query(client, marker):
    hits = [(q, kw) for q, kw in client.queries if marker in q]
    if not hits:
        raise AssertionError(f"no query containing {marker!r}")
    return hits[-1]


class TestTheClusterPass(unittest.TestCase):
    def test_root_endpoints_sharing_a_body_on_three_baseurls_are_marked(self):
        client = _Client()
        stats = client.update_graph_from_http_probe(_recon(), "u1", "p1")
        q, kw = _query(client, "shared_body_cluster = size(bases)")
        self.assertEqual((kw["user_id"], kw["project_id"]), ("u1", "p1"))
        self.assertIn("BaseURL {user_id: $user_id, project_id: $project_id}", q)
        self.assertIn("Endpoint {user_id: $user_id, project_id: $project_id, path: '/'}", q)
        self.assertIn("e.body_sha256 IS NOT NULL", q)
        self.assertEqual(kw["statuses"], [200, 403])
        self.assertEqual(kw["min_bases"], http_mixin.SHARED_BODY_MIN_BASEURLS)
        self.assertEqual(http_mixin.SHARED_BODY_MIN_BASEURLS, 3)
        self.assertIn("WITH e.body_sha256 AS body, collect(DISTINCT bu.url) AS bases", q)
        self.assertIn("WHERE size(bases) >= $min_bases", q)
        self.assertEqual(stats["shared_body_endpoints"], 3)

    def test_endpoints_that_left_a_cluster_lose_the_mark(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(), "u1", "p1")
        q, kw = _query(client, "REMOVE e.shared_body_cluster")
        self.assertIn("Endpoint {user_id: $user_id, project_id: $project_id}", q)
        self.assertIn("NOT elementId(e) IN $clustered", q)
        self.assertEqual(kw["clustered"], ["4:x:1", "4:x:2", "4:x:3"])
        self.assertEqual((kw["user_id"], kw["project_id"]), ("u1", "p1"))

    def test_the_pass_runs_after_the_endpoint_writes(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(), "u1", "p1")
        order = [i for i, (q, _) in enumerate(client.queries)
                 if "MERGE (e:Endpoint" in q or "shared_body_cluster" in q]
        kinds = ["merge" if "MERGE (e:Endpoint" in client.queries[i][0] else "cluster" for i in order]
        self.assertEqual(kinds[0], "merge")
        self.assertEqual(kinds[-2:], ["cluster", "cluster"])

    def test_the_pass_never_moves_updated_at(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(), "u1", "p1")
        for q, _ in client.queries:
            if "shared_body_cluster" in q:
                self.assertNotIn("updated_at", q)

    def test_a_failed_pass_is_an_error_not_a_crash(self):
        client = _Client(fail_on="shared_body_cluster = size(bases)")
        stats = client.update_graph_from_http_probe(_recon(), "u1", "p1")
        self.assertTrue(any("shared body cluster" in e for e in stats["errors"]))
        self.assertFalse([q for q, _ in client.queries if "REMOVE e.shared_body_cluster" in q])


if __name__ == "__main__":
    unittest.main()
