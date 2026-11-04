"""LIVE-Neo4j: the route exposure writer, the prune and the report exclusion (plan §15).

Writes through the real mixin into a throwaway tenant, then checks that a
re-write merges, that the prune deletes an unseen unconfirmed candidate but
keeps an agent-confirmed one, that no Endpoint is created at an artifact path,
and that the report/Insights predicate (webapp graphMute.ts, rendered here
verbatim) hides a pending candidate and shows a confirmed one.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_route_exposure_graph_live.py -v
"""

import os
import sys
import time
import unittest
import uuid
from datetime import datetime, timezone

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
BASE = "http://10.0.0.5"

#: webapp/src/lib/graphMute.ts agentCandidateConfirmedOrNA('v'), as it renders.
EXCLUSION = ("NOT (v.source IN ['serialized_scan', 'route_exposure'] AND "
             "coalesce(v.needs_agent_confirmation, false) = true AND "
             "NOT EXISTS { (:ChainFinding)-[:CONFIRMS]->(v) })")


def _finding(path, kind="anonymous_access", **over):
    candidate = kind in ("anonymous_access", "sensitive_data")
    f = {"endpoint_url": BASE + path, "baseurl": BASE, "path": path, "http_method": "GET",
         "source": "route_exposure", "exposure_kind": kind,
         "vulnerability_type": {"anonymous_access": "unauthenticated_endpoint",
                                "env_file": "exposed_env_file"}.get(kind, kind),
         "route_class": "internal_api", "needs_agent_confirmation": candidate,
         "severity": "info" if candidate else "high", "confidence": 0.9, "anon_status": 200,
         "auth_expected_by": ["path_word"], "leak_signals": [], "pii_types": [],
         "pii_record_estimate": 0, "sensitive_fields": [], "secret_types": [],
         "generated_by": "found", "variant_of": "", "catch_all_check": "passed",
         "signature": "" if candidate else "env_lines", "evidence_snippet": "x"}
    f.update(over)
    return f


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveRouteExposureGraph(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.base_mixin import BaseMixin
        from graph_db.mixins.recon.route_exposure_mixin import RouteExposureMixin

        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"rexp-{run}", f"REXP_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(RouteExposureMixin, BaseMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        with self.driver.session() as s:
            s.run("MERGE (bu:BaseURL {url: $b, user_id: $u, project_id: $p}) "
                  "MERGE (e:Endpoint {path: '/api/v2/orders/42', method: 'GET', baseurl: $b, user_id: $u, project_id: $p}) "
                  "MERGE (f:Endpoint {path: '/internal/users/export', method: 'GET', baseurl: $b, user_id: $u, project_id: $p}) "
                  "MERGE (bu)-[:HAS_ENDPOINT]->(e) MERGE (bu)-[:HAS_ENDPOINT]->(f)",
                  b=BASE, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
        self.driver.close()

    def _write(self, findings, **extra):
        data = {"findings": findings, **extra}
        return self.client.update_graph_from_route_exposure({"route_exposure": data}, self.uid, self.pid)

    def _q(self, query, **params):
        with self.driver.session() as s:
            return [r.data() for r in s.run(query, u=self.uid, p=self.pid, **params)]

    def test_write_rewrite_status_and_new_endpoint(self):
        stats = self._write([_finding("/internal/users/export"), _finding("/.env", "env_file")],
                            endpoint_status=[{"baseurl": BASE, "path": "/api/v2/orders/42", "method": "GET",
                                              "anon_status": 401}],
                            new_endpoints=[{"baseurl": BASE, "path": "/api/admin/export", "method": "GET",
                                            "category": "admin", "anon_status": 200, "generated_by": "seed"},
                                           {"baseurl": BASE, "path": "/.git/HEAD", "anon_status": 200}])
        self.assertEqual(stats["errors"], [])
        self._write([_finding("/internal/users/export", anon_status=206)])
        rows = self._q("MATCH (v:Vulnerability {source:'route_exposure'}) WHERE v.user_id=$u AND v.project_id=$p "
                       "RETURN v.path AS path, v.anon_status AS s ORDER BY path")
        self.assertEqual(rows, [{"path": "/.env", "s": 200}, {"path": "/internal/users/export", "s": 206}])
        attached = self._q("MATCH (e:Endpoint)-[:HAS_VULNERABILITY]->(v:Vulnerability) "
                           "WHERE v.user_id=$u AND v.project_id=$p RETURN e.path AS path")
        self.assertEqual(attached, [{"path": "/internal/users/export"}])
        on_base = self._q("MATCH (:BaseURL)-[:HAS_VULNERABILITY]->(v:Vulnerability) "
                          "WHERE v.user_id=$u AND v.project_id=$p RETURN count(v) AS n")
        self.assertEqual(on_base, [{"n": 2}])
        status = self._q("MATCH (e:Endpoint {path:'/api/v2/orders/42'}) WHERE e.user_id=$u AND e.project_id=$p "
                         "RETURN e.anon_status AS s")
        self.assertEqual(status, [{"s": 401}])
        made = self._q("MATCH (:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint {source:'route_exposure'}) "
                       "WHERE e.user_id=$u AND e.project_id=$p RETURN e.path AS path, e.generated_by AS g")
        self.assertEqual(made, [{"path": "/api/admin/export", "g": "seed"}])
        artifact = self._q("MATCH (e:Endpoint) WHERE e.user_id=$u AND e.project_id=$p "
                           "AND (e.path CONTAINS '/.git/' OR e.path STARTS WITH '/.env') RETURN count(e) AS n")
        self.assertEqual(artifact, [{"n": 0}])

    def test_prune_keeps_a_confirmed_candidate_and_deletes_an_unseen_one(self):
        self._write([_finding("/internal/users/export"), _finding("/api/admin/export")])
        self._q("MATCH (v:Vulnerability {path:'/internal/users/export'}) WHERE v.user_id=$u AND v.project_id=$p "
                "CREATE (cf:ChainFinding {finding_id: 'cf-' + $u, finding_type: 'vulnerability_confirmed', "
                "confidence: 90, user_id: $u, project_id: $p})-[:CONFIRMS]->(v)")
        time.sleep(1.1)
        since = datetime.now(timezone.utc).isoformat()
        result = self.client.prune_unseen_findings(self.uid, self.pid, ["route_exposure"], since)
        self.assertEqual((result["pruned"], result["stale"]), (1, 1))
        left = self._q("MATCH (v:Vulnerability) WHERE v.user_id=$u AND v.project_id=$p "
                       "RETURN v.path AS path, v.stale_since IS NOT NULL AS stale")
        self.assertEqual(left, [{"path": "/internal/users/export", "stale": True}])

    def test_report_predicate_hides_pending_and_shows_confirmed(self):
        self._write([_finding("/internal/users/export"), _finding("/api/admin/export"),
                     _finding("/.env", "env_file")])
        self._q("MATCH (v:Vulnerability {path:'/api/admin/export'}) WHERE v.user_id=$u AND v.project_id=$p "
                "CREATE (cf:ChainFinding {finding_id: 'cf2-' + $u, finding_type: 'vulnerability_confirmed', "
                "user_id: $u, project_id: $p})-[:CONFIRMS]->(v)")
        rows = self._q(f"MATCH (v:Vulnerability) WHERE v.user_id=$u AND v.project_id=$p AND {EXCLUSION} "
                       "RETURN v.path AS path ORDER BY path")
        self.assertEqual([r["path"] for r in rows], ["/.env", "/api/admin/export"])


if __name__ == "__main__":
    unittest.main()
