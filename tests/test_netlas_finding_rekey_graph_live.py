"""LIVE proof of tooling/scripts/netlas_finding_rekey.py (plan 04.5).

On a real Neo4j, a bare-id Netlas finding (muted, judged "False positive" by a
person, proven by the agent) is moved to its per-IP id(s) with all of that
intact: renamed in place on one IP, copied to each IP on several, merged onto a
node a scan already wrote. `updated_at` never moves, and a second run finds
nothing. With DATABASE_URL set, the Postgres statements also run against the
real schema, inside a transaction that is rolled back.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD (and DATABASE_URL) exported:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL redamon-agent python -m pytest tests/test_netlas_finding_rekey_graph_live.py -v
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

CVE = "CVE-2018-15473"
A, B = "198.51.100.80", "198.51.100.81"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestNetlasRekeyGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"nrk-{run}", f"NRK_{run}"
        self.project = {"id": self.pid, "user_id": self.uid}

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $u, project_id: $p}) DETACH DELETE n", u=self.uid, p=self.pid)

    def _seed(self, *ips):
        """A bare-id Netlas finding from an earlier release, under one Service per IP."""
        with self.driver.session() as s:
            s.run(
                """
                CREATE (v:Vulnerability:Muted {id: $cve, source: 'netlas', name: $cve,
                        user_id: $u, project_id: $p, muted_by: 'user-1',
                        triage_status: 'likely_noise', triage_source: 'human',
                        updated_at: datetime('2026-10-01T00:00:00Z')})
                CREATE (cf:ChainFinding {id: 'cf-1', user_id: $u, project_id: $p,
                        finding_type: 'vulnerability_confirmed'})
                CREATE (cf)-[:CONFIRMS {confidence: 90, note: 'banner and exploit'}]->(v)
                WITH v
                UNWIND $ips AS ip
                CREATE (i:IP {address: ip, user_id: $u, project_id: $p})
                CREATE (svc:Service {name: 'ssh', port_number: 22, ip_address: ip,
                        user_id: $u, project_id: $p})
                CREATE (svc)-[:HAS_VULNERABILITY]->(v)
                """, cve=CVE, u=self.uid, p=self.pid, ips=list(ips))

    def _apply(self):
        from tooling.scripts import netlas_finding_rekey as rk
        with self.driver.session() as s:
            plan = rk.plan_project(s, self.project)
            return [rk.rekey_graph(s, self.uid, self.pid, r) for r in plan["rekeys"]]

    def _nodes(self):
        with self.driver.session() as s:
            return {r["id"]: dict(r) for r in s.run(
                """
                MATCH (v:Vulnerability {user_id: $u, project_id: $p})
                RETURN v.id AS id, v:Muted AS muted, v.triage_status AS status,
                       v.triage_source AS by, v.target_ip AS ip, v.target_port AS port,
                       toString(v.updated_at) AS seen,
                       [(cf:ChainFinding)-[r:CONFIRMS]->(v) | r.confidence] AS proof,
                       [(parent)-[:HAS_VULNERABILITY]->(v) | labels(parent)[0]] AS parents
                """, u=self.uid, p=self.pid)}

    def test_one_ip_is_renamed_with_everything_on_it(self):
        self._seed(A)
        self.assertEqual(self._apply(), ["renamed"])
        node = self._nodes()[f"netlas-{CVE}-{A}-22"]
        self.assertEqual((node["muted"], node["status"], node["by"]), (True, "likely_noise", "human"))
        self.assertEqual((node["ip"], node["port"], node["proof"], node["parents"]), (A, 22, [90], ["IP"]))
        self.assertTrue(node["seen"].startswith("2026-10-01"))

    def test_several_ips_each_get_the_mute_the_decision_and_the_proof(self):
        self._seed(A, B)
        self.assertEqual(self._apply(), ["split"])
        nodes = self._nodes()
        self.assertEqual(set(nodes), {f"netlas-{CVE}-{ip}-22" for ip in (A, B)})
        for ip in (A, B):
            node = nodes[f"netlas-{CVE}-{ip}-22"]
            self.assertEqual((node["muted"], node["status"], node["proof"], node["parents"]),
                             (True, "likely_noise", [90], ["IP"]))
            self.assertTrue(node["seen"].startswith("2026-10-01"))

    def test_a_node_the_scan_already_wrote_takes_the_block(self):
        self._seed(A)
        with self.driver.session() as s:
            s.run("""
                MATCH (i:IP {address: $ip, user_id: $u, project_id: $p})
                CREATE (i)-[:HAS_VULNERABILITY]->(:Vulnerability {id: $id, source: 'netlas',
                        user_id: $u, project_id: $p, triage_ai_verdict: 'real',
                        updated_at: datetime()})
                """, ip=A, id=f"netlas-{CVE}-{A}-22", u=self.uid, p=self.pid)
        self.assertEqual(self._apply(), ["merged"])
        nodes = self._nodes()
        self.assertEqual(list(nodes), [f"netlas-{CVE}-{A}-22"])
        node = nodes[f"netlas-{CVE}-{A}-22"]
        self.assertEqual((node["muted"], node["status"], node["proof"]), (True, "likely_noise", [90]))

    def test_a_second_run_finds_nothing(self):
        self._seed(A, B)
        self._apply()
        self.assertEqual(self._apply(), [])

    @unittest.skipUnless(os.getenv("DATABASE_URL"), "DATABASE_URL not set")
    def test_the_postgres_statements_run_on_the_real_schema(self):
        import psycopg
        from tooling.scripts import netlas_finding_rekey as rk
        rekey = {"old_id": CVE, "cve": CVE, "targets": [
            {"ip": ip, "port": 22, "new_id": f"netlas-{CVE}-{ip}-22"} for ip in (A, B)]}
        with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
            try:
                with conn.cursor() as cur:
                    rk.rekey_postgres(cur, self.pid, rekey)
            finally:
                conn.rollback()


if __name__ == "__main__":
    unittest.main()
