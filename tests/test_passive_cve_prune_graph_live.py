"""LIVE-Neo4j proof that passive CVEs are pruned per IP (plan 04.1).

A run that looked up some IPs and not others prunes the passive CVEs of the
IPs it looked up and keeps those of the IPs it could not; a CVE written before
its writer stored `target_ip` is first given the IP its id names, or the keep
could not match it. A muted CVE is kept as stale, as for every source.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD exported from the repo .env:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_passive_cve_prune_graph_live.py -v
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

UNQUERIED, QUERIED, GONE = "198.51.100.21", "198.51.100.22", "198.51.100.23"
SHODAN = ["shodan_api", "internetdb", "shodan", "shodan_host_lookup"]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestPassiveCvePruneGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"passive-{run}", f"PASSIVE_{run}"
        with self.client.driver.session() as s:
            # A previous run's findings, an hour old. The legacy rows carry no
            # target_ip, as Shodan's did before its grading and CriminalIP's always.
            s.run(
                """
                UNWIND $rows AS r
                CREATE (v:Vulnerability {id: r.id, source: r.source, name: r.cve,
                        user_id: $u, project_id: $p,
                        updated_at: datetime() - duration('PT1H')})
                FOREACH (_ IN CASE WHEN r.ip IS NULL THEN [] ELSE [1] END |
                  SET v.target_ip = r.ip)
                FOREACH (_ IN CASE WHEN r.muted THEN [1] ELSE [] END |
                  SET v:Muted, v.muted_by = 'user-1')
                """,
                u=self.uid, p=self.pid, rows=[
                    {"id": f"shodan-CVE-2018-15473-{UNQUERIED}", "source": "shodan_api",
                     "cve": "CVE-2018-15473", "ip": None, "muted": False},
                    {"id": f"criminalip-CVE-2021-44228-{UNQUERIED}", "source": "criminalip",
                     "cve": "CVE-2021-44228", "ip": None, "muted": False},
                    {"id": f"shodan-CVE-2018-15473-{QUERIED}", "source": "internetdb",
                     "cve": "CVE-2018-15473", "ip": QUERIED, "muted": False},
                    {"id": f"criminalip-CVE-2021-44228-{QUERIED}", "source": "criminalip",
                     "cve": "CVE-2021-44228", "ip": None, "muted": False},
                    {"id": f"shodan-CVE-2019-6111-{GONE}", "source": "shodan_api",
                     "cve": "CVE-2019-6111", "ip": GONE, "muted": True},
                    {"id": "CVE-2018-15473", "source": "netlas",
                     "cve": "CVE-2018-15473", "ip": None, "muted": False},
                ])

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n {user_id: $u, project_id: $p}) DETACH DELETE n",
                  u=self.uid, p=self.pid)

    def _nodes(self):
        with self.client.driver.session() as s:
            return {r["id"]: dict(r) for r in s.run(
                """
                MATCH (v:Vulnerability {user_id: $u, project_id: $p})
                RETURN v.id AS id, v.target_ip AS ip, v.stale_since IS NOT NULL AS stale,
                       v.updated_at < datetime() - duration('PT30M') AS old
                """, u=self.uid, p=self.pid)}

    def _prune(self):
        from graph_db.mixins.base_mixin import run_timestamp
        since = run_timestamp()
        self.client.prune_unseen_findings(self.uid, self.pid, SHODAN + ["criminalip"], since,
                                          keep_hosts=[UNQUERIED])
        self.client.prune_unseen_findings(self.uid, self.pid, ["netlas"], since)

    def test_the_backfill_gives_older_rows_their_ip_and_nothing_else(self):
        self.assertEqual(self.client.backfill_passive_cve_hosts(self.uid, self.pid), 3)
        nodes = self._nodes()
        self.assertEqual(nodes[f"shodan-CVE-2018-15473-{UNQUERIED}"]["ip"], UNQUERIED)
        self.assertEqual(nodes[f"criminalip-CVE-2021-44228-{QUERIED}"]["ip"], QUERIED)
        self.assertIsNone(nodes["CVE-2018-15473"]["ip"])
        self.assertTrue(all(n["old"] for n in nodes.values()), "updated_at must not move")
        self.assertEqual(self.client.backfill_passive_cve_hosts(self.uid, self.pid), 0)

    def test_only_the_ip_the_run_could_not_look_up_keeps_its_cves(self):
        self.client.backfill_passive_cve_hosts(self.uid, self.pid)
        self._prune()
        nodes = self._nodes()
        self.assertEqual(set(nodes), {
            f"shodan-CVE-2018-15473-{UNQUERIED}", f"criminalip-CVE-2021-44228-{UNQUERIED}",
            f"shodan-CVE-2019-6111-{GONE}"})
        self.assertFalse(nodes[f"shodan-CVE-2018-15473-{UNQUERIED}"]["stale"])
        self.assertTrue(nodes[f"shodan-CVE-2019-6111-{GONE}"]["stale"])

    def test_without_the_backfill_the_older_rows_would_be_lost(self):
        self._prune()
        self.assertNotIn(f"criminalip-CVE-2021-44228-{UNQUERIED}", self._nodes())


if __name__ == "__main__":
    unittest.main()
