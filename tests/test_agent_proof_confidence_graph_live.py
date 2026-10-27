"""LIVE-Neo4j: an agent's low-confidence confirmation is not proof.

`ChainFinding.confidence` (0-100, the writer defaults to 80) was never read, so
any `vulnerability_confirmed` CONFIRMS edge made its finding T1 and immune to
review, including a confirmation the agent itself rated as a guess off a status
code. The proof fact query (a run's scoring) and `_LIVE_PROOF` (every verdict,
review and publish transaction) must both require 70 or more, and a missing
value must keep counting. The unit tests read the query text; this runs it.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_agent_proof_confidence_graph_live.py -v

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
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

#: finding id -> the confirming ChainFinding's confidence (None: not stored).
CONFIRMATIONS = {"v-low": 50, "v-edge": 70, "v-high": 90, "v-old": None}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveAgentProofConfidenceCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"apconf-{run}"
        self.pid = f"APCONF_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        with self.driver.session() as s:
            for vid, confidence in CONFIRMATIONS.items():
                s.run(
                    """
                    CREATE (v:Vulnerability {id: $vid, user_id: $u, project_id: $p,
                                             source: 'nuclei', severity: 'high',
                                             name: $vid, updated_at: datetime()})
                    CREATE (cf:ChainFinding {id: 'cf-' + $vid, user_id: $u, project_id: $p,
                                             finding_type: 'vulnerability_confirmed',
                                             title: 'confirmed by status code'})
                    SET cf.confidence = $confidence
                    CREATE (cf)-[:CONFIRMS]->(v)
                    """, vid=vid, u=self.uid, p=self.pid, confidence=confidence)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid)
        self.driver.close()

    def test_the_run_s_proof_fact_counts_only_confident_confirmations(self):
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES, build_project_facts

        query = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "proof")["query"]
        with self.driver.session() as s:
            rows = [dict(r) for r in s.run(query, userId=self.uid, projectId=self.pid)]
        facts = build_project_facts({"proof": rows})
        self.assertEqual(facts.proven_finding_ids, {"v-edge", "v-high", "v-old"})

    def test_live_proof_in_a_write_transaction_agrees(self):
        for vid, confidence in CONFIRMATIONS.items():
            with self.subTest(finding=vid, confidence=confidence):
                detail = self.client.get_triage_detail(self.uid, self.pid, vid)
                self.assertTrue(detail.get("found"), detail)
                proven = confidence is None or confidence >= 70
                self.assertIs(bool(detail["row"]["proven_now"]), proven)
                self.assertEqual(bool(detail["row"]["proof_types"]), proven)


if __name__ == "__main__":
    unittest.main()
