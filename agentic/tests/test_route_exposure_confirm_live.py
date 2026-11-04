"""LIVE-Neo4j: an agent proof promotes a route-exposure candidate (plan §23.12).

Through the agent's real writer (`_write_finding`, the body behind
fire_record_finding) into a throwaway tenant:
  1. a `vulnerability_confirmed` finding naming the candidate's id lands a
     CONFIRMS edge, the triage proof query returns the id, and score() puts the
     candidate at T1;
  2. a `custom` finding naming another candidate lands the edge without
     promotion (the proof query's closed type list);
  3. a made-up id writes nothing;
  4. a lead is confirmed only from the access_control skill while the module
     is on, while any skill may record its re-check of a signature finding.
The tenant is deleted afterwards. Self-skips unless the driver imports and a
database answers:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/agentic \\
    -e PYTHONPATH=/repo/agentic:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_route_exposure_confirm_live.py -v
"""

import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_SKIP_REASON = None
try:
    import neo4j as _neo4j
except ImportError:
    _neo4j = None
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _neo4j is not None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _alive() -> bool:
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD), connection_timeout=3)
        drv.verify_connectivity()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _alive()


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class AgentProofPromotesTheCandidate(unittest.TestCase):
    def setUp(self):
        from cypherfix_triage import fact_queries
        from orchestrator_helpers import chain_graph_writer as writer
        self.writer, self.fact_queries = writer, fact_queries
        self.uid = f"rex-live-{uuid.uuid4().hex[:10]}"
        self.pid = f"rex-live-{uuid.uuid4().hex[:10]}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.chain, self.step = f"chain-{self.uid}", f"step-{self.uid}"
        with self.driver.session() as s:
            s.run("CREATE (:AttackChain {chain_id: $c, user_id: $u, project_id: $p})"
                  "-[:HAS_STEP]->(:ChainStep {step_id: $s, chain_id: $c, user_id: $u, project_id: $p})",
                  c=self.chain, s=self.step, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n", u=self.uid, p=self.pid)
        self.driver.close()
        self.writer.close_driver()

    def _candidate(self, vid, vtype="unauthenticated_endpoint", lead=True):
        props = {"id": vid, "user_id": self.uid, "project_id": self.pid, "source": "route_exposure",
                 "type": vtype, "severity": "info" if lead else "high", "needs_agent_confirmation": lead,
                 "exposure_kind": "anonymous_access" if lead else "env_file", "route_class": "admin_function",
                 "matched_at": "http://192.0.2.10/internal/users", "host": "192.0.2.10"}
        with self.driver.session() as s:
            s.run("CREATE (v:Vulnerability) SET v = $props", props=props)
        return props

    def _record(self, finding_type, ids, skill="access_control", module=True):
        self.writer._write_finding(
            _URI, _USER, _PASSWORD,
            finding_id=f"cf-{uuid.uuid4().hex[:12]}", chain_id=self.chain, step_id=self.step,
            user_id=self.uid, project_id=self.pid, finding_type=finding_type, severity="high",
            title="Unauthenticated admin route", description="", evidence="anon 200, 12 records",
            confidence=90, phase="exploitation", iteration=1, related_cves=[], related_ips=[],
            related_finding_ids=ids, skill=skill, route_exposure_on=module)

    def _confirms(self, vid):
        with self.driver.session() as s:
            row = s.run("MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {id: $v, user_id: $u, project_id: $p}) "
                        "RETURN collect(cf.finding_type) AS types", v=vid, u=self.uid, p=self.pid).single()
        return row["types"]

    def _facts(self):
        query = next(q["query"] for q in self.fact_queries.PROJECT_FACT_QUERIES if q["name"] == "proof")
        with self.driver.session() as s:
            rows = [r.data() for r in s.run(query, userId=self.uid, projectId=self.pid)]
        return self.fact_queries.build_project_facts({"proof": rows})

    def test_proof_lands_and_promotes_custom_lands_without(self):
        from cypherfix_triage import score_model
        proven = self._candidate(f"rex-{uuid.uuid4().hex[:16]}")
        custom = self._candidate(f"rex-{uuid.uuid4().hex[:16]}")
        self._record("vulnerability_confirmed", [proven["id"]])
        self._record("custom", [custom["id"]])

        self.assertEqual(self._confirms(proven["id"]), ["vulnerability_confirmed"])
        self.assertEqual(self._confirms(custom["id"]), ["custom"])

        facts = self._facts()
        self.assertIn(proven["id"], facts.proven_finding_ids)
        self.assertNotIn(custom["id"], facts.proven_finding_ids)
        finding = {**proven, "label": "Vulnerability"}
        self.assertEqual(score_model.score(finding, facts).tier, "T1")
        self.assertNotEqual(score_model.score({**custom, "label": "Vulnerability"}, facts).tier, "T1")

    def test_a_made_up_id_writes_nothing(self):
        real = self._candidate(f"rex-{uuid.uuid4().hex[:16]}")
        self._record("vulnerability_confirmed", ["rex-does-not-exist"])
        with self.driver.session() as s:
            edges = s.run("MATCH (cf:ChainFinding {user_id: $u, project_id: $p})-[r:CONFIRMS]->() RETURN count(r) AS n",
                          u=self.uid, p=self.pid).single()["n"]
        self.assertEqual(edges, 0)
        self.assertEqual(self._confirms(real["id"]), [])

    def test_only_access_control_confirms_a_lead(self):
        lead = self._candidate(f"rex-{uuid.uuid4().hex[:16]}")
        signature = self._candidate(f"rex-{uuid.uuid4().hex[:16]}", "exposed_env_file", lead=False)
        for skill in ("rce", "path_traversal", "", "user_skill:x"):
            self._record("vulnerability_confirmed", [lead["id"], signature["id"]], skill=skill)
        self.assertEqual(self._confirms(lead["id"]), [])
        self.assertEqual(len(self._confirms(signature["id"])), 4)
        # With the module off, access_control has no proof standard to apply.
        self._record("vulnerability_confirmed", [lead["id"], signature["id"]], skill="access_control",
                     module=False)
        self.assertEqual(self._confirms(lead["id"]), [])
        self.assertEqual(len(self._confirms(signature["id"])), 5)
        self._record("vulnerability_confirmed", [lead["id"]], skill="access_control")
        self.assertEqual(self._confirms(lead["id"]), ["vulnerability_confirmed"])


if __name__ == "__main__":
    unittest.main()
