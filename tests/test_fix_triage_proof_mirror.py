"""_LIVE_PROOF must keep mirroring score_model.is_proven.

A person's verdict and an MCP review re-combine the finding with the proof read
live by `_LIVE_PROOF`. When is_proven stopped counting a validated public
client key (an AIza Maps key, a Stripe publishable key) as proof, the Cypher
twin had to stop too, or every such write lifted the key back to T1 "proven".

graph_db cannot import the agent's model, so the list is duplicated; these
tests pin the copies equal and the Cypher shape that uses it.

Run: python -m pytest tests/test_fix_triage_proof_mirror.py
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (_REPO, os.path.join(_REPO, "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

from graph_db.mixins.recon import triage_mixin  # noqa: E402
from cypherfix_triage import score_model as sm  # noqa: E402


class TestLiveProofMirrorsIsProven(unittest.TestCase):
    def test_the_public_key_lists_are_the_same(self):
        self.assertEqual(set(triage_mixin._PUBLIC_CLIENT_KEY_TYPES),
                         set(sm.PUBLIC_CLIENT_KEY_TYPES))

    def test_the_validated_arm_excludes_public_client_keys(self):
        proof = " ".join(triage_mixin._LIVE_PROOF.split())
        arm = re.search(r"\(toLower\(coalesce\(n\.validation_status, ''\)\) = 'validated'"
                        r" AND NONE\(name IN \[n\.secret_type, n\.key_type, n\.detector_name\]"
                        r" WHERE toLower\(coalesce\(name, ''\)\) IN \[(.*?)\]\)\)", proof)
        self.assertIsNotNone(arm, proof)
        listed = set(re.findall(r"'([^']+)'", arm.group(1)))
        self.assertEqual(listed, set(sm.PUBLIC_CLIENT_KEY_TYPES))

    def test_no_bare_validated_arm_is_left(self):
        # The old unconditional arm would still prove every validated public key.
        proof = " ".join(triage_mixin._LIVE_PROOF.split())
        self.assertNotIn("OR toLower(coalesce(n.validation_status, '')) = 'validated' OR", proof)

    def test_is_proven_agrees_for_each_name_property(self):
        facts = sm.ProjectFacts()
        for name in sorted(sm.PUBLIC_CLIENT_KEY_TYPES):
            for field in ("secret_type", "detector_name"):
                with self.subTest(name=name, field=field):
                    row = {"id": "x", "validation_status": "validated", field: name.upper()}
                    self.assertFalse(sm.is_proven(row, facts))
        self.assertTrue(sm.is_proven(
            {"id": "x", "validation_status": "validated", "secret_type": "Stripe Secret Key"},
            facts))


class TestAgentConfidenceMirrorsTheModel(unittest.TestCase):
    THRESHOLD = (f"coalesce(toInteger(cf.confidence), {sm.AGENT_CONFIDENCE_DEFAULT}) "
                 f">= {sm.PROOF_MIN_AGENT_CONFIDENCE}")

    def test_the_threshold_and_default_are_the_same(self):
        self.assertEqual(triage_mixin._PROOF_MIN_CONFIDENCE, sm.PROOF_MIN_AGENT_CONFIDENCE)
        self.assertEqual(triage_mixin._PROOF_DEFAULT_CONFIDENCE, sm.AGENT_CONFIDENCE_DEFAULT)

    def test_live_proof_reads_the_agent_s_confidence(self):
        self.assertIn(self.THRESHOLD, " ".join(triage_mixin._LIVE_PROOF.split()))

    def test_the_proof_types_the_detail_shows_use_the_same_bar(self):
        # A confirmation that does not count as proof must not be listed as one.
        source = open(triage_mixin.__file__).read()
        listed = re.search(r"\[\(cf:ChainFinding\)-\[:CONFIRMS\]->\(n\)(.*?)\| cf\.finding_type\]",
                           source, re.S)
        self.assertIsNotNone(listed)
        self.assertIn("_PROOF_CONFIDENCE", listed.group(1))


if __name__ == "__main__":
    unittest.main()
