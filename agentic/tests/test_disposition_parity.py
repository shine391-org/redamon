"""Python's disposition agrees with the webapp's, on the webapp's own vectors.

`combine_layers` stores a finding's disposition and blocker; the webapp computes
them from the stored props for a node no run has stored them on yet
(webapp/src/lib/triage/disposition.ts), and shows the stored ones otherwise. The
two must give the same answer for the same finding, or a finding changes bucket
the moment a run rescores it. Both read the same vector files:

- disposition.gates.vectors.json: findings a v3.10 run scored, with their gates;
- disposition.vectors.json: the read-side table. Python sees only the rows a
  run could have produced (scored, no stored answer, no v3.1 AI source).

Run: ./agentic/run_tests.sh tests/test_disposition_parity.py
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402

_VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                        "webapp", "src", "lib", "triage")


def _load(name):
    with open(os.path.join(_VECTORS, name), encoding="utf-8") as fh:
        return json.load(fh)


def _inputs(props):
    """The stored tier inputs, with the node's own public-key test that
    publicClientKeys.ts applies (the flag, or the pattern name)."""
    raw = props.get("triage_tier_inputs")
    try:
        stored = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        stored = None
    inputs = sm.TierInputs.from_dict(stored)
    secret_type = str(props.get("secret_type") or "").strip().lower()
    if props.get("public_client_key") is True or secret_type in sm.PUBLIC_CLIENT_KEY_TYPES:
        inputs.public_client_key = True
    return inputs


def _python_disposition(props):
    status = props.get("triage_status")
    person = status if (props.get("triage_source") == "human"
                        and status in sm.DECISION_STATUSES) else None
    return sm.disposition_of(props.get("triage_state") or sm.STATE_OPEN,
                             props.get("triage_tier_rule") or "", person, _inputs(props))


def _a_run_could_store(props):
    return (isinstance(props.get("triage_tier_rule"), str) and props["triage_tier_rule"]
            and "triage_disposition" not in props and props.get("triage_source") != "ai")


class TestTheTwoHalvesAgree(unittest.TestCase):
    def test_every_gate_vector(self):
        vectors = _load("disposition.gates.vectors.json")
        self.assertGreater(len(vectors), 10)
        for v in vectors:
            with self.subTest(why=v["why"]):
                self.assertEqual(_python_disposition(v["props"]), (v["disposition"], v["blocker"]))

    def test_every_read_side_vector_a_run_could_have_produced(self):
        vectors = [v for v in _load("disposition.vectors.json") if _a_run_could_store(v["props"])]
        self.assertGreater(len(vectors), 10)
        for v in vectors:
            with self.subTest(why=v["why"]):
                self.assertEqual(_python_disposition(v["props"]), (v["disposition"], v["blocker"]))

    def test_the_words_are_the_webapp_s(self):
        """disposition.ts quotes these; a reworded blocker would split a
        report's candidates into two groups for one reason."""
        with open(os.path.join(_VECTORS, "disposition.ts"), encoding="utf-8") as fh:
            ts = fh.read()
        for word in (sm.TIER_RULE_PROVEN, sm.TIER_RULE_NO_IMPACT, sm.BLOCKER_NOT_TRIAGED,
                     sm.BLOCKER_AI_FALSE_POSITIVE, *sm.DISPOSITIONS, *sm.GATES):
            with self.subTest(word=word):
                self.assertIn(f"'{word}'", ts)
        for failed, unknown in sm.GATE_BLOCKERS.values():
            with self.subTest(blocker=failed):
                self.assertIn(f"'{failed}'", ts)
                self.assertIn(f"'{unknown}'", ts)


if __name__ == "__main__":
    unittest.main()
