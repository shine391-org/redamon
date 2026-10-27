"""A TruffleHog credential tested and found dead (plan 05.8).

TruffleHog wrote `unvalidated` for "verification ran and the credential is
not live", while js_recon means "no validator" by the same word, and the board
could only tell them apart by a `validated_at` no writer sets: a dead
credential stayed open. It now writes `rejected`, which the board reads as
inactive. Nodes written before keep `unvalidated`, which the readers take as
rejected for MultiscannerFinding only.
"""
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for extra in (REPO_ROOT, REPO_ROOT / "scanners", REPO_ROOT / "agentic"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from trufflehog_scan import findings as fnd  # noqa: E402
from trufflehog_graph_fake import FakeClient, finding, scan_payload  # noqa: E402


class TestTheScannerWritesRejected(unittest.TestCase):
    def test_verification_ran_and_the_credential_is_dead(self):
        self.assertEqual(fnd.validation_status({"Verified": False}), "rejected")
        self.assertEqual(fnd.REJECTED, "rejected")
        self.assertIn(fnd.REJECTED, fnd.VALIDATION_STATUSES)

    def test_it_never_writes_the_ambiguous_word_again(self):
        for result in ({"Verified": False}, {"Verified": True},
                       {"Verified": False, "VerificationError": "dial tcp: timeout"}):
            for enabled in (True, False):
                with self.subTest(result=result, enabled=enabled):
                    self.assertNotEqual(fnd.validation_status(result, enabled), "unvalidated")
        self.assertNotIn("unvalidated", fnd.VALIDATION_STATUSES)


class TestTheGraphKeepsIt(unittest.TestCase):
    def test_a_dead_credential_is_stored_rejected(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(scan_payload("git", "repository", [
            dict(finding("acme/app", "a.py"), validation_status=fnd.validation_status({"Verified": False})),
        ]), "u1", "p1")
        self.assertEqual([f["validation_status"] for f in c.findings()], ["rejected"])

    def test_an_artifact_without_the_field_derives_rejected_too(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(scan_payload("git", "repository", [
            dict(finding("acme/app", "a.py"), validation_status="", verified=False),
        ]), "u1", "p1")
        self.assertEqual([f["validation_status"] for f in c.findings()], ["rejected"])


class TestTheBoardDropsIt(unittest.TestCase):
    def setUp(self):
        try:
            from cypherfix_triage import score_model as sm
        except ImportError as e:  # pragma: no cover - the agent image has it
            self.skipTest(f"score_model is not importable here: {e}")
        self.sm = sm

    def _row(self, status):
        return {"id": "f", "label": "MultiscannerFinding", "source": "trufflehog", "host": "h1",
                "secret_type": "AWS", "detector_name": "AWS", "validation_status": status}

    def test_a_verified_and_dead_credential_is_inactive(self):
        facts = self.sm.ProjectFacts(live_hosts={"h1"})
        status = fnd.validation_status({"Verified": False})
        self.assertEqual(self.sm.score(self._row(status), facts).state, self.sm.STATE_INACTIVE)

    def test_one_that_could_not_be_verified_stays_open(self):
        facts = self.sm.ProjectFacts(live_hosts={"h1"})
        status = fnd.validation_status({"Verified": False, "VerificationError": "timeout"})
        self.assertEqual(self.sm.score(self._row(status), facts).state, self.sm.STATE_OPEN)
