"""The access-control skill's differential oracle must not call a redirect to
login a bypass.

The CORE PRINCIPLE said any move "403/401 -> 2xx/3xx" IS the finding, while
the same prompt's FALSE-POSITIVE GATE and its "Medium = status/length
differential only" rule say a different-but-still-denied answer is not. A 302
to /login is the protection working.

Run: ./agentic/run_tests.sh tests/test_access_control_oracle_prompt.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from prompts.access_control_prompts import ACCESS_CONTROL_TOOLS  # noqa: E402


def _flat(text: str) -> str:
    return " ".join(text.split())


class TestTheDifferentialOracle(unittest.TestCase):
    PROMPT = _flat(ACCESS_CONTROL_TOOLS)

    def test_a_bare_status_move_to_3xx_is_no_longer_the_finding(self):
        self.assertNotIn("403/401 -> 2xx/3xx", self.PROMPT)

    def test_success_needs_the_protected_content_or_a_real_redirect(self):
        self.assertIn("403/401 -> 2xx WITH the protected content", self.PROMPT)
        self.assertIn("a 3xx whose `Location` is NOT a login, landing or error route", self.PROMPT)

    def test_a_redirect_to_login_is_named_as_the_protection_working(self):
        self.assertIn("A redirect to a login, landing or error route is the protection "
                      "working, not a bypass", self.PROMPT)

    def test_the_false_positive_gate_is_kept(self):
        self.assertIn("A path-normalization/verb bypass counts ONLY if the response actually "
                      "returns the protected content", self.PROMPT)


if __name__ == "__main__":
    unittest.main()
