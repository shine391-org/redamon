"""Keyword-anchored patterns are bounded (plan 05.4).

A bare `.*` between the keyword and the value let one match span a whole
minified bundle: "azure" anywhere early on the line plus any long quoted
string anywhere later was an Azure AD client secret. The gap is now at most
120 characters, matched lazily, and the Azure pattern needs the value to be
assigned to the client-secret key. Every value here is synthetic.
"""

from __future__ import annotations

import re
import sys
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

URL = "https://app.example.com/static/main.js"
AZURE_VALUE = "Qx7~Lm2.Rt9_Wn4-Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko"


def _names(js: str) -> list:
    return [f["name"] for f in patterns.scan_js_content(js, URL)[0]]


def _named(js: str, name: str) -> dict:
    return next(f for f in patterns.scan_js_content(js, URL)[0] if f["name"] == name)


def _filler(length: int) -> str:
    unit = "var q=function(a,b){return a+b};"
    return (unit * (length // len(unit) + 1))[:length]


class TestNoUnboundedGap(unittest.TestCase):
    def test_no_pattern_has_a_bare_dot_star(self):
        unbounded = [name for name, regex, *_ in patterns._RAW_PATTERNS
                     if re.search(r"(?<!\\)\.[*+]", regex)]
        self.assertEqual(unbounded, [])

    def test_the_gap_is_lazy_and_at_most_120(self):
        gaps = [name for name, regex, *_ in patterns._RAW_PATTERNS
                if "[^\\n]{0," in regex and "[^\\n]{0,120}?" not in regex]
        self.assertEqual(gaps, [])


class TestAzureAdClientSecret(unittest.TestCase):
    def test_msal_empty_default_with_a_long_string_later_is_no_hit(self):
        js = ('const cfg={auth:{authority:"https://login.microsoftonline.com/common",'
              'clientId:"x",clientSecret:""},cache:{}};' + _filler(60)
              + 'const build="' + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0" + '";'
              + ' // azure')
        self.assertNotIn("Azure AD Client Secret", _names("/* azure msal */" + js))

    def test_a_value_assigned_to_the_client_secret_is_a_hit(self):
        js = 'const azureAd = { clientId: "abc", clientSecret: "' + AZURE_VALUE + '" };'
        finding = _named(js, "Azure AD Client Secret")
        self.assertTrue(finding["matched_text"].endswith(AZURE_VALUE + '"'))
        self.assertEqual(finding["confidence"], "medium")

    def test_msal_and_aad_keywords_count_too(self):
        for keyword in ("msalConfig", "AAD_APP"):
            js = f'const {keyword} = {{ client_secret: "{AZURE_VALUE}" }};'
            with self.subTest(keyword=keyword):
                self.assertIn("Azure AD Client Secret", _names(js))

    def test_the_keyword_must_be_near(self):
        js = "azure" + _filler(300) + 'clientSecret: "' + AZURE_VALUE + '"'
        self.assertNotIn("Azure AD Client Secret", _names(js))


class TestNoRunawayMatch(unittest.TestCase):
    def test_an_anchor_at_the_start_of_a_30000_char_line(self):
        line = "etsy_config=1;" + _filler(30000) + 'x="' + "k3x9q2m7a8b1c4d5e6f7g8h9" + '";'
        start = time.monotonic()
        findings = patterns.scan_js_content(line, URL)[0]
        self.assertLess(time.monotonic() - start, 10)
        self.assertNotIn("Etsy Access Token", [f["name"] for f in findings])
        for f in findings:
            self.assertLess(len(f["matched_text"]), 400, f["name"])

    def test_a_value_near_its_anchor_is_still_found(self):
        js = _filler(500) + 'etsyKey:"' + "k3x9q2m7a8b1c4d5e6f7g8h9" + '"' + _filler(500)
        finding = _named(js, "Etsy Access Token")
        self.assertTrue(finding["matched_text"].startswith("etsy"))

    def test_the_nearest_value_is_taken_not_the_last(self):
        js = ('cloudflare={token:"' + "x7Kp2Lm9Qz4Wn8Rt1Yb6Vc3Hd5Jf0Gs2Ue8Ya1QZ" + '"};'
              + _filler(60) + 'other="' + "Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8cB7aZ" + '"')
        finding = _named(js, "Cloudflare API Token")
        self.assertIn("x7Kp2Lm9", finding["matched_text"])
        self.assertNotIn("Z9yX8wV7", finding["matched_text"])


if __name__ == "__main__":
    unittest.main()
