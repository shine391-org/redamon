"""Keys that are public by design (plan 05.2).

Browser keys, write-only analytics keys, DSNs and publishable keys ship to
every browser that loads the page. They stay visible as Secret findings, at
severity info with `public_client_key`, instead of critical, high or medium.
Every value here is synthetic.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

URL = "https://app.example.com/static/main.js"

#: One synthetic hit per public family: (pattern name, the code that holds it).
PUBLIC_SAMPLES = {
    "GCP API Key": 'const k = "AIza' + "Sy8Kq2Lm7Zx4Wp9Rt1Vb6Nc3Hd5Jf0Gs2Ue" + '";',
    "Firebase API Key": 'firebaseToken: "' + "Q2xk9LmP0z7Rt4Wn8Yb1Vc6Hd3Jf5Gs2" + '"',
    "Segment Write Key": 'segmentWriteKey: "' + "x7Kp2Lm9Qz4Wn8Rt1Yb6Vc3Hd5Jf0Gs2" + '"',
    "Amplitude API Key": 'amplitudeApiKey: "' + "9f3c1a7e5b2d8f40c6e1a9b3d7f2c5e8" + '"',
    "New Relic Browser API Token": 'nr.init("NRJS-' + "4a9c2e7f1b3d5e8a6c0" + '")',
    "Sentry DSN": 'Sentry.init({dsn: "https://' + "7c2e9a4f1b6d3e8a5c0f2b7d9e1a4c6f"
                  + '@o4505.ingest.sentry.io/4505123"})',
    "Stripe Publishable Key": 'Stripe("pk_live_' + "4fT9qZ2mX7cV1bN8kL3pR6sW" + '")',
    "Google reCAPTCHA Key": 'grecaptcha.render(el, {sitekey: "6L' + "c9Kq2Lm7Zx4Wp9Rt1Vb6Nc3Hd5Jf0Gs2Ue8Ya1Q" + '"})',
    "Mapbox Token": 'mapboxgl.accessToken = "pk.' + "eyJ1Ijoic3ludGgiLCJhIjoiY2x6OXE3a2" + "Z4MDFxbTJrcHE4dzN4cWJ2ZiJ9XyZ7" + '";',
    "Algolia App ID": 'algoliaAppId: "' + "Q7R2M9X4K1" + '"',
    "Algolia Search Key": 'algoliaSearchKey: "' + "3e8b1f6a9c2d5e7f0a4b8c1d6e9f2a5b" + '"',
    "Intercom App ID": 'intercomAppId: "' + "k3x9q2m7" + '"',
    "Pusher Key": 'pusherKey: "' + "a7c3e9f1b5d2e8a4c6f0" + '"',
    "Clerk Publishable Key": 'clerk("pk_live_' + "Y2xlcmsuZXhhbXBsZS5jb20k9Qz" + '")',
    "Mailgun Public Key": 'mg.pub = "pubkey-' + "4e9a1c7f3b5d8e2a6c0f9b1d7e3a5c8f" + '";',
    "Flutterwave Public Key": 'FlutterwaveCheckout({public_key: "FLWPUBK-' + "x7Kp2Lm9Qz4Wn8Rt1Yb6Vc3Hd5Jf0Gs2" + '-X"})',
}


def _findings(js: str) -> list:
    return patterns.scan_js_content(js, URL)[0]


def _named(js: str, name: str) -> dict:
    found = [f for f in _findings(js) if f["name"] == name or name in f.get("alternate_names", ())]
    if not found:
        raise AssertionError(f"{name} not found in {[f['name'] for f in _findings(js)]}")
    return found[0]


class TestPublicClientKeysAreInfo(unittest.TestCase):
    def test_the_list_names_real_patterns(self):
        known = {p["name"] for p in patterns.JS_SECRET_PATTERNS} | set(patterns.DERIVED_SECRET_NAMES)
        self.assertEqual(set(patterns.PUBLIC_CLIENT_KEY_NAMES) - known, set())

    def test_every_listed_family_has_a_sample_here(self):
        derived_later = {"Supabase anon key", "Supabase Publishable Key"}
        self.assertEqual(set(patterns.PUBLIC_CLIENT_KEY_NAMES) - derived_later,
                         set(PUBLIC_SAMPLES))

    def test_each_family_is_info_and_flagged(self):
        for name, js in PUBLIC_SAMPLES.items():
            with self.subTest(name=name):
                finding = _named(js, name)
                self.assertEqual(finding["severity"], "info")
                self.assertIs(finding["public_client_key"], True)

    def test_a_secret_key_beside_them_keeps_its_severity(self):
        js = 'Stripe("pk_live_4fT9qZ2mX7cV1bN8kL3pR6sW"); const s = "sk_live_' + "8Hq3Lz5mW1cX9bV2nK7pT4rY" + '";'
        secret = _named(js, "Stripe Secret Key")
        self.assertEqual(secret["severity"], "critical")
        self.assertIs(secret["public_client_key"], False)


class TestNoSecretTwinForAPublicKey(unittest.TestCase):
    def test_a_mailgun_public_key_is_not_also_a_mailgun_api_key(self):
        names = [f["name"] for f in _findings(PUBLIC_SAMPLES["Mailgun Public Key"])]
        self.assertEqual(names, ["Mailgun Public Key"])

    def test_a_mailgun_api_key_still_reports(self):
        js = 'mailgun({key: "key-' + "8d2f6b0a4c9e1f7b3d5a8c2e6f0b4d9a" + '"})'
        finding = _named(js, "Mailgun API Key")
        self.assertEqual(finding["severity"], "high")


class TestAlgoliaSearchKeys(unittest.TestCase):
    """A search-only key and an admin key share one format; only a label
    naming it a search key makes it public."""

    def test_a_labelled_search_key_is_public(self):
        finding = _named(PUBLIC_SAMPLES["Algolia Search Key"], "Algolia Search Key")
        self.assertNotIn("Algolia API Key", [f["name"] for f in _findings(PUBLIC_SAMPLES["Algolia Search Key"])])
        self.assertEqual(finding["severity"], "info")

    def test_an_unlabelled_algolia_key_stays_high(self):
        js = 'algoliaAdminKey: "' + "3e8b1f6a9c2d5e7f0a4b8c1d6e9f2a5b" + '"'
        finding = _named(js, "Algolia API Key")
        self.assertEqual(finding["severity"], "high")
        self.assertIs(finding["public_client_key"], False)


if __name__ == "__main__":
    unittest.main()
