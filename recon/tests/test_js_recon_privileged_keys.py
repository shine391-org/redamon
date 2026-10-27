"""Secrets that look public but are privileged (plan 05.6).

A Supabase key is a JWT whose `role` decides everything: `anon` ships to every
browser, `service_role` bypasses row-level security. The payload is decoded
with the stdlib (never verified: the token is target-controlled). Also the
new Supabase key formats, signed cloud-storage URLs and write-capable
webhooks. Every token and URL here is synthetic and unsigned.
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns

URL = "https://app.example.com/static/main.js"
SIG = "Xq9Lm2Rt7Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4Pz7Nb3"


def b64url(data) -> str:
    raw = data if isinstance(data, bytes) else json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(payload, header=None) -> str:
    return f"{b64url(header or {'alg': 'HS256', 'typ': 'JWT'})}.{b64url(payload)}.{SIG}"


def supabase_jwt(role: str) -> str:
    return jwt({"iss": "supabase", "ref": "qzxkvlmwprtnbydhc", "role": role,
                "iat": 1700000000, "exp": 2000000000})


def _findings(js: str) -> list:
    return patterns.scan_js_content(js, URL)[0]


def _named(js: str, name: str) -> list:
    return [f for f in _findings(js) if f["name"] == name]


class TestSupabaseJwtRole(unittest.TestCase):
    def test_a_service_role_key_is_critical(self):
        token = supabase_jwt("service_role")
        found = _named(f'const supabaseServiceKey = "{token}";', "Supabase service_role key")
        self.assertEqual(len(found), 1, [f["name"] for f in _findings(f'k="{token}"')])
        self.assertEqual((found[0]["severity"], found[0]["confidence"]), ("critical", "high"))
        self.assertIs(found[0]["public_client_key"], False)

    def test_an_anon_key_is_a_public_client_key(self):
        token = supabase_jwt("anon")
        found = _named(f'const supabaseAnonKey = "{token}";', "Supabase anon key")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["severity"], "info")
        self.assertIs(found[0]["public_client_key"], True)

    def test_a_bare_jwt_is_judged_by_its_role_too(self):
        found = _named(f'headers.apikey = "{supabase_jwt("service_role")}";', "Supabase service_role key")
        self.assertEqual(len(found), 1)

    def test_one_key_is_one_finding_even_when_two_patterns_match_it(self):
        token = supabase_jwt("anon")
        js = f'createClient(url, supabaseAnonKey = "{token}")'
        names = [f["name"] for f in _findings(js)]
        self.assertEqual(names.count("Supabase anon key"), 1, names)
        self.assertNotIn("JWT Token", names)
        self.assertNotIn("Supabase Key", names)

    def test_another_role_keeps_the_pattern(self):
        names = [f["name"] for f in _findings(f'token = "{supabase_jwt("authenticated")}"')]
        self.assertIn("JWT Token", names)
        self.assertFalse([n for n in names if n.startswith("Supabase ")])

    def test_an_undecodable_payload_keeps_the_pattern(self):
        broken = f"{b64url({'alg': 'HS256'})}.eyJ{'!' * 0}notbase64json.{SIG}"
        names = [f["name"] for f in _findings(f'token = "{broken}"')]
        self.assertIn("JWT Token", names)

    def test_an_oversized_payload_is_not_decoded(self):
        big = jwt({"role": "service_role", "pad": "a" * 5000})
        found = [f for f in _findings(f'token = "{big}"') if f["name"].startswith("Supabase")]
        self.assertEqual(found, [])
        self.assertIsNone(patterns._jwt_role(big))

    def test_the_role_reader_is_defensive(self):
        self.assertEqual(patterns._jwt_role(supabase_jwt("anon")), "anon")
        for token in ("", "abc", "eyJ.eyJ.x", jwt(["role", "anon"]), jwt({"role": 7})):
            with self.subTest(token=token):
                self.assertIsNone(patterns._jwt_role(token))


class TestSupabaseKeyFormats(unittest.TestCase):
    def test_a_secret_key_is_critical(self):
        found = _named('const k = "sb_secret_' + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5" + '";', "Supabase Secret Key")
        self.assertEqual(found[0]["severity"], "critical")

    def test_a_publishable_key_is_a_public_client_key(self):
        found = _named('const k = "sb_publishable_' + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5" + '";',
                       "Supabase Publishable Key")
        self.assertEqual((found[0]["severity"], found[0]["public_client_key"]), ("info", True))

    def test_lookalikes_are_not_keys(self):
        names = [f["name"] for f in _findings('const sb_secretive = "x"; cls("sb_publishable_");')]
        self.assertFalse([n for n in names if n.startswith("Supabase")])


AMZ = ("https://reports-bucket.s3.eu-west-1.amazonaws.com/q3/report.pdf?"
       "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAQ7R2M9X4K1T8B3V6%2F20991231%2F"
       "eu-west-1%2Fs3%2Faws4_request&X-Amz-Date={date}&X-Amz-Expires={expires}"
       "&X-Amz-SignedHeaders=host&X-Amz-Signature=" + "4f9c1a7e5b2d8f40c6e1a9b3d7f2c5e8"
       "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d")
GOOG = ("https://storage.googleapis.com/media-bucket/a.png?X-Goog-Algorithm=GOOG4-RSA-SHA256"
        "&X-Goog-Credential=svc%40example-project.iam.gserviceaccount.com%2F20991231%2Fauto"
        "%2Fstorage%2Fgoog4_request&X-Goog-Date=20991231T093015Z&X-Goog-Expires=600"
        "&X-Goog-SignedHeaders=host&X-Goog-Signature=" + "ab12" * 64)


class TestSignedUrls(unittest.TestCase):
    NAME = "Signed URL in client code"

    def test_a_live_aws_presigned_url_is_medium(self):
        found = _named(f'fetch("{AMZ.format(date="20991231T093015Z", expires="3600")}")', self.NAME)
        self.assertEqual(found[0]["severity"], "medium")

    def test_an_expired_one_is_low(self):
        found = _named(f'fetch("{AMZ.format(date="20200101T093015Z", expires="3600")}")', self.NAME)
        self.assertEqual(found[0]["severity"], "low")

    def test_a_gcs_signed_url_is_medium(self):
        self.assertEqual(_named(f'img.src = "{GOOG}";', self.NAME)[0]["severity"], "medium")

    def test_a_signature_without_a_credential_is_not_one(self):
        url = "https://cdn.example.com/a.js?X-Amz-Signature=" + "4f9c1a7e" * 8
        self.assertEqual(_named(f'load("{url}")', self.NAME), [])

    def test_a_plain_bucket_url_is_not_one(self):
        self.assertEqual(_named('fetch("https://reports-bucket.s3.amazonaws.com/a.pdf")', self.NAME), [])


class TestWriteCapableWebhooks(unittest.TestCase):
    def test_zapier_catch_hook(self):
        js = 'post("https://hooks.zapier.com/hooks/catch/1234567/b3x9q2m/", data)'
        found = _named(js, "Zapier Webhook")
        self.assertEqual(found[0]["severity"], "high")

    def test_zapier_lookalike(self):
        self.assertEqual(_named('a("https://zapier.com/apps/hooks/integrations")', "Zapier Webhook"), [])

    def test_make_hook(self):
        js = 'post("https://hook.eu1.make.com/' + "k3x9q2m7a8b1c4d5e6f7g8h9z0y1x2w3" + '", data)'
        found = _named(js, "Make Webhook")
        self.assertEqual(found[0]["severity"], "high")

    def test_make_lookalike(self):
        self.assertEqual(_named('a("https://www.make.com/en/help/tools/webhooks")', "Make Webhook"), [])


if __name__ == "__main__":
    unittest.main()
