"""What the JS Recon writer stores on a Secret node (plan 05).

The detector computes a masked context and flags keys that are public by
design; the writer must put both on the node, with the context capped.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402


class _Result:
    def single(self):
        return {"linked": 0, "created": True, "enriched": 0}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return _Result()


class _Client(JsReconMixin):
    def __init__(self):
        self.session_obj = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session_obj


def _secret(**overrides) -> dict:
    secret = {
        "id": "abc123", "name": "AWS Access Key ID", "matched_text": "AKIAQ7R2M9X4K1T8B3V6",
        "redacted_value": "AKIAQ7...B3V6", "severity": "critical", "confidence": "high",
        "category": "cloud", "line_number": 1,
        "source_url": "https://app.example.com/static/main.js",
        "validation": {"status": "unvalidated"},
    }
    secret.update(overrides)
    return secret


def _secret_write(secret: dict) -> tuple:
    client = _Client()
    client.update_graph_from_js_recon({
        "domain": "example.com",
        "js_recon": {"scan_metadata": {"scan_timestamp": "2026-10-24T00:00:00Z"},
                     "secrets": [secret]},
    }, "u1", "p1")
    for query, kwargs in client.session_obj.calls:
        if "MERGE (s:Secret" in query:
            return query, kwargs
    raise AssertionError("no Secret write")


class TestSecretContext(unittest.TestCase):
    def test_the_context_is_written(self):
        query, kwargs = _secret_write(_secret(context="const k = 'AKIAQ7...B3V6';"))
        self.assertIn("s.context = $context", query)
        self.assertEqual(kwargs["context"], "const k = 'AKIAQ7...B3V6';")

    def test_the_context_is_capped_at_400_characters(self):
        _, kwargs = _secret_write(_secret(context="x" * 1000))
        self.assertEqual(len(kwargs["context"]), 400)

    def test_a_missing_context_is_stored_empty(self):
        _, kwargs = _secret_write(_secret())
        self.assertEqual(kwargs["context"], "")


class TestPublicClientKeyFlag(unittest.TestCase):
    def test_a_public_key_is_written_at_info_with_the_flag(self):
        query, kwargs = _secret_write(_secret(
            name="GCP API Key", severity="info", public_client_key=True,
            matched_text="AIzaSy8Kq2Lm7Zx4Wp9Rt1Vb6Nc3Hd5Jf0Gs2Ue"))
        self.assertIn("s.public_client_key = $public_client_key", query)
        self.assertIs(kwargs["public_client_key"], True)
        self.assertEqual(kwargs["severity"], "info")

    def test_any_other_secret_is_written_false(self):
        _, kwargs = _secret_write(_secret())
        self.assertIs(kwargs["public_client_key"], False)


if __name__ == "__main__":
    unittest.main()
