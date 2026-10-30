"""OpenRouter app attribution must point at the live RedAmon site.

OpenRouter credits traffic to the app named in the HTTP-Referer / X-Title
headers and links that URL from its public app pages. The referer used to be
https://redamon.dev, a domain that does not exist, so every RedAmon user on
OpenRouter credited a dead link.

These tests build a real ChatOpenAI via `setup_llm` (no network is touched at
construction time) and read the headers it will send.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.llm_setup import setup_llm  # noqa: E402


class OpenRouterAttributionTests(unittest.TestCase):
    def setUp(self):
        self.llm = setup_llm("openrouter/openai/gpt-4o-mini", openrouter_api_key="test-key")

    def test_referer_is_the_redamon_site(self):
        self.assertEqual(self.llm.default_headers.get("HTTP-Referer"), "https://www.redamon.org")

    def test_title_names_the_app(self):
        self.assertEqual(self.llm.default_headers.get("X-Title"), "RedAmon Agent")

    def test_requests_go_to_openrouter(self):
        self.assertEqual(self.llm.openai_api_base, "https://openrouter.ai/api/v1")


if __name__ == "__main__":
    unittest.main()
