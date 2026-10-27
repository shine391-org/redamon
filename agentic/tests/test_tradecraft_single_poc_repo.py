"""Single-PoC GitHub repos are readable through tradecraft_lookup.

Regression for the "PoC not found" loop of the "agent stuck" incident: a repo
built around one PoC (two CVE ids repeated across its README) was auto-typed
cve-poc-db. That type only probes archive paths ({year}/{CVE}.md), which such
a repo does not have, so every lookup answered "PoC not found" and the agent
cycled through other slugs and spellings. A GitHub rate limit also read as
"not found".

Run: ./agentic/run_tests.sh tests/test_tradecraft_single_poc_repo.py
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import project_settings as _ps  # noqa: E402


def setUpModule():
    if not hasattr(_ps, "DEFAULT_AGENT_SETTINGS"):
        raise unittest.SkipTest("project_settings stubbed by an earlier test (import-time pollution)")


from orchestrator_helpers import tradecraft_lookup as tl  # noqa: E402
from orchestrator_helpers.tradecraft_lookup import (  # noqa: E402
    FetchResult,
    TradecraftLookupManager,
    detect_type,
    verify_resource,
)

CVE_A, CVE_B = "CVE-2026-109618", "CVE-2026-109619"
POC_README = (
    f"# php2shell PoC\n\nProof of concept for {CVE_A} and {CVE_B}.\n\n"
    + "\n".join(f"## Chain {c}: {CVE_A} / {CVE_B} exploitation step" for c in "ABCDE") * 6
    + "\n```python\nprint('pwn')\n```\n"
)


class _Resp:
    def __init__(self, status, text="", json=None, headers=None):
        self.status_code = status
        self.text = text
        self._json = json
        self.headers = headers or {}

    def json(self):
        return self._json


class _FakeGitHub:
    """Routes request URLs to canned responses (first regex match wins)."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def client_class(self):
        gh = self

        class _Client:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                pass

            async def get(self, url, **kw):
                gh.calls.append(url)
                for pattern, resp in gh.routes:
                    if re.search(pattern, url):
                        return resp
                return _Resp(404)

        return _Client


class _StubLLM:
    async def ainvoke(self, *a, **kw):
        class R:
            content = "summary"
        return R()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class DetectType(unittest.TestCase):
    def test_single_poc_readme_is_not_an_archive(self):
        # Two ids repeated well over 20 times: the old count rule said cve-poc-db.
        self.assertGreater(POC_README.count("CVE-"), 20)
        self.assertEqual(detect_type("https://github.com/example-owner/php2shell-poc", POC_README),
                         "github-repo")

    def test_repo_named_for_one_cve_is_not_an_archive(self):
        self.assertEqual(detect_type("https://github.com/example-owner/CVE-2026-109618-poc", ""),
                         "github-repo")

    def test_archives_are_still_detected(self):
        self.assertEqual(detect_type("https://github.com/trickest/cve", ""), "cve-poc-db")
        self.assertEqual(detect_type("https://github.com/example-owner/cvelist", ""), "cve-poc-db")
        many = "\n".join(f"CVE-2024-{i:05d}" for i in range(25))
        self.assertEqual(detect_type("https://github.com/example-owner/poc-collection", many),
                         "cve-poc-db")

    def test_case_insensitive_ids_count_once(self):
        body = " ".join([f"cve-2024-{i:05d} CVE-2024-{i:05d}" for i in range(15)])
        self.assertEqual(detect_type("https://github.com/example-owner/notes", body), "github-repo")


class VerifyRetypesWhenThereIsNoArchiveLayout(unittest.TestCase):
    def _verify(self, url, routes):
        gh = _FakeGitHub(routes)

        async def fake_smart(u, **kw):
            return FetchResult(text="readme " * 200, content_type="text/html", status=200,
                               tier=1, raw_bytes=b"<html><body>repo page</body></html>" * 30)

        with mock.patch.object(tl, "smart_fetch", fake_smart), \
                mock.patch.object(tl, "validate_url", lambda u: (True, "")), \
                mock.patch.object(tl.httpx, "AsyncClient", gh.client_class()):
            return run(verify_resource(url, llm=_StubLLM(), mcp_manager=None)), gh

    def test_cve_named_repo_without_year_folders_becomes_github_repo(self):
        meta = _Resp(200, json={"default_branch": "main"})
        routes = [
            (r"/repos/example-owner/cve-poc-collection/contents$",
             _Resp(200, json=[{"type": "file", "name": "README.md"},
                              {"type": "dir", "name": "exploits"}])),
            (r"/git/trees/main", _Resp(200, json={"tree": [
                {"type": "blob", "path": "README.md"},
                {"type": "blob", "path": "exploits/chain_a.md"}]})),
            (r"/repos/example-owner/cve-poc-collection$", meta),
        ]
        result, _ = self._verify("https://github.com/example-owner/cve-poc-collection", routes)
        self.assertEqual(result["resource_type"], "github-repo")
        paths = [e["path"] for e in result["sitemap"]["tree"]]
        self.assertIn("README.md", paths)
        self.assertIn("exploits/chain_a.md", paths)

    def test_real_archive_with_year_folders_stays_cve_poc_db(self):
        routes = [
            (r"/repos/trickest/cve/contents$",
             _Resp(200, json=[{"type": "dir", "name": "2025"}, {"type": "dir", "name": "2026"}])),
            (r"/repos/trickest/cve$", _Resp(200, json={"default_branch": "main"})),
        ]
        result, _ = self._verify("https://github.com/trickest/cve", routes)
        self.assertEqual(result["resource_type"], "cve-poc-db")
        self.assertEqual(result["sitemap"], {"owner": "trickest", "repo": "cve", "branch": "main"})

    def test_listing_error_keeps_the_detected_type(self):
        routes = [
            (r"/contents$", _Resp(403, headers={"x-ratelimit-remaining": "0"})),
            (r"/repos/trickest/cve$", _Resp(200, json={"default_branch": "main"})),
        ]
        result, _ = self._verify("https://github.com/trickest/cve", routes)
        self.assertEqual(result["resource_type"], "cve-poc-db")


class LookupOnAnAlreadyMistypedResource(unittest.TestCase):
    """The resource your colleague added is stored as cve-poc-db with 0 entries;
    it must work without being re-verified."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tc_single_poc_")
        self.mgr = TradecraftLookupManager(llm=_StubLLM(), mcp_manager=None, cache_root=self.tmp)
        self.mgr.set_resources([{
            "id": "r1", "slug": "php2shell-poc", "name": "php2shell-poc",
            "url": "https://github.com/example-owner/php2shell-poc", "enabled": True,
            "resourceType": "cve-poc-db", "summary": "PoC for two PHP RCEs",
            "sitemap": {"owner": "example-owner", "repo": "php2shell-poc", "branch": "main"},
            "cacheTtlSec": 0,
        }])
        self.tool = self.mgr.get_tool()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _lookup(self, routes, cve=CVE_A):
        gh = _FakeGitHub(routes)
        with mock.patch.object(tl.httpx, "AsyncClient", gh.client_class()):
            out = run(self.tool.ainvoke({"resource_id": "php2shell-poc",
                                         "query": "exploitation chains", "cve_id": cve}))
        return out, gh

    def test_archive_miss_falls_back_to_the_readme_that_names_the_cve(self):
        out, gh = self._lookup([(r"/readme$", _Resp(200, text=POC_README))])
        self.assertNotIn("PoC not found", out)
        self.assertIn("[BEGIN UNTRUSTED TRADECRAFT RESULT]", out)
        self.assertIn("Chain E", out)
        self.assertIn("repository README", out)
        self.assertIn("https://github.com/example-owner/php2shell-poc#readme", out)
        self.assertTrue(any(c.endswith("/readme") for c in gh.calls))

    def test_second_lookup_is_served_from_cache(self):
        self._lookup([(r"/readme$", _Resp(200, text=POC_README))])
        out, gh = self._lookup([])
        self.assertIn("Chain E", out)
        self.assertEqual(gh.calls, [])

    def test_readme_that_does_not_name_the_cve_is_still_not_found(self):
        out, _ = self._lookup([(r"/readme$", _Resp(200, text="# unrelated tool"))])
        self.assertIn("PoC not found for CVE-2026-109618", out)
        self.assertIn("README does not mention it", out)

    def test_rate_limit_is_an_error_not_a_miss(self):
        out, _ = self._lookup([(r"api\.github\.com",
                                _Resp(403, headers={"x-ratelimit-remaining": "0"}))])
        self.assertTrue(out.startswith("Error: could not look up CVE-2026-109618"), out)
        self.assertIn("HTTP 403", out)
        self.assertIn("rate_remaining=0", out)
        self.assertIn("NOT a 'PoC not found' answer", out)

    def test_archive_entry_still_wins_when_present(self):
        out, gh = self._lookup([(r"/contents/2026/CVE-2026-109618\.md$",
                                 _Resp(200, text="# archived PoC body"))])
        self.assertIn("archived PoC body", out)
        self.assertFalse(any(c.endswith("/readme") for c in gh.calls))

    def test_registry_text_tells_the_agent_not_to_loop(self):
        desc = self.mgr.build_registry_entry()["description"]
        self.assertIn('"PoC not found" is final for that slug and CVE', desc)


if __name__ == "__main__":
    unittest.main()
