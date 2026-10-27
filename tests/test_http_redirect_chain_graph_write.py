"""The redirect chain reaches the probed Endpoint in the graph.

http_probe stores the final page's status under the first URL, so a host that
answers 302 to a login page read as "200 Login" to ranking and to the AI. The
URL entry now carries `final_url`, `first_status_code`, `redirect_chain_codes`
and `redirected_off_host`; update_graph_from_http_probe must put them on that
URL's Endpoint, never on the thin BaseURL.

Hermetic: a fake driver records every query; no Neo4j.
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

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402

FIELDS = ("final_url", "first_status_code", "redirect_chain_codes", "redirected_off_host")


class _Result:
    def single(self):
        return None

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        return _Result()


class _Driver:
    def __init__(self, queries):
        self.queries = queries

    def session(self):
        return _Session(self.queries)


class _Client(HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = _Driver(self.queries)


def _recon(**chain):
    url = "http://old.example.com"
    entry = {"url": url, "host": "old.example.com", "status_code": 200, **chain}
    return {
        "domain": "example.com",
        "subdomains": ["old.example.com"],
        "metadata": {},
        "http_probe": {"scan_metadata": {}, "by_url": {url: entry},
                       "by_host": {"old.example.com": {"urls": [url], "technologies": [],
                                                       "servers": [], "status_codes": [200]}}},
    }


def _writes(client, merge):
    return [kw["props"] for q, kw in client.queries if merge in q and "props" in kw]


class TestTheChainReachesTheEndpoint(unittest.TestCase):
    def test_the_four_fields_are_written_on_the_endpoint(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(
            final_url="https://idp.example.net/saml/login", first_status_code=302,
            redirect_chain_codes=[302, 200], redirected_off_host=True), "u1", "p1")
        [props] = _writes(client, "MERGE (e:Endpoint")
        self.assertEqual(props["final_url"], "https://idp.example.net/saml/login")
        self.assertEqual(props["first_status_code"], 302)
        self.assertEqual(props["redirect_chain_codes"], [302, 200])
        self.assertIs(props["redirected_off_host"], True)
        self.assertEqual(props["status_code"], 200)

    def test_no_redirect_still_writes_false_not_nothing(self):
        """`SET e += $props`: a missing key would keep the previous scan's True."""
        client = _Client()
        client.update_graph_from_http_probe(_recon(
            final_url="http://old.example.com", first_status_code=200,
            redirect_chain_codes=[200], redirected_off_host=False), "u1", "p1")
        [props] = _writes(client, "MERGE (e:Endpoint")
        self.assertIs(props["redirected_off_host"], False)
        self.assertEqual(props["redirect_chain_codes"], [200])

    def test_nothing_lands_on_the_baseurl(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(
            final_url="https://idp.example.net/", first_status_code=302,
            redirect_chain_codes=[302, 200], redirected_off_host=True), "u1", "p1")
        [base] = _writes(client, "MERGE (u:BaseURL")
        for field in FIELDS + ("status_code", "title", "content_type"):
            self.assertNotIn(field, base)

    def test_an_entry_from_an_older_recon_file_writes_no_chain_keys(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(), "u1", "p1")
        [props] = _writes(client, "MERGE (e:Endpoint")
        for field in FIELDS:
            self.assertNotIn(field, props)


if __name__ == "__main__":
    unittest.main()
