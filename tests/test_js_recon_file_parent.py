"""Where a JS file node hangs, and what the write counts (plans 06.9 and 06.4).

06.9: a js_file node linked only to an existing BaseURL. A file on a host with
none (a host found only through JS, an unprobed port) got no parent, and the
relationship counter went up anyway. It now falls back to the in-scope
Subdomain, never creates a BaseURL for an unprobed host, and counts only links
that were made.

06.4: a Secret or Endpoint found in a source map's own source text carries
``source_url = <map_url>#<source>``; it must hang off its own js_file node and
take the map's origin as its base_url.
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


class FakeResult:
    def __init__(self, record):
        self.record = record

    def single(self):
        return self.record


class FakeSession:
    """Answers a link query by whether its parent node exists."""

    def __init__(self, baseurls=(), subdomains=(), domains=()):
        self.baseurls, self.subdomains, self.domains = set(baseurls), set(subdomains), set(domains)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "HAS_JS_FILE" in query:
            if "BaseURL" in query:
                return FakeResult({"linked": int(kwargs.get("base_url") in self.baseurls)})
            if "Subdomain" in query:
                return FakeResult({"linked": int(kwargs.get("host") in self.subdomains)})
            if "Domain" in query:
                return FakeResult({"linked": int(kwargs.get("dname") in self.domains or not kwargs.get("dname"))})
        if "RETURN created AS created" in query:
            return FakeResult({"created": True})
        if "RETURN count(r) AS linked" in query:
            return FakeResult({"linked": 1})
        return FakeResult({"enriched": 0})


class Client(JsReconMixin):
    def __init__(self, session):
        driver = MagicMock()
        driver.session.return_value = session
        self.driver = driver


def _recon(secret_url, **extra):
    return {
        "domain": "example.com",
        "subdomains": ["app.example.com", "api.example.com"],
        "js_recon": {
            "scan_metadata": {"scan_timestamp": "2026-10-24T00:00:00Z"},
            "secrets": [{"id": "s1", "name": "Generic Token", "matched_text": "x" * 20,
                         "source_url": secret_url, "severity": "low"}],
        },
        **extra,
    }


def _file_queries(session):
    return [(q, k) for q, k in session.calls if "HAS_JS_FILE" in q]


class TestJsFileParent(unittest.TestCase):
    def test_a_file_on_a_probed_host_hangs_off_its_baseurl(self):
        session = FakeSession(baseurls={"https://app.example.com"}, subdomains={"app.example.com"})
        stats = Client(session).update_graph_from_js_recon(
            _recon("https://app.example.com/static/js/main.js"), "u1", "p1")
        [(query, kw)] = _file_queries(session)
        self.assertIn("BaseURL", query)
        self.assertEqual(kw["base_url"], "https://app.example.com")
        # file -> BaseURL, file -> Secret
        self.assertEqual(stats["relationships_created"], 2)

    def test_a_file_on_an_unprobed_host_hangs_off_its_subdomain(self):
        session = FakeSession(baseurls=set(), subdomains={"api.example.com"})
        stats = Client(session).update_graph_from_js_recon(
            _recon("https://api.example.com:8443/bundle.js"), "u1", "p1")
        queries = _file_queries(session)
        self.assertEqual(len(queries), 2)
        sub_query, sub_kw = queries[1]
        self.assertIn("MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})", sub_query)
        self.assertEqual(sub_kw["host"], "api.example.com")
        self.assertEqual(stats["relationships_created"], 2)

    def test_no_baseurl_is_ever_created_for_the_file(self):
        session = FakeSession(subdomains={"api.example.com"})
        Client(session).update_graph_from_js_recon(_recon("https://api.example.com:8443/bundle.js"), "u1", "p1")
        for query, _ in _file_queries(session):
            self.assertNotIn("MERGE (bu:BaseURL", query)
            self.assertNotIn("MERGE (s:Subdomain", query)

    def test_an_out_of_scope_host_gets_no_parent_and_is_not_counted(self):
        session = FakeSession(subdomains={"cdn.vendor-example.org"})
        stats = Client(session).update_graph_from_js_recon(
            _recon("https://cdn.vendor-example.org/lib.js"), "u1", "p1")
        self.assertFalse(any("Subdomain" in q for q, _ in _file_queries(session)))
        # Only the file -> Secret link.
        self.assertEqual(stats["relationships_created"], 1)

    def test_a_missing_subdomain_node_is_not_counted(self):
        session = FakeSession()
        stats = Client(session).update_graph_from_js_recon(
            _recon("https://api.example.com:8443/bundle.js"), "u1", "p1")
        self.assertEqual(stats["relationships_created"], 1)

    def test_an_upload_is_counted_only_when_its_domain_exists(self):
        stats = Client(FakeSession(domains=set())).update_graph_from_js_recon(
            _recon("upload://bundle.js"), "u1", "p1")
        self.assertEqual(stats["relationships_created"], 1)
        stats = Client(FakeSession(domains={"example.com"})).update_graph_from_js_recon(
            _recon("upload://bundle.js"), "u1", "p1")
        self.assertEqual(stats["relationships_created"], 2)

    def test_every_link_query_is_tenant_scoped(self):
        session = FakeSession(subdomains={"api.example.com"})
        Client(session).update_graph_from_js_recon(_recon("https://api.example.com:8443/bundle.js"), "u1", "p1")
        for query, kw in _file_queries(session):
            self.assertIn("user_id: $uid", query)
            self.assertIn("project_id: $pid", query)
            self.assertEqual((kw["uid"], kw["pid"]), ("u1", "p1"))


MAP = "https://app.example.com/static/js/main.4f3a.js.map"


class TestSourceMapPseudoFiles(unittest.TestCase):
    def _secret_write(self, session):
        [(query, kw)] = [(q, k) for q, k in session.calls if "MERGE (s:Secret" in q]
        return kw

    def test_a_secret_from_a_map_source_takes_the_maps_origin(self):
        session = FakeSession(baseurls={"https://app.example.com"})
        Client(session).update_graph_from_js_recon(_recon(f"{MAP}#src/config.ts"), "u1", "p1")
        kw = self._secret_write(session)
        self.assertEqual(kw["source_url"], f"{MAP}#src/config.ts")
        self.assertEqual(kw["base_url"], "https://app.example.com")

    def test_the_pseudo_file_node_hangs_off_the_maps_baseurl_and_names_the_source(self):
        session = FakeSession(baseurls={"https://app.example.com"})
        Client(session).update_graph_from_js_recon(_recon(f"{MAP}#src/config.ts"), "u1", "p1")
        [file_props] = [k["props"] for q, k in session.calls
                        if "MERGE (jf:JsReconFinding" in q and k["props"]["finding_type"] == "js_file"]
        self.assertEqual(file_props["source_url"], f"{MAP}#src/config.ts")
        self.assertEqual(file_props["title"], "main.4f3a.js.map#src/config.ts")
        [(_, kw)] = _file_queries(session)
        self.assertEqual(kw["base_url"], "https://app.example.com")

    def test_the_secret_links_to_the_pseudo_file_node(self):
        session = FakeSession(baseurls={"https://app.example.com"})
        Client(session).update_graph_from_js_recon(_recon(f"{MAP}#src/config.ts"), "u1", "p1")
        [file_props] = [k["props"] for q, k in session.calls
                        if "MERGE (jf:JsReconFinding" in q and k["props"]["finding_type"] == "js_file"]
        [(_, link)] = [(q, k) for q, k in session.calls if "HAS_SECRET" in q]
        self.assertEqual(link["fid"], file_props["id"])


if __name__ == "__main__":
    unittest.main()
