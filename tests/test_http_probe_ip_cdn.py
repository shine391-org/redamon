"""httpx's CDN and ASN reach the IP node (plan 11.2).

update_graph_from_http_probe wrote `cdn`, `is_cdn` and `asn` on the Endpoint
only, so a CDN or ASN that only httpx saw never reached the IP the IP
attribution step and the board read. The writer now also tags the resolved IP:
is_cdn is set true (never true -> false), a blank cdn_name and asn are filled,
and cdn_source is 'httpx' when httpx is the first tool to tag the address.

httpx's -asn reports an object ({"as_number": "AS13335", ...}); Neo4j rejects a
map property, which dropped the whole Endpoint write, so both nodes store the
"AS<n>" string Netlas and FOFA already use.

Hermetic: a fake driver records every query; no Neo4j. Addresses are RFC 5737.
"""

import os
import sys
import unittest
from collections.abc import Mapping
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402

EDGE_IP = "192.0.2.20"
PLAIN_IP = "192.0.2.21"


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
        self.queries.append((" ".join(query.split()), kwargs))
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

    def ip_tags(self):
        return [(q, kw) for q, kw in self.queries
                if q.startswith("MATCH (i:IP {address: $ip") and "cdn_source" in q]


def _recon(*entries):
    by_url = {e["url"]: e for e in entries}
    return {
        "domain": "example.com", "subdomains": [], "metadata": {},
        "http_probe": {"scan_metadata": {}, "by_url": by_url, "by_host": {}},
    }


def _entry(url, ip, **extra):
    return {"url": url, "host": url.split("//")[1], "status_code": 200, "ip": ip, **extra}


class TestTheResolvedIpIsTagged(unittest.TestCase):
    def setUp(self):
        self.client = _Client()
        self.client.update_graph_from_http_probe(_recon(
            _entry("https://www.example.com", EDGE_IP, is_cdn=True, cdn="cloudflare",
                   asn={"as_number": "AS13335", "as_name": "CLOUDFLARENET"}),
            _entry("https://api.example.com", PLAIN_IP, is_cdn=False, cdn=None, asn=None),
        ), "u1", "p1")

    def test_one_tag_write_for_the_cdn_ip(self):
        tags = self.client.ip_tags()
        self.assertEqual([kw["ip"] for _q, kw in tags], [EDGE_IP])
        _q, kw = tags[0]
        self.assertIs(kw["is_cdn"], True)
        self.assertEqual(kw["cdn_name"], "cloudflare")
        self.assertEqual(kw["asn"], "AS13335")

    def test_the_tag_matches_a_tenant_scoped_ip_and_never_creates_one(self):
        query, kw = self.client.ip_tags()[0]
        self.assertIn("MATCH (i:IP {address: $ip, user_id: $user_id, project_id: $project_id})", query)
        self.assertNotIn("MERGE (i:IP", query)
        self.assertEqual((kw["user_id"], kw["project_id"]), ("u1", "p1"))

    def test_is_cdn_is_never_set_false_and_first_values_are_kept(self):
        query, _kw = self.client.ip_tags()[0]
        self.assertIn("i.is_cdn = CASE WHEN $is_cdn THEN true ELSE i.is_cdn END", query)
        self.assertIn("i.cdn_name = coalesce(i.cdn_name, $cdn_name)", query)
        self.assertIn("i.asn = coalesce(i.asn, $asn)", query)

    def test_httpx_claims_the_source_only_for_an_untagged_ip(self):
        query, _kw = self.client.ip_tags()[0]
        self.assertIn("coalesce(i.is_cdn, false) AS already_tagged", query)
        self.assertIn("WHEN $is_cdn AND NOT already_tagged THEN 'httpx'", query)

    def test_the_endpoint_stores_the_asn_as_a_string(self):
        endpoint_props = [kw["props"] for q, kw in self.client.queries
                          if q.startswith("MERGE (e:Endpoint") and "props" in kw]
        self.assertEqual(len(endpoint_props), 2)
        for props in endpoint_props:
            self.assertFalse([k for k, v in props.items() if isinstance(v, Mapping)],
                             "a map property makes Neo4j reject the whole Endpoint")
        self.assertEqual(endpoint_props[0]["asn"], "AS13335")


class TestAsnOnlyAndNothing(unittest.TestCase):
    def test_an_asn_alone_fills_the_asn_and_claims_no_cdn(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(
            _entry("https://www.example.com", PLAIN_IP, is_cdn=False, asn="AS64500 Example Net")),
            "u1", "p1")
        tags = client.ip_tags()
        self.assertEqual(len(tags), 1)
        self.assertIs(tags[0][1]["is_cdn"], False)
        self.assertIsNone(tags[0][1]["cdn_name"])
        self.assertEqual(tags[0][1]["asn"], "AS64500")

    def test_no_cdn_and_no_asn_writes_no_tag(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(
            _entry("https://www.example.com", PLAIN_IP, is_cdn=False, cdn=None, asn=None)),
            "u1", "p1")
        self.assertEqual(client.ip_tags(), [])

    def test_no_resolved_ip_writes_no_tag(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(
            _entry("https://www.example.com", None, is_cdn=True, cdn="cloudflare")), "u1", "p1")
        self.assertEqual(client.ip_tags(), [])


if __name__ == "__main__":
    unittest.main()
