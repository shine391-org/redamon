"""tlsx writer: a CDN named by the certificate issuer reaches IP.is_cdn.

tls_scan attributes a CDN from the certificate issuer on port_scan.by_ip, but in
a full run the port graph write has already happened by then, so the tag never
reached the graph. The tlsx writer now carries it: for every IP tlsx attributed
(payload key ``cdn_by_ip``) it sets is_cdn, fills a blank cdn_name and stamps
cdn_source 'tlsx' unless another tool had already tagged the IP.

Driven against a session double that records every statement; no Neo4j.
Fixture IPs are RFC 5737 documentation addresses.

Run: python -m pytest tests/test_tlsx_writer_cdn.py
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.tlsx_mixin import TlsxMixin  # noqa: E402

EDGE_IP = "192.0.2.10"
PLAIN_IP = "192.0.2.11"


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        result = MagicMock()
        result.single.return_value = {"matched": 1}
        return result


class _Writer(TlsxMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def cdn_writes(self):
        return [(q, p) for q, p in self.session.calls if "cdn_source" in q]


def _entry(ip, issuer):
    return {"scanned_ip": ip, "port": 993, "probe_status": True,
            "fingerprint_sha256": (ip[-1] * 64), "subject_cn": "mail.example.com",
            "issuer_dn": issuer, "san": []}


def _recon(cdn_by_ip):
    return {
        "domain": "example.com", "domains": ["example.com"],
        "tlsx": {
            "by_target": {
                f"{EDGE_IP}:993": _entry(EDGE_IP, "CN=Cloudflare Inc ECC CA-3"),
                f"{PLAIN_IP}:993": _entry(PLAIN_IP, "CN=R11, O=Let's Encrypt"),
            },
            "cdn_by_ip": cdn_by_ip,
        },
    }


class TestCdnTagReachesTheGraph(unittest.TestCase):
    def setUp(self):
        self.w = _Writer()
        self.stats = self.w.update_graph_from_tlsx(_recon({EDGE_IP: "cloudflare"}), "u1", "p1")

    def test_the_attributed_ip_is_tagged(self):
        writes = self.w.cdn_writes()
        self.assertEqual(len(writes), 1)
        query, params = writes[0]
        self.assertEqual(params["ip"], EDGE_IP)
        self.assertEqual(params["name"], "cloudflare")
        self.assertIn("i.is_cdn = true", query)
        self.assertIn("i.cdn_name = coalesce(i.cdn_name, $name)", query)
        self.assertIn("'tlsx'", query)
        self.assertEqual(self.stats["ips_cdn_tagged"], 1)

    def test_an_ip_tlsx_did_not_attribute_is_not_touched(self):
        self.assertFalse(any(p.get("ip") == PLAIN_IP for _q, p in self.w.cdn_writes()))

    def test_the_write_matches_a_tenant_scoped_ip_and_never_creates_one(self):
        query, params = self.w.cdn_writes()[0]
        self.assertIn("MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})", query)
        self.assertNotIn("MERGE (i:IP", query)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_it_never_writes_is_cdn_false(self):
        query, _ = self.w.cdn_writes()[0]
        self.assertNotIn("is_cdn = false", query)
        self.assertNotIn("$is_cdn", query)

    def test_another_tools_attribution_keeps_its_source(self):
        # naabu tagged the IP first: tlsx agrees, it does not claim the tag.
        query, _ = self.w.cdn_writes()[0]
        self.assertIn("coalesce(i.is_cdn, false)", query)
        self.assertIn("THEN i.cdn_source ELSE 'tlsx'", query)


class TestNothingAttributed(unittest.TestCase):
    def test_no_cdn_by_ip_writes_no_cdn_statement(self):
        for payload in ({}, None):
            with self.subTest(payload=payload):
                w = _Writer()
                stats = w.update_graph_from_tlsx(_recon(payload), "u1", "p1")
                self.assertEqual(w.cdn_writes(), [])
                self.assertEqual(stats["ips_cdn_tagged"], 0)

    def test_blank_entries_are_skipped(self):
        w = _Writer()
        w.update_graph_from_tlsx(_recon({"": "cloudflare", EDGE_IP: ""}), "u1", "p1")
        self.assertEqual(w.cdn_writes(), [])


if __name__ == "__main__":
    unittest.main()
