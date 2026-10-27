"""The IP attribution writer puts each IP's tag on its graph node (plan 11.3).

ownership, ownership_reasons, current_dns_names and default_cert_names land on
the tenant-scoped IP, which is matched and never created. A shared edge also
gets the CDN tag: is_cdn true (never cleared), a blank cdn_name filled, and
cdn_source 'ip_attribution' only when no scanner tagged the address first.
The writer never touches updated_at: a tag is not a sighting.

Driven against a session double that records every statement; no Neo4j.
Addresses are RFC 5737.
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

from graph_db.mixins.recon.ip_attribution_mixin import IpAttributionMixin  # noqa: E402

EDGE = "192.0.2.30"
OWN = "192.0.2.31"


class _Session:
    def __init__(self, matched=1, fail_on=None):
        self.calls = []
        self.matched = matched
        self.fail_on = fail_on

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        if self.fail_on and params.get("ip") == self.fail_on:
            raise RuntimeError("write refused")
        self.calls.append((" ".join(query.split()), params))
        result = MagicMock()
        result.single.return_value = {"matched": self.matched}
        return result


class _Writer(IpAttributionMixin):
    def __init__(self, **session):
        self.session = _Session(**session)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _recon(by_ip):
    return {"domain": "example.com", "ip_attribution": {"by_ip": by_ip}}


EDGE_ENTRY = {
    "ownership": "shared_edge", "cdn_name": "cloudflare",
    "ownership_reasons": ["default certificate covers no target domain",
                          "in a published CDN edge range"],
    "current_dns_names": 2, "default_cert_names": ["sni.cloudflaressl.com"],
}
OWN_ENTRY = {
    "ownership": "dedicated",
    "ownership_reasons": ["default certificate covers example.com", "no CDN or edge signal"],
    "current_dns_names": 1,
}


class TestTheTagReachesTheIp(unittest.TestCase):
    def setUp(self):
        self.w = _Writer()
        self.stats = self.w.update_graph_from_ip_attribution(
            _recon({EDGE: EDGE_ENTRY, OWN: OWN_ENTRY}), "u1", "p1")
        self.by_ip = {p["ip"]: (q, p) for q, p in self.w.session.calls}

    def test_one_write_per_ip_with_its_properties(self):
        self.assertEqual(set(self.by_ip), {EDGE, OWN})
        _q, params = self.by_ip[OWN]
        self.assertEqual(params["props"], {
            "ownership": "dedicated",
            "ownership_reasons": ["default certificate covers example.com", "no CDN or edge signal"],
            "current_dns_names": 1,
        })
        self.assertEqual(self.by_ip[EDGE][1]["props"]["default_cert_names"], ["sni.cloudflaressl.com"])
        self.assertEqual(self.stats["ips_tagged"], 2)

    def test_the_write_matches_a_tenant_scoped_ip_and_never_creates_one(self):
        for query, params in self.by_ip.values():
            self.assertIn("MATCH (i:IP {address: $ip, user_id: $uid, project_id: $pid})", query)
            self.assertNotIn("MERGE", query)
            self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_a_shared_edge_gets_the_cdn_tag_without_clearing_anyones(self):
        query, params = self.by_ip[EDGE]
        self.assertEqual(params["edge_cdn"], "cloudflare")
        self.assertIn("i.is_cdn = CASE WHEN $edge_cdn IS NOT NULL THEN true ELSE i.is_cdn END", query)
        self.assertIn("coalesce(i.cdn_name, $edge_cdn)", query)
        self.assertIn("THEN 'ip_attribution' ELSE i.cdn_source END", query)
        self.assertIn("coalesce(i.is_cdn, false) AS already_tagged", query)

    def test_a_dedicated_ip_gets_no_cdn_tag(self):
        self.assertIsNone(self.by_ip[OWN][1]["edge_cdn"])

    def test_it_never_writes_updated_at(self):
        for query, _p in self.by_ip.values():
            self.assertNotIn("updated_at", query)

    def test_props_carry_no_map_and_no_cdn_name(self):
        for _q, params in self.by_ip.values():
            for value in params["props"].values():
                self.assertNotIsInstance(value, dict)
            self.assertNotIn("cdn_name", params["props"])


class TestEdgeCases(unittest.TestCase):
    def test_no_payload_writes_nothing(self):
        for recon in ({}, {"ip_attribution": None}, _recon({}), _recon(None)):
            with self.subTest(recon=recon):
                w = _Writer()
                stats = w.update_graph_from_ip_attribution(recon, "u1", "p1")
                self.assertEqual(w.session.calls, [])
                self.assertEqual(stats["ips_tagged"], 0)

    def test_a_malformed_entry_is_skipped(self):
        w = _Writer()
        w.update_graph_from_ip_attribution(
            _recon({"": OWN_ENTRY, EDGE: "junk", OWN: {"ownership": "not ours"}}), "u1", "p1")
        self.assertEqual(w.session.calls, [])

    def test_an_ip_not_in_the_graph_counts_nothing(self):
        w = _Writer(matched=0)
        stats = w.update_graph_from_ip_attribution(_recon({OWN: OWN_ENTRY}), "u1", "p1")
        self.assertEqual(stats["ips_tagged"], 0)

    def test_a_failed_write_costs_that_ip_only(self):
        w = _Writer(fail_on=EDGE)
        stats = w.update_graph_from_ip_attribution(_recon({EDGE: EDGE_ENTRY, OWN: OWN_ENTRY}), "u1", "p1")
        self.assertEqual(stats["ips_tagged"], 1)
        self.assertEqual(len(stats["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
