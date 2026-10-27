"""IP-mode IP nodes: the version spelling and the whois blanks.

update_graph_from_ip_recon wrote IP.version as 'v4' / 'v6' while every other
writer writes 'ipv4' / 'ipv6', so the report and Insights showed IPv4 0 /
IPv6 0 for an IP-mode project. It also stored a whois answer with no org or
country as `organization: ""` / `country: ""`, which every `IS NOT NULL` or
`coalesce(...)` reader counts as present.

The Neo4j session is a fake that records each query and its parameters.
Fixture addresses are RFC 5737 / RFC 3849 documentation ranges.

Run: ./redamon.sh test unit (root-agent section), or one file in the agent image.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402

V4, V4_BARE, V6 = "192.0.2.10", "198.51.100.7", "2001:db8::10"


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return MagicMock()


class _Writer(DomainMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def ip_props(self):
        return {p["addr"]: p["props"] for q, p in self.session.calls
                if "MERGE (i:IP" in q and "props" in p}


def _recon(whois):
    subs = {
        "a.ip-targets.p1": {"ips": {"ipv4": [V4]}, "is_mock": True},
        "b.ip-targets.p1": {"ips": {"ipv4": [V4_BARE]}, "is_mock": True},
        "c.ip-targets.p1": {"ips": {"ipv6": [V6]}, "is_mock": True},
    }
    return {
        "metadata": {"root_domain": "ip-targets.p1"},
        "subdomains": list(subs),
        "dns": {"subdomains": subs},
        "whois": {"ip_whois": whois},
    }


class TestIpReconIpProps(unittest.TestCase):
    def setUp(self):
        self.writer = _Writer()
        self.writer.update_graph_from_ip_recon(_recon({
            V4: {"org": "Example Org", "country": "IT"},
            V4_BARE: {"org": "", "country": ""},
            V6: {"org": "Example Org v6"},
        }), "u1", "p1")
        self.props = self.writer.ip_props()

    def test_the_version_uses_the_spelling_every_reader_counts(self):
        self.assertEqual(self.props[V4]["version"], "ipv4")
        self.assertEqual(self.props[V4_BARE]["version"], "ipv4")
        self.assertEqual(self.props[V6]["version"], "ipv6")

    def test_a_whois_answer_is_stored(self):
        self.assertEqual(self.props[V4]["organization"], "Example Org")
        self.assertEqual(self.props[V4]["country"], "IT")

    def test_a_blank_whois_field_is_never_stored_as_an_empty_string(self):
        self.assertNotIn("organization", self.props[V4_BARE])
        self.assertNotIn("country", self.props[V4_BARE])
        self.assertEqual(self.props[V6]["organization"], "Example Org v6")
        self.assertNotIn("country", self.props[V6])

    def test_no_property_is_an_empty_string(self):
        for addr, props in self.props.items():
            with self.subTest(addr=addr):
                self.assertNotIn("", props.values())

    def test_the_merge_stays_tenant_scoped(self):
        merges = [(q, p) for q, p in self.writer.session.calls if "MERGE (i:IP" in q]
        self.assertEqual(len(merges), 3)
        for query, params in merges:
            self.assertIn("user_id: $uid, project_id: $pid", query)
            self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))


if __name__ == "__main__":
    unittest.main()
