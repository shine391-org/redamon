"""The zone a wildcard check ran on carries its answer (plan 08.3).

is_wildcard_zone and wildcard_ips land on the node for that zone: the org
Domain for a registrable domain, the Subdomain of that name for anything
deeper (a scan root below its org, or a parent many names sat under). Only
MATCH and SET: the stamp never creates a node, and never a Domain.
"""
import unittest


class _Result:
    def __init__(self, row=None):
        self._row = row if row is not None else {"n": 1, "matched": 1, "linked": 0,
                                                 "exists": False, "seeded": 1}

    def single(self):
        return self._row

    def __iter__(self):
        return iter([])

    def data(self):
        return []

    def consume(self):
        return None


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result()

    def execute_write(self, work):
        return work(self)


class _Driver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _Session(self.calls)


def _client(*mixins):
    cls = type("Client", tuple(mixins), {})
    c = cls.__new__(cls)
    c.driver = _Driver()
    return c


def _group(root, org, include_root=False):
    return {"scan_root": root, "org_domain": org, "mode": "enumerate",
            "include_root": include_root, "exact_hosts": []}


ZONES = {
    "example.com": {"is_wildcard": True, "ips": ["203.0.113.10"]},
    "api.example.com": {"is_wildcard": False, "ips": []},
}


def _stamps(calls):
    return [(q, p) for q, p in calls if "is_wildcard_zone" in q]


class TestStampWriter(unittest.TestCase):
    def _stamp(self, recon):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        c = _client(DomainMixin)
        n = c.update_graph_wildcard_zones(recon, "u1", "p1")
        return n, c.driver.calls

    def test_the_org_zone_is_its_domain_and_a_deeper_zone_its_subdomain(self):
        n, calls = self._stamp({"domain": "api.example.com", "wildcard_zones": ZONES,
                                "scope_groups": [_group("api.example.com", "example.com", True)]})
        stamps = _stamps(calls)
        self.assertEqual(n, 2)
        by_zone = {p["zone"]: (q, p) for q, p in stamps}
        domain_q, domain_p = by_zone["example.com"]
        self.assertIn("MATCH (d:Domain {name: $zone, user_id: $user_id, project_id: $project_id})", domain_q)
        self.assertEqual((domain_p["is_wildcard"], domain_p["ips"]), (True, ["203.0.113.10"]))
        sub_q, sub_p = by_zone["api.example.com"]
        self.assertIn("MATCH (s:Subdomain {name: $zone, user_id: $user_id, project_id: $project_id})", sub_q)
        self.assertEqual((sub_p["is_wildcard"], sub_p["ips"]), (False, []))
        for q, p in stamps:
            self.assertNotIn("MERGE", q)
            self.assertNotIn("CREATE", q)
            self.assertEqual((p["user_id"], p["project_id"]), ("u1", "p1"))

    def test_without_scope_groups_the_scan_root_is_its_own_org(self):
        _, calls = self._stamp({"domain": "example.com",
                                "wildcard_zones": {"example.com": ZONES["example.com"]}})
        (q, p), = _stamps(calls)
        self.assertIn("(d:Domain", q)

    def test_nothing_to_stamp_runs_no_query(self):
        for recon in ({"domain": "example.com"}, {"domain": "example.com", "wildcard_zones": {}},
                      {"domain": "example.com", "wildcard_zones": "junk"}):
            n, calls = self._stamp(recon)
            self.assertEqual((n, calls), (0, []))

    def test_a_malformed_entry_is_skipped_and_ips_are_strings(self):
        zones = {"example.com": {"is_wildcard": True, "ips": ["203.0.113.10", 7, None]},
                 "": {"is_wildcard": True, "ips": []},
                 "bad.example.com": "not a dict"}
        _, calls = self._stamp({"domain": "example.com", "wildcard_zones": zones})
        (q, p), = _stamps(calls)
        self.assertEqual(p["ips"], ["203.0.113.10"])


class TestDiscoveryWritersStamp(unittest.TestCase):
    def test_the_domain_discovery_writer_stamps_its_zones(self):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        c = _client(DomainMixin)
        c.update_graph_from_domain_discovery({
            "domain": "example.com", "metadata": {"root_domain": "example.com"},
            "whois": {}, "subdomains": [], "dns": {"domain": {}, "subdomains": {}},
            "wildcard_zones": {"example.com": ZONES["example.com"]},
        }, "u1", "p1")
        (q, p), = _stamps(c.driver.calls)
        self.assertEqual(p["zone"], "example.com")

    def test_the_partial_discovery_writer_stamps_its_zones(self):
        from graph_db.mixins.recon.domain_mixin import DomainMixin
        from graph_db.mixins.recon.user_input_mixin import UserInputMixin
        c = _client(UserInputMixin, DomainMixin)
        c.update_graph_from_partial_discovery(recon_data={
            "domain": "example.com", "subdomains": [], "dns": {},
            "wildcard_zones": {"example.com": ZONES["example.com"]},
        }, user_id="u1", project_id="p1", org_domain="example.com")
        (q, p), = _stamps(c.driver.calls)
        self.assertEqual(p["zone"], "example.com")


class TestTlsxWriterSkipsWildcardOnlySans(unittest.TestCase):
    """A SAN name the wildcard control dropped answers only through its zone's
    wildcard: the certificate keeps it in its san list, but no Subdomain is
    created or linked for it."""

    def test_no_covers_host_for_a_dropped_san(self):
        from graph_db.mixins.recon.tlsx_mixin import TlsxMixin
        c = _client(TlsxMixin)
        c.update_graph_from_tlsx({
            "domain": "example.com", "domains": ["example.com"],
            "tlsx": {
                "by_target": {"192.0.2.10:443": {
                    "scanned_ip": "192.0.2.10", "port": 443, "probe_status": True,
                    "fingerprint_sha256": "a" * 64, "subject_cn": "api.example.com",
                    "san": ["api.example.com", "ghost.example.com"]}},
                "wildcard_dropped": ["ghost.example.com"],
            },
        }, "u1", "p1")
        linked = [p["name"] for q, p in c.driver.calls if "COVERS_HOST" in q]
        self.assertEqual(linked, ["api.example.com"])
        cert = [p for q, p in c.driver.calls if "MERGE (c:Certificate" in q]
        self.assertTrue(cert)
        self.assertIn("ghost.example.com", str(cert[0]))

    def test_without_the_list_every_in_scope_san_is_linked_as_before(self):
        from graph_db.mixins.recon.tlsx_mixin import TlsxMixin
        c = _client(TlsxMixin)
        c.update_graph_from_tlsx({
            "domain": "example.com", "domains": ["example.com"],
            "tlsx": {"by_target": {"192.0.2.10:443": {
                "scanned_ip": "192.0.2.10", "port": 443, "probe_status": True,
                "fingerprint_sha256": "a" * 64, "subject_cn": "api.example.com",
                "san": ["api.example.com", "ghost.example.com"]}}},
        }, "u1", "p1")
        linked = sorted(p["name"] for q, p in c.driver.calls if "COVERS_HOST" in q)
        self.assertEqual(linked, ["api.example.com", "ghost.example.com"])


if __name__ == "__main__":
    unittest.main()
