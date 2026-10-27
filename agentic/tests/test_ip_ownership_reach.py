"""The Priority Board reads the IP attribution tag (plan 11.4).

- A finding on an IP tagged shared_edge (a CDN edge serving many tenants) has
  its reach capped at 0.5: below the 0.7 the KEV and "Act soon" rules need.
- A passive CVE (Shodan, Netlas, ...) on an IP no current DNS name points at
  is capped the same way: the IP may have left the target. Never for an
  IP-mode target, which is listed by address.
- An IP with no tag (written before plan 11) keeps today's reach.

Hosts are RFC 5737 addresses and example.com names.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model as sm  # noqa: E402
from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES, build_project_facts  # noqa: E402

EDGE = "198.51.100.20"
OWN = "198.51.100.21"
GONE = "198.51.100.22"
TARGET_IP = "198.51.100.23"


def _facts(**over):
    rows = [
        {"ip": EDGE, "ownership": "shared_edge", "dns_names": 3, "ip_mode": False},
        {"ip": OWN, "ownership": "dedicated", "dns_names": 1, "ip_mode": False},
        {"ip": GONE, "ownership": "unknown", "dns_names": 0, "ip_mode": False},
        {"ip": TARGET_IP, "ownership": "unknown", "dns_names": 0, "ip_mode": True},
    ]
    raw = {"ip_ownership": rows,
           "live_hosts": [{"hosts": [EDGE, OWN, f"https://{EDGE}:443", "www.example.com"]}]}
    raw.update(over)
    return build_project_facts(raw)


NO_CVSS = sm.parse_cvss_vector(None)


class TestTheFacts(unittest.TestCase):
    def test_the_fact_query_is_tenant_scoped(self):
        q = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "ip_ownership")
        self.assertIn("MATCH (ip:IP {user_id: $userId, project_id: $projectId})", q["query"])

    def test_the_reducer(self):
        facts = _facts()
        self.assertEqual(facts.shared_edge_hosts, {EDGE})
        self.assertEqual(facts.ip_ownership, {EDGE: "shared_edge", OWN: "dedicated",
                                              GONE: "unknown", TARGET_IP: "unknown"})
        self.assertEqual(facts.no_dns_name_hosts, {GONE})

    def test_a_row_without_a_count_is_not_a_zero(self):
        facts = build_project_facts({"ip_ownership": [
            {"ip": GONE, "ownership": "unknown", "dns_names": None, "ip_mode": False}]})
        self.assertEqual(facts.no_dns_name_hosts, set())

    def test_no_rows_is_unknown_not_false(self):
        facts = build_project_facts({})
        self.assertEqual((facts.shared_edge_hosts, facts.no_dns_name_hosts, facts.ip_ownership),
                         (set(), set(), {}))


class TestSharedEdgeReach(unittest.TestCase):
    def test_a_finding_on_a_shared_edge_ip_is_capped(self):
        r = sm.reach({"triage_host": EDGE, "source": "nuclei"}, _facts(), NO_CVSS)
        self.assertEqual(r.value, sm.SHARED_EDGE_MAX_REACH)
        self.assertEqual(r.value, 0.5)
        self.assertIn("shared CDN edge", r.evidence)

    def test_the_url_spelling_of_the_ip_is_capped_too(self):
        r = sm.reach({"triage_host": f"https://{EDGE}:443", "source": "nuclei"}, _facts(), NO_CVSS)
        self.assertEqual(r.value, 0.5)

    def test_a_hostname_served_through_the_cdn_is_not(self):
        r = sm.reach({"triage_host": "www.example.com", "source": "nuclei"}, _facts(), NO_CVSS)
        self.assertEqual(r.value, 1.0)

    def test_dedicated_and_untagged_ips_keep_their_reach(self):
        self.assertEqual(sm.reach({"triage_host": OWN}, _facts(), NO_CVSS).value, 1.0)
        no_tag = build_project_facts({"live_hosts": [{"hosts": [EDGE]}]})
        self.assertEqual(sm.reach({"triage_host": EDGE}, no_tag, NO_CVSS).value, 1.0)

    def test_a_lower_reach_is_never_raised(self):
        vector = sm.parse_cvss_vector("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(sm.reach({"triage_host": EDGE}, _facts(), vector).value, 0.3)


class TestLeftTheTarget(unittest.TestCase):
    def _cve(self, host, source="shodan"):
        return {"triage_host": host, "source": source, "target_port": 22}

    def test_a_passive_cve_on_an_ip_no_name_points_at_is_capped(self):
        facts = _facts(port_hosts=[{"host": GONE, "how": "active", "ports": [22]}])
        r = sm.reach(self._cve(GONE), facts, NO_CVSS)
        self.assertEqual(r.value, sm.LEFT_TARGET_MAX_REACH)
        self.assertIn("no current DNS name", r.evidence)

    def test_an_active_finding_there_is_not(self):
        facts = _facts(port_hosts=[{"host": GONE, "how": "active", "ports": [22]}])
        self.assertEqual(sm.reach(self._cve(GONE, source="nuclei"), facts, NO_CVSS).value, 1.0)

    def test_an_ip_mode_target_is_never_capped(self):
        facts = _facts(port_hosts=[{"host": TARGET_IP, "how": "active", "ports": [22]}])
        self.assertEqual(sm.reach(self._cve(TARGET_IP), facts, NO_CVSS).value, 1.0)

    def test_an_ip_names_still_point_at_is_not(self):
        facts = _facts(port_hosts=[{"host": OWN, "how": "active", "ports": [22]}])
        self.assertEqual(sm.reach(self._cve(OWN), facts, NO_CVSS).value, 1.0)


class TestTheTier(unittest.TestCase):
    def test_a_kev_cve_on_a_shared_edge_is_no_longer_act_now(self):
        inputs = sm.TierInputs(proven=False, kev=True)
        r = sm.reach({"triage_host": EDGE}, _facts(), NO_CVSS).value
        tier, _rule = sm.tier_rule(inputs, 0.9, 0.9, 0.9, r)
        self.assertNotEqual(tier, "T1")
        self.assertEqual(sm.tier_rule(inputs, 0.9, 0.9, 0.9, 1.0)[0], "T1")

    def test_the_model_version_moved(self):
        self.assertNotIn(sm.SCORE_MODEL_VERSION, ("v3.8.0",))


if __name__ == "__main__":
    unittest.main()
