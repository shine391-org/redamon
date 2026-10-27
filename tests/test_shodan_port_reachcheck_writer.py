"""Graph side of the Shodan port re-check (plan 04.2).

- A Shodan CVE stores `port_confirmed`: True/False as checked, an unknown from a
  full run removes an older value, and a CVE that carries no verdict (partial
  recon could not say) leaves the stored one alone.
- A Port only Shodan or InternetDB reported is `passive_only: true`, set on
  create; naabu, masscan and nmap set it false when they find the same port,
  so a closed port 22 no longer reads as open just because Shodan saw it once.

Fake Neo4j sessions: these pin the Cypher the writers send.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from graph_db.mixins.recon.port_mixin import PortMixin  # noqa: E402

IP = "198.51.100.40"


class _Result(list):
    def single(self):
        return self[0] if self else None

    def consume(self):
        return MagicMock()


class _Session:
    def __init__(self, reads=()):
        self.calls = []
        self.reads = list(reads)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if "RETURN i.address AS ip" in query:
            return _Result(self.reads)
        return _Result([])


class _Writer(OsintMixin, PortMixin):
    def __init__(self, reads=()):
        self.session = _Session(reads)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _shodan(cves=(), hosts=()):
    w = _Writer()
    w.update_graph_from_shodan({"domain": "example.com", "domains": ["example.com"],
                                "shodan": {"hosts": list(hosts), "cves": list(cves)}}, "u1", "p1")
    return w.session.calls


def _cve(**extra):
    return {"cve_id": "CVE-2018-15473", "ip": IP, "source": "shodan_api", "port": 22, **extra}


def _vuln_write(calls):
    return next((q, p) for q, p in calls if "MERGE (v:Vulnerability" in q)


class TestPortConfirmed(unittest.TestCase):
    def test_a_checked_port_is_written(self):
        for verdict in (True, False):
            query, params = _vuln_write(_shodan([_cve(port_confirmed=verdict)]))
            self.assertIn("SET v.port_confirmed = $port_confirmed", query)
            self.assertEqual((params["set_port_confirmed"], params["port_confirmed"]),
                             (True, verdict))

    def test_an_unknown_from_a_full_run_removes_the_old_value(self):
        _, params = _vuln_write(_shodan([_cve(port_confirmed=None)]))
        self.assertEqual((params["set_port_confirmed"], params["port_confirmed"]), (True, None))

    def test_no_verdict_leaves_the_stored_one(self):
        query, params = _vuln_write(_shodan([_cve()]))
        self.assertFalse(params["set_port_confirmed"])
        self.assertIn("CASE WHEN $set_port_confirmed", query)

    def test_it_never_rides_in_the_generic_props(self):
        _, params = _vuln_write(_shodan([_cve(port_confirmed=False)]))
        self.assertNotIn("port_confirmed", params["props"])


class TestPassiveOnlyPorts(unittest.TestCase):
    def test_shodan_and_internetdb_ports_are_passive_on_create_only(self):
        host = {"ip": IP, "services": [{"port": 22, "transport": "tcp", "product": ""}],
                "ports": [22, 8080]}
        ports = [q for q, _ in _shodan(hosts=[host]) if "MERGE (p:Port" in q]
        self.assertEqual(len(ports), 2)
        for query in ports:
            on_create = query.split("ON CREATE SET", 1)[1].split("ON MATCH SET", 1)
            self.assertIn("p.passive_only = true", on_create[0])
            self.assertNotIn("passive_only", on_create[1])

    def test_the_active_port_scan_marks_its_ports_active(self):
        w = _Writer()
        w.update_graph_from_port_scan({"domain": "example.com", "port_scan": {
            "by_ip": {IP: {"ports": [22]}},
            "by_host": {"www.example.com": {"ip": IP, "port_details": [
                {"port": 22, "protocol": "tcp", "service": "ssh"}]}},
        }}, "u1", "p1")
        merges = [q for q, _ in w.session.calls if "MERGE (p:Port" in q]
        self.assertTrue(merges)
        for query in merges:
            self.assertIn("p.passive_only = false", query)

    def test_a_port_nmap_found_is_active(self):
        w = _Writer()
        w.update_graph_from_nmap({"domain": "example.com", "nmap_scan": {
            "new_open_ports": [{"ip": IP, "port": 22, "protocol": "tcp"}],
            "by_ip": {}, "services_detected": [], "nse_vulns": []}}, "u1", "p1")
        query = next(q for q, _ in w.session.calls if "MERGE (p:Port" in q)
        self.assertIn("p.passive_only = false", query)


class TestActiveOpenPorts(unittest.TestCase):
    def test_reads_only_actively_found_open_ports_of_the_ips_asked(self):
        w = _Writer(reads=[{"ip": IP, "ports": [443, 22]}])
        self.assertEqual(w.active_open_ports("u1", "p1", {IP}), {IP: {22, 443}})
        query, params = w.session.calls[0]
        self.assertEqual((params["uid"], params["pid"], params["ips"]), ("u1", "p1", [IP]))
        self.assertIn("p.passive_only = false", query)
        self.assertIn("'shodan'", query)
        self.assertIn("'internetdb'", query)

    def test_no_ip_asks_nothing(self):
        w = _Writer()
        self.assertEqual(w.active_open_ports("u1", "p1", set()), {})
        self.assertEqual(w.session.calls, [])


if __name__ == "__main__":
    unittest.main()
