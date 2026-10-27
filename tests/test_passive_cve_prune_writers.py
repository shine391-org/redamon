"""Graph side of pruning passive CVEs (plan 04.1).

The prune keeps a host the run could not look up by matching the finding's
host fields, `target_ip` among them. CriminalIP never stored one, and Shodan
only since its evidence grading, so an older CVE on such a host would have been
deleted: the backfill gives them the IP their id already names. CriminalIP's
writer also refreshed nothing on a re-run, `updated_at` included, so every one
of its CVEs would have looked unseen and been pruned at the second scan.

Fake Neo4j sessions: these pin the Cypher the writers send.
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin, _ip_from_passive_cve_id  # noqa: E402


class _Result(list):
    def single(self):
        return self[0] if self else None


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
        if "RETURN v.id AS id" in query:
            return _Result(self.reads)
        return _Result([{"n": len(params.get("rows") or [])}])


class _Writer(OsintMixin):
    def __init__(self, reads=()):
        self.session = _Session(reads)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


class TestIpFromId(unittest.TestCase):
    def test_reads_the_ip_the_writers_put_in_the_id(self):
        self.assertEqual(_ip_from_passive_cve_id("shodan-CVE-2018-15473-198.51.100.7"),
                         "198.51.100.7")
        self.assertEqual(_ip_from_passive_cve_id("criminalip-CVE-2021-44228-2001:db8::5"),
                         "2001:db8::5")

    def test_anything_else_is_no_ip(self):
        for vid in ("CVE-2018-15473", "netlas-CVE-2018-15473-198.51.100.7-22",
                    "shodan-CVE-2018-15473-not-an-ip", "shodan-CVE-2018-15473-", None, ""):
            self.assertIsNone(_ip_from_passive_cve_id(vid), vid)


class TestBackfill(unittest.TestCase):
    def test_older_passive_cves_get_the_ip_their_id_names(self):
        w = _Writer(reads=[
            {"id": "shodan-CVE-2018-15473-198.51.100.7"},
            {"id": "criminalip-CVE-2021-44228-198.51.100.8"},
            {"id": "shodan-CVE-2018-15473-garbage"},
        ])
        self.assertEqual(w.backfill_passive_cve_hosts("u1", "p1"), 2)
        (read, read_params), (write, write_params) = w.session.calls
        self.assertIn("v.target_ip IS NULL", read)
        self.assertEqual((read_params["uid"], read_params["pid"]), ("u1", "p1"))
        self.assertEqual(set(read_params["sources"]),
                         {"shodan_api", "internetdb", "shodan", "shodan_host_lookup", "criminalip"})
        self.assertEqual(write_params["rows"], [
            {"id": "shodan-CVE-2018-15473-198.51.100.7", "ip": "198.51.100.7"},
            {"id": "criminalip-CVE-2021-44228-198.51.100.8", "ip": "198.51.100.8"},
        ])
        self.assertIn("user_id: $uid, project_id: $pid", write)
        self.assertIn("WHERE v.target_ip IS NULL", write)
        self.assertNotIn("updated_at", write)

    def test_nothing_to_do_writes_nothing(self):
        w = _Writer(reads=[])
        self.assertEqual(w.backfill_passive_cve_hosts("u1", "p1"), 0)
        self.assertEqual(len(w.session.calls), 1)


def _criminalip_calls(ip="198.51.100.9"):
    w = _Writer()
    w.update_graph_from_criminalip({
        "domain": "example.com",
        "criminalip": {"ip_reports": [{
            "ip": ip, "score": {}, "issues": {}, "whois": {}, "ports": [],
            "vulnerabilities": [{"cve_id": "CVE-2021-44228", "cvssv3_score": 10.0}],
        }]},
    }, "u1", "p1")
    return w.session.calls


class TestCriminalIPRefreshesItsFindings(unittest.TestCase):
    def test_a_rerun_refreshes_updated_at_and_the_host(self):
        merge, params = next((q, p) for q, p in _criminalip_calls()
                             if "MERGE (v:Vulnerability" in q)
        parts = re.search(r"ON CREATE SET(.*?)\n\s*SET\s(.*)", merge, re.S)
        self.assertIsNotNone(parts, "the MERGE needs a SET outside ON CREATE")
        on_create, every_run = parts.groups()
        self.assertIn("v.updated_at = datetime()", every_run)
        self.assertIn("v.target_ip = $ip", every_run)
        self.assertNotIn("v.updated_at", on_create)
        self.assertIn("v.source = 'criminalip'", on_create)
        self.assertEqual(params["ip"], "198.51.100.9")


if __name__ == "__main__":
    unittest.main()
