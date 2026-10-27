"""Passive enrichers no longer take over a Port the active scan found (plan 04.3).

Censys, FOFA, Netlas, ZoomEye and CriminalIP ran a plain `SET p.source = ...`
on the Port they MERGE. A port naabu found then read as found by a passive
provider, and the Priority Board scored its reach as passively seen. `source`
is provenance: it is set on create only, like every first-writer field.

Fake Neo4j sessions: these pin the Cypher the writers send.
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

IP = "198.51.100.50"


class _Result(list):
    def single(self):
        return None


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append(query)
        return _Result()


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


PAYLOADS = {
    "censys": ("update_graph_from_censys",
               {"censys": {"hosts": [{"ip": IP, "services": [{"port": 22}]}]}}),
    "fofa": ("update_graph_from_fofa", {"fofa": {"results": [{"ip": IP, "port": 22}]}}),
    "netlas": ("update_graph_from_netlas", {"netlas": {"results": [{"ip": IP, "port": 22}]}}),
    "zoomeye": ("update_graph_from_zoomeye", {"zoomeye": {"results": [{"ip": IP, "port": 22}]}}),
    "criminalip": ("update_graph_from_criminalip",
                   {"criminalip": {"ip_reports": [{"ip": IP, "ports": [{"port": 22}]}]}}),
}


def _on_create(query: str) -> str:
    """The ON CREATE SET clause, up to the next clause keyword."""
    lines = query.split("\n")
    start = next(i for i, line in enumerate(lines) if "ON CREATE SET" in line)
    block = [lines[start].split("ON CREATE SET", 1)[1]]
    for line in lines[start + 1:]:
        if re.match(r"\s*[A-Z]", line):
            break
        block.append(line)
    return "\n".join(block)


def _port_merge(source: str) -> str:
    method, payload = PAYLOADS[source]
    w = _Writer()
    getattr(w, method)({"domain": "example.com", "domains": ["example.com"], **payload}, "u1", "p1")
    merges = [q for q in w.session.calls if "MERGE (p:Port" in q]
    assert len(merges) == 1, (source, merges)
    return merges[0]


class TestPortSourceIsProvenance(unittest.TestCase):
    def test_each_passive_writer_sets_source_on_create_only(self):
        for source in PAYLOADS:
            with self.subTest(source=source):
                query = _port_merge(source)
                self.assertIn(f"p.source = '{source}'", _on_create(query))
                self.assertEqual(query.count("p.source"), 1, query)

    def test_last_seen_still_moves_on_every_run(self):
        for source in PAYLOADS:
            with self.subTest(source=source):
                query = _port_merge(source)
                every_run = query.split("ON CREATE SET", 1)[1].split("\n", 1)[1]
                self.assertIn("p.updated_at = datetime()", every_run)


if __name__ == "__main__":
    unittest.main()
