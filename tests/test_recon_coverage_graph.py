"""The graph side of partial-coverage recon runs (hermetic).

- prune_unseen_findings(keep_hosts=...) keeps every finding about a host the
  run skipped, and the host patterns travel as parameters, never in the query;
- update_graph_coverage matches the run's Domain on the tenant triple only.

A fake driver captures what the mixins send; tests/test_recon_coverage_graph_live.py
runs the same queries against a real Neo4j.
"""
import json
import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.base_mixin import BaseMixin, keep_host_patterns  # noqa: E402
from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402


class _Result:
    def __init__(self, row):
        self._row = row

    def single(self):
        return self._row


class _Session:
    def __init__(self, calls, row):
        self.calls = calls
        self.row = row

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result(self.row)


class _Driver:
    def __init__(self, row):
        self.calls = []
        self.row = row

    def session(self):
        return _Session(self.calls, self.row)


class _Client(BaseMixin, DomainMixin):
    def __init__(self, row):
        self.driver = _Driver(row)


def _prune_query(calls):
    (query, params), = [c for c in calls if "DETACH DELETE d" in c[0]]
    return query, params


class TestKeepHostPatterns(unittest.TestCase):
    def _matches(self, host, value):
        return any(re.fullmatch(p, value) for p in keep_host_patterns([host]))

    def test_every_shape_a_finding_writer_stores(self):
        for value in ("a.example.com", "a.example.com:8443", "https://a.example.com",
                      "https://a.example.com/login?x=1", "http://a.example.com:8080/",
                      "wss://a.example.com/socket", "https://user@a.example.com/",
                      "A.EXAMPLE.COM".lower()):
            with self.subTest(value=value):
                self.assertTrue(self._matches("a.example.com", value))

    def test_never_a_different_host(self):
        for value in ("b.example.com", "xa.example.com", "a.example.com.evil.test",
                      "https://evil.test/?next=a.example.com", "https://a.example.comx/",
                      "sub.a.example.com", ""):
            with self.subTest(value=value):
                self.assertFalse(self._matches("a.example.com", value))

    def test_ip_targets(self):
        self.assertTrue(self._matches("198.51.100.7", "https://198.51.100.7"))
        self.assertTrue(self._matches("198.51.100.7", "198.51.100.7"))
        self.assertFalse(self._matches("198.51.100.7", "198.51.100.70"))
        self.assertTrue(self._matches("::1", "https://[::1]:8443/x"))

    def test_regex_metacharacters_are_escaped(self):
        # A '.' must not match any character.
        self.assertFalse(self._matches("a.example.com", "aXexampleXcom"))

    def test_hostile_names_are_dropped_before_they_reach_a_pattern(self):
        patterns = keep_host_patterns(["ok.example.com", "evil.com'); DROP", "a|b", "x*",
                                       "", None, "[::1]"])
        joined = "".join(patterns)
        self.assertIn(re.escape("ok.example.com"), joined)
        for bad in ("DROP", "a|b", "x*", "evil"):
            self.assertNotIn(bad, joined)

    def test_many_hosts_are_split_into_short_patterns(self):
        hosts = [f"h{i}.example.com" for i in range(250)]
        patterns = keep_host_patterns(hosts)
        self.assertEqual(len(patterns), 3)
        self.assertTrue(any(re.fullmatch(p, "https://h249.example.com/") for p in patterns))


class TestPruneKeepHosts(unittest.TestCase):
    def _prune(self, keep_hosts):
        client = _Client({"pruned": 0, "stale": 0, "revived": 0})
        client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00",
                                     keep_hosts=keep_hosts)
        return _prune_query(client.driver.calls)

    def test_no_keep_hosts_leaves_the_query_unchanged(self):
        plain_client = _Client({"pruned": 0, "stale": 0, "revived": 0})
        plain_client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00")
        plain_query, plain_params = _prune_query(plain_client.driver.calls)
        query, params = self._prune(())
        self.assertEqual(query, plain_query)
        self.assertEqual(params, plain_params)
        self.assertNotIn("keep_patterns", query)

    def test_hosts_travel_as_parameters_never_in_the_query_text(self):
        query, params = self._prune(["a.example.com", "198.51.100.7"])
        self.assertIn("$keep_patterns", query)
        self.assertNotIn("a.example.com", query)
        self.assertNotIn("198", query)
        self.assertEqual(len(params["keep_patterns"]), 1)
        self.assertTrue(re.fullmatch(params["keep_patterns"][0], "https://a.example.com/x"))

    def test_the_tenant_predicate_and_sources_stay(self):
        query, params = self._prune(["a.example.com"])
        self.assertIn("n.user_id = $uid AND n.project_id = $pid", query)
        self.assertIn("coalesce(n.source, '') IN $sources", query)
        self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))

    def test_every_host_field_is_checked(self):
        query, _ = self._prune(["a.example.com"])
        for field in ("host", "hostname", "matched_at", "url", "base_url", "source_url",
                      "endpoint", "matched_ip", "ip_address", "probe_url"):
            self.assertIn(f"toStringOrNull(n.{field})", query)

    def test_the_revive_query_is_unchanged(self):
        client = _Client({"pruned": 0, "stale": 0, "revived": 0})
        client.prune_unseen_findings("u1", "p1", ["nuclei"], "2026-01-01T00:00:00+00:00",
                                     keep_hosts=["a.example.com"])
        revive = [q for q, _ in client.driver.calls if "REMOVE n.stale_since" in q]
        self.assertEqual(len(revive), 1)
        self.assertNotIn("keep_patterns", revive[0])


class _TxSession(_Session):
    """A session whose execute_write runs the unit of work on itself, as the
    driver does, recording that the statements ran inside it."""

    def __init__(self, calls, rows):
        super().__init__(calls, None)
        self.rows = rows
        self.in_write = False

    def execute_write(self, work):
        self.in_write = True
        try:
            return work(self)
        finally:
            self.in_write = False

    def run(self, query, **params):
        self.calls.append((query, params, self.in_write))
        return _Result(self.rows[0] if "RETURN elementId(d)" in query else self.rows[1])


class _TxDriver(_Driver):
    def __init__(self, stored, written=None):
        super().__init__(None)
        self.rows = (stored, written if written is not None else {"n": 1})

    def session(self):
        return _TxSession(self.calls, self.rows)


class _TxClient(BaseMixin, DomainMixin):
    def __init__(self, stored, written=None):
        self.driver = _TxDriver(stored, written)


class TestUpdateGraphCoverage(unittest.TestCase):
    """§4.11.4: the record lands on the scan root's ORG Domain; the groups of
    one org merge into it within a run, keyed on the run's start."""

    RECORD = {"at": "2026-01-01T00:00:00+00:00", "gaps_json": "[]",
              "skipped_hosts": [], "nuclei_truncated": False}
    STORED = {"eid": "4:x:1", "run": None, "gaps": None, "skipped": None,
              "truncated": None, "roots": None}

    def test_it_locks_the_org_domain_before_reading_in_one_unit_of_work(self):
        client = _TxClient(self.STORED)
        rec = dict(self.RECORD, org_domain="Example.com")
        self.assertEqual(client.update_graph_coverage("u1", "p1", "api.example.com", rec, "RUN1"), 1)
        (lock_q, lock_p, lock_tx), (write_q, write_p, write_tx) = client.driver.calls
        self.assertTrue(lock_tx and write_tx)
        self.assertIn("MATCH (d:Domain {user_id: $user_id, project_id: $project_id})", lock_q)
        self.assertIn("toLower(d.name) = $org", lock_q)
        self.assertLess(lock_q.index("SET d._scope_lock = true REMOVE d._scope_lock"),
                        lock_q.index("RETURN"))
        self.assertEqual((lock_p["org"], lock_p["user_id"], lock_p["project_id"]),
                         ("example.com", "u1", "p1"))
        self.assertNotIn("MERGE", lock_q + write_q)
        for prop in ("recon_coverage_at", "recon_coverage_gaps", "recon_skipped_hosts",
                     "recon_nuclei_truncated", "recon_coverage_roots", "recon_coverage_run",
                     "recon_selection_json"):
            self.assertIn(f"d.{prop}", write_q)
        self.assertEqual(write_p["roots"], ["api.example.com"])
        self.assertEqual(write_p["run"], "RUN1")

    def test_it_writes_the_selection_block_the_reader_parses(self):
        """F07/DoD 4: the coverage record's selection_json is persisted on the
        Domain as recon_selection_json - the property the API coverage reader
        reads - instead of being dropped by merge_coverage."""
        client = _TxClient(self.STORED)
        rec = dict(self.RECORD, selection_json=json.dumps(
            {"recorded": True, "selection_unknown": False, "plan_ids": ["P1"],
             "exhaustive": False}))
        self.assertEqual(client.update_graph_coverage("u1", "p1", "example.com", rec, "RUN1"), 1)
        (_, _, _), (write_q, write_p, _) = client.driver.calls
        self.assertIn("d.recon_selection_json", write_q)
        self.assertEqual(json.loads(write_p["selection_json"])["plan_ids"], ["P1"])

    def test_a_run_without_a_selection_block_writes_null(self):
        client = _TxClient(self.STORED)
        client.update_graph_coverage("u1", "p1", "example.com", dict(self.RECORD), "RUN1")
        (_, _, _), (write_q, write_p, _) = client.driver.calls
        self.assertIn("d.recon_selection_json", write_q)
        self.assertIsNone(write_p["selection_json"])

    def test_without_an_org_the_scan_root_is_its_own_domain(self):
        client = _TxClient(self.STORED)
        client.update_graph_coverage("u1", "p1", "ip-targets.p1", self.RECORD)
        (_, lock_p, _), _ = client.driver.calls
        self.assertEqual(lock_p["org"], "ip-targets.p1")

    def test_zero_matched_is_reported_as_zero_and_nothing_is_written(self):
        client = _TxClient(None)
        self.assertEqual(client.update_graph_coverage("u1", "p1", "example.com", self.RECORD), 0)
        self.assertEqual(len(client.driver.calls), 1)

    def test_a_missing_gaps_value_is_an_empty_array(self):
        client = _TxClient(self.STORED)
        client.update_graph_coverage("u1", "p1", "example.com", {"at": self.RECORD["at"]})
        _, (_, params, _) = client.driver.calls
        self.assertEqual(params["gaps_json"], "[]")
        self.assertEqual(params["skipped_hosts"], [])
        self.assertIs(params["nuclei_truncated"], False)


class TestMergeCoverage(unittest.TestCase):
    """The pure merge the unit of work calls (it may be retried)."""

    def _merge(self, stored, record, root, run):
        from graph_db.mixins.recon.domain_mixin import merge_coverage
        return merge_coverage(stored, record, root, run)

    def test_the_first_group_of_a_run_overwrites(self):
        stored = {"run": "OLD", "gaps": '[{"source": "x", "root": "old.test"}]',
                  "skipped": ["old.test:443"], "truncated": True, "roots": ["old.test"]}
        out = self._merge(stored, {"gaps_json": '[{"source": "shodan"}]', "skipped_hosts": ["a.ex.com:80"],
                                   "nuclei_truncated": False}, "a.ex.com", "NEW")
        self.assertEqual(json.loads(out["gaps_json"]), [{"source": "shodan", "root": "a.ex.com"}])
        self.assertEqual(out["skipped_hosts"], ["a.ex.com:80"])
        self.assertIs(out["nuclei_truncated"], False)
        self.assertEqual(out["roots"], ["a.ex.com"])

    def test_a_later_group_of_the_same_run_merges(self):
        stored = {"run": "R", "gaps": '[{"source": "shodan", "root": "a.ex.com"}]',
                  "skipped": ["a.ex.com:80"], "truncated": True, "roots": ["a.ex.com"]}
        out = self._merge(stored, {"gaps_json": '[{"source": "shodan", "root": "ex.com"}]',
                                   "skipped_hosts": ["a.ex.com:80", "ex.com:443"],
                                   "nuclei_truncated": False}, "ex.com", "R")
        self.assertEqual(json.loads(out["gaps_json"]), [{"source": "shodan", "root": "a.ex.com"},
                                                       {"source": "shodan", "root": "ex.com"}])
        self.assertEqual(out["skipped_hosts"], ["a.ex.com:80", "ex.com:443"])
        self.assertIs(out["nuclei_truncated"], True)
        self.assertEqual(out["roots"], ["a.ex.com", "ex.com"])

    def test_no_run_marker_always_overwrites(self):
        stored = {"run": None, "gaps": "[]", "skipped": ["x:1"], "truncated": True, "roots": ["a"]}
        out = self._merge(stored, {"gaps_json": "[]"}, "b", None)
        self.assertEqual(out["roots"], ["b"])
        self.assertEqual(out["skipped_hosts"], [])

    def test_the_selection_block_survives_the_merge(self):
        """F07/DoD 4: a later group's selection block merges with the stored one
        (recorded OR-ed, plan ids unioned, exhaustive only when every group cut
        nothing) instead of first-group-wins."""
        stored = {"run": "R", "gaps": "[]", "skipped": [], "truncated": False,
                  "roots": ["a.ex.com"],
                  "selection": json.dumps({"recorded": True, "selection_unknown": False,
                                           "plan_ids": ["P1"], "exhaustive": False})}
        out = self._merge(stored, {"gaps_json": "[]", "selection_json": json.dumps(
            {"recorded": True, "selection_unknown": False, "plan_ids": ["P2"],
             "exhaustive": True})}, "ex.com", "R")
        self.assertEqual(json.loads(out["selection_json"]),
                         {"recorded": True, "selection_unknown": False,
                          "plan_ids": ["P1", "P2"], "exhaustive": False})

    def test_the_first_group_of_a_run_replaces_the_selection_block(self):
        stored = {"run": "OLD", "gaps": "[]", "skipped": [], "truncated": False,
                  "roots": ["old.test"],
                  "selection": json.dumps({"recorded": True, "selection_unknown": False,
                                           "plan_ids": ["P-OLD"], "exhaustive": False})}
        out = self._merge(stored, {"gaps_json": "[]", "selection_json": json.dumps(
            {"recorded": True, "selection_unknown": False, "plan_ids": ["P-NEW"],
             "exhaustive": True})}, "a.ex.com", "NEW")
        self.assertEqual(json.loads(out["selection_json"])["plan_ids"], ["P-NEW"])

    def test_no_selection_block_is_absent_not_an_empty_object(self):
        out = self._merge({"run": "R", "gaps": "[]", "skipped": [], "truncated": False,
                           "roots": ["a"]}, {"gaps_json": "[]"}, "b", "R")
        self.assertNotIn("selection_json", out)

    def test_the_merge_never_reads_the_clock(self):
        # run_timestamp() changes on every call; keying on it made every group
        # overwrite the last (§4.11.4).
        import ast
        import inspect
        import textwrap
        from graph_db.mixins.recon import domain_mixin
        for fn in (domain_mixin.merge_coverage, domain_mixin.DomainMixin.update_graph_coverage):
            calls = {getattr(n.func, "id", getattr(n.func, "attr", None))
                     for n in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(fn))))
                     if isinstance(n, ast.Call)}
            self.assertNotIn("run_timestamp", calls, fn.__name__)


if __name__ == "__main__":
    unittest.main()
