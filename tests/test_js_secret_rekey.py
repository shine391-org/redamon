"""tooling/scripts/js_secret_rekey.py (plan 05.4).

Bounding the keyword-anchored patterns shortens a match that used to run to
the last candidate on a minified line, and a JS Recon Secret's id is a hash of
its match. The script moves such a finding to the id the scanner now writes,
with its mute, its Priority Board layers (a person's DECISION included), its
CONFIRMS proof edges, its un-mute exemptions, fix items and captured
transactions. Fake Neo4j and Postgres; every value is synthetic.
"""
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tooling.scripts import js_secret_rekey as rk  # noqa: E402

patterns = rk.patterns  # recon.helpers is not importable in the agent image

UID, PID = "u-js", "p-js"
URL = "https://app.example.com/static/main.js"
FILLER = "var q=function(a,b){return a+b};" * 2

# The patterns as they were before plan 05.4, to build the stored match.
OLD_ETSY = re.compile(r"(?i)etsy.*['\"][a-z0-9]{24}['\"]")
OLD_AZURE = re.compile(r"(?i)azure.*client.?secret.*['\"][a-zA-Z0-9~._-]{34,}['\"]")

ETSY_LINE = ('etsyKey:"k3x9q2m7a8b1c4d5e6f7g8h9",' + FILLER
             + 'other:"z9y8x7w6v5u4t3s2r1q0p9o8"')
AZURE_LINE = ('/* azure */ cfg={clientId:"x",clientSecret:""}; build="'
              + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0" + '"')


def _stored(old_regex, line, name):
    """The node the old pattern wrote for `line`: (node id, matched text)."""
    text = old_regex.search(line).group(0)
    return rk._node_id(UID, PID, patterns._make_finding_id(name, text, URL)), text


def _scanned_id(line, name):
    """The node id the scanner writes for `line` today."""
    finding = next(f for f in patterns.scan_js_content(line, URL)[0] if f["name"] == name)
    return rk._node_id(UID, PID, finding["id"]), finding["matched_text"]


class FakeSession:
    def __init__(self, rows=(), nodes=None):
        self.rows = list(rows)
        self.nodes = nodes or {}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if query is rk.JS_SECRETS:
            return list(self.rows)
        if query is rk.READ_NODES:
            return [{"id": i, **self.nodes[i]} for i in params["ids"] if i in self.nodes]
        return []

    def writes(self):
        return [(q, p) for q, p in self.calls if q not in (rk.JS_SECRETS, rk.READ_NODES)]


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = [("id",), ("user_id",)]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.conn.log.append(("sql", " ".join(sql.split()), params))

    def fetchall(self):
        return self.conn.rows


class FakeConn:
    def __init__(self, rows=((PID, UID),)):
        self.rows = list(rows)
        self.log = []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.log.append(("commit",))


class TestPlan(unittest.TestCase):
    def test_a_runaway_match_moves_to_the_id_the_scanner_writes_now(self):
        old_id, old_text = _stored(OLD_ETSY, ETSY_LINE, "Etsy Access Token")
        new_id, new_text = _scanned_id(ETSY_LINE, "Etsy Access Token")
        self.assertNotEqual(old_id, new_id)
        plan = rk.plan_secret(UID, PID, old_id, old_text, URL)
        self.assertEqual(plan["status"], "moved")
        self.assertEqual((plan["new_id"], plan["matched_text"]), (new_id, new_text))
        self.assertEqual(plan["sample"], patterns.redact(new_text))

    def test_a_match_the_bounds_do_not_change_stays(self):
        line = 'etsyKey:"k3x9q2m7a8b1c4d5e6f7g8h9"'
        old_id, old_text = _stored(OLD_ETSY, line, "Etsy Access Token")
        self.assertEqual(_scanned_id(line, "Etsy Access Token")[0], old_id)
        self.assertEqual(rk.plan_secret(UID, PID, old_id, old_text, URL), {"status": "same"})

    def test_a_match_the_new_pattern_rejects_is_left_alone(self):
        old_id, old_text = _stored(OLD_AZURE, AZURE_LINE, "Azure AD Client Secret")
        plan = rk.plan_secret(UID, PID, old_id, old_text, URL)
        self.assertEqual(plan, {"status": "unmatched", "pattern": "Azure AD Client Secret"})

    def test_an_id_no_pattern_reproduces_is_left_alone(self):
        self.assertEqual(rk.plan_secret(UID, PID, rk._node_id(UID, PID, "0" * 16), "x", URL),
                         {"status": "unknown"})
        self.assertEqual(rk.plan_secret(UID, PID, "secret-other-project-abc", "x", URL),
                         {"status": "unknown"})

    def test_plan_project_lists_moves_and_unmatched(self):
        etsy_id, etsy_text = _stored(OLD_ETSY, ETSY_LINE, "Etsy Access Token")
        azure_id, azure_text = _stored(OLD_AZURE, AZURE_LINE, "Azure AD Client Secret")
        session = FakeSession(rows=[
            {"id": etsy_id, "matched_text": etsy_text, "source_url": URL},
            {"id": azure_id, "matched_text": azure_text, "source_url": URL},
        ])
        plan = rk.plan_project(session, {"id": PID, "user_id": UID})
        self.assertEqual([r["old_id"] for r in plan["rekeys"]], [etsy_id])
        self.assertEqual(plan["unmatched"], [{"old_id": azure_id, "pattern": "Azure AD Client Secret"}])

    def test_every_query_is_scoped_to_one_project(self):
        for name in ("JS_SECRETS", "READ_NODES", "RENAME", "MERGE_ONTO_NEW", "COPY_PROOF", "DELETE_OLD"):
            query = getattr(rk, name)
            with self.subTest(query=name):
                self.assertIn("$pid", query)
                self.assertIn("$uid", query)
                self.assertNotIn("updated_at", query)
        self.assertIn("s.source = 'js_recon'", rk.JS_SECRETS)

    def test_the_node_id_is_the_writers(self):
        src = (_REPO / "graph_db" / "mixins" / "recon" / "js_recon_mixin.py").read_text()
        self.assertIn('node_id = f"secret-{user_id}-{project_id}-{secret_id}"', src)


def _rekey():
    old_id, old_text = _stored(OLD_ETSY, ETSY_LINE, "Etsy Access Token")
    return rk.plan_secret(UID, PID, old_id, old_text, URL)


DECIDED = {"source": "js_recon", "user_id": UID, "project_id": PID,
           "triage_status": "likely_noise", "triage_source": "human",
           "triage_verdict_at": "2026-10-01T00:00:00Z",
           "muted_at": "2026-10-01T00:00:00Z", "muted_by": "user-1",
           "updated_at": "2026-10-01T00:00:00Z"}


class TestRekeyGraph(unittest.TestCase):
    def test_nothing_at_the_new_id_renames_in_place(self):
        r = _rekey()
        s = FakeSession(nodes={r["old_id"]: {"muted": True, "props": dict(DECIDED)}})
        self.assertEqual(rk.rekey_graph(s, UID, PID, r), "renamed")
        (query, params), = s.writes()
        self.assertIs(query, rk.RENAME)
        self.assertEqual((params["old"], params["new"], params["matched"], params["sample"]),
                         (r["old_id"], r["new_id"], r["matched_text"], r["sample"]))

    def test_a_node_already_at_the_new_id_gets_the_decision_and_the_mute(self):
        r = _rekey()
        s = FakeSession(nodes={
            r["old_id"]: {"muted": True, "props": dict(DECIDED)},
            r["new_id"]: {"muted": False, "props": {"source": "js_recon", "user_id": UID,
                                                     "project_id": PID}},
        })
        self.assertEqual(rk.rekey_graph(s, UID, PID, r), "merged")
        merge, proof, delete = s.writes()
        self.assertTrue(merge[0].startswith(rk.MERGE_ONTO_NEW.split("{remove}")[0]))
        self.assertEqual(merge[1]["carried"]["triage_status"], "likely_noise")
        self.assertEqual(merge[1]["carried"]["muted_by"], "user-1")
        self.assertIs(merge[1]["mute"], True)
        self.assertNotIn("updated_at", merge[1]["carried"])
        self.assertIs(proof[0], rk.COPY_PROOF)
        self.assertEqual((delete[0], delete[1]["old"]), (rk.DELETE_OLD, r["old_id"]))

    def test_an_old_node_already_gone_is_skipped(self):
        r = _rekey()
        s = FakeSession(nodes={})
        self.assertEqual(rk.rekey_graph(s, UID, PID, r), "gone")
        self.assertEqual(s.writes(), [])


class TestRekeyPostgres(unittest.TestCase):
    def test_exemptions_fix_items_and_captures_follow_the_finding(self):
        r = _rekey()
        conn = FakeConn()
        with conn.cursor() as cur:
            rk.rekey_postgres(cur, PID, r)
        sqls = [entry[1] for entry in conn.log]
        self.assertTrue(sqls[0].startswith("INSERT INTO node_filter_exemptions"))
        self.assertTrue(sqls[1].startswith("DELETE FROM node_filter_exemptions"))
        self.assertTrue(sqls[2].startswith("UPDATE remediations"))
        self.assertTrue(sqls[3].startswith("UPDATE captured_http_transactions"))
        for _, sql, params in conn.log:
            self.assertIn("project_id = %(pid)s", sql)
            self.assertEqual((params["pid"], params["old"], params["new"], params["label"]),
                             (PID, r["old_id"], r["new_id"], "Secret"))


class TestRun(unittest.TestCase):
    def _session(self):
        etsy_id, etsy_text = _stored(OLD_ETSY, ETSY_LINE, "Etsy Access Token")
        return FakeSession(rows=[{"id": etsy_id, "matched_text": etsy_text, "source_url": URL}],
                           nodes={etsy_id: {"muted": False, "props": dict(DECIDED)}})

    def test_a_dry_run_writes_nothing(self):
        session, conn, lines = self._session(), FakeConn(), []
        summary = rk.run(conn, FakeDriver(session), None, apply=False, out=lines.append)
        self.assertEqual(len(summary[PID]["rekeys"]), 1)
        self.assertEqual(session.writes(), [])
        self.assertEqual([e for e in conn.log if e[0] == "commit"], [])
        self.assertTrue(any("(dry run)" in line for line in lines))
        self.assertIn("would re-key 1 secret(s) in 1 project(s)", lines[-1])

    def test_apply_moves_postgres_first_then_the_graph(self):
        session, conn, lines = self._session(), FakeConn(), []
        summary = rk.run(conn, FakeDriver(session), PID, apply=True, out=lines.append)
        self.assertEqual(summary[PID]["outcomes"], ["renamed"])
        self.assertIn(("commit",), conn.log)
        self.assertTrue(any("done: 1 renamed" in line for line in lines))

    def test_a_blank_project_is_refused(self):
        with self.assertRaises(ValueError):
            rk.run(FakeConn(), FakeDriver(FakeSession()), "  ", apply=False)


class TestMain(unittest.TestCase):
    def test_apply_refuses_while_services_run(self):
        with patch.object(rk, "services_are_up", return_value=["agent"]):
            self.assertEqual(rk.main(["--all", "--apply"]), 2)


if __name__ == "__main__":
    unittest.main()
