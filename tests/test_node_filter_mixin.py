"""The node-filter sweep, against a fake driver that plays the graph's part.

The fake answers the projection page by page (honouring the keyset cursor and
the rule-muted-only narrowing) and applies the three writes with the same
guards the real Cypher re-checks, so these tests pin the DECISIONS: what gets
muted, released, re-attributed or left alone, and that a preview writes
nothing. The Cypher itself is pinned in test_node_filters_engine.py and run
against Neo4j in test_node_filters_graph_live.py.

Run: ./redamon.sh test unit   (root-agent section)
"""
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_REPO = Path(__file__).resolve().parent.parent
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from graph_db.mixins.node_filter_mixin import NodeFilterMixin, node_filter_page_size  # noqa: E402

UID, PID = "u1", "p1"

INFO_RULE = {"id": "k3f9a2", "name": "Informational templates", "enabled": True,
             "all": [{"field": "severity", "op": "in", "value": ["info"]}]}
HIGH_KEEP = {"id": "p81c0d", "name": "High and above", "enabled": True,
             "all": [{"field": "severity", "op": "gte", "value": "high"}]}


def config(*rules, mode="denylist", kind="vuln.nuclei", enabled=True):
    return {"mode": mode, "rules": {"version": 1, "kinds": {
        kind: {"enabled": enabled, "action": "mute", "rules": list(rules)}}}}


def node(key, severity="info", muted=False, muted_by="", guards=(), source="nuclei"):
    return {"key": key, "muted": muted, "muted_by": muted_by,
            "g_human": "human" in guards, "g_confirmed": "confirmed" in guards,
            "g_chain": "chain" in guards, "display": f"finding {key}",
            "host": "api.example.com", "source": source,
            "props": {"severity": severity}}


class FakeGraph:
    """Nodes of one kind, served and written the way the real queries would."""

    def __init__(self, nodes):
        self.nodes = {n["key"]: n for n in nodes}
        self.queries = []
        self.writes = []

    def run(self, query, **params):
        self.queries.append((query, params))
        result = MagicMock()
        if "LIMIT $page" in query:
            rows = sorted((n for n in self.nodes.values() if n["key"] > params["after"]),
                          key=lambda n: n["key"])
            if "STARTS WITH $rule_prefix" in query:
                rows = [n for n in rows if n["muted"] and n["muted_by"].startswith("rule:")]
            if "$sources" in query:
                rows = [n for n in rows if n["source"] in params["sources"]]
            page = [dict(n, props=dict(n["props"])) for n in rows[:params["page"]]]
            result.__iter__ = lambda _s: iter(page)
            return result
        self.writes.append((query, params))
        guarded = lambda n: n["g_human"] or n["g_confirmed"] or n["g_chain"]  # noqa: E731
        count = 0
        if query.startswith("UNWIND $rows") and "SET n:Muted" in query:
            for row in params["rows"]:
                n = self.nodes.get(row["key"])
                if n and not n["muted"] and not guarded(n):
                    n.update(muted=True, muted_by=row["muted_by"], reason=row["reason"])
                    count += 1
        elif query.startswith("UNWIND $rows"):
            for row in params["rows"]:
                n = self.nodes.get(row["key"])
                if n and n["muted"] and n["muted_by"].startswith("rule:") and n["muted_by"] != row["muted_by"] and not guarded(n):
                    n.update(muted_by=row["muted_by"], reason=row["reason"])
                    count += 1
        elif query.startswith("UNWIND $keys"):
            for key in params["keys"]:
                n = self.nodes.get(key)
                if n and n["muted"] and n["muted_by"].startswith("rule:"):
                    n.update(muted=False, muted_by="")
                    count += 1
        result.single.return_value = {"n": count}
        return result


class Client(NodeFilterMixin):
    def __init__(self, graph):
        self.graph = graph
        session = MagicMock()
        session.run = graph.run
        session.__enter__ = lambda _s: session
        session.__exit__ = lambda *_: False
        self.driver = MagicMock()
        self.driver.session.return_value = session
        self.log_lines = []

    def sweep(self, cfg, **kw):
        kw.setdefault("kinds", ["vuln.nuclei"])
        return self.apply_node_filters(UID, PID, cfg, log=self.log_lines.append, **kw)


class TestDenylist(unittest.TestCase):
    def test_mutes_what_a_rule_matches_and_names_the_rule(self):
        g = FakeGraph([node("a", "info"), node("b", "high")])
        stats = Client(g).sweep(config(INFO_RULE))
        self.assertTrue(g.nodes["a"]["muted"])
        self.assertEqual(g.nodes["a"]["muted_by"], "rule:vuln.nuclei/k3f9a2")
        self.assertEqual(g.nodes["a"]["reason"], "Filter rule: Informational templates")
        self.assertFalse(g.nodes["b"]["muted"])
        ks = stats["kinds"]["vuln.nuclei"]
        self.assertEqual((ks["to_mute"], ks["muted"], ks["would_mute"]), (1, 1, 1))
        self.assertEqual(ks["rules"]["k3f9a2"]["matched"], 1)

    def test_disabling_the_rule_and_sweeping_again_brings_them_back(self):
        g = FakeGraph([node("a", "info")])
        Client(g).sweep(config(INFO_RULE))
        self.assertTrue(g.nodes["a"]["muted"])
        stats = Client(g).sweep(config({**INFO_RULE, "enabled": False}))
        self.assertFalse(g.nodes["a"]["muted"])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["unmuted"], 1)
        # An inactive kind only reads the nodes a rule muted.
        projection = [q for q, _ in g.queries if "LIMIT $page" in q][-1]
        self.assertIn("STARTS WITH $rule_prefix", projection)

    def test_a_second_sweep_changes_nothing(self):
        g = FakeGraph([node("a", "info"), node("b", "high")])
        Client(g).sweep(config(INFO_RULE))
        g.writes.clear()
        stats = Client(g).sweep(config(INFO_RULE))
        self.assertEqual(g.writes, [])
        self.assertEqual(stats["totals"]["to_mute"], 0)
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["would_mute"], 1)

    def test_a_rule_mute_moves_to_the_rule_that_now_matches(self):
        g = FakeGraph([node("a", "info", muted=True, muted_by="rule:vuln.nuclei/gone01")])
        stats = Client(g).sweep(config(INFO_RULE))
        self.assertEqual(g.nodes["a"]["muted_by"], "rule:vuln.nuclei/k3f9a2")
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["restamped"], 1)


class TestAllowlist(unittest.TestCase):
    def test_mutes_everything_no_rule_keeps(self):
        g = FakeGraph([node("a", "info"), node("b", "high"), node("c", "critical")])
        stats = Client(g).sweep(config(HIGH_KEEP, mode="allowlist"))
        self.assertTrue(g.nodes["a"]["muted"])
        self.assertEqual(g.nodes["a"]["muted_by"], "rule:vuln.nuclei/allowlist")
        self.assertEqual(g.nodes["a"]["reason"], "Filter rule: allowlist (kept by no rule)")
        self.assertFalse(g.nodes["b"]["muted"] or g.nodes["c"]["muted"])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["rules"]["allowlist"]["matched"], 1)

    def test_each_keep_rule_counts_what_it_keeps(self):
        crit_keep = {**HIGH_KEEP, "id": "c0ffee", "name": "Critical",
                     "all": [{"field": "severity", "op": "in", "value": ["critical"]}]}
        g = FakeGraph([node("a", "info"), node("b", "high"), node("c", "critical")])
        stats = Client(g).sweep(config(HIGH_KEEP, crit_keep, mode="allowlist"), dry_run=True)
        rules = stats["kinds"]["vuln.nuclei"]["rules"]
        self.assertEqual(rules["p81c0d"]["matched"], 2)
        self.assertEqual({s["key"] for s in rules["p81c0d"]["samples"]}, {"b", "c"})
        self.assertEqual(rules["c0ffee"]["matched"], 1)
        # A kept node is not muted, so it adds nothing to the mute counts.
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["would_mute"], 1)
        self.assertEqual(rules["allowlist"]["matched"], 1)

    def test_the_log_says_kept_for_a_keep_rule(self):
        client = Client(FakeGraph([node("a", "info"), node("b", "high")]))
        client.sweep(config(HIGH_KEEP, mode="allowlist"))
        self.assertIn('[NODE-FILTER] vuln.nuclei mode=allowlist rule="High and above" kept=1',
                      client.log_lines)
        self.assertIn('[NODE-FILTER] vuln.nuclei mode=allowlist rule="Kept by no rule" matched=1',
                      client.log_lines)

    def test_a_node_missing_the_field_is_not_kept_and_is_counted(self):
        g = FakeGraph([node("a", severity=None)])
        stats = Client(g).sweep(config(HIGH_KEEP, mode="allowlist"))
        self.assertTrue(g.nodes["a"]["muted"])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["missing"], {"severity": 1})

    def test_an_invalid_keep_rule_filters_nothing_in_that_kind(self):
        bad = {**HIGH_KEEP, "id": "zz9999", "all": [{"field": "nope", "op": "in", "value": ["x"]}]}
        g = FakeGraph([node("a", "info")])
        stats = Client(g).sweep(config(HIGH_KEEP, bad, mode="allowlist"))
        self.assertFalse(g.nodes["a"]["muted"])
        self.assertFalse(stats["kinds"]["vuln.nuclei"]["active"])


class TestGuardsAndPeople(unittest.TestCase):
    def test_guarded_nodes_are_never_muted(self):
        g = FakeGraph([node("h", guards=("human",)), node("c", guards=("confirmed",)),
                       node("x", guards=("chain",))])
        stats = Client(g).sweep(config(INFO_RULE))
        self.assertFalse(any(n["muted"] for n in g.nodes.values()))
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["guarded"], 3)
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["to_mute"], 0)

    def test_a_node_that_became_guarded_while_rule_muted_is_released(self):
        # X2: a human verdict set on a rule-muted finding.
        g = FakeGraph([node("a", "info", muted=True, muted_by="rule:vuln.nuclei/k3f9a2", guards=("human",))])
        stats = Client(g).sweep(config(INFO_RULE))
        self.assertFalse(g.nodes["a"]["muted"])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["unmuted"], 1)

    def test_an_exempt_node_is_released_and_never_muted_again(self):
        g = FakeGraph([node("a", "info", muted=True, muted_by="rule:vuln.nuclei/k3f9a2"), node("b", "info")])
        stats = Client(g).sweep(config(INFO_RULE), exemptions=[("Vulnerability", "a"), ("Vulnerability", "b")])
        self.assertFalse(g.nodes["a"]["muted"] or g.nodes["b"]["muted"])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["exempt"], 2)

    def test_an_exemption_is_per_label(self):
        g = FakeGraph([node("a", "info")])
        Client(g).sweep(config(INFO_RULE), exemptions=[("Secret", "a")])
        self.assertTrue(g.nodes["a"]["muted"])

    def test_a_persons_mute_is_never_touched(self):
        g = FakeGraph([node("a", "high", muted=True, muted_by="alice"),
                       node("b", "info", muted=True, muted_by="alice")])
        stats = Client(g).sweep(config(INFO_RULE))
        self.assertTrue(g.nodes["a"]["muted"] and g.nodes["b"]["muted"])
        self.assertEqual(g.nodes["b"]["muted_by"], "alice")
        self.assertEqual(g.writes, [])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["operator_muted"], 2)

    def test_the_guard_recheck_wins_a_race_with_the_read(self):
        # The row was read unguarded; a verdict landed before the write.
        g = FakeGraph([node("a", "info")])
        original = g.run

        def racing(query, **params):
            if query.startswith("UNWIND $rows"):
                g.nodes["a"]["g_human"] = True
            return original(query, **params)
        g.run = racing
        client = Client(g)
        client.driver.session.return_value.run = racing
        stats = client.sweep(config(INFO_RULE))
        self.assertFalse(g.nodes["a"]["muted"])
        self.assertEqual((stats["kinds"]["vuln.nuclei"]["to_mute"], stats["kinds"]["vuln.nuclei"]["muted"]), (1, 0))


class TestPreview(unittest.TestCase):
    def test_a_preview_writes_nothing_and_counts_what_apply_would(self):
        nodes = [node(f"n{i:03d}", "info" if i % 3 else "high") for i in range(30)]
        preview_graph = FakeGraph([dict(n) for n in nodes])
        preview = Client(preview_graph).sweep(config(INFO_RULE), dry_run=True)
        self.assertEqual(preview_graph.writes, [])
        apply_graph = FakeGraph([dict(n) for n in nodes])
        applied = Client(apply_graph).sweep(config(INFO_RULE))
        self.assertEqual(preview["kinds"]["vuln.nuclei"]["to_mute"], applied["kinds"]["vuln.nuclei"]["muted"])
        self.assertEqual(preview["totals"]["to_mute"], 20)

    def test_a_preview_keeps_at_most_five_samples_per_rule(self):
        g = FakeGraph([node(f"n{i:02d}", "info") for i in range(12)])
        stats = Client(g).sweep(config(INFO_RULE), dry_run=True)
        samples = stats["kinds"]["vuln.nuclei"]["rules"]["k3f9a2"]["samples"]
        self.assertEqual(len(samples), 5)
        self.assertEqual(samples[0], {"key": "n00", "name": "finding n00",
                                      "host": "api.example.com", "guards": []})

    def test_a_preview_reports_the_hosts_and_cves_it_would_newly_hide(self):
        # For the Apply modal's "open remediations may relate" count.
        cve = dict(node("c", "info"), display="CVE-2021-44228")
        g = FakeGraph([node("a", "info"), cve, node("b", "high"),
                       node("m", "info", muted=True, muted_by="rule:vuln.nuclei/k3f9a2")])
        stats = Client(g).sweep(config(INFO_RULE), dry_run=True)
        self.assertEqual(stats["related"], {"hosts": ["api.example.com"], "cves": ["CVE-2021-44228"]})

    def test_an_apply_reports_no_related_hints(self):
        stats = Client(FakeGraph([node("a", "info")])).sweep(config(INFO_RULE))
        self.assertEqual(stats["related"], {"hosts": [], "cves": []})

    def test_a_preview_logs_nothing(self):
        client = Client(FakeGraph([node("a")]))
        client.sweep(config(INFO_RULE), dry_run=True)
        self.assertEqual(client.log_lines, [])


class TestPagingAndScope(unittest.TestCase):
    def test_keyset_paging_walks_every_node_once(self):
        g = FakeGraph([node(f"n{i:03d}", "info") for i in range(25)])
        stats = Client(g).sweep(config(INFO_RULE), page_size=10)
        pages = [p for q, p in g.queries if "LIMIT $page" in q]
        self.assertEqual([p["after"] for p in pages], ["", "n009", "n019"])
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["scanned"], 25)
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["muted"], 25)

    def test_the_unmute_only_reconciles_rows_that_were_read(self):
        # A rule-muted node outside the touched set is left as it is.
        g = FakeGraph([node("a", "info", muted=True, muted_by="rule:vuln.nuclei/k3f9a2", source="osv")])
        Client(g).sweep(config({**INFO_RULE, "enabled": False}), sources=["nuclei"])
        self.assertTrue(g.nodes["a"]["muted"])

    def test_a_scan_sweep_is_scoped_by_time_and_source(self):
        g = FakeGraph([node("a", "info")])
        Client(g).sweep(config(INFO_RULE), touched_since="2026-09-23T10:00:00+00:00",
                        sources=["nuclei", "security_check"])
        query, params = [(q, p) for q, p in g.queries if "LIMIT $page" in q][0]
        self.assertEqual(params["touched_since"], "2026-09-23T10:00:00+00:00")
        self.assertEqual(params["sources"], ["nuclei", "security_check"])
        self.assertIn("datetime(toString(n.updated_at)) >= datetime($touched_since)", query)

    def test_a_source_scope_skips_kinds_it_cannot_produce(self):
        g = FakeGraph([])
        stats = Client(g).apply_node_filters(UID, PID, config(INFO_RULE), sources=["nuclei"],
                                             log=lambda *_: None)
        self.assertEqual(list(stats["kinds"]), ["vuln.nuclei"])

    def test_the_deadline_stops_the_sweep_and_marks_it_partial(self):
        g = FakeGraph([node(f"n{i:03d}", "info") for i in range(30)])
        stats = Client(g).sweep(config(INFO_RULE), page_size=10, deadline=time.monotonic() - 1)
        self.assertTrue(stats["partial"])
        self.assertLessEqual(stats["kinds"].get("vuln.nuclei", {"scanned": 0})["scanned"], 10)

    def test_the_heartbeat_is_called_per_page(self):
        g = FakeGraph([node(f"n{i:03d}", "info") for i in range(25)])
        beats = []
        Client(g).sweep(config(INFO_RULE), page_size=10, heartbeat=beats.append)
        self.assertEqual(len(beats), 3)
        self.assertEqual(beats[-1], {"kind": "vuln.nuclei", "scanned": 25})

    def test_the_page_size_is_bounded(self):
        self.assertGreaterEqual(node_filter_page_size(), 50)
        self.assertLessEqual(node_filter_page_size(), 20000)


class TestFailsClosed(unittest.TestCase):
    def test_unusable_rules_touch_nothing(self):
        g = FakeGraph([node("a", "info", muted=True, muted_by="rule:vuln.nuclei/k3f9a2")])
        client = Client(g)
        stats = client.sweep({"mode": "denylist", "rules": "{not json"})
        self.assertFalse(stats["ok"])
        self.assertEqual(g.queries, [])
        self.assertTrue(g.nodes["a"]["muted"])
        self.assertTrue(client.log_lines[0].startswith("[!][NODE-FILTER]"))

    def test_a_missing_tenant_is_refused(self):
        with self.assertRaises(ValueError):
            Client(FakeGraph([])).apply_node_filters("", PID, config(INFO_RULE))

    def test_the_log_lines(self):
        client = Client(FakeGraph([node("a", "info")]))
        client.sweep(config(INFO_RULE))
        self.assertIn("[NODE-FILTER] vuln.nuclei mode=denylist muted=1 unmuted=0 restamped=0 guarded=0 exempt=0",
                      client.log_lines)
        self.assertIn('[NODE-FILTER] vuln.nuclei mode=denylist rule="Informational templates" matched=1',
                      client.log_lines)


if __name__ == "__main__":
    unittest.main()


class TestLegacyValidationAliasInAPreview(unittest.TestCase):
    """The webapp's preview is this dry run (agentic/node_filter_runs.preview):
    a saved rule on 'invalid' counts a node stored as 'rejected'."""

    def test_a_saved_invalid_rule_previews_rejected_nodes(self):
        rule = {"id": "v1nval", "name": "Keys that failed validation", "enabled": True,
                "all": [{"field": "validation_status", "op": "in", "value": ["invalid"]}]}
        nodes = []
        for key, status in (("s1", "rejected"), ("s2", "invalid"), ("s3", "unknown")):
            n = node(key, source="js_recon")
            n["props"] = {"validation_status": status}
            nodes.append(n)
        g = FakeGraph(nodes)
        stats = Client(g).sweep(config(rule, kind="secret"), kinds=["secret"], dry_run=True)
        self.assertEqual(stats["kinds"]["secret"]["would_mute"], 2)
        self.assertEqual(g.writes, [])
