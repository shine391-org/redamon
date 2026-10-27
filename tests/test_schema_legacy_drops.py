"""Legacy DROPs in graph_db/schema.py never remove a live constraint or index.

init_schema runs on every scan-container spawn and every agent graph call. A
DROP that names something init_schema then recreates rebuilds it every time: a
full re-index, with a window in which concurrent MERGEs have no uniqueness
guard. That is what happened to subdomain_unique, ip_unique and baseurl_unique,
whose names survived the move to tenant-scoped keys (drift-map #5).

It also keeps the index lists free of duplicate and dead declarations
(drift-map #62): a name declared twice is one index counted as two, and an
index removed from the lists must be DROPped so existing databases lose it too.

Run: ./redamon.sh test unit (root tests, agent image)
"""
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from graph_db import schema  # noqa: E402
from graph_db.schema_keys import KEY_CONSTRAINTS  # noqa: E402

DECLARED = {k["constraint"]: k for k in KEY_CONSTRAINTS}
INDEX_NAMES = [
    re.match(r"CREATE INDEX (\w+) ", s).group(1)
    for s in schema.TENANT_INDEXES + schema.ADDITIONAL_INDEXES
]
CREATED_INDEXES = set(INDEX_NAMES)


def _dropped(kind):
    pattern = re.compile(rf"DROP {kind} (\w+) IF EXISTS")
    return [pattern.match(s).group(1)
            for s in schema.DROP_LEGACY_CONSTRAINTS if pattern.match(s)]


class TestNoUnconditionalDropOfALiveName(unittest.TestCase):
    def test_every_legacy_drop_statement_is_parsed(self):
        """A statement neither pattern reads would escape the two tests below."""
        parsed = len(_dropped("CONSTRAINT")) + len(_dropped("INDEX"))
        self.assertEqual(parsed, len(schema.DROP_LEGACY_CONSTRAINTS))

    def test_no_unconditional_constraint_drop_names_a_declared_constraint(self):
        live = sorted(set(_dropped("CONSTRAINT")) & set(DECLARED))
        self.assertEqual(live, [], (
            "DROP_LEGACY_CONSTRAINTS drops a constraint schema_keys.py declares, "
            "so every init_schema rebuilds it. A name that kept its name while "
            "its key changed goes in LEGACY_SHAPED_CONSTRAINTS instead."))

    def test_no_unconditional_index_drop_names_a_created_index(self):
        live = sorted(set(_dropped("INDEX")) & CREATED_INDEXES)
        self.assertEqual(live, [])

    def test_every_conditional_drop_is_a_declared_constraint(self):
        """A name schema_keys.py no longer declares has no shape to compare
        with; it belongs in the unconditional list."""
        for name in schema.LEGACY_SHAPED_CONSTRAINTS:
            with self.subTest(name=name):
                self.assertIn(name, DECLARED)


class TestIndexDeclarations(unittest.TestCase):
    def test_every_index_statement_is_parsed(self):
        self.assertEqual(len(INDEX_NAMES),
                         len(schema.TENANT_INDEXES) + len(schema.ADDITIONAL_INDEXES))

    def test_index_names_are_unique(self):
        dupes = sorted({n for n in INDEX_NAMES if INDEX_NAMES.count(n) > 1})
        self.assertEqual(dupes, [], "an index is declared more than once")

    def test_the_dead_exploit_index_is_dropped_not_created(self):
        """Nothing writes the `Exploit` label (ExploitGvm is a different one)."""
        self.assertIn("idx_exploit_tenant", _dropped("INDEX"))
        ddl = " ".join(schema.TENANT_INDEXES + schema.ADDITIONAL_INDEXES)
        self.assertNotRegex(ddl, r":Exploit\)")


def _shape(name, properties=None):
    k = DECLARED[name]
    return {"name": name, "labelsOrTypes": [k["label"]],
            "properties": properties if properties is not None
            else list(k["key_properties"])}


class FakeResult(list):
    def single(self):
        return self[0] if self else None


class FakeSession:
    """Answers SHOW CONSTRAINTS with `constraints` (or raises), and reports
    every one-shot migration as already applied so only the DDL runs."""

    def __init__(self, constraints=(), show_fails=False):
        self.constraints = list(constraints)
        self.show_fails = show_fails
        self.queries = []

    def run(self, query, **params):
        self.queries.append(query)
        if query.startswith("SHOW CONSTRAINTS"):
            if self.show_fails:
                raise RuntimeError("permission denied")
            return FakeResult(self.constraints)
        if "RedamonSchemaMigration" in query and query.startswith("MATCH"):
            return FakeResult([{"c": 1}])
        return FakeResult()


def _all_tenant_shaped():
    return [_shape(k["constraint"]) for k in KEY_CONSTRAINTS]


class TestConditionalDropBehaviour(unittest.TestCase):
    def test_a_live_tenant_scoped_constraint_is_left_alone(self):
        session = FakeSession(_all_tenant_shaped())
        schema.init_schema(session)
        drops = [q for q in session.queries if q.startswith("DROP CONSTRAINT")]
        for name in list(DECLARED):
            with self.subTest(name=name):
                self.assertNotIn(f"DROP CONSTRAINT {name} IF EXISTS", drops)

    def test_a_legacy_shaped_constraint_is_dropped_before_its_create(self):
        legacy = {"subdomain_unique": ["name"], "ip_unique": ["address"],
                  "baseurl_unique": ["url"]}
        rows = [_shape(n, legacy.get(n)) for n in DECLARED]
        session = FakeSession(rows)
        schema.init_schema(session)
        for name in legacy:
            with self.subTest(name=name):
                drop = session.queries.index(f"DROP CONSTRAINT {name} IF EXISTS")
                create = next(i for i, q in enumerate(session.queries)
                              if q.startswith(f"CREATE CONSTRAINT {name} "))
                self.assertLess(drop, create)

    def test_only_the_mismatched_one_is_dropped(self):
        rows = [_shape(n, ["name"] if n == "ip_unique" else None) for n in DECLARED]
        session = FakeSession(rows)
        schema.drop_legacy_shaped_constraints(session)
        drops = [q for q in session.queries if q.startswith("DROP")]
        self.assertEqual(drops, ["DROP CONSTRAINT ip_unique IF EXISTS"])

    def test_a_constraint_on_another_label_is_a_mismatch(self):
        row = _shape("baseurl_unique")
        row["labelsOrTypes"] = ["Endpoint"]
        session = FakeSession([row])
        schema.drop_legacy_shaped_constraints(session)
        self.assertIn("DROP CONSTRAINT baseurl_unique IF EXISTS", session.queries)

    def test_an_absent_constraint_issues_no_drop(self):
        session = FakeSession([])
        schema.drop_legacy_shaped_constraints(session)
        self.assertEqual([q for q in session.queries if q.startswith("DROP")], [])

    def test_unreadable_constraints_fall_towards_dropping(self):
        """Keeping a global constraint makes the same-name CREATE a silent
        no-op, which is worse than one extra re-index."""
        session = FakeSession(show_fails=True)
        schema.drop_legacy_shaped_constraints(session)
        for name in schema.LEGACY_SHAPED_CONSTRAINTS:
            with self.subTest(name=name):
                self.assertIn(f"DROP CONSTRAINT {name} IF EXISTS", session.queries)


if __name__ == "__main__":
    unittest.main()
