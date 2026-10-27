"""Every copy of the global reference labels equals the tenant filter's.

GLOBAL_REFERENCE_LABELS in graph_db/tenant_filter.py decides which labels a
query may leave without a tenant predicate: the public CVE / CWE / CAPEC
catalogue, one node per id for the whole database. The webapp cannot import
Python, so three TypeScript files carry their own list. A label one copy exempts
and the source does not is a cross-tenant read (ExploitGvm was once exempt in
injectProjectFilter.ts, which left `MATCH (e:ExploitGvm)` unscoped); a label the
source exempts and a copy does not is scoped to a tenant property it never
carries, so that path matches nothing.

Each copy is parsed from its file and compared with the constant itself, never
with a list written into this test.

Run: python -m pytest tests/test_reference_labels_mirrors.py
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db import schema, schema_keys  # noqa: E402
from graph_db.tenant_filter import GLOBAL_REFERENCE_LABELS  # noqa: E402

_WEBAPP_SRC = os.path.join(_REPO, "webapp", "src")

#: (file, constant) for every TypeScript copy. The regex in `_ts_list` reads
#: both `new Set([...])` and `[...] as const` forms.
TS_COPIES = (
    ("webapp/src/app/api/graph-views/execute/injectProjectFilter.ts", "GLOBAL_LABELS"),
    ("webapp/src/lib/graphRestore.ts", "GLOBAL_REFERENCE_LABELS"),
    ("webapp/src/lib/mcp/graphGuard.ts", "GLOBAL_REFERENCE_LABELS"),
)


def _ts_list(relpath, name):
    with open(os.path.join(_REPO, relpath), encoding="utf-8") as f:
        src = f.read()
    m = re.search(
        rf"\bconst {name}\b[^=]*=\s*(?:new Set\(\s*)?\[(.*?)\]", src, re.S)
    if not m:
        raise AssertionError(
            f"{name} not found in {relpath}: if it was renamed or moved, point "
            f"TS_COPIES at the new spelling instead of dropping the check")
    body = re.sub(r"//[^\n]*", "", m.group(1))
    return re.findall(r"""['"]([^'"]+)['"]""", body)


class TestPythonCopies(unittest.TestCase):
    def test_the_source_is_not_empty(self):
        """An empty source would make every equality below vacuous."""
        self.assertTrue(GLOBAL_REFERENCE_LABELS)

    def test_schema_exposes_the_tenant_filter_list(self):
        """base_mixin's clears and the reference-node tenant strip read it."""
        labels = schema.GLOBAL_REFERENCE_LABELS
        self.assertEqual(set(labels), set(GLOBAL_REFERENCE_LABELS))
        self.assertEqual(len(labels), len(set(labels)))

    def test_no_exempt_label_has_a_tenant_scoped_key(self):
        """A label whose uniqueness key carries user_id/project_id is
        per-tenant data, so exempting it from the filter reads across tenants.
        Each exempt label must also be declared, or it is not a real label."""
        keys = {k["label"]: k["key_properties"] for k in schema_keys.KEY_CONSTRAINTS}
        for label in sorted(GLOBAL_REFERENCE_LABELS):
            with self.subTest(label=label):
                self.assertIn(label, keys, "not declared in graph_db/schema_keys.py")
                self.assertFalse(
                    {"user_id", "project_id"} & set(keys[label]),
                    f"{label} is keyed per tenant: {keys[label]}")


class TestTypeScriptCopies(unittest.TestCase):
    def setUp(self):
        if not os.path.isdir(_WEBAPP_SRC):
            self.skipTest(f"webapp sources not present ({_WEBAPP_SRC})")

    def test_every_copy_equals_the_tenant_filter_list(self):
        source = set(GLOBAL_REFERENCE_LABELS)
        for relpath, name in TS_COPIES:
            with self.subTest(copy=f"{relpath}:{name}"):
                labels = _ts_list(relpath, name)
                self.assertEqual(len(labels), len(set(labels)), f"duplicates: {labels}")
                self.assertEqual(
                    set(labels), source,
                    f"{relpath} {name} drifted from graph_db/tenant_filter.py: "
                    f"exempt only in the copy={sorted(set(labels) - source)}, "
                    f"missing from the copy={sorted(source - set(labels))}")


if __name__ == "__main__":
    unittest.main()
