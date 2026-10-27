"""The coverage-stamp vocabulary is declared three times; they must agree (plan 09.1).

graph_db/coverage_stamps.py is the source: the writer refuses any other module
or status. recon/helpers/coverage_stamps.py builds the rows, and
webapp/src/lib/coverageStamps.ts reads them for the node drawer, the report and
MCP graph_summary. A status recon writes but the writer drops never reaches the
graph; one the webapp does not know reads as "not scanned".
"""
import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.coverage_stamps import COVERAGE_FIELDS, COVERAGE_MODULES, COVERAGE_STATUSES  # noqa: E402

_TS = os.path.join(_REPO, "webapp", "src", "lib", "coverageStamps.ts")
_RECON = os.path.join(_REPO, "recon", "helpers", "coverage_stamps.py")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class TestCoverageVocabulary(unittest.TestCase):
    def test_the_webapp_names_the_same_modules_in_the_same_order(self):
        keys = re.findall(r"\{\s*key:\s*'([a-z_]+)'", _read(_TS))
        self.assertEqual(tuple(keys), COVERAGE_MODULES)

    def test_the_webapp_knows_every_status(self):
        m = re.search(r"COVERAGE_STATUSES\s*=\s*\[([^\]]*)\]", _read(_TS))
        self.assertEqual(tuple(re.findall(r"'([a-z_]+)'", m.group(1))), COVERAGE_STATUSES)

    def test_the_webapp_stamps_the_same_fields(self):
        m = re.search(r"const FIELDS\s*=\s*\[([^\]]*)\]", _read(_TS))
        self.assertEqual(tuple(re.findall(r"'([a-z_]+)'", m.group(1))), COVERAGE_FIELDS)

    def test_recon_writes_only_statuses_the_writer_keeps(self):
        m = re.search(r"^STATUSES\s*=\s*\(([^)]*)\)", _read(_RECON), re.M)
        self.assertEqual(tuple(re.findall(r'"([a-z_]+)"', m.group(1))), COVERAGE_STATUSES)


if __name__ == "__main__":
    unittest.main()
