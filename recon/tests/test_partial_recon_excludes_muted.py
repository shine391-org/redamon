"""Regression: a muted finding still seeded a partial re-scan.

`graph_builders.py` reads JsReconFinding nodes out of the graph to build the
target list for a partial GraphQL re-run. It was not mute-aware, so a finding an
operator had suppressed as noise was still used to DRIVE a new scan -- and the
scan then re-created findings from it. Mute held everywhere it was read for
DISPLAY and nowhere it was read for INPUT.

This is a ninth read path; the feature plan's inventory listed eight. Plan 12.12
then replaced that query: JS Recon writes its GraphQL endpoints as Endpoint
nodes, so the seed reads those, and no finding label seeds the scan.

Asserted on the query source rather than against a live database: the defect was
a missing clause in the Cypher, the surrounding function needs a real Neo4j
session and a fully built recon_data dict, and the clause is what regresses.

Run: python -m pytest recon/tests/test_partial_recon_excludes_muted.py
"""

import os
import re
import sys
import unittest

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _RECON not in sys.path:
    sys.path.insert(0, _RECON)

_BUILDERS = os.path.join(_RECON, "partial_recon_modules", "graph_builders.py")

#: Labels an operator can suppress. Anything read out of the graph to seed a
#: scan must exclude them. Mirrors MUTEABLE_LABELS in the triage mixin.
MUTEABLE = (
    "Vulnerability", "JsReconFinding", "Secret", "MultiscannerFinding",
    "GithubSecret", "GithubSensitiveFile", "MalPackageFinding", "ExploitGvm",
)


def source() -> str:
    with open(_BUILDERS, encoding="utf-8") as fh:
        return fh.read()


def cypher_blocks(src: str) -> list:
    """Every triple-quoted block in the file that runs a MATCH."""
    return [b for b in re.findall(r'"""(.*?)"""', src, re.DOTALL) if "MATCH" in b]


class TestMutedFindingsDoNotSeedAScan(unittest.TestCase):
    def test_the_graphql_seed_reads_endpoints_not_findings(self):
        # The GraphQL seed used to read JsReconFinding, and once let muted ones
        # back in. JS Recon writes its GraphQL endpoints as Endpoint nodes (an
        # asset, never muted), and the finding query matched nothing, so plan
        # 12.12 replaced it: no finding label seeds the GraphQL scan any more.
        blocks = [b for b in cypher_blocks(source()) if "endpoint_type" in b]
        self.assertTrue(blocks, "the GraphQL Endpoint seed query is missing")
        for block in blocks:
            self.assertIn("e.endpoint_type IN ['graphql', 'graphql_introspection']", block)
        self.assertFalse([b for b in cypher_blocks(source()) if "JsReconFinding" in b
                          and "graphql" in b.lower()])

    def test_every_seed_query_reading_a_finding_label_excludes_muted(self):
        # The general rule, so the next seed query added here cannot repeat it.
        offenders = []
        for block in cypher_blocks(source()):
            for label in MUTEABLE:
                if re.search(rf":{label}\b", block) and "Muted" not in block:
                    offenders.append((label, block.strip().splitlines()[0][:70]))
        self.assertEqual(offenders, [],
                         f"seed queries reading findings without a mute filter: {offenders}")

    def test_the_scanner_still_finds_its_extractor(self):
        # Guards the test itself: a regex that matched nothing would make the
        # assertions above vacuously true.
        self.assertGreater(len(cypher_blocks(source())), 3)


if __name__ == "__main__":
    unittest.main()
