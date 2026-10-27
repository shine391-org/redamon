"""TruffleHog graph ingest: source-scoped clearing, stable ids, tenant MERGE keys.

The first test here is the one the whole multi-source migration hinges on:
**ingest source A, ingest source B, assert A survives.** The old ingest called an
unscoped `clear_trufflehog_data` at its head, so the Docker scan finishing would
DETACH DELETE every HuggingFace finding — with no error, no warning, and a
perfect-looking JSON artifact left behind to suggest everything worked.

Driven against a fake Neo4j session that records Cypher + parameters and models
MERGE/DELETE semantics, so the write contract is checked without a live
database. `tests/test_trufflehog_graph_live.py` covers the same paths against a
real Neo4j when a stack is up.
"""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from graph_db.mixins.secret_mixin import SecretMixin  # noqa: E402


from trufflehog_graph_fake import (  # noqa: E402
    FakeClient, finding, scan_payload,
)


# ---------------------------------------------------------------------------

class TestScopedClearPreservesOtherSources(unittest.TestCase):
    """THE test. Everything else in the migration is recoverable; this is not."""

    def test_ingesting_source_b_does_not_erase_source_a(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("huggingface", "model", [finding("acme/llm", "config.json")]),
            "u1", "p1")
        self.assertEqual(len(c.findings("huggingface")), 1)

        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app:1.0", "/app/.env")]),
            "u1", "p1")

        self.assertEqual(len(c.findings("huggingface")), 1,
                         "the docker ingest erased the huggingface findings")
        self.assertEqual(len(c.findings("docker")), 1)

    def test_each_source_keeps_its_own_scan_node(self):
        c = FakeClient()
        for source, kind in (("docker", "image"), ("huggingface", "model"), ("github", "repository")):
            c.update_graph_from_trufflehog(
                scan_payload(source, kind, [finding("a")]), "u1", "p1")
        scans = c.nodes_of("MultiscannerScan")
        self.assertEqual(len(scans), 3)
        self.assertEqual(sorted(s["source"] for s in scans),
                         ["docker", "github", "huggingface"])

    def test_re_running_one_source_replaces_only_its_own_findings(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [finding("acme/api", "a.py")]), "u1", "p1")
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app", "/x")]), "u1", "p1")
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [finding("acme/api", "b.py")]), "u1", "p1")

        github = c.findings("github")
        self.assertEqual([f["location"] for f in github], ["b.py"])
        self.assertEqual(len(c.findings("docker")), 1)

    def test_ingest_always_uses_the_scoped_clear(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("a")]), "u1", "p1")
        # An "__ALL__" entry means an unscoped wipe ran during ingest.
        self.assertNotIn("__ALL__", [scope for _label, scope in c.store["deletes"]])

    def test_unscoped_clear_remains_available_for_project_deletion(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("a")]), "u1", "p1")
        c.update_graph_from_trufflehog(
            scan_payload("github", "repository", [finding("b")]), "u1", "p1")
        c.clear_trufflehog_data("u1", "p1")
        self.assertEqual(c.findings(), [])
        self.assertEqual(c.nodes_of("MultiscannerScan"), [])

    def test_scoped_clear_sweeps_every_asset_label(self):
        # Missing one label leaks its nodes forever; a source is never re-run to
        # clean them up.
        c = FakeClient()
        c.clear_trufflehog_data("u1", "p1", source="docker")
        swept = {label for label, _scope in c.store["deletes"]}
        for label in SecretMixin.TRUFFLEHOG_ALL_ASSET_LABELS:
            self.assertIn(label, swept)

    def test_legacy_untagged_nodes_are_swept_with_github(self):
        """Nodes written before the multi-source model carry no `source`. The
        scanner was github-only then, so that is what they are — and only the
        github clear may claim them."""
        c = FakeClient()
        c.store["nodes"][("MultiscannerFinding", (("id", "legacy"), ("project_id", "p1"), ("user_id", "u1")))] = {
            "id": "legacy", "user_id": "u1", "project_id": "p1", "source": None,
        }
        c.clear_trufflehog_data("u1", "p1", source="docker")
        self.assertEqual(len(c.findings()), 1, "a docker clear took the legacy github data")

        c.clear_trufflehog_data("u1", "p1", source="github")
        self.assertEqual(len(c.findings()), 0)

    def test_another_project_is_never_touched(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("a")]), "u1", "p1")
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("b")]), "u1", "p2")
        c.clear_trufflehog_data("u1", "p1", source="docker")
        remaining = c.findings()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["project_id"], "p2")


class TestTenantScopedMerge(unittest.TestCase):
    """A MERGE missing the tenant keys merges one project's data into another's."""

    def test_every_node_merges_on_the_tenant_triple(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app")]), "u1", "p1")
        self.assertTrue(c.store["merge_keys"])
        for label, keys in c.store["merge_keys"]:
            self.assertEqual(
                keys, ("id", "project_id", "user_id"),
                f"{label} MERGEs on {keys}, not the tenant triple",
            )

    def test_two_tenants_do_not_share_a_node(self):
        c = FakeClient()
        payload = scan_payload("docker", "image", [finding("acme/app")])
        c.update_graph_from_trufflehog(payload, "u1", "p1")
        c.update_graph_from_trufflehog(payload, "u2", "p2")
        self.assertEqual(len(c.nodes_of("MultiscannerScan")), 2)
        self.assertEqual(len(c.findings()), 2)


class TestNodeShape(unittest.TestCase):
    def test_asset_label_follows_the_source_shape(self):
        cases = {
            "repository": "MultiscannerRepository",
            "image": "MultiscannerImage",
            "model": "MultiscannerModel",
            "bucket": "MultiscannerBucket",
            "endpoint": "MultiscannerEndpoint",
        }
        for kind, label in cases.items():
            c = FakeClient()
            c.update_graph_from_trufflehog(
                scan_payload("docker", kind, [finding("asset-x")]), "u1", "p1")
            self.assertEqual(len(c.nodes_of(label)), 1, f"{kind} -> {label}")

    def test_unknown_asset_kind_falls_back_to_endpoint(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "spaceship", [finding("a")]), "u1", "p1")
        self.assertEqual(len(c.nodes_of("MultiscannerEndpoint")), 1)

    def test_relationship_chain(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app")]), "u1", "p1")
        self.assertIn("HAS_MULTISCANNER_SCAN", c.store["rels"])
        self.assertIn("HAS_ASSET", c.store["rels"])
        self.assertIn("HAS_FINDING", c.store["rels"])

    def test_source_is_stamped_on_every_level(self):
        # The scoped clear matches on it; a node without one can never be cleaned.
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app")]), "u1", "p1")
        for label in ("MultiscannerScan", "MultiscannerImage", "MultiscannerFinding"):
            for node in c.nodes_of(label):
                self.assertEqual(node["source"], "docker", f"{label} has no source")

    def test_findings_dedup_within_a_source(self):
        c = FakeClient()
        dup = finding("acme/app", "/x", "AWS", 1)
        stats = c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [dup, dict(dup)]), "u1", "p1")
        self.assertEqual(stats["findings_deduplicated"], 1)
        self.assertEqual(len(c.findings()), 1)

    def test_identical_findings_from_two_sources_are_two_nodes(self):
        c = FakeClient()
        same = finding("acme/app", "/app/.env", "AWS", 1)
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [dict(same)]), "u1", "p1")
        c.update_graph_from_trufflehog(
            scan_payload("filesystem", "endpoint", [dict(same)]), "u1", "p1")
        self.assertEqual(len(c.findings()), 2)

    def test_findings_without_a_detector_are_skipped(self):
        c = FakeClient()
        stats = c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("a", detector="")]), "u1", "p1")
        self.assertEqual(stats["findings_created"], 0)

    def test_payload_without_a_source_is_refused(self):
        # Writing it would produce nodes no scoped clear can ever match.
        c = FakeClient()
        stats = c.update_graph_from_trufflehog(
            {"target": "x", "findings": [finding("a")]}, "u1", "p1")
        self.assertEqual(stats["findings_created"], 0)
        self.assertTrue(stats["errors"])

    def test_deprecated_aliases_are_still_written(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app", "/app/.env")]), "u1", "p1")
        node = c.findings()[0]
        self.assertEqual(node["repository"], node["asset"])
        self.assertEqual(node["file"], node["location"])


class TestValidationStatus(unittest.TestCase):
    def test_scanner_supplied_status_is_preserved(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image",
                         [finding("a", validation_status="unverified", verified=False)]),
            "u1", "p1")
        self.assertEqual(c.findings()[0]["validation_status"], "unverified")

    def test_status_is_derived_when_absent(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [
                dict(finding("a", "x1"), validation_status="", verified=True),
                dict(finding("a", "x2"), validation_status="", verified=False),
                dict(finding("a", "x3"), validation_status="", verified=False,
                     verification_error="timeout"),
            ]), "u1", "p1")
        by_location = {f["location"]: f["validation_status"] for f in c.findings()}
        self.assertEqual(by_location["x1"], "validated")
        self.assertEqual(by_location["x2"], "rejected")
        self.assertEqual(by_location["x3"], "verify_error")

    def test_finding_kind_is_carried(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image",
                         [finding("a", finding_kind="image_history")]), "u1", "p1")
        self.assertEqual(c.findings()[0]["finding_kind"], "image_history")


class TestStableIds(unittest.TestCase):
    """6.6: builtin hash() is randomised per process, so the same asset used to
    get a new node id on every run. The blanket clear hid it; scoped clearing
    would have made it visible as duplicated and orphaned nodes."""

    def test_ids_are_deterministic_across_clients(self):
        ids = []
        for _ in range(2):
            c = FakeClient()
            c.update_graph_from_trufflehog(
                scan_payload("docker", "image", [finding("acme/app", "/app/.env")]),
                "u1", "p1")
            ids.append(sorted(n["id"] for n in c.store["nodes"].values() if "id" in n))
        self.assertEqual(ids[0], ids[1])

    def test_ids_embed_the_source(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding("acme/app")]), "u1", "p1")
        self.assertTrue(c.nodes_of("MultiscannerScan")[0]["id"].endswith("-docker"))
        self.assertIn("-docker-", c.findings()[0]["id"])

    def test_digest_matches_the_scanner_side_implementation(self):
        """The two live in different images and cannot import each other; if they
        disagree, every re-scan orphans the previous run's nodes."""
        sys.path.insert(0, str(REPO_ROOT / "scanners"))
        from trufflehog_scan.findings import digest as scanner_digest
        parts = ("u1", "p1", "docker:acme/app:/app/.env:1:AWS")
        self.assertEqual(SecretMixin._trufflehog_digest(*parts), scanner_digest(*parts))

    def test_digest_is_12_hex_chars(self):
        d = SecretMixin._trufflehog_digest("a", "b")
        self.assertEqual(len(d), 12)
        self.assertRegex(d, r"^[0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()


class TestBackwardCompatibility(unittest.TestCase):
    """Old rows and old artifacts must keep working: the graph holds nodes
    written before this change, and an out.json from a previous release can be
    re-ingested after an upgrade."""

    def test_a_pre_migration_finding_without_validation_status_is_derived(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(scan_payload("github", "repository", [{
            # exactly the old finding shape: no source, no validation_status,
            # no finding_kind, and the pre-rename repository/file keys.
            "detector_name": "AWS", "verified": True,
            "repository": "acme/api", "file": "app.py", "line": 3,
        }]), "u1", "p1")
        node = c.findings()[0]
        self.assertEqual(node["validation_status"], "validated")
        self.assertEqual(node["finding_kind"], "secret")
        self.assertEqual(node["asset"], "acme/api")
        self.assertEqual(node["location"], "app.py")

    def test_a_payload_without_statistics_still_writes_a_scan_node(self):
        c = FakeClient()
        stats = c.update_graph_from_trufflehog(
            {"source": "docker", "asset_kind": "image", "target": "x", "findings": []},
            "u1", "p1")
        self.assertEqual(stats["scan_created"], 1)
        self.assertEqual(c.nodes_of("MultiscannerScan")[0]["total_findings"], 0)

    def test_ingesting_the_same_payload_twice_is_idempotent(self):
        # The status sweep can retry an ingest; a second pass must leave the
        # same node set, not duplicates.
        c = FakeClient()
        payload = scan_payload("docker", "image", [finding("acme/app", "/app/.env")])
        first = c.update_graph_from_trufflehog(payload, "u1", "p1")
        before = {k: dict(v) for k, v in c.store["nodes"].items()}
        second = c.update_graph_from_trufflehog(payload, "u1", "p1")
        self.assertEqual(first["findings_created"], second["findings_created"])
        self.assertEqual(set(before), set(c.store["nodes"]))


class TestBoundaryAndBadInput(unittest.TestCase):
    def test_a_finding_with_unicode_survives_the_write(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image",
                         [finding("acmé/app:1.0-🐷", "/app/ünïcode.env")]), "u1", "p1")
        node = c.findings()[0]
        self.assertEqual(node["asset"], "acmé/app:1.0-🐷")
        self.assertEqual(node["location"], "/app/ünïcode.env")

    def test_an_empty_findings_list_still_records_the_run(self):
        c = FakeClient()
        c.update_graph_from_trufflehog(scan_payload("s3", "bucket", []), "u1", "p1")
        self.assertEqual(len(c.nodes_of("MultiscannerScan")), 1)
        self.assertEqual(c.findings(), [])

    def test_a_very_long_asset_name_is_not_truncated_into_a_collision(self):
        c = FakeClient()
        a, b = "x" * 4000, "x" * 4000 + "y"
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [finding(a, "/1"), finding(b, "/2")]), "u1", "p1")
        self.assertEqual(len(c.nodes_of("MultiscannerImage")), 2)

    def test_null_versus_missing_fields_behave_the_same(self):
        c = FakeClient()
        explicit_null = dict(finding("a"), link=None, commit=None, timestamp=None)
        c.update_graph_from_trufflehog(
            scan_payload("docker", "image", [explicit_null]), "u1", "p1")
        self.assertEqual(len(c.findings()), 1)

    def test_a_findings_value_that_is_not_a_list_does_not_crash_the_ingest(self):
        c = FakeClient()
        stats = c.update_graph_from_trufflehog(
            {"source": "docker", "asset_kind": "image", "target": "x", "findings": None},
            "u1", "p1")
        self.assertEqual(stats["findings_created"], 0)
