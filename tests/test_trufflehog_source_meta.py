"""TruffleHog result normalisation: source metadata, validation status, ids.

The old extractor understood three metadata keys (Github, Git, Filesystem) and
returned all-empty strings for everything else. That is the quietest failure in
the whole feature: an empty ``asset`` drops the ``HAS_FINDING`` edge AND collapses
every dedup key to the same string, so all findings from that source but one
disappear with no error anywhere. One fixture per key, plus the unknown-key
fallback, is what keeps that from coming back.
"""

import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from trufflehog_scan import findings as fnd  # noqa: E402


def result(meta_key, meta, **top):
    payload = {
        "DetectorName": "AWS",
        "DetectorDescription": "AWS access key",
        "Verified": False,
        "Redacted": "AKIA****",
        "SourceMetadata": {"Data": {meta_key: meta}},
    }
    payload.update(top)
    return payload


class TestSourceMetaPerKey(unittest.TestCase):
    def test_github(self):
        meta = fnd.extract_source_meta(result("Github", {
            "repository": "https://github.com/acme/api.git", "file": "src/app.py",
            "commit": "deadbeef", "line": 42, "email": "dev@acme.io",
            "link": "https://github.com/acme/api/blob/deadbeef/src/app.py#L42",
        }))
        self.assertEqual(meta["asset"], "https://github.com/acme/api.git")
        self.assertEqual(meta["location"], "src/app.py")
        self.assertEqual(meta["commit"], "deadbeef")
        self.assertEqual(meta["line"], 42)

    def test_git(self):
        meta = fnd.extract_source_meta(result("Git", {
            "repository": "https://git.example.com/a.git", "file": "conf/.env", "commit": "abc123",
        }))
        self.assertEqual(meta["asset"], "https://git.example.com/a.git")
        self.assertEqual(meta["location"], "conf/.env")

    def test_gitlab(self):
        meta = fnd.extract_source_meta(result("Gitlab", {
            "repository": "https://gitlab.com/acme/api.git", "file": "ci/deploy.sh",
        }))
        self.assertEqual(meta["asset"], "https://gitlab.com/acme/api.git")

    def test_docker_capitalised_keys_and_extras(self):
        # docker.go emits Image, Tag, Layer and File — all capitalised, unlike
        # the git family's lowercase keys.
        meta = fnd.extract_source_meta(result("Docker", {
            "Image": "acme/app", "Tag": "1.25", "Layer": "sha256:abcd", "File": "/app/.env",
        }))
        self.assertEqual(meta["asset"], "acme/app")
        self.assertEqual(meta["location"], "/app/.env")
        self.assertEqual(meta["extra"]["Tag"], "1.25")
        self.assertEqual(meta["extra"]["Layer"], "sha256:abcd")

    def test_huggingface(self):
        meta = fnd.extract_source_meta(result("HuggingFace", {
            "repository": "acme/llm", "file": "config.json", "commit": "r1",
        }))
        self.assertEqual(meta["asset"], "acme/llm")
        self.assertEqual(meta["location"], "config.json")

    def test_s3_and_gcs(self):
        s3 = fnd.extract_source_meta(result("S3", {"bucket": "acme-prod", "file": "dumps/db.sql"}))
        self.assertEqual((s3["asset"], s3["location"]), ("acme-prod", "dumps/db.sql"))
        gcs = fnd.extract_source_meta(result("GCS", {"bucket": "acme-gcs", "filename": "keys.json"}))
        self.assertEqual((gcs["asset"], gcs["location"]), ("acme-gcs", "keys.json"))

    def test_filesystem(self):
        meta = fnd.extract_source_meta(result("Filesystem", {"file": "/scan-roots/recon_output/x.json"}))
        self.assertEqual(meta["location"], "/scan-roots/recon_output/x.json")

    def test_jenkins(self):
        meta = fnd.extract_source_meta(result("Jenkins", {
            "jenkins_url": "https://ci.acme.io", "project_name": "deploy-prod", "build_number": 42,
        }))
        self.assertEqual(meta["asset"], "https://ci.acme.io")
        self.assertEqual(meta["location"], "deploy-prod")

    def test_elasticsearch(self):
        meta = fnd.extract_source_meta(result("Elasticsearch", {
            "node": "es-01", "index": "logs-2026", "document_id": "abc",
        }))
        self.assertEqual(meta["asset"], "es-01")
        self.assertEqual(meta["location"], "logs-2026")

    def test_postman(self):
        meta = fnd.extract_source_meta(result("Postman", {
            "workspace_name": "Acme API", "collection_name": "Auth", "environment": "prod",
        }))
        self.assertEqual(meta["asset"], "Acme API")
        self.assertEqual(meta["location"], "Auth")

    def test_circleci_and_travisci(self):
        cci = fnd.extract_source_meta(result("CircleCI", {"project": "acme/api", "build_number": 7}))
        self.assertTrue(cci["asset"])
        tci = fnd.extract_source_meta(result("TravisCI", {"repository": "acme/api", "username": "svc"}))
        self.assertEqual(tci["asset"], "acme/api")

    def test_every_registered_source_has_a_metadata_spec(self):
        # A source that can be started but whose findings cannot be read produces
        # a scan with zero results and no error.
        from trufflehog_scan import sources as reg
        for source_id in reg.SOURCES:
            meta_key = fnd.SOURCE_META_KEYS.get(source_id)
            self.assertIsNotNone(meta_key, f"{source_id} has no metadata key mapping")
            self.assertIn(meta_key, fnd._META_SPECS,
                          f"{source_id} can be scanned but its findings cannot be read")

    def test_github_experimental_reports_under_the_github_key(self):
        self.assertEqual(fnd.SOURCE_META_KEYS["github_experimental"], "github")


class TestUnknownMetadataKey(unittest.TestCase):
    def test_unknown_key_degrades_visibly(self):
        seen = []
        meta = fnd.extract_source_meta(
            result("Slack", {"channel": "#general", "file": "pinned.txt"}),
            on_unknown=seen.append,
        )
        self.assertEqual(seen, ["Slack"])
        self.assertEqual(meta["asset"], "unknown:Slack")
        # Never empty: an empty asset drops the edge AND collapses the dedup key.
        self.assertTrue(meta["asset"])
        self.assertEqual(meta["location"], "pinned.txt")

    def test_unknown_key_findings_still_dedup_apart(self):
        a = fnd.normalise(result("Slack", {"file": "a.txt"}), "github")
        b = fnd.normalise(result("Slack", {"file": "b.txt"}), "github")
        self.assertNotEqual(
            fnd.dedup_key("github", a["asset"], a["location"], a["line"], a["detector_name"]),
            fnd.dedup_key("github", b["asset"], b["location"], b["line"], b["detector_name"]),
        )

    def test_missing_metadata_block_is_survivable(self):
        meta = fnd.extract_source_meta({"DetectorName": "AWS"})
        self.assertEqual(meta["asset"], "")
        self.assertEqual(meta["line"], 0)


class TestValidationStatus(unittest.TestCase):
    """6.5a: 'not live' and 'never checked' must never collapse into one state."""

    def test_verified_is_validated(self):
        self.assertEqual(fnd.validation_status({"Verified": True}), fnd.VALIDATED)

    def test_verification_ran_and_failed_is_rejected(self):
        self.assertEqual(fnd.validation_status({"Verified": False}), fnd.REJECTED)

    def test_verify_error_is_not_proof_of_death(self):
        status = fnd.validation_status({"Verified": False, "VerificationError": "dial tcp: timeout"})
        self.assertEqual(status, fnd.VERIFY_ERROR)
        self.assertNotEqual(status, fnd.REJECTED)

    def test_verification_disabled_makes_everything_unverified(self):
        # Even a `Verified: true` payload cannot be trusted as live when we told
        # TruffleHog not to verify.
        self.assertEqual(fnd.validation_status({"Verified": True}, verification_enabled=False),
                         fnd.UNVERIFIED)
        self.assertEqual(fnd.validation_status({"Verified": False}, verification_enabled=False),
                         fnd.UNVERIFIED)

    def test_statuses_are_the_four_documented_ones(self):
        self.assertEqual(set(fnd.VALIDATION_STATUSES),
                         {"validated", "rejected", "verify_error", "unverified"})


class TestStableIds(unittest.TestCase):
    """6.6: builtin hash() is randomised per process; ids must not be."""

    def test_digest_is_deterministic_and_short(self):
        d = fnd.digest("u1", "p1", "acme/api")
        self.assertEqual(len(d), 12)
        self.assertEqual(d, fnd.digest("u1", "p1", "acme/api"))

    def test_digest_separates_fields_unambiguously(self):
        # "ab"+"c" and "a"+"bc" must not collide.
        self.assertNotEqual(fnd.digest("ab", "c"), fnd.digest("a", "bc"))

    def test_digest_matches_a_precomputed_value(self):
        # Pinned so a future refactor to a different algorithm is caught here
        # rather than by orphaned graph nodes after a re-scan.
        import hashlib
        expected = hashlib.sha1(b"u1\x1fp1\x1facme/api").hexdigest()[:12]
        self.assertEqual(fnd.digest("u1", "p1", "acme/api"), expected)

    def test_dedup_key_is_source_scoped(self):
        # The same secret in the same place found by two sources is two findings.
        self.assertNotEqual(
            fnd.dedup_key("docker", "acme/app", "/app/.env", 1, "AWS"),
            fnd.dedup_key("github", "acme/app", "/app/.env", 1, "AWS"),
        )


class TestNormalise(unittest.TestCase):
    def test_full_shape(self):
        finding = fnd.normalise(
            result("Github", {"repository": "acme/api", "file": "app.py", "line": 3, "commit": "c1"},
                   Verified=True, ExtraData={"account": "1234"}),
            "github",
        )
        self.assertEqual(finding["source"], "github")
        # Canonicalised to the clone-URL form: a github `repository` arrives as a
        # bare slug from a comment and as a clone URL from a file, and one repo
        # must be ONE asset. See test_github_comment_asset_matches_the_file_asset.
        self.assertEqual(finding["asset"], "https://github.com/acme/api.git")
        self.assertEqual(finding["location"], "app.py")
        self.assertEqual(finding["validation_status"], "validated")
        self.assertEqual(finding["finding_kind"], "secret")
        self.assertEqual(json.loads(finding["extra_data"])["account"], "1234")

    def test_deprecated_aliases_mirror_the_new_fields(self):
        # Kept for one release so existing report Cypher keeps matching (6.5).
        finding = fnd.normalise(result("Github", {"repository": "acme/api", "file": "app.py"}), "github")
        self.assertEqual(finding["repository"], finding["asset"])
        self.assertEqual(finding["file"], finding["location"])

    def test_raw_secret_bytes_are_never_carried_forward(self):
        finding = fnd.normalise(result("Github", {"repository": "a"}, Raw="AKIAREALSECRET"), "github")
        self.assertNotIn("AKIAREALSECRET", json.dumps(finding))

    def test_docker_history_findings_are_labelled(self):
        finding = fnd.normalise(result("Docker", {
            "Image": "acme/app", "Tag": "1.0",
            "File": "image-metadata:history:3:created-by",
        }), "docker")
        self.assertEqual(finding["finding_kind"], "image_history")

    def test_docker_asset_name_carries_the_tag(self):
        # Two tags of one image can hold different secrets, so they must be
        # different asset nodes.
        meta = fnd.extract_source_meta(result("Docker", {"Image": "acme/app", "Tag": "1.0"}))
        self.assertEqual(fnd.asset_name("docker", meta), "acme/app:1.0")

    def test_docker_asset_name_left_alone_when_already_qualified(self):
        meta = fnd.extract_source_meta(result("Docker", {"Image": "acme/app:2.0", "Tag": "2.0"}))
        self.assertEqual(fnd.asset_name("docker", meta), "acme/app:2.0")

    def test_github_comment_asset_matches_the_file_asset(self):
        # THE bug this exists for: TruffleHog reports `repository` as a clone URL
        # for a finding in a file, but as a bare `owner/repo` for one in an issue
        # or PR comment. Verbatim, that is two asset nodes for ONE repository -
        # the repo's findings split across both, and assets_scanned inflated.
        in_file = fnd.extract_source_meta(result("Github", {
            "repository": "https://github.com/acme/api.git", "file": "app.py",
            "link": "https://github.com/acme/api/blob/deadbeef/app.py#L1",
        }))
        in_comment = fnd.extract_source_meta(result("Github", {
            "repository": "acme/api",
            "link": "https://github.com/acme/api/issues/7#issuecomment-1",
        }))
        self.assertEqual(fnd.asset_name("github", in_file),
                         fnd.asset_name("github", in_comment))
        self.assertEqual(fnd.asset_name("github", in_comment),
                         "https://github.com/acme/api.git")

    def test_github_comment_asset_keeps_an_enterprise_host(self):
        # The host comes from the finding's own link, not a hardcoded
        # github.com: rewriting a GHE repo as a github.com one would merge two
        # different hosts' repositories of the same name into one node.
        meta = fnd.extract_source_meta(result("Github", {
            "repository": "acme/api",
            "link": "https://ghe.acme.io/acme/api/pull/3#issuecomment-9",
        }))
        self.assertEqual(fnd.asset_name("github", meta),
                         "https://ghe.acme.io/acme/api.git")

    def test_github_gist_asset_is_left_alone(self):
        # A gist already arrives as a URL, on a different host, and must not be
        # rewritten into a repository coordinate.
        meta = fnd.extract_source_meta(result("Github", {
            "repository": "https://gist.github.com/abc123.git", "file": "notes.md",
        }))
        self.assertEqual(fnd.asset_name("github", meta),
                         "https://gist.github.com/abc123.git")

    def test_github_experimental_shares_the_normalisation(self):
        # github-experimental reports under the same `Github` metadata key, so it
        # would grow the same split.
        meta = fnd.extract_source_meta(result("Github", {"repository": "acme/api"}))
        self.assertEqual(fnd.asset_name("github_experimental", meta),
                         "https://github.com/acme/api.git")

    def test_asset_falls_back_to_the_run_target_when_metadata_has_none(self):
        # Filesystem metadata is just file+line. An empty asset drops the graph
        # edge and collapses the dedup key for every finding of the source.
        finding = fnd.normalise(
            result("Filesystem", {"file": "/scan-roots/recon_output/a.env", "line": 1}),
            "filesystem", default_asset="recon_output",
        )
        self.assertEqual(finding["asset"], "recon_output")

    def test_asset_is_never_empty_even_with_no_target(self):
        finding = fnd.normalise(result("Filesystem", {"file": "a.env"}), "filesystem")
        self.assertTrue(finding["asset"])

    def test_metadata_asset_wins_over_the_fallback(self):
        finding = fnd.normalise(
            result("Github", {"repository": "acme/api", "file": "a.py"}),
            "github", default_asset="acme",
        )
        # The point of this test is that metadata beats `default_asset`; the
        # value is the canonical github spelling of that same metadata.
        self.assertEqual(finding["asset"], "https://github.com/acme/api.git")

    def test_verification_disabled_propagates_into_the_finding(self):
        finding = fnd.normalise(result("Github", {"repository": "a"}, Verified=False),
                                "github", verification_enabled=False)
        self.assertEqual(finding["validation_status"], "unverified")


if __name__ == "__main__":
    unittest.main()


class TestRealBinaryOutputShapes(unittest.TestCase):
    """Shapes captured from the PINNED binary (trufflehog 3.96.0), not inferred.

    The docker block is the reason these exist: the upstream Go struct fields are
    `Image`/`File`/`Layer`, but 3.96.0 emits them LOWERCASE. An exact-match
    lookup on the documented capitalisation would have produced an empty asset —
    which drops the graph edge and collapses the dedup key for every docker
    finding, with no error anywhere.
    """

    def test_real_git_metadata_from_3_96_0(self):
        meta = fnd.extract_source_meta({"SourceMetadata": {"Data": {"Git": {
            "commit": "207a8d0198b7795967da11124ed8b3356732d73f",
            "file": "config.env",
            "email": "Dev <dev@example.test>",
            "repository": "file:///w/repo",
            "timestamp": "2026-08-17 12:18:43 +0000",
            "line": 1,
            "repository_local_path": "/tmp/trufflehog-77-3142031296",
        }}}})
        self.assertEqual(meta["asset"], "file:///w/repo")
        self.assertEqual(meta["location"], "config.env")
        self.assertEqual(meta["commit"], "207a8d0198b7795967da11124ed8b3356732d73f")
        self.assertEqual(meta["line"], 1)
        self.assertEqual(meta["email"], "Dev <dev@example.test>")

    def test_real_docker_metadata_is_lowercase_in_3_96_0(self):
        meta = fnd.extract_source_meta({"SourceMetadata": {"Data": {"Docker": {
            "file": "image-metadata:history:2:created-by",
            "image": "/w/probe.tar",
            "layer": "sha256:5c4b4e76e94f35ce46133a596e2b2590925a4ef372bba23188d5a2c021518a5b",
        }}}})
        self.assertEqual(meta["asset"], "/w/probe.tar")
        self.assertEqual(meta["location"], "image-metadata:history:2:created-by")
        self.assertEqual(meta["extra"]["Layer"], meta["extra"].get("Layer"))
        self.assertTrue(any("sha256:" in str(v) for v in meta["extra"].values()))

    def test_the_documented_capitalisation_also_still_works(self):
        # Whichever way a future release spells them.
        meta = fnd.extract_source_meta({"SourceMetadata": {"Data": {"Docker": {
            "File": "/app/.env", "Image": "acme/app", "Tag": "1.0", "Layer": "sha256:abc",
        }}}})
        self.assertEqual(meta["asset"], "acme/app")
        self.assertEqual(meta["location"], "/app/.env")

    def test_a_real_history_path_is_classified_as_image_history(self):
        # Verified against the binary: a secret in a RUN directive reports this path.
        self.assertEqual(fnd.finding_kind("image-metadata:history:2:created-by"),
                         fnd.KIND_IMAGE_HISTORY)

    def test_verification_error_field_name_matches_the_binary(self):
        # Captured from a real run with verification on and no network.
        result = {"Verified": False, "VerificationError":
                  "lookup sts.us-east-1.amazonaws.com: network is unreachable"}
        self.assertEqual(fnd.validation_status(result), fnd.VERIFY_ERROR)

    def test_raw_secret_fields_the_binary_emits_are_never_carried_forward(self):
        # 3.96.0 emits Raw, RawV2 AND SecretParts; all three hold the real secret.
        finding = fnd.normalise({
            "DetectorName": "AWS", "Verified": False, "Redacted": "AKIA****",
            "Raw": "AKIA7QF2ML9XKPD3WR5T",
            "RawV2": "AKIA7QF2ML9XKPD3WR5T:SECRETVALUE",
            "SecretParts": {"access_key_id": "AKIA7QF2ML9XKPD3WR5T",
                            "secret_access_key": "SECRETVALUE"},
            "SourceMetadata": {"Data": {"Git": {"repository": "r", "file": "f"}}},
        }, "git")
        blob = json.dumps(finding)
        self.assertNotIn("SECRETVALUE", blob)
        self.assertNotIn("AKIA7QF2ML9XKPD3WR5T", blob)
