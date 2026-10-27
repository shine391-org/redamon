"""TrufflehogRunner: job file in, findings JSON out.

Covers the run-level contract the orchestrator depends on — one output file per
(project, source), a status that distinguishes "clean" from "failed", and stats
the graph ingest reads — plus the parsing behaviour that decides whether a
parallel run's findings survive.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from trufflehog_scan import findings as fnd  # noqa: E402
from trufflehog_scan import sources as reg  # noqa: E402
from trufflehog_scan.job_config import JobConfig, load_job  # noqa: E402
from trufflehog_scan.trufflehog_runner import TrufflehogRunner  # noqa: E402


def jsonl_result(detector="AWS", repo="acme/api", path="app.py", line=1, verified=False):
    return json.dumps({
        "DetectorName": detector,
        "DetectorDescription": "desc",
        "Verified": verified,
        "Redacted": "AKIA****",
        "SourceMetadata": {"Data": {"Github": {
            "repository": repo, "file": path, "line": line, "commit": "c1",
        }}},
    })


class _FakeProcess:
    """Stands in for the TruffleHog subprocess: emits JSONL, then exits."""

    def __init__(self, lines, returncode=0, stderr=""):
        self.stdout = iter(lines)
        self.stderr = _FakeStream(stderr)
        self.returncode = returncode

    def wait(self):
        return self.returncode


class _FakeStream:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text


class RunnerTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def make_job(self, source="github", config=None, common=None):
        return JobConfig(
            project_id="p1", user_id="u1", source=source,
            config=config if config is not None else {"orgs": ["acme"]},
            common=common or {},
            run_dir=str(self.tmp / "run"),
            output_file=str(self.tmp / f"trufflehog_p1_{source}.json"),
        )

    def run_with(self, runner, lines, returncode=0, stderr=""):
        with patch("subprocess.Popen", return_value=_FakeProcess(lines, returncode, stderr)):
            return runner.run()


class TestJobConfig(RunnerTestCase):
    def test_job_file_wins_over_env(self):
        job_path = self.tmp / "job.json"
        job_path.write_text(json.dumps({
            "project_id": "from-file", "user_id": "u1", "source": "docker",
            "config": {"images": ["nginx:1.25"]}, "common": {"concurrency": 4},
        }))
        job = load_job({"TRUFFLEHOG_JOB": str(job_path), "PROJECT_ID": "from-env"})
        self.assertEqual(job.project_id, "from-file")
        self.assertEqual(job.source, "docker")
        self.assertEqual(job.config["images"], ["nginx:1.25"])

    def test_env_fallback_lets_the_container_be_driven_directly(self):
        job = load_job({"PROJECT_ID": "p1", "TRUFFLEHOG_SOURCE": "github"})
        self.assertEqual(job.project_id, "p1")
        self.assertEqual(job.source, "github")

    def test_output_path_is_per_source(self):
        a = load_job({"PROJECT_ID": "p1", "TRUFFLEHOG_SOURCE": "docker"})
        b = load_job({"PROJECT_ID": "p1", "TRUFFLEHOG_SOURCE": "huggingface"})
        self.assertNotEqual(a.output_file, b.output_file)
        self.assertTrue(a.output_file.endswith("trufflehog_p1_docker.json"))

    def test_dashed_source_is_normalised(self):
        job = load_job({"PROJECT_ID": "p", "TRUFFLEHOG_SOURCE": "github-experimental"})
        self.assertEqual(job.source, "github_experimental")

    def test_verification_enabled_tracks_the_common_switch(self):
        self.assertTrue(JobConfig("p").verification_enabled)
        self.assertFalse(JobConfig("p", common={"skipVerification": True}).verification_enabled)

    def test_run_id_defaults_to_the_source(self):
        # The run key IS the source (C3): one run per source, unlimited distinct.
        job = load_job({"PROJECT_ID": "p", "TRUFFLEHOG_SOURCE": "docker"})
        self.assertEqual(job.run_id, "docker")


class TestRunnerParsing(RunnerTestCase):
    def test_findings_are_collected_and_stats_updated(self):
        runner = TrufflehogRunner(self.make_job(), env={})
        found = self.run_with(runner, [
            jsonl_result(verified=True),
            jsonl_result(detector="Slack", path="b.py", line=9),
            "time=... msg=\"scanning\"",  # non-JSON progress line
        ])
        self.assertEqual(len(found), 2)
        self.assertEqual(runner.stats["total_findings"], 2)
        self.assertEqual(runner.stats["validated"], 1)
        self.assertEqual(runner.stats["rejected"], 1)
        self.assertEqual(runner.stats["assets_scanned"], 1)
        self.assertEqual(runner.stats["detector_types"], {"AWS": 1, "Slack": 1})

    def test_identical_findings_dedup_within_a_run(self):
        runner = TrufflehogRunner(self.make_job(), env={})
        found = self.run_with(runner, [jsonl_result(), jsonl_result()])
        self.assertEqual(len(found), 1)

    def test_non_json_output_never_aborts_the_run(self):
        runner = TrufflehogRunner(self.make_job(), env={})
        found = self.run_with(runner, ["not json at all", "{broken", jsonl_result()])
        self.assertEqual(len(found), 1)

    def test_unknown_metadata_key_is_recorded_in_stats(self):
        runner = TrufflehogRunner(self.make_job(), env={})
        line = json.dumps({
            "DetectorName": "AWS",
            "SourceMetadata": {"Data": {"Slack": {"channel": "#ops", "file": "pin.txt"}}},
        })
        self.run_with(runner, [line])
        self.assertEqual(runner.stats["unknown_metadata_keys"], ["Slack"])

    def test_verification_off_marks_every_finding_unverified(self):
        job = self.make_job(common={"skipVerification": True})
        runner = TrufflehogRunner(job, env={})
        found = self.run_with(runner, [jsonl_result(verified=True)])
        self.assertEqual(found[0]["validation_status"], "unverified")


class TestRunnerOutput(RunnerTestCase):
    def test_output_file_shape(self):
        runner = TrufflehogRunner(self.make_job(source="docker", config={"images": ["nginx:1.25"]}), env={})
        self.run_with(runner, [jsonl_result()])
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["source"], "docker")
        self.assertEqual(data["asset_label"], "MultiscannerImage")
        self.assertEqual(data["asset_kind"], "image")
        self.assertEqual(data["run_id"], "docker")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["target"], "nginx:1.25")
        self.assertTrue(data["verification_enabled"])
        self.assertEqual(len(data["findings"]), 1)

    def test_a_scan_error_reaches_the_artifact(self):
        """The reason for a failure used to be lost entirely: TruffleHog reports
        it as a structured record on stderr, the runner logged the raw line and
        dropped it, and the container is auto-removed - so an errored run carried
        no explanation anywhere."""
        runner = TrufflehogRunner(self.make_job(), env={})
        runner._record_scan_error({
            "level": "error", "msg": "error running scan",
            "error": "failed to stat .git",
        })
        runner._write_final("error")
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["status"], "error")
        self.assertIn("failed to stat .git", data["error"])

    def test_error_is_absent_from_a_completed_artifact(self):
        """Regression: F4 - `error` was emitted whenever any command had failed,
        including on a run that completed. The orchestrator treats its presence
        as the failure signal, so a successful multi-command scan would have
        looked failed."""
        runner = TrufflehogRunner(self.make_job(), env={})
        runner._record_scan_error({"level": "error", "error": "one target refused"})
        runner._write_final("completed")
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["status"], "completed")
        self.assertNotIn("error", data)

    def test_a_scan_error_is_redacted_before_it_is_published(self):
        """The message quotes the target, and for git that is a URI the
        credential was spliced into."""
        env = {"GIT_TOKEN": "ghp_supersecrettoken123456"}
        runner = TrufflehogRunner(self.make_job(source="git", config={"uri": "https://x/y.git"}), env=env)
        runner._record_scan_error({
            "level": "error",
            "error": "could not clone https://u:ghp_supersecrettoken123456@x/y.git",
        })
        runner._write_final("error")
        blob = Path(runner.output_file).read_text()
        self.assertNotIn("ghp_supersecrettoken123456", blob)

    def test_a_duplicate_error_record_is_kept_once(self):
        runner = TrufflehogRunner(self.make_job(), env={})
        for _ in range(3):
            runner._record_scan_error({"level": "error", "error": "same thing"})
        runner._write_final("error")
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["error"].count("same thing"), 1)

    def test_an_empty_error_record_is_ignored(self):
        """Boundary: a record with neither msg nor error must not produce a
        blank `error` key, which reads as a failure with no reason."""
        runner = TrufflehogRunner(self.make_job(), env={})
        runner._record_scan_error({"level": "error"})
        runner._write_final("completed")
        data = json.loads(Path(runner.output_file).read_text())
        self.assertNotIn("error", data)

    def test_envelope_is_written_before_the_first_finding(self):
        # A container killed mid-scan must still leave the ingest step something
        # readable rather than a missing file.
        runner = TrufflehogRunner(self.make_job(), env={})
        seen = {}

        class _Recording(_FakeProcess):
            def __init__(self, lines):
                seen["existed_at_first_line"] = Path(runner.output_file).exists()
                super().__init__(lines)

        with patch("subprocess.Popen", side_effect=lambda *a, **k: _Recording([jsonl_result()])):
            runner.run()
        self.assertTrue(seen["existed_at_first_line"])

    def test_nonzero_exit_with_no_findings_is_an_error_not_a_clean_scan(self):
        # Recording a failed scan as `completed` tells the operator "no secrets
        # here", which is the opposite of what happened.
        runner = TrufflehogRunner(self.make_job(), env={})
        self.run_with(runner, [], returncode=1, stderr="fatal: auth failed")
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["status"], "error")

    def test_nonzero_exit_with_findings_still_completes(self):
        runner = TrufflehogRunner(self.make_job(), env={})
        self.run_with(runner, [jsonl_result()], returncode=1)
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["status"], "completed")

    def test_two_sources_write_to_different_files(self):
        a = TrufflehogRunner(self.make_job(source="github"), env={})
        b = TrufflehogRunner(self.make_job(source="docker", config={"images": ["nginx:1.25"]}), env={})
        self.assertNotEqual(a.output_file, b.output_file)

    def test_invalid_config_fails_before_spawning_anything(self):
        runner = TrufflehogRunner(self.make_job(config={}), env={})
        with patch("subprocess.Popen", side_effect=AssertionError("must not spawn")):
            with self.assertRaises(ValueError):
                runner.run()
        data = json.loads(Path(runner.output_file).read_text())
        self.assertEqual(data["status"], "error")


class TestRunnerLogRedaction(RunnerTestCase):
    def test_command_echo_never_shows_a_credential(self):
        env = {"GIT_USERNAME": "svc", "GIT_TOKEN": "glpat_supersecret"}
        job = self.make_job(source="git", config={"uri": "https://git.example.com/a.git"})
        runner = TrufflehogRunner(job, env=env)
        printed = []
        with patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(str(x) for x in a))):
            self.run_with(runner, [])
        blob = "\n".join(printed)
        self.assertNotIn("glpat_supersecret", blob)
        self.assertIn("git.example.com", blob)

    def test_stderr_from_the_binary_is_redacted_too(self):
        env = {"GITHUB_TOKEN": "ghp_leakedinstderr"}
        runner = TrufflehogRunner(self.make_job(), env=env)
        printed = []
        with patch("builtins.print", side_effect=lambda *a, **k: printed.append(" ".join(str(x) for x in a))):
            self.run_with(runner, [], stderr="auth failed for token ghp_leakedinstderr")
        self.assertNotIn("ghp_leakedinstderr", "\n".join(printed))


class TestDockerExpansion(RunnerTestCase):
    """Scan-all-tags / all-architectures is OUR expansion, not a TruffleHog flag."""

    def _runner(self, config):
        return TrufflehogRunner(self.make_job(source="docker", config=config), env={})

    def test_disabled_by_default(self):
        runner = self._runner({"images": ["nginx:1.25"]})
        commands = runner.build_commands()
        self.assertEqual(len(commands), 1)
        self.assertIn("--image=nginx:1.25", commands[0])

    def test_expansion_produces_one_image_flag_per_digest(self):
        runner = self._runner({"images": ["acme/app"], "scanAllTags": True})
        digests = ["sha256:" + "a" * 64, "sha256:" + "b" * 64]
        with patch.object(TrufflehogRunner, "_list_dockerhub_digests", return_value=digests):
            argv = runner.build_commands()[0]
        self.assertIn(f"--image=acme/app@{digests[0]}", argv)
        self.assertIn(f"--image=acme/app@{digests[1]}", argv)

    def test_max_images_caps_the_pull_count(self):
        # Every expansion multiplies pulls directly against a 10/hour anonymous
        # Docker Hub limit, so the cap is a rate-limit control, not a nicety.
        runner = self._runner({"images": ["acme/app"], "scanAllTags": True, "maxImages": 2})
        digests = [f"sha256:{i:064x}" for i in range(10)]
        with patch.object(TrufflehogRunner, "_list_dockerhub_digests", return_value=digests):
            argv = runner.build_commands()[0]
        self.assertEqual(len([a for a in argv if a.startswith("--image=")]), 2)

    def test_listing_failure_falls_back_to_the_plain_reference(self):
        runner = self._runner({"images": ["acme/app"], "scanAllTags": True})
        with patch.object(TrufflehogRunner, "_list_dockerhub_digests", return_value=[]):
            argv = runner.build_commands()[0]
        self.assertIn("--image=acme/app", argv)

    def test_non_dockerhub_registries_are_not_listed(self):
        runner = self._runner({"images": ["ghcr.io/acme/app"], "scanAllTags": True})
        self.assertEqual(runner._list_dockerhub_digests("ghcr.io/acme/app", False), [])


if __name__ == "__main__":
    unittest.main()
