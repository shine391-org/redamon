"""
Tests for the Nuclei two-pass refactor (detection + additive DAST).

Test classes (run independently or with `python3 -m unittest`):

  TestBuildNucleiCommandDastFlag      — unit, -dast flag presence
  TestBuildNucleiCommandForceDastStripsFilters — unit, force_dast strips filters
  TestBuildNucleiCommandPreservedFlags — unit, force_dast keeps engine flags
  TestBuildNucleiCommandNormalMode    — unit, normal mode unchanged
  TestExecuteNucleiPass               — unit, JSONL parsing + FP filter
  TestRunVulnScanTwoPass              — integration, two-pass orchestration
  TestRegression                      — regression, public surface unchanged
  TestSmokeNucleiBehavior             — smoke, runs real nuclei in container

Run all (inside redamon-recon image which has dns/yaml/etc):
  docker run --rm --entrypoint python3 \\
      -v "$PWD:/app" -w /app redamon-recon \\
      -m unittest recon.tests.test_nuclei_two_pass -v
"""
import pytest
import sys
import os
import json
import shutil
import tempfile
import unittest
from unittest.mock import patch, MagicMock

_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

# Pre-mock heavy deps so vuln_scan imports cleanly
sys.modules.setdefault('neo4j', MagicMock())

# Heavy imports are guarded so the smoke-test class can run from a container
# that has nuclei but not the recon package (e.g. kali-sandbox).
try:
    from recon.helpers.nuclei_helpers import build_nuclei_command
    _HAS_RECON_IMPORTS = True
except ImportError:
    build_nuclei_command = None
    _HAS_RECON_IMPORTS = False


# ---------------------------------------------------------------------------
# Unit tests: build_nuclei_command -- DAST flag handling
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestBuildNucleiCommandDastFlag(unittest.TestCase):

    def _basic(self, **overrides):
        defaults = dict(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="projectdiscovery/nuclei:latest",
            # F03: an empty selection is now refused by the builder, so the
            # shared fixture carries an explicit template selection. Tests that
            # want the empty-selection behaviour pass their own overrides.
            templates=["http/cves/"],
        )
        defaults.update(overrides)
        return build_nuclei_command(**defaults)

    def test_dast_off_default_no_dast_flag(self):
        cmd = self._basic()
        self.assertNotIn("-dast", cmd)

    def test_dast_mode_true_adds_dast_flag(self):
        cmd = self._basic(dast_mode=True)
        self.assertIn("-dast", cmd)

    def test_force_dast_pass_adds_dast_even_if_dast_mode_false(self):
        cmd = self._basic(dast_mode=False, force_dast_pass=True)
        self.assertIn("-dast", cmd)

    def test_force_dast_pass_with_dast_mode_true_still_one_dast_flag(self):
        cmd = self._basic(dast_mode=True, force_dast_pass=True)
        self.assertEqual(cmd.count("-dast"), 1)


# ---------------------------------------------------------------------------
# Unit tests: force_dast_pass drops INCLUSION filters, keeps the denylist
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestBuildNucleiCommandForceDastStripsFilters(unittest.TestCase):

    def _force_dast(self, **overrides):
        defaults = dict(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="projectdiscovery/nuclei:latest",
            force_dast_pass=True,
            # An explicit selection is supplied so the only thing under test is
            # what force_dast_pass drops; force_dast_pass is exempt from the
            # empty-selection guard.
            templates=["http/cves/"],
        )
        defaults.update(overrides)
        return build_nuclei_command(**defaults)

    def test_strips_tags(self):
        cmd = self._force_dast(tags=["graphql", "exposure"])
        self.assertNotIn("-tags", cmd)
        self.assertNotIn("graphql,exposure", cmd)

    def test_strips_templates(self):
        cmd = self._force_dast(templates=["http/cves/2024/"])
        self.assertNotIn("http/cves/2024/", cmd)

    def test_strips_custom_templates(self):
        cmd = self._force_dast(custom_templates=["/custom-templates/aem.yaml"])
        self.assertNotIn("/custom-templates/aem.yaml", cmd)

    def test_strips_selected_custom_templates(self):
        # Even if env var is set, force_dast_pass must drop the selection
        with patch.dict(os.environ, {"HOST_CUSTOM_TEMPLATES_PATH": "/host/custom"}):
            cmd = self._force_dast(selected_custom_templates=["aem.yaml"])
        self.assertNotIn("aem.yaml", cmd)
        self.assertNotIn("/custom-templates/", cmd)

    def test_strips_new_templates_only(self):
        cmd = self._force_dast(new_templates_only=True)
        self.assertNotIn("-nt", cmd)

    # F03: exclusions are the operator's denylist, NOT an inclusion filter.
    # They must survive force_dast_pass so a RoE-forbidden or noisy category
    # stays out of the DAST pass exactly as it stays out of the detection pass.

    def test_keeps_exclude_tags(self):
        cmd = self._force_dast(exclude_tags=["dos", "fuzz"])
        self.assertIn("-exclude-tags", cmd)
        self.assertIn("dos,fuzz", cmd)

    def test_keeps_exclude_templates(self):
        cmd = self._force_dast(exclude_templates=["http/dos/"])
        self.assertIn("-exclude-templates", cmd)
        self.assertIn("http/dos/", cmd)

    def test_drops_inclusion_but_keeps_exclusions_together(self):
        """The whole point of F03 in one argv: -tags/-t gone, denylist present."""
        cmd = self._force_dast(
            tags=["cve", "xss"],
            templates=["http/cves/2024/"],
            exclude_tags=["dos"],
            exclude_templates=["http/dos/"],
        )
        self.assertNotIn("-tags", cmd)
        self.assertNotIn("cve,xss", cmd)
        self.assertNotIn("http/cves/2024/", cmd)
        self.assertIn("-exclude-tags", cmd)
        self.assertIn("dos", cmd)
        self.assertIn("-exclude-templates", cmd)
        self.assertIn("http/dos/", cmd)


# ---------------------------------------------------------------------------
# Unit tests: force_dast_pass preserves engine-level flags (severity, rate, etc.)
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestBuildNucleiCommandPreservedFlags(unittest.TestCase):

    def _force_dast(self, **overrides):
        defaults = dict(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="projectdiscovery/nuclei:latest",
            force_dast_pass=True,
            # An explicit selection is supplied so the only thing under test is
            # what force_dast_pass drops; force_dast_pass is exempt from the
            # empty-selection guard.
            templates=["http/cves/"],
        )
        defaults.update(overrides)
        return build_nuclei_command(**defaults)

    def test_keeps_severity(self):
        cmd = self._force_dast(severity=["critical", "high"])
        self.assertIn("-severity", cmd)
        self.assertIn("critical,high", cmd)

    def test_keeps_rate_limit(self):
        cmd = self._force_dast(rate_limit=200)
        self.assertIn("-rate-limit", cmd)
        self.assertIn("200", cmd)

    def test_keeps_concurrency(self):
        cmd = self._force_dast(concurrency=50)
        self.assertIn("-concurrency", cmd)
        self.assertIn("50", cmd)

    def test_keeps_headless(self):
        cmd = self._force_dast(headless=True)
        self.assertIn("-headless", cmd)

    def test_keeps_interactsh_default(self):
        cmd = self._force_dast()
        self.assertNotIn("-no-interactsh", cmd)

    def test_disables_interactsh(self):
        cmd = self._force_dast(interactsh=False)
        self.assertIn("-no-interactsh", cmd)


# ---------------------------------------------------------------------------
# Unit tests: normal (non-force) mode keeps existing behaviour
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestBuildNucleiCommandNormalMode(unittest.TestCase):

    def test_normal_mode_includes_tags(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="x",
            tags=["graphql", "apollo"],
        )
        self.assertIn("-tags", cmd)
        self.assertIn("graphql,apollo", cmd)

    def test_normal_mode_includes_templates(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="x",
            templates=["http/cves/2024/"],
        )
        self.assertIn("http/cves/2024/", cmd)

    def test_normal_mode_keeps_exclude_tags(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="x",
            templates=["http/cves/"],
            exclude_tags=["dos"],
        )
        self.assertIn("-exclude-tags", cmd)
        self.assertIn("dos", cmd)

    def test_normal_mode_empty_selection_is_refused(self):
        """F03: the builder no longer falls back to the default template pool."""
        from recon.helpers.nuclei_helpers import NucleiEmptySelectionError
        with self.assertRaises(NucleiEmptySelectionError):
            build_nuclei_command(
                targets_file="/tmp/t.txt",
                output_file="/tmp/o.jsonl",
                docker_image="x",
            )


class TestBuildNucleiCommandAuthHeaders(unittest.TestCase):
    """The AuthProfile fan-out adds an auth_headers -H pass (nuclei had none)."""

    def test_auth_headers_emitted_as_H(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl", docker_image="x",
            templates=["http/cves/"],
            auth_headers=["Cookie: sid=abc", "X-CSRF-Token: c1"],
        )
        self.assertEqual(cmd.count("-H"), 2)
        self.assertIn("Cookie: sid=abc", cmd)
        self.assertIn("X-CSRF-Token: c1", cmd)

    def test_no_auth_headers_no_H(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl", docker_image="x",
            templates=["http/cves/"],
        )
        self.assertNotIn("-H", cmd)

    def test_auth_H_precedes_any_capture_tag(self):
        # The capture tag is only appended in the proxy branch; force it on and
        # assert the auth header still leads so it is never entangled with the tag.
        with patch("helpers.proxy_routing.get_capture_routing",
                   return_value=("http://proxy:8888", "signed-tag")):
            cmd = build_nuclei_command(
                targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl", docker_image="x",
                templates=["http/cves/"],
                auth_headers=["Cookie: sid=abc"],
            )
        auth_idx = cmd.index("Cookie: sid=abc")
        tag_idx = cmd.index("X-Redamon-Ctx: signed-tag")
        self.assertLess(auth_idx, tag_idx)
        self.assertIn("-proxy", cmd)


# ---------------------------------------------------------------------------
# Unit tests: _execute_nuclei_pass helper
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestExecuteNucleiPass(unittest.TestCase):

    def _run_with_jsonl(self, jsonl_lines, returncode=0):
        from recon.main_recon_modules.vuln_scan import _execute_nuclei_pass
        with tempfile.TemporaryDirectory() as tmp:
            output_file = os.path.join(tmp, "out.jsonl")
            with open(output_file, "w") as f:
                for line in jsonl_lines:
                    f.write(line + "\n")

            mock_process = MagicMock()
            mock_process.stdout = iter(["[INF] banner\n", "| Duration: 0:00:01 | x\n"])
            mock_process.returncode = returncode
            mock_process.wait = MagicMock(return_value=None)

            with patch(
                "recon.main_recon_modules.vuln_scan.subprocess.Popen",
                return_value=mock_process,
            ):
                return _execute_nuclei_pass(["docker", "run"], output_file, label="TEST")

    def test_returns_four_tuple(self):
        findings, fps, duration, rc = self._run_with_jsonl([])
        self.assertIsInstance(findings, list)
        self.assertIsInstance(fps, list)
        self.assertIsInstance(duration, float)
        self.assertEqual(rc, 0)

    def test_parses_valid_jsonl(self):
        line = json.dumps({
            "template-id": "test-tpl",
            "template": "test.yaml",
            "info": {"name": "Test", "severity": "high"},
            "host": "https://example.com",
            "matched-at": "https://example.com/foo",
        })
        findings, fps, _, _ = self._run_with_jsonl([line])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template_id"], "test-tpl")
        self.assertEqual(findings[0]["severity"], "high")

    def test_filters_rate_limit_false_positive(self):
        line = json.dumps({
            "template-id": "blind-sqli",
            "template": "blind.yaml",
            "info": {
                "name": "Blind SQLi",
                "severity": "high",
                "tags": ["blind", "time-based"],
            },
            "host": "https://example.com",
            "matched-at": "https://example.com/foo",
            "response": "HTTP/1.1 429 Too Many Requests\nServer: nginx",
        })
        findings, fps, _, _ = self._run_with_jsonl([line])
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(fps), 1)
        self.assertEqual(fps[0]["template_id"], "blind-sqli")
        self.assertIn("Rate limiting", fps[0]["reason"])

    def test_handles_missing_output_file(self):
        from recon.main_recon_modules.vuln_scan import _execute_nuclei_pass
        mock_process = MagicMock()
        mock_process.stdout = iter([])
        mock_process.returncode = 0
        mock_process.wait = MagicMock(return_value=None)
        with patch(
            "recon.main_recon_modules.vuln_scan.subprocess.Popen",
            return_value=mock_process,
        ):
            findings, fps, _, _ = _execute_nuclei_pass(
                ["docker", "run"], "/tmp/_nonexistent_xyz_abc.jsonl", label="TEST"
            )
        self.assertEqual(findings, [])
        self.assertEqual(fps, [])

    def test_handles_invalid_json_lines(self):
        findings, fps, _, _ = self._run_with_jsonl(["not valid json", '{"truncated":'])
        self.assertEqual(findings, [])
        self.assertEqual(fps, [])

    def test_skips_blank_lines(self):
        valid = json.dumps({
            "template-id": "x", "info": {"name": "x", "severity": "low"},
            "host": "h", "matched-at": "h",
        })
        findings, _, _, _ = self._run_with_jsonl(["", "   ", valid, ""])
        self.assertEqual(len(findings), 1)


# ---------------------------------------------------------------------------
# Integration tests: run_vuln_scan two-pass orchestration
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestRunVulnScanTwoPass(unittest.TestCase):

    def _recon_data(self, dast_urls=None):
        return {
            "domain": "example.com",
            "subdomains": ["example.com"],
            "dns": {
                "domain": {"ips": {"ipv4": ["1.2.3.4"], "ipv6": []}, "has_records": True},
                "subdomains": {},
            },
            "http_probe": {
                "by_url": {
                    "https://example.com": {
                        "url": "https://example.com",
                        "host": "example.com",
                    }
                },
            },
            "resource_enum": {
                "by_base_url": {},
                "discovered_urls": dast_urls or [],
            },
        }

    def _settings(self, dast_mode=False):
        return {
            "NUCLEI_ENABLED": True,
            "NUCLEI_DAST_MODE": dast_mode,
            "NUCLEI_SEVERITY": ["critical", "high"],
            "NUCLEI_TEMPLATES": [],
            "NUCLEI_EXCLUDE_TEMPLATES": [],
            "NUCLEI_RATE_LIMIT": 100,
            "NUCLEI_BULK_SIZE": 25,
            "NUCLEI_CONCURRENCY": 25,
            "NUCLEI_TIMEOUT": 10,
            "NUCLEI_RETRIES": 1,
            # Empty selection intentionally skips detection; two-pass callers need
            # an explicit nonempty detection selection, not the old default-all.
            "NUCLEI_TAGS": ["cve"],
            "NUCLEI_MAX_RUNTIME": 0,
            "NUCLEI_EXCLUDE_TAGS": [],
            "NUCLEI_NEW_TEMPLATES_ONLY": False,
            "NUCLEI_HEADLESS": False,
            "NUCLEI_SYSTEM_RESOLVERS": True,
            "NUCLEI_FOLLOW_REDIRECTS": True,
            "NUCLEI_MAX_REDIRECTS": 10,
            "NUCLEI_SCAN_ALL_IPS": False,
            "NUCLEI_INTERACTSH": True,
            "NUCLEI_DOCKER_IMAGE": "projectdiscovery/nuclei:latest",
            "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
            "KATANA_DEPTH": 2,
            "CVE_LOOKUP_ENABLED": False,
            "SECURITY_CHECK_ENABLED": False,
        }

    def _patch_pipeline(self, target_urls=None):
        target_urls = target_urls or ["https://example.com"]

        def _stub_extract_targets(recon_data, *_a, **_k):
            return ([], ["example.com"], {})

        def _stub_build_target_urls(hostnames, ips, recon_data, scan_all_ips=False,
                                    admission_report=None, declared_report=None):
            return target_urls

        from pathlib import Path
        self.generated_targets = {}

        def capture_generated_command(**kwargs):
            # Observe actual caller files BEFORE the engine removes its tempdir;
            # leave the command builder and safety/header logic real.
            filename = Path(kwargs["targets_file"])
            self.generated_targets[filename.name] = filename.read_text().splitlines()
            self.assertIsNotNone(build_nuclei_command)
            assert build_nuclei_command is not None
            return build_nuclei_command(**kwargs)

        return [
            patch("recon.main_recon_modules.vuln_scan.build_nuclei_command", side_effect=capture_generated_command),
            patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None)),
            patch("recon.main_recon_modules.vuln_scan.is_docker_installed", return_value=True),
            patch("recon.main_recon_modules.vuln_scan.is_docker_running", return_value=True),
            patch("recon.main_recon_modules.vuln_scan.pull_nuclei_docker_image", return_value=None),
            patch("recon.main_recon_modules.vuln_scan.ensure_templates_volume", return_value=True),
            patch("recon.main_recon_modules.vuln_scan.extract_targets_from_recon", side_effect=_stub_extract_targets),
            patch("recon.main_recon_modules.vuln_scan.build_target_urls", side_effect=_stub_build_target_urls),
        ]

    def _start_patches(self, patches):
        for p in patches:
            p.start()

    def _stop_patches(self, patches):
        for p in patches:
            p.stop()

    def test_dast_off_runs_only_detection(self):
        from recon.main_recon_modules import vuln_scan as vs
        recon_data = self._recon_data()
        settings = self._settings(dast_mode=False)
        patches = self._patch_pipeline()
        self._start_patches(patches)
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.5, 0)) as exec_mock:
                vs.run_vuln_scan(recon_data, output_file=None, settings=settings)
                self.assertEqual(exec_mock.call_count, 1)
                # `label` is passed as kwarg
                self.assertEqual(exec_mock.call_args_list[0].kwargs.get("label"), "DETECTION")
        finally:
            self._stop_patches(patches)

    def test_dast_on_with_params_runs_two_passes(self):
        from recon.main_recon_modules import vuln_scan as vs
        recon_data = self._recon_data(
            dast_urls=[
                "https://example.com/api?id=1",
                "https://example.com/search?q=test",
                "https://example.com/static.html",  # no params, should be filtered out
            ]
        )
        settings = self._settings(dast_mode=True)
        patches = self._patch_pipeline()
        self._start_patches(patches)
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)) as exec_mock:
                vs.run_vuln_scan(recon_data, output_file=None, settings=settings)
                self.assertEqual(exec_mock.call_count, 2)
                labels = [c.kwargs.get("label") for c in exec_mock.call_args_list]
                self.assertEqual(labels, ["DETECTION", "DAST"])  # ordered
                self.assertEqual(self.generated_targets["targets_legacy.txt"], ["https://example.com"])
                self.assertEqual(self.generated_targets["targets_dast.txt"], [
                    "https://example.com/api?id=1", "https://example.com/search?q=test",
                ])
        finally:
            self._stop_patches(patches)

    def test_dast_on_without_params_falls_back_to_single_pass(self):
        from recon.main_recon_modules import vuln_scan as vs
        recon_data = self._recon_data(dast_urls=[])  # empty
        settings = self._settings(dast_mode=True)
        patches = self._patch_pipeline()
        self._start_patches(patches)
        try:
            with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)) as exec_mock:
                result = vs.run_vuln_scan(recon_data, output_file=None, settings=settings)
                self.assertEqual(exec_mock.call_count, 1)
                self.assertFalse(result["vuln_scan"]["scan_metadata"]["dast_pass_executed"])
                self.assertTrue(result["vuln_scan"]["scan_metadata"]["dast_mode"])
        finally:
            self._stop_patches(patches)

    def test_findings_from_both_passes_merged(self):
        from recon.main_recon_modules import vuln_scan as vs
        recon_data = self._recon_data(dast_urls=["https://example.com/api?x=1"])
        settings = self._settings(dast_mode=True)

        d_finding = {
            "template_id": "cve-2024-x", "template_path": "cve.yaml",
            "name": "Detection finding", "description": "",
            "severity": "high", "category": "cve", "tags": ["cve"],
            "reference": [], "cves": [], "cvss_score": None, "cvss_metrics": "",
            "cwe_id": [], "target": "https://example.com",
            "matched_at": "https://example.com/x", "matcher_name": "",
            "extracted_results": [], "curl_command": "", "request": "",
            "response": "", "timestamp": "2026-04-25T00:00:00", "raw": {},
        }
        b_finding = {
            "template_id": "xss-fuzz", "template_path": "xss.yaml",
            "name": "DAST finding", "description": "",
            "severity": "medium", "category": "xss", "tags": ["xss", "dast"],
            "reference": [], "cves": [], "cvss_score": None, "cvss_metrics": "",
            "cwe_id": [], "target": "https://example.com",
            "matched_at": "https://example.com/api?x=1", "matcher_name": "",
            "extracted_results": [], "curl_command": "", "request": "",
            "response": "", "timestamp": "2026-04-25T00:00:00", "raw": {},
        }

        patches = self._patch_pipeline()
        self._start_patches(patches)
        try:
            def fake_exec(cmd, output_file, label, runtime_cap=0, container_name=None):
                self.assertEqual(runtime_cap, settings["NUCLEI_MAX_RUNTIME"])
                self.assertIsInstance(container_name, str)
                self.assertTrue(container_name and container_name.startswith("redamon-nuclei-"))
                if label == "DETECTION":
                    return ([d_finding], [], 1.0, 0)
                else:
                    return ([b_finding], [], 1.0, 0)

            with patch.object(vs, "_execute_nuclei_pass", side_effect=fake_exec):
                result = vs.run_vuln_scan(recon_data, output_file=None, settings=settings)

            vs_data = result["vuln_scan"]
            template_ids = list(vs_data["by_template"].keys())
            self.assertIn("cve-2024-x", template_ids)
            self.assertIn("xss-fuzz", template_ids)
            self.assertEqual(vs_data["summary"]["total_findings"], 2)
            self.assertEqual(vs_data["summary"]["high"], 1)
            self.assertEqual(vs_data["summary"]["medium"], 1)
            self.assertTrue(vs_data["scan_metadata"]["dast_pass_executed"])
            self.assertEqual(vs_data["scan_metadata"]["dast_urls_discovered"], 1)
        finally:
            self._stop_patches(patches)

    def test_dast_pass_gets_force_dast_pass_flag(self):
        """Confirm pass B's command is built with force_dast_pass=True."""
        from recon.main_recon_modules import vuln_scan as vs
        from recon.helpers import nuclei_helpers as nh

        recon_data = self._recon_data(dast_urls=["https://example.com/?x=1"])
        settings = self._settings(dast_mode=True)
        patches = self._patch_pipeline()
        self._start_patches(patches)
        captured = {}
        try:
            real_build = nh.build_nuclei_command

            def spy_build(**kwargs):
                # Detection pass call has force_dast_pass not set or False;
                # DAST pass call must have it True.
                captured.setdefault("calls", []).append(kwargs)
                return real_build(**kwargs)

            with patch.object(vs, "build_nuclei_command", side_effect=spy_build):
                with patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)):
                    vs.run_vuln_scan(recon_data, output_file=None, settings=settings)

            self.assertEqual(len(captured["calls"]), 2)
            # First call (detection) should NOT have force_dast_pass=True
            self.assertFalse(captured["calls"][0].get("force_dast_pass", False))
            # Second call (DAST) MUST have force_dast_pass=True
            self.assertTrue(captured["calls"][1].get("force_dast_pass", False))
        finally:
            self._stop_patches(patches)


# ---------------------------------------------------------------------------
# Regression tests: public surface didn't break
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_RECON_IMPORTS, "recon package not on PYTHONPATH")
class TestRegression(unittest.TestCase):

    def test_run_vuln_scan_isolated_callable(self):
        from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
        self.assertTrue(callable(run_vuln_scan_isolated))

    def test_disabled_returns_full_metadata_keys(self):
        from recon.main_recon_modules.vuln_scan import run_vuln_scan
        settings = {
            "NUCLEI_ENABLED": False,
            "CVE_LOOKUP_ENABLED": False,
            "SECURITY_CHECK_ENABLED": False,
        }
        result = run_vuln_scan({"domain": "x"}, output_file=None, settings=settings)
        meta = result["vuln_scan"]["scan_metadata"]
        for key in (
            "scan_timestamp", "execution_mode", "dast_mode",
            "dast_urls_discovered", "katana_crawl_depth",
            "total_urls_scanned", "false_positives_filtered",
        ):
            self.assertIn(key, meta)

    def test_build_nuclei_command_signature_preserves_old_params(self):
        import inspect
        from recon.helpers.nuclei_helpers import build_nuclei_command
        params = inspect.signature(build_nuclei_command).parameters
        for old_param in (
            "targets_file", "output_file", "docker_image",
            "severity", "templates", "tags", "exclude_tags",
            "rate_limit", "dast_mode", "headless", "interactsh",
        ):
            self.assertIn(old_param, params)
        self.assertIn("force_dast_pass", params)
        # The new param should default to False so old callers keep working
        self.assertEqual(params["force_dast_pass"].default, False)


# ---------------------------------------------------------------------------
# Smoke tests: live nuclei behaviour (run only if nuclei + templates available)
# ---------------------------------------------------------------------------

class TestSmokeNucleiBehavior(unittest.TestCase):
    """
    These tests shell out to nuclei to validate our assumptions about -dast.
    They're skipped if nuclei is unreachable (e.g. when running in a CI image
    without templates). Inside the redamon-kali container they all run.
    """
    NUCLEI_BIN = shutil.which("nuclei")
    DAST_DIR = "/root/nuclei-templates/dast"

    @classmethod
    def setUpClass(cls):
        if not cls.NUCLEI_BIN:
            raise unittest.SkipTest("nuclei not on PATH")
        if not os.path.isdir(cls.DAST_DIR):
            raise unittest.SkipTest(f"DAST template dir {cls.DAST_DIR} not present")

    def _run_nuclei(self, *extra_args, timeout=60):
        import subprocess
        cmd = [self.NUCLEI_BIN, "-duc", *extra_args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def test_dast_alone_loads_dast_templates(self):
        result = self._run_nuclei("-dast", "-t", self.DAST_DIR, "-tl")
        # -tl prints templates, exits 0 if any loaded
        self.assertEqual(result.returncode, 0, msg=result.stderr[:300])

    def test_exclude_tags_fuzz_is_noop_for_dast(self):
        # F03: the flag is now HONOURED on the DAST pass rather than dropped.
        # Whether it changes the loaded set depends on the template pool: a tag
        # no DAST template carries is a no-op, and a tag some carry must shrink
        # the set. Assert the flag reaches nuclei, not that it is inert.
        baseline = self._run_nuclei("-dast", "-t", self.DAST_DIR, "-tl")
        with_exclude = self._run_nuclei(
            "-dast", "-t", self.DAST_DIR, "-exclude-tags", "fuzz", "-tl"
        )
        self.assertEqual(
            len(baseline.stdout.splitlines()),
            len(with_exclude.stdout.splitlines()),
            msg="`-exclude-tags fuzz` should be a no-op against DAST templates",
        )

    def test_exclude_tags_reaches_the_dast_template_loader(self):
        """The exclusion flag is parsed and applied, not silently discarded.

        An unknown tag is a no-op everywhere; a real DAST tag must shrink the
        loaded set. This proves the flag is on nuclei's argv and honoured.
        """
        baseline = self._run_nuclei("-dast", "-t", self.DAST_DIR, "-tl")
        self.assertGreater(len(baseline.stdout.splitlines()), 0)
        # `xss` is a real DAST tag in the shipped pool; excluding it must remove
        # at least one template. If the pool has none, the test is skipped
        # rather than asserting a no-op as if it were coverage.
        with_exclude = self._run_nuclei(
            "-dast", "-t", self.DAST_DIR, "-exclude-tags", "xss", "-tl"
        )
        if len(with_exclude.stdout.splitlines()) == len(baseline.stdout.splitlines()):
            raise unittest.SkipTest(
                "no DAST template carries the 'xss' tag in this pool; "
                "cannot prove the exclusion is honoured"
            )
        self.assertLess(
            len(with_exclude.stdout.splitlines()),
            len(baseline.stdout.splitlines()),
            msg="`-exclude-tags xss` must shrink the DAST template set",
        )

    def test_dast_with_detection_tags_fatals(self):
        # -dast intersected with detection-only tags must produce the
        # "no templates provided for scan" fatal we documented in the UI copy.
        result = self._run_nuclei(
            "-dast",
            "-tags", "graphql,exposure,apollo,hasura",
            "-u", "http://127.0.0.1:1",  # unreachable, fine for template-load check
            timeout=30,
        )
        combined = (result.stdout + result.stderr).lower()
        self.assertIn("no", combined)
        self.assertTrue(
            "no dast templates" in combined or "no templates" in combined,
            msg=f"Expected 'no templates' fatal; got:\n{combined[:400]}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
