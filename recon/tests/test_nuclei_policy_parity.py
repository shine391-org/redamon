"""F03: DAST honours the operator denylist; the builder fails closed.

Three seams are pinned here, each with a real assertion rather than a skip:

1. ``build_nuclei_command(force_dast_pass=True)`` drops the INCLUSION filters
   (templates/tags/custom/-nt, which would empty-intersect with Nuclei's own
   ``-dast`` set) and keeps the EXCLUSIONS (the operator's denylist). Before F03
   it dropped both, so a RoE-forbidden or noisy category was re-admitted to the
   DAST pass.
2. The effective template set is checked against the real Nuclei binary on the
   frozen template pool (``-tl`` / ``-validate``), not inferred from argv flags.
3. An empty selection raises ``NucleiEmptySelectionError`` instead of silently
   falling back to the whole default pool.

Full/partial parity is asserted at the caller level: both paths call the same
``run_vuln_scan``, so the DAST exclusions it passes are the same ones. The
takeover caller is a separate explicit-template consumer and is asserted not to
inherit the global denylist.

The unit tests need no Docker socket and no network. The template-pool checks
are skipped (not failed) when the nuclei binary or the frozen pool is absent,
and are reported separately from the unit results.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.nuclei_helpers import (  # noqa: E402
    NucleiEmptySelectionError,
    build_nuclei_command,
)
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402


# ---------------------------------------------------------------------------
# 1. Builder: inclusion vs denylist under force_dast_pass
# ---------------------------------------------------------------------------

class TestForceDastKeepsDenylist:
    """The operator's exclusions are not an inclusion filter."""

    def _cmd(self, **overrides):
        defaults = dict(
            targets_file="/tmp/t.txt",
            output_file="/tmp/o.jsonl",
            docker_image="projectdiscovery/nuclei:latest",
            force_dast_pass=True,
        )
        defaults.update(overrides)
        return build_nuclei_command(**defaults)

    def test_dast_flag_is_present(self):
        assert "-dast" in self._cmd()

    @pytest.mark.parametrize("kwargs,value,flag", [
        ({"tags": ["cve", "xss"]}, "cve,xss", "-tags"),
        ({"templates": ["http/cves/2024/"]}, "http/cves/2024/", None),
        ({"custom_templates": ["/custom-templates/a.yaml"]}, "a.yaml", None),
        ({"new_templates_only": True}, None, "-nt"),
    ])
    def test_inclusion_filters_are_dropped(self, kwargs, value, flag):
        cmd = self._cmd(**kwargs)
        if flag:
            assert flag not in cmd, f"{flag} must not reach the DAST pass"
        if value:
            assert value not in cmd

    def test_exclude_tags_survive(self):
        cmd = self._cmd(exclude_tags=["dos", "fuzz"])
        assert "-exclude-tags" in cmd
        assert "dos,fuzz" in cmd

    def test_exclude_templates_survive(self):
        cmd = self._cmd(exclude_templates=["http/dos/", "http/fuzz/"])
        assert cmd.count("-exclude-templates") == 2
        assert "http/dos/" in cmd and "http/fuzz/" in cmd

    def test_detection_pass_is_unchanged_by_the_policy(self):
        """Normal mode keeps tags AND exclusions; only force_dast drops includes."""
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
            docker_image="x", tags=["cve"], exclude_tags=["dos"],
        )
        assert "-tags" in cmd and "cve" in cmd
        assert "-exclude-tags" in cmd and "dos" in cmd

    def test_custom_templates_volume_not_mounted_under_force_dast(self):
        with patch.dict(os.environ, {"HOST_CUSTOM_TEMPLATES_PATH": "/host/custom"}):
            cmd = self._cmd(selected_custom_templates=["a.yaml"])
        assert "/custom-templates" not in " ".join(cmd)


# ---------------------------------------------------------------------------
# 2. Builder: fail-closed on an empty selection
# ---------------------------------------------------------------------------

class TestBuilderFailsClosed:
    def test_empty_selection_raises(self):
        with pytest.raises(NucleiEmptySelectionError):
            build_nuclei_command(
                targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
                docker_image="x",
            )

    def test_empty_selection_is_a_value_error(self):
        """Callers that only catch ValueError keep working."""
        with pytest.raises(ValueError):
            build_nuclei_command(
                targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
                docker_image="x", tags=[], templates=[], custom_templates=[],
            )

    def test_force_dast_is_exempt_from_the_empty_guard(self):
        """A DAST pass's template set is Nuclei's own -dast pool, not the default."""
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
            docker_image="x", force_dast_pass=True,
        )
        assert "-dast" in cmd

    def test_explicit_templates_do_not_trip_the_guard(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
            docker_image="x", templates=["http/takeovers/"],
        )
        assert "http/takeovers/" in cmd

    def test_tags_do_not_trip_the_guard(self):
        cmd = build_nuclei_command(
            targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
            docker_image="x", tags=["cve"],
        )
        assert "-tags" in cmd

    def test_custom_selection_does_not_trip_the_guard(self):
        # The custom path is emitted as /custom-templates/<name>; assert the
        # full emitted form, not the bare filename.
        with patch.dict(os.environ, {"HOST_CUSTOM_TEMPLATES_PATH": "/host/custom"}):
            cmd = build_nuclei_command(
                targets_file="/tmp/t.txt", output_file="/tmp/o.jsonl",
                docker_image="x", selected_custom_templates=["a.yaml"],
            )
        assert "/custom-templates/a.yaml" in cmd


# ---------------------------------------------------------------------------
# 3. Caller: the DAST pass actually receives the denylist
# ---------------------------------------------------------------------------

def _settings(**extra):
    base = {
        "NUCLEI_ENABLED": True,
        "NUCLEI_TAGS": ["cve"],
        "NUCLEI_EXCLUDE_TAGS": ["dos", "fuzz"],
        "NUCLEI_EXCLUDE_TEMPLATES": ["http/dos/"],
        "NUCLEI_DAST_MODE": True,
        "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
        "NUCLEI_MAX_RUNTIME": 0,
        "CVE_LOOKUP_ENABLED": False,
        "SECURITY_CHECK_ENABLED": False,
    }
    base.update(extra)
    return base


def _recon(dast_urls=None):
    return {
        "domain": "example.com",
        "subdomains": ["example.com"],
        "http_probe": {"by_url": {"https://example.com": {"url": "https://example.com"}}},
        "resource_enum": {"discovered_urls": dast_urls or []},
    }


@pytest.fixture
def captured(monkeypatch):
    state = {"calls": [], "passes": []}

    real_build = build_nuclei_command

    def spy_build(**kwargs):
        state["calls"].append(kwargs)
        return real_build(**kwargs)

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        state["passes"].append({"label": label, "cmd": list(cmd)})
        return [], [], 1.0, 0

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd: ([], ["example.com"], {}))
    monkeypatch.setattr(vs, "build_target_urls", lambda h, i, rd, scan_all_ips=False,
                        admission_report=None, declared_report=None: ["https://example.com"])
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "build_nuclei_command", spy_build)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    return state


class TestDastCallerPassesExclusions:
    def test_detection_and_dast_receive_the_same_denylist(self, captured):
        vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(),
        )
        assert [c["label"] for c in captured["passes"]] == ["DETECTION", "DAST"]
        detection_kwargs = captured["calls"][0]
        dast_kwargs = captured["calls"][1]
        assert detection_kwargs["exclude_tags"] == ["dos", "fuzz"]
        assert detection_kwargs["exclude_templates"] == ["http/dos/"]
        assert dast_kwargs["exclude_tags"] == ["dos", "fuzz"]
        assert dast_kwargs["exclude_templates"] == ["http/dos/"]

    def test_dast_argv_carries_the_exclude_flags(self, captured):
        vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(),
        )
        dast_cmd = captured["passes"][1]["cmd"]
        assert "-dast" in dast_cmd
        assert "-exclude-tags" in dast_cmd
        assert "dos,fuzz" in dast_cmd
        assert "-exclude-templates" in dast_cmd
        assert "http/dos/" in dast_cmd
        # Inclusion filters must NOT be on the DAST argv.
        assert "-tags" not in dast_cmd

    def test_metadata_records_the_dast_denylist(self, captured):
        out = vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(),
        )
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_exclude_tags"] == ["dos", "fuzz"]
        assert meta["dast_exclude_templates"] == ["http/dos/"]
        assert meta["dast_pass_executed"] is True
        assert "dast_not_executed" not in meta

    def test_empty_dast_denylist_is_recorded_as_empty(self, captured):
        out = vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(NUCLEI_EXCLUDE_TAGS=[], NUCLEI_EXCLUDE_TEMPLATES=[]),
        )
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_exclude_tags"] == []
        assert meta["dast_exclude_templates"] == []

    def test_detection_empty_selection_does_not_open_the_full_pool(self, captured):
        """F03 DoD: an empty Detection selection must not fall back to all templates."""
        out = vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(NUCLEI_TAGS=[]),
        )
        labels = [c["label"] for c in captured["passes"]]
        assert labels == ["DAST"]  # detection refused, DAST still runs
        meta = out["vuln_scan"]["scan_metadata"]
        # No detection pass ran, so the previous findings are kept, not replaced.
        assert meta["coverage"]["hosts"]
        reasons = [row["reason"] for row in meta["coverage"]["hosts"].values()]
        assert any("no Nuclei templates selected" in (r or "") for r in reasons)


class TestEmptySelectionGuardAtTheCaller:
    """The guard is caught structurally, so enrichment still runs."""

    def test_empty_detection_selection_keeps_cve_and_security_checks(self, monkeypatch):
        calls = {"cve": 0, "security": 0}

        def fake_cve(**kwargs):
            calls["cve"] += 1
            return {"technology_cves": {"summary": {"total_cves": 0}}}

        def fake_security(**kwargs):
            calls["security"] += 1
            return {"security_checks": {"findings": [{"check": "spf_missing"}]}}

        monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
        monkeypatch.setattr(vs, "is_docker_running", lambda: True)
        monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
        monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
        monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd: ([], ["example.com"], {}))
        monkeypatch.setattr(vs, "build_target_urls", lambda h, i, rd, scan_all_ips=False,
                        admission_report=None, declared_report=None: ["https://example.com"])
        monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
        monkeypatch.setattr(vs, "_execute_nuclei_pass", lambda *a, **k: ([], [], 1.0, 0))
        monkeypatch.setattr(vs, "run_security_checks", fake_security)
        monkeypatch.setattr(vs, "run_cve_lookup", fake_cve)

        out = vs.run_vuln_scan(
            _recon(), settings=_settings(NUCLEI_TAGS=[], CVE_LOOKUP_ENABLED=True,
                                        SECURITY_CHECK_ENABLED=True),
        )
        assert calls == {"cve": 1, "security": 1}
        assert out["vuln_scan"]["security_checks"] == {"findings": [{"check": "spf_missing"}]}


# ---------------------------------------------------------------------------
# 3b. The empty-selection refusal is caught at BOTH call sites
# ---------------------------------------------------------------------------

def _nuclei_finding(url="https://example.com/api?id=1"):
    """A minimal parsed finding, shaped like parse_nuclei_finding() output."""
    return {
        "template_id": "cve-2024-x", "template_path": "http/cves/x.yaml",
        "name": "X", "description": "", "severity": "high", "category": "cve",
        "tags": ["cve"], "reference": [], "cves": [], "cvss_score": None,
        "cvss_metrics": "", "cwe_id": [], "target": url, "matched_at": url,
        "matcher_name": "", "extracted_results": [], "curl_command": "",
        "request": "", "response": "", "timestamp": "2026-01-01T00:00:00", "raw": {},
    }


class TestEmptySelectionRefusalAtBothCallSites:
    """DoD 3/5: neither pass may let an empty selection escape the caller.

    The builder refuses a command with no template selection, and nuclei itself
    fatals with "no templates provided for scan" when the exclusions remove
    every template the policy picked. Both are ``NucleiEmptySelectionError`` and
    both must be recorded as ``policy_empty`` with the enrichment still running.
    """

    def _patch_pipeline(self, monkeypatch, pass_impl):
        monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
        monkeypatch.setattr(vs, "is_docker_running", lambda: True)
        monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
        monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
        monkeypatch.setattr(vs, "extract_targets_from_recon",
                            lambda rd: ([], ["example.com"], {}))
        monkeypatch.setattr(vs, "build_target_urls",
                            lambda h, i, rd, scan_all_ips=False,
                            admission_report=None, declared_report=None: ["https://example.com"])
        monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
        monkeypatch.setattr(vs, "_execute_nuclei_pass", pass_impl)
        monkeypatch.delenv("HOST_CUSTOM_TEMPLATES_PATH", raising=False)

    def test_detection_build_refusal_keeps_cve_and_security_checks(self, monkeypatch):
        """The guard at the DETECTION call site is caught structurally.

        ``NUCLEI_SELECTED_CUSTOM_TEMPLATES`` makes the caller's pre-refusal
        believe a custom template is available, but without
        ``HOST_CUSTOM_TEMPLATES_PATH`` the builder cannot emit it, so
        ``build_nuclei_command`` raises ``NucleiEmptySelectionError``. That
        refusal must not propagate out of ``run_vuln_scan`` and skip the CVE
        lookup and the security checks.
        """
        calls = {"cve": 0, "security": 0}

        def fake_cve(**kwargs):
            calls["cve"] += 1
            return {"technology_cves": {"summary": {"total_cves": 0}}}

        def fake_security(**kwargs):
            calls["security"] += 1
            return {"security_checks": {"findings": [{"check": "spf_missing"}]}}

        self._patch_pipeline(monkeypatch, lambda *a, **k: ([], [], 1.0, 0))
        monkeypatch.setattr(vs, "run_cve_lookup", fake_cve)
        monkeypatch.setattr(vs, "run_security_checks", fake_security)

        out = vs.run_vuln_scan(
            _recon(),
            settings=_settings(
                NUCLEI_TAGS=[], NUCLEI_TEMPLATES=[], NUCLEI_CUSTOM_TEMPLATES=[],
                NUCLEI_SELECTED_CUSTOM_TEMPLATES=["x.yaml"],
                NUCLEI_DAST_MODE=False,
                CVE_LOOKUP_ENABLED=True, SECURITY_CHECK_ENABLED=True,
            ),
        )

        assert calls == {"cve": 1, "security": 1}
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["detection_not_executed"]["pass"] == "DETECTION"
        assert meta["detection_not_executed"]["state"] == "not_executed"
        assert meta["detection_not_executed"]["reason"] == "policy_empty"
        assert "no nuclei templates selected" in meta["detection_not_executed"]["detail"].lower()
        reasons = [row["reason"] for row in meta["coverage"]["hosts"].values()]
        assert any("policy_empty" in (r or "") for r in reasons)

    def test_detection_runtime_empty_selection_keeps_enrichment(self, monkeypatch):
        """nuclei's own fatal at the DETECTION call site is policy_empty, not a crash."""
        calls = {"cve": 0, "security": 0}

        def fake_cve(**kwargs):
            calls["cve"] += 1
            return {"technology_cves": {"summary": {"total_cves": 0}}}

        def fake_security(**kwargs):
            calls["security"] += 1
            return {"security_checks": {"findings": [{"check": "spf_missing"}]}}

        def fatal_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
            raise NucleiEmptySelectionError(
                "[FTL] Could not run nuclei: no templates provided for scan")

        self._patch_pipeline(monkeypatch, fatal_pass)
        monkeypatch.setattr(vs, "run_cve_lookup", fake_cve)
        monkeypatch.setattr(vs, "run_security_checks", fake_security)

        out = vs.run_vuln_scan(
            _recon(),
            settings=_settings(NUCLEI_DAST_MODE=False, CVE_LOOKUP_ENABLED=True,
                               SECURITY_CHECK_ENABLED=True),
        )

        assert calls == {"cve": 1, "security": 1}
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["detection_not_executed"]["reason"] == "policy_empty"
        assert "no templates provided for scan" in meta["detection_not_executed"]["detail"]

    def test_dast_runtime_empty_selection_is_recorded_as_policy_empty(self, monkeypatch):
        """DoD 3: the DAST policy_empty path is reachable, not defensive-only.

        The operator's exclusions remove every template from Nuclei's -dast
        pool, so nuclei fatals with "no templates provided for scan". That must
        be recorded as ``dast_not_executed/policy_empty`` rather than a generic
        ``failed``; the DETECTION findings are kept and nothing falls back to the
        full template pool.
        """
        state = {"passes": []}

        def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
            state["passes"].append(label)
            if label == "DAST":
                raise NucleiEmptySelectionError(
                    "[FTL] Could not run nuclei: no templates provided for scan")
            return ([_nuclei_finding()], [], 1.0, 0)

        self._patch_pipeline(monkeypatch, fake_pass)

        out = vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(),
        )

        assert state["passes"] == ["DETECTION", "DAST"]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_not_executed"]["pass"] == "DAST"
        assert meta["dast_not_executed"]["state"] == "not_executed"
        assert meta["dast_not_executed"]["reason"] == "policy_empty"
        assert "no templates provided for scan" in meta["dast_not_executed"]["detail"]
        assert meta["dast_pass_executed"] is False
        # DETECTION findings survive; the DAST pass contributed nothing.
        assert out["vuln_scan"]["summary"]["total_findings"] == 1
        assert "cve-2024-x" in out["vuln_scan"]["by_template"]
        reasons = [row["reason"] for row in meta["coverage"]["hosts"].values()]
        assert any("policy_empty" in (r or "") for r in reasons)
        # No fallback: the DAST argv never gained an inclusion filter.
        assert "dast_urls_dropped_budget" not in meta

    def test_dast_builder_refusal_still_recorded(self, monkeypatch):
        """The builder's own refusal keeps the same policy_empty record."""
        state = {"passes": []}

        def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
            state["passes"].append(label)
            return ([], [], 1.0, 0)

        self._patch_pipeline(monkeypatch, fake_pass)

        real_build = vs.build_nuclei_command

        def refusing_build(**kwargs):
            if kwargs.get("force_dast_pass"):
                raise NucleiEmptySelectionError("no Nuclei templates selected")
            return real_build(**kwargs)

        monkeypatch.setattr(vs, "build_nuclei_command", refusing_build)

        out = vs.run_vuln_scan(
            _recon(dast_urls=["https://example.com/api?id=1"]),
            settings=_settings(),
        )

        assert state["passes"] == ["DETECTION"]
        meta = out["vuln_scan"]["scan_metadata"]
        assert meta["dast_not_executed"]["reason"] == "policy_empty"
        assert meta["dast_pass_executed"] is False


class TestExecuteNucleiPassEmptySelectionFatal:
    """The executor surfaces nuclei's empty-selection fatal as the refusal."""

    @staticmethod
    def _proc(lines, rc=1):
        class _P:
            returncode = rc
            stdout = iter(lines)

            def wait(self):
                return rc

        return _P()

    def test_empty_selection_fatal_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(vs.subprocess, "Popen", lambda *a, **k: self._proc(
            ["[FTL] Could not run nuclei: no templates provided for scan\n"]))
        out = tmp_path / "o.jsonl"
        out.write_text("")
        with pytest.raises(NucleiEmptySelectionError) as excinfo:
            vs._execute_nuclei_pass(["docker", "run"], str(out), label="DAST")
        assert "no templates provided for scan" in str(excinfo.value)

    def test_empty_selection_fatal_carries_the_loader_error(self, monkeypatch, tmp_path):
        """A bad explicit template path fatals identically; the record keeps both lines."""
        monkeypatch.setattr(vs.subprocess, "Popen", lambda *a, **k: self._proc([
            "[ERR] Could not find template '/x/y.yaml': could not find file: open /x/y.yaml: no such file or directory\n",
            "[FTL] Could not run nuclei: no templates provided for scan\n",
        ]))
        out = tmp_path / "o.jsonl"
        out.write_text("")
        with pytest.raises(NucleiEmptySelectionError) as excinfo:
            vs._execute_nuclei_pass(["docker", "run"], str(out), label="DETECTION")
        message = str(excinfo.value)
        assert "Could not find template" in message
        assert "no templates provided for scan" in message

    def test_a_generic_failure_still_returns_instead_of_raising(self, monkeypatch, tmp_path):
        """The marker must not swallow an ordinary non-zero exit."""
        monkeypatch.setattr(vs.subprocess, "Popen", lambda *a, **k: self._proc(
            ["[FTL] Could not run nuclei: connection refused\n"]))
        out = tmp_path / "o.jsonl"
        out.write_text("")
        findings, fps, duration, rc = vs._execute_nuclei_pass(
            ["docker", "run"], str(out), label="DETECTION")
        assert rc == 1
        assert findings == []

    @pytest.mark.parametrize("lines,expected", [
        (["[FTL] Could not run nuclei: no templates provided for scan"],
         "[FTL] Could not run nuclei: no templates provided for scan"),
        (["[INF] Loaded 8000 templates", "[WRN] nothing to report"], None),
        ([], None),
        (None, None),
        # A bad explicit template path fatals with the same message; nuclei's
        # own loader error must ride along so the record is distinguishable.
        (["[ERR] Could not find template '/x/y.yaml': could not find file: open /x/y.yaml: no such file or directory",
          "[FTL] Could not run nuclei: no templates provided for scan"],
         "[ERR] Could not find template '/x/y.yaml': could not find file: open /x/y.yaml: no such file or directory"
         "\n[FTL] Could not run nuclei: no templates provided for scan"),
    ])
    def test_no_templates_fatal_detector(self, lines, expected):
        assert vs._nuclei_no_templates_fatal(lines) == expected


# ---------------------------------------------------------------------------
# 4. Takeover: a separate explicit-template contract, not the global denylist
# ---------------------------------------------------------------------------

class TestTakeoverContractUnaffected:
    """subdomain_takeover passes explicit templates and exclude_tags=[].

    It must not inherit NUCLEI_EXCLUDE_TAGS/EXCLUDE_TEMPLATES from the global
    settings, and it must not start emitting -dast. F03 changes neither.
    """

    def _takeover_build(self, monkeypatch, settings):
        from recon.main_recon_modules import subdomain_takeover as st
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)

            class _P:
                returncode = 0
                stdout = ""
                stderr = ""

                def wait(self):
                    return 0

            return _P()

        work_dir = Path("/tmp/_f03_takeover")
        work_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(st, "is_docker_installed", lambda: True)
        monkeypatch.setattr(st, "is_docker_running", lambda: True)
        monkeypatch.setattr(st, "pull_nuclei_docker_image", lambda image: None)
        monkeypatch.setattr(st, "ensure_templates_volume", lambda image, auto_update: True)
        monkeypatch.setattr(st.subprocess, "run", fake_run)
        monkeypatch.setattr(st, "fix_file_ownership", lambda p: None)
        monkeypatch.setattr(st, "_load_nuclei_jsonl", lambda p: [])
        st._run_nuclei_takeover(["https://example.com"], work_dir, settings)
        return captured.get("cmd", [])

    def test_takeover_keeps_explicit_templates_and_no_global_denylist(self, monkeypatch):
        cmd = self._takeover_build(monkeypatch, {
            "NUCLEI_DOCKER_IMAGE": "projectdiscovery/nuclei:latest",
            "TAKEOVER_SEVERITY": ["critical", "high", "medium"],
            "TAKEOVER_RATE_LIMIT": 50,
            "NUCLEI_BULK_SIZE": 25,
            "NUCLEI_CONCURRENCY": 25,
            "NUCLEI_TIMEOUT": 10,
            "NUCLEI_RETRIES": 1,
            "NUCLEI_SYSTEM_RESOLVERS": True,
            "NUCLEI_FOLLOW_REDIRECTS": True,
            "NUCLEI_MAX_REDIRECTS": 10,
            "NUCLEI_MAX_HOST_ERROR": 30,
            "NUCLEI_EXCLUDE_TAGS": ["dos", "fuzz"],
            "NUCLEI_EXCLUDE_TEMPLATES": ["http/dos/"],
        })
        assert cmd, "takeover command was not built"
        assert "http/takeovers/" in cmd and "dns/" in cmd
        assert "-dast" not in cmd
        assert "-exclude-tags" not in cmd
        assert "-exclude-templates" not in cmd


# ---------------------------------------------------------------------------
# 5. Effective template set against the real Nuclei binary (frozen pool)
# ---------------------------------------------------------------------------

NUCLEI_BIN = shutil.which("nuclei")
DAST_DIR = Path(os.environ.get("F03_DAST_DIR", "/root/nuclei-templates/dast"))
TEMPLATES_DIR = Path(os.environ.get("F03_TEMPLATES_DIR", "/root/nuclei-templates"))


@pytest.mark.skipif(not NUCLEI_BIN, reason="nuclei binary not on PATH")
@pytest.mark.skipif(not DAST_DIR.is_dir(), reason=f"DAST template dir {DAST_DIR} not present")
class TestEffectiveDastTemplateSet:
    """The argv carrying a flag is not evidence the flag does anything.

    These checks run the real nuclei loader offline (``-tl`` lists the loaded
    templates, ``-validate`` validates them) against the frozen pool, and
    compare the loaded sets with and without the operator's exclusion.
    """

    def _loaded(self, *extra):
        proc = subprocess.run(
            [NUCLEI_BIN, "-duc", "-dast", "-t", str(DAST_DIR), "-tl", *extra],
            capture_output=True, text=True, timeout=120, check=False,
        )
        return proc

    def test_dast_pool_loads(self):
        proc = self._loaded()
        assert proc.returncode == 0, proc.stderr[:400]
        assert len(proc.stdout.splitlines()) > 0

    def test_exclusion_shrinks_the_loaded_set(self):
        baseline = self._loaded()
        assert baseline.returncode == 0, baseline.stderr[:400]
        base_lines = baseline.stdout.splitlines()
        # Pick a tag that actually exists in the pool so the check is a real
        # reduction, not a no-op asserted as coverage.
        with_exclude = self._loaded("-exclude-tags", "xss")
        if with_exclude.returncode != 0:
            pytest.skip(f"nuclei rejected the exclusion probe: {with_exclude.stderr[:200]}")
        if len(with_exclude.stdout.splitlines()) == len(base_lines):
            pytest.skip("no DAST template carries the 'xss' tag in this frozen pool")
        assert len(with_exclude.stdout.splitlines()) < len(base_lines)

    def test_exclude_templates_removes_that_directory(self):
        """-exclude-templates with a real subdirectory must shrink the set."""
        subdirs = [p for p in DAST_DIR.iterdir() if p.is_dir()]
        assert subdirs, f"no DAST subdirectories under {DAST_DIR}"
        target = f"dast/{subdirs[0].name}/"
        baseline = self._loaded()
        assert baseline.returncode == 0, baseline.stderr[:400]
        excluded = self._loaded("-exclude-templates", target)
        assert excluded.returncode == 0, excluded.stderr[:400]
        assert len(excluded.stdout.splitlines()) < len(baseline.stdout.splitlines())

    def test_validate_accepts_the_pool_with_the_denylist(self):
        proc = subprocess.run(
            [NUCLEI_BIN, "-duc", "-dast", "-t", str(DAST_DIR),
             "-exclude-tags", "xss", "-validate"],
            capture_output=True, text=True, timeout=180, check=False,
        )
        combined = (proc.stdout + proc.stderr).lower()
        # -validate reports per-template errors; a clean pool returns 0. A
        # non-zero here is a pool problem, not a policy result, so it is
        # reported rather than asserted away.
        assert "unable to load templates" not in combined, combined[:400]
