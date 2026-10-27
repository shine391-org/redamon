"""No recon module imports recon.main, and AI Surface's window check fails closed (plan 12.15).

The container runs `python /app/recon/main.py`, so `recon.main` is a SECOND
module object: importing it re-runs the pipeline's top level (another
get_settings() against the webapp, the stealth/AI/governor passes, the proxy
probe, a possible ScopeRefused). AI Surface Recon did that to reach
_check_roe_time_window, inside `except Exception: pass`, so any failure of the
import silently skipped the window check; partial Nmap did it to reach
merge_nmap_into_port_scan.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402

RECON = PROJECT_ROOT / "recon"


def _in_a_fresh_process(body: str) -> str:
    code = textwrap.dedent(f"""
        import sys
        sys.path[:0] = [{str(PROJECT_ROOT)!r}, {str(RECON)!r}]
    """) + textwrap.dedent(body)
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    return out.stdout.strip().splitlines()[-1]


def test_ai_surface_recon_runs_without_importing_recon_main():
    last = _in_a_fresh_process("""
        from unittest import mock
        from recon.main_recon_modules import ai_surface_recon as ais
        with mock.patch.object(ais, "_gather_candidates", return_value={}):
            ais.run_ai_surface_recon({"domain": "example.com"}, settings={
                "AI_SURFACE_RECON_ENABLED": True, "ROE_ENABLED": True,
                "ROE_TIME_WINDOW_ENABLED": True, "ROE_TIME_WINDOW_DAYS": [],
            })
        print("recon.main" in sys.modules)
    """)
    assert last == "False"


def test_the_nmap_merge_lives_outside_recon_main():
    last = _in_a_fresh_process("""
        from recon.helpers.nmap_merge import merge_nmap_into_port_scan
        from recon.partial_recon_modules import port_scanning
        print("recon.main" in sys.modules)
    """)
    assert last == "False"


def test_no_module_imports_recon_main():
    offenders = [str(p.relative_to(PROJECT_ROOT)) for p in RECON.rglob("*.py")
                 if "tests" not in p.parts and p.name != "main.py"
                 and "from recon.main import" in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_main_still_re_exports_both_names():
    with mock.patch("recon.project_settings.get_settings", return_value={
            'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
            'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [], 'USE_BRUTEFORCE_FOR_SUBDOMAINS': False,
            'SCAN_MODULES': [], 'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': ''}):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    from recon.helpers import nmap_merge, roe_scope
    assert rm._check_roe_time_window is roe_scope._check_roe_time_window
    assert rm.merge_nmap_into_port_scan is nmap_merge.merge_nmap_into_port_scan


class TestTheWindowCheckFailsClosed:
    def test_ai_surface_skips_itself_when_the_check_raises(self, monkeypatch):
        from recon.helpers import roe_scope
        from recon.main_recon_modules import ai_surface_recon as ais

        def broken(settings, _now=None):
            raise RuntimeError("zoneinfo exploded")

        monkeypatch.setattr(roe_scope, "_check_roe_time_window", broken)
        gather = mock.MagicMock(return_value={})
        monkeypatch.setattr(ais, "_gather_candidates", gather)
        combined = {"domain": "example.com"}
        out = ais.run_ai_surface_recon(combined, settings={"AI_SURFACE_RECON_ENABLED": True})
        assert out == {"domain": "example.com"}
        gather.assert_not_called()
        assert "ai_surface_recon" in cb.coverage_report().degraded_sources

    def test_outside_the_window_it_does_not_probe_and_keeps_its_findings(self, monkeypatch):
        from recon.helpers import roe_scope
        from recon.main_recon_modules import ai_surface_recon as ais
        monkeypatch.setattr(roe_scope, "_check_roe_time_window", lambda s, _now=None: (False, "closed"))
        gather = mock.MagicMock(return_value={})
        monkeypatch.setattr(ais, "_gather_candidates", gather)
        ais.run_ai_surface_recon({"domain": "example.com"}, settings={"AI_SURFACE_RECON_ENABLED": True})
        gather.assert_not_called()
        assert "ai_surface_recon" in cb.coverage_report().degraded_sources
