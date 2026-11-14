"""Execute run_nuclei AND real run_vuln_scan, faking only external consumers."""
import contextlib
import copy
import io
from unittest.mock import patch

import pytest
from test_partial_override_contract import (
    vuln_caller, vuln_scan, TOGGLE_KEYS, _SYNTHETIC_GRAPH, _silence_graph_writes,
)


@pytest.mark.parametrize('enabled', [False, True])
@pytest.mark.parametrize('mode', ['off', 'shadow'])
def test_modal_controls_actual_cve_security_and_mitre_dispatch(enabled, mode):
    # Docker-unavailable is a deliberate synthetic control. The real scanner
    # must still run its optional non-Nuclei stages according to the overrides;
    # no Docker daemon, network, template download or target probe is available.
    config = {'domains': ['synthetic.test'], 'include_graph_targets': True,
              'settings_overrides': {key: enabled for key in TOGGLE_KEYS},
              '_settings': {key: not enabled for key in TOGGLE_KEYS}}
    config['_settings'].update({'PLANNER_MODE': mode, 'NUCLEI_AI_TAGS': False})
    from recon.main_recon_modules import add_mitre
    with patch.object(vuln_caller, '_build_vuln_scan_data_from_graph',
                      return_value=copy.deepcopy(_SYNTHETIC_GRAPH)), \
         patch.object(vuln_scan, 'is_docker_installed', return_value=False), \
         patch.object(vuln_scan, 'run_cve_lookup', return_value={}) as cve, \
         patch.object(vuln_scan, 'run_security_checks', return_value={}) as security, \
         patch.object(add_mitre, 'run_mitre_enrichment', side_effect=lambda result, **kw: result) as mitre, \
         _silence_graph_writes(), contextlib.redirect_stdout(io.StringIO()):
        vuln_caller.run_nuclei(config)
    assert cve.call_count == int(enabled)
    assert security.call_count == int(enabled)
    assert mitre.call_count == int(enabled)
    if enabled:
        assert cve.call_args.kwargs['enabled'] is True
        assert security.call_args.kwargs['settings']['SECURITY_CHECK_ENABLED'] is True
        assert mitre.call_args.kwargs['settings']['MITRE_ENABLED'] is True
    assert config['_settings']['CVE_LOOKUP_ENABLED'] is not enabled


@pytest.mark.parametrize('dast', [False, True])
def test_off_shadow_preserve_actual_native_argv_and_target_files(monkeypatch, dast):
    from pathlib import Path
    from recon.helpers import nuclei_helpers
    from helpers import proxy_routing

    query_url = 'https://synthetic.test/path/?q=a%26b&q=x%2By&blank='
    captured = {}
    current_mode = None

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        host_dir = next(arg.rsplit(':/targets:ro', 1)[0]
                        for arg in cmd if arg.endswith(':/targets:ro'))
        filename = Path(cmd[cmd.index('-l') + 1]).name
        targets = (Path(host_dir) / filename).read_text().splitlines()
        # Only discard the Docker envelope's per-run UUID/path. The complete
        # native argument tail, including policies, remains byte-for-byte.
        native = cmd[cmd.index('projectdiscovery/nuclei:latest') + 1:]
        captured.setdefault(current_mode, []).append((label, native, targets))
        return [], [], 0.0, 0

    monkeypatch.setattr(vuln_scan, 'is_docker_installed', lambda: True)
    monkeypatch.setattr(vuln_scan, 'is_docker_running', lambda: True)
    monkeypatch.setattr(vuln_scan, 'pull_nuclei_docker_image', lambda image: True)
    monkeypatch.setattr(vuln_scan, 'ensure_templates_volume', lambda *args: True)
    monkeypatch.setattr(vuln_scan, 'extract_targets_from_recon', lambda rd, settings=None: ([], ['synthetic.test'], {}))
    monkeypatch.setattr(vuln_scan, 'build_nuclei_command', nuclei_helpers.build_nuclei_command)
    monkeypatch.setattr(vuln_scan, '_execute_nuclei_pass', fake_pass)
    monkeypatch.setattr(vuln_scan, 'set_fp_ai_ctx', lambda **kw: None)
    monkeypatch.setattr(proxy_routing, 'get_capture_routing', lambda tool: (None, None))
    for mode in ('off', 'shadow'):
        current_mode = mode
        data = copy.deepcopy(_SYNTHETIC_GRAPH)
        data['http_probe']['by_url'] = {query_url: {'host': 'synthetic.test'}}
        data['resource_enum']['discovered_urls'] = [query_url]
        data['resource_enum']['by_base_url'] = {
            'https://synthetic.test': {'endpoints': {
                '/path/': {'sample_url': query_url, 'methods': ['GET'],
                           'parameters': {'query': [{'name': 'q'}, {'name': 'blank'}]}}
            }}
        }
        config = {'domains': ['synthetic.test'], 'include_graph_targets': True,
                  '_settings': {'NUCLEI_TAGS': ['cve'], 'NUCLEI_DAST_MODE': dast,
                                'NUCLEI_RATE_LIMIT': 42, 'NUCLEI_AUTO_UPDATE_TEMPLATES': False,
                                'NUCLEI_AI_TAGS': False, 'NUCLEI_MAX_RUNTIME': 0,
                                'NUCLEI_EXCLUDE_TAGS': ['dos', 'fuzz'],
                                'NUCLEI_EXCLUDE_TEMPLATES': ['synthetic-denied.yaml']},
                  'settings_overrides': {**{key: False for key in TOGGLE_KEYS},
                                         'PLANNER_MODE': mode, 'NUCLEI_RATE_LIMIT': 7}}
        with patch.object(vuln_caller, '_build_vuln_scan_data_from_graph', return_value=data), \
             _silence_graph_writes(), contextlib.redirect_stdout(io.StringIO()):
            vuln_caller.run_nuclei(config)
    assert captured['off'] == captured['shadow']
    assert [row[0] for row in captured['off']] == (['DETECTION', 'DAST'] if dast else ['DETECTION'])
    for label, native, targets in captured['off']:
        assert query_url in targets
        assert native[native.index('-rate-limit') + 1] == '7'
        assert '-exclude-tags' in native and 'dos,fuzz' in native
        assert '-exclude-templates' in native and 'synthetic-denied.yaml' in native
