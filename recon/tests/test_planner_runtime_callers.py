"""Offline actual-dispatch regressions; no Docker socket, graph or targets."""
import copy
import json
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from recon.tests import test_nuclei_two_pass as fixtures

def Fixture():
    return fixtures.TestRunVulnScanTwoPass()
from recon.main_recon_modules import vuln_scan as vs
from recon.helpers.planner_manifest import read_manifest_in_context


def settings(**extra):
    return dict(Fixture()._settings(dast_mode=True), PLANNER_TENANT='tenant-test',
                PLANNER_PROJECT_ID='project-test', PLANNER_RUN_ID='run-test',
                PLANNER_GROUP_ID='domain:example.com', PLANNER_MANIFEST_ENABLED=True, TARGET_DOMAIN='example.com',
                **extra)


def execute(tmp_path, opts, targets=None, data=None, isolated=False):
    fixture = Fixture()
    fixture.generated_targets = {}
    artifact = tmp_path / 'artifact.json'
    artifact.write_text(json.dumps({'unrelated_tool': {'durable': True}}))
    data = data or fixture._recon_data(dast_urls=['https://example.com/search?q=a%26b'])
    calls = []
    with ExitStack() as stack:
        for p in fixture._patch_pipeline(targets or ['https://example.com', 'https://example.com/app?q=a%26b']):
            stack.enter_context(p)
        stack.enter_context(patch('recon.helpers.planner_runtime.publish_plan_pointer'))
        def dispatch(*args, **kwargs):
            # Assert plan is durable and strictly readable BEFORE execution.
            saved = json.loads(artifact.read_text())
            pointer = saved['planner_manifest']
            manifest = read_manifest_in_context(Path(pointer['plan_manifest_path']),
                expected_context={'tenant': 'tenant-test', 'project_id': 'project-test', 'run_id': 'run-test',
                                  'group_id': opts['PLANNER_GROUP_ID']},
                expected_sha256=pointer['plan_manifest_sha256'])
            assert manifest['status'] == 'known'
            assert saved.get('unrelated_tool', {}).get('durable') is True if isolated else True
            calls.append({'cmd': args[0], 'label': kwargs['label'], 'manifest': manifest})
            return [], [], 0.01, 0
        stack.enter_context(patch.object(vs, '_execute_nuclei_pass', side_effect=dispatch))
        result = vs.run_vuln_scan_isolated(data, opts, artifact) if isolated else vs.run_vuln_scan(data, artifact, opts)
    return fixture.generated_targets, calls, result, artifact


@pytest.mark.parametrize('mode', ['off', 'shadow', 'enforce'])
def test_actual_modes_and_target_selection(tmp_path, mode):
    opts = settings(PLANNER_MODE=mode, PLANNER_CONSUMER_TARGET_SELECTION=True,
                    PLANNER_CONSUMER_AI_TAGS=True, NUCLEI_TAGS=['ssl'])
    # Legacy AI remains off; planner shadow must not invoke its selector.
    with patch('recon.helpers.ai_planner.nuclei_tags.get_ai_tags', return_value=['ssl']) as ai:
        files, calls, result, _ = execute(tmp_path, opts)
    assert ai.call_count == (1 if mode == 'enforce' else 0)
    assert files['targets_dast.txt'] == ['https://example.com/search?q=a%26b']
    if mode == 'enforce':
        assert files['targets_origin_safe.txt'] == ['https://example.com']
        assert 'targets_legacy.txt' not in files
    else:
        assert files['targets_legacy.txt'] == ['https://example.com', 'https://example.com/app?q=a%26b']
    manifest = calls[0]['manifest']
    if mode != 'off':
        assert manifest['tasks'] and manifest['tasks'][0]['provenance']
        assert manifest['plan_id']
    assert manifest['inventory']['source'] == 'resource_enum'


def test_actual_ai_consumer_prune_only(tmp_path):
    opts = settings(PLANNER_MODE='enforce', PLANNER_CONSUMER_AI_TAGS=True,
                    NUCLEI_TAGS=['cve', 'ssl'], NUCLEI_EXCLUDE_TAGS=['dos'])
    with patch('recon.helpers.ai_planner.nuclei_tags.get_ai_tags', return_value=['ssl', 'dos', 'alien']):
        _, calls, _, _ = execute(tmp_path, opts)
    command = calls[0]['cmd']
    assert command[command.index('-tags') + 1] == 'ssl'
    selection = calls[0]['manifest']['selection']['ai_tags']
    assert selection['effective_tags'] == ['ssl']


@pytest.mark.parametrize('mode,enabled', [('off', True), ('shadow', True), ('enforce', False), ('enforce', True)])
def test_actual_two_pass_consumer_defers_unsupported_body(tmp_path, mode, enabled):
    data = Fixture()._recon_data(dast_urls=['https://example.com/api?q=a%26b'] * 2)
    data['resource_enum']['by_base_url'] = {'https://example.com': {'endpoints': {
        '/api': {'methods': ['POST'], 'parameters': {'body': [{'name': 'payload'}]}}
    }}}
    opts = settings(PLANNER_MODE=mode, PLANNER_CONSUMER_TWO_PASS=enabled)
    files, calls, result, _ = execute(tmp_path, opts, data=data)
    effective = mode == 'enforce' and enabled
    assert ('targets_dast.txt' in files) is not effective
    assert len(calls) == (1 if effective else 2)
    if effective:
        assert calls[0]['manifest']['consumers']['two_pass']['deferred_count'] == 1
        assert calls[0]['manifest']['selection']['deferred_dast_count'] == 1
        assert calls[0]['manifest']['tasks'][-1]['method'] == 'POST'
        assert result['selection_coverage']['exhaustive'] is False


def test_isolated_pointer_merge_and_redaction(tmp_path):
    marker = 'synthetic-sensitive-marker'
    opts = settings(PLANNER_MODE='shadow', NUCLEI_TEMPLATES=[f'https://u:{marker}@example.com/template?token={marker}'],
                    NUCLEI_TAGS=[], NUCLEI_CUSTOM_HEADERS=[f'Authorization: {marker}'])
    files, calls, result, artifact = execute(tmp_path, opts, isolated=True)
    pointer = result['planner_manifest']
    serialized = Path(pointer['plan_manifest_path']).read_text()
    assert marker not in serialized
    assert marker not in json.dumps(pointer)
    assert json.loads(artifact.read_text())['unrelated_tool']['durable'] is True
    assert files['targets_legacy.txt'][1].endswith('?q=a%26b')
    assert result['planner_manifest']['plan_manifest_sha256']


def test_routing_uses_admitted_encoded_urls_not_inventory_synthesis(tmp_path):
    data = Fixture()._recon_data(dast_urls=[])
    data['resource_enum']['by_base_url'] = {'https://unadmitted.invalid': {'endpoints': {
        '/secret': {'parameters': {'query': [{'name': 'token'}]}}
    }}}
    opts = settings(PLANNER_MODE='shadow', NUCLEI_ROUTING_MODE='enforce', NUCLEI_TAGS=['mystery'])
    files, calls, _, _ = execute(tmp_path, opts, data=data)
    assert files['targets_unknown.txt'] == ['https://example.com', 'https://example.com/app?q=a%26b']
    assert 'unadmitted.invalid' not in '\n'.join(files['targets_unknown.txt'])


def test_missing_origin_and_oversize_are_compatibility(tmp_path):
    opts = settings(PLANNER_MODE='enforce', PLANNER_CONSUMER_TARGET_SELECTION=True, NUCLEI_TAGS=['ssl'])
    targets = ['https://example.com/path?q=a%26b']
    files, calls, _, _ = execute(tmp_path, opts, targets=targets)
    assert files['targets_unknown.txt'] == targets
    targets = [f'https://example.com/p{i}' for i in range(70)]
    files, calls, _, _ = execute(tmp_path, opts, targets=targets)
    assert calls[0]['manifest']['oversize'] is True
    assert files['targets_legacy.txt'] == targets


def test_partial_caller_supplies_canonical_context_and_calls_same_boundary(monkeypatch):
    from recon.partial_recon_modules import vulnerability_scanning as partial
    monkeypatch.setenv('USER_ID', 'tenant-test')
    monkeypatch.setenv('PROJECT_ID', 'project-test')
    monkeypatch.setenv('PARTIAL_RECON_RUN_ID', 'run-test')
    captured = {}
    def scan(data, **kwargs):
        captured.update(kwargs['settings'])
        return data
    client = MagicMock()
    client.__enter__.return_value.verify_connection.return_value = False
    with patch.object(partial, 'partial_settings', return_value={'MITRE_ENABLED': False}), \
         patch.object(partial, 'graph_url_fingerprints', return_value={}), \
         patch.object(vs, 'run_vuln_scan', side_effect=scan), \
         patch('graph_db.Neo4jClient', return_value=client):
        partial.run_nuclei({'domain': 'example.com', 'tool_id': 'nuclei', 'include_graph_targets': False,
                            'user_targets': {'urls': ['https://example.com/path?q=a%26b']}})
    assert {k: captured[k] for k in ('PLANNER_TENANT', 'PLANNER_PROJECT_ID', 'PLANNER_RUN_ID', 'PLANNER_GROUP_ID')} == {
        'PLANNER_TENANT': 'tenant-test', 'PLANNER_PROJECT_ID': 'project-test',
        'PLANNER_RUN_ID': 'run-test', 'PLANNER_GROUP_ID': 'partial:nuclei'}


def test_actual_partial_context_manifest(tmp_path):
    opts = settings(PLANNER_MODE='shadow')
    opts['PLANNER_GROUP_ID'] = 'partial:nuclei'
    _, calls, _, _ = execute(tmp_path, opts)
    assert calls[0]['manifest']['group_id'] == 'partial:nuclei'


@pytest.mark.parametrize('values,expected', [
    ({}, ('off', True, True, True, 0, 0)),
    ({'nucleiRoutingMode': 'enforce', 'jsReconFetchAdmission': False, 'arjunLateSources': False,
      'chunkCheckpointEnabled': False, 'checkpointBudgetPerGroup': 2, 'checkpointBudgetPerTool': 3},
     ('enforce', False, False, False, 2, 3)),
    ({'nucleiRoutingMode': 'invalid', 'jsReconFetchAdmission': 'false', 'arjunLateSources': 0,
      'checkpointBudgetPerGroup': True, 'checkpointBudgetPerTool': -1}, ('off', True, True, True, 0, 0)),
])
def test_project_loader_real_mapping(values, expected):
    from recon import project_settings
    response = MagicMock()
    response.json.return_value = {'targetDomain': 'example.com', **values}
    with patch('requests.get', return_value=response):
        loaded = project_settings.fetch_project_settings('project-test', 'http://webapp.invalid')
    assert tuple(loaded[k] for k in ('NUCLEI_ROUTING_MODE', 'JS_RECON_FETCH_ADMISSION',
        'ARJUN_LATE_SOURCES', 'CHUNK_CHECKPOINT_ENABLED', 'CHECKPOINT_BUDGET_PER_GROUP',
        'CHECKPOINT_BUDGET_PER_TOOL')) == expected


@pytest.mark.parametrize('mode', ['off', 'shadow'])
def test_legacy_ai_remains_enabled_in_off_shadow_without_extra_calls(tmp_path, mode):
    opts = settings(PLANNER_MODE=mode, NUCLEI_AI_TAGS=True, NUCLEI_TAGS=['cve', 'ssl'],
                    PLANNER_CONSUMER_AI_TAGS=True)
    with patch('recon.helpers.ai_planner.nuclei_tags.get_ai_tags', return_value=['ssl']) as ai:
        _, calls, _, _ = execute(tmp_path, opts)
    assert ai.call_count == 1
    command = calls[0]['cmd']
    assert command[command.index('-tags') + 1] == 'ssl'


def test_two_pass_never_enables_dast_or_changes_encoded_requests(tmp_path):
    opts = settings(PLANNER_MODE='enforce', PLANNER_CONSUMER_TWO_PASS=True)
    opts['NUCLEI_DAST_MODE'] = False
    targets = ['https://example.com/api?q=%2F&q=&q=a%26b', 'https://example.com/api?q=/']
    files, calls, _, _ = execute(tmp_path, opts, targets=targets)
    assert len(calls) == 1
    assert 'targets_dast.txt' not in files
    assert files['targets_legacy.txt'] == targets


def test_mixed_template_tag_policy_keeps_legacy_intersection(tmp_path):
    opts = settings(PLANNER_MODE='enforce', PLANNER_CONSUMER_TARGET_SELECTION=True,
                    NUCLEI_ROUTING_MODE='enforce', NUCLEI_TEMPLATES=['ssl/test.yaml'],
                    NUCLEI_TAGS=['ssl'])
    files, calls, _, _ = execute(tmp_path, opts)
    assert 'targets_legacy.txt' in files
    assert len(calls) == 2
    assert '-t' in calls[0]['cmd'] and '-tags' in calls[0]['cmd']
    assert 'indivisible' in calls[0]['manifest']['selection']['routing_compatibility_reason']


def test_missing_context_and_unwritable_manifest_do_not_change_dispatch(tmp_path):
    from recon.helpers import planner_runtime as runtime
    opts = settings(PLANNER_MODE='shadow')
    opts['PLANNER_GROUP_ID'] = ''
    data = {}
    assert runtime.persist_dispatch(opts, data, tmp_path / 'artifact.json', [], {}, [], []) is None
    assert 'planner_manifest' not in data
    opts['PLANNER_GROUP_ID'] = 'domain:example.com'
    with patch('recon.helpers.planner_manifest.write_manifest', side_effect=OSError('synthetic-failure')):
        assert runtime.persist_dispatch(opts, data, tmp_path / 'artifact.json', [], {}, [], []) is None
    assert 'planner_manifest' not in data
