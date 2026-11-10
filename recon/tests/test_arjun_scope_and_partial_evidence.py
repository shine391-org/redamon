"""F06: actual generated input/argv -> salvage -> caller/artifact -> graph/coverage.

All target traffic is mocked. Two process-lifecycle cases use a local fake binary
that only writes JSON and exits/sleeps, inside the network-disabled test container.
Regression tests import only existing entry points so they run on pinned base too.
"""
import copy
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from unittest import mock

import pytest

from recon.helpers.resource_enum import arjun_helpers as ah
from recon.tests.test_coverage_prune import recon_main, graph  # fixture reuse

URL = 'https://api.example.test/api/users'
OPTIONS = dict(methods=['GET'], threads=2, timeout=7, scan_timeout=5,
               chunk_size=31, rate_limit=1, stable=False, passive=False,
               disable_redirects=True, custom_headers=['X-Identity: test'],
               allowed_hosts={'api.example.test'})


def fake_spawn(captured, payload=None, rc=0, timeout=False):
    def spawn(cmd, **kwargs):
        inputs = Path(cmd[cmd.index('-i') + 1]).read_text().splitlines()
        method = cmd[cmd.index('-m') + 1]
        captured.append({'inputs': inputs, 'method': method, 'cmd': cmd, 'env': kwargs.get('env', {})})
        output = payload if payload is not None else json.dumps({u: {'params': ['hidden'], 'method': method} for u in inputs})
        Path(cmd[cmd.index('-oJ') + 1]).write_text(output)
        proc = mock.MagicMock(returncode=rc)
        proc.communicate.return_value = ('', '')
        if timeout:
            proc.communicate.side_effect = [subprocess.TimeoutExpired(cmd, 1), ('', '')]
        return proc
    return spawn


@pytest.fixture(autouse=True)
def no_capture_or_network():
    with mock.patch('helpers.proxy_routing.get_capture_routing', return_value=(None, None)):
        yield


@pytest.mark.parametrize('url,host', [
    ('https://[2001:db8::1]:8443/a', '2001:db8::1'),
    ('http://192.0.2.1:8080/a', '192.0.2.1'),
    ('https://API.EXAMPLE.TEST:443/a', 'api.example.test'),
])
def test_result_host_scope_uses_parsed_hostname(url, host):
    payload = json.dumps({url: {'params': ['debug'], 'method': 'GET'},
                          'https://evil.example/a': {'params': ['foreign']}})
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn([], payload)):
        results, meta = ah.run_arjun_discovery([url], **{**OPTIONS, 'allowed_hosts': {host}})
    assert [r['url'] for r in results] == [url]
    assert [r['domain'] for r in meta['external_domains']] == ['evil.example']


@pytest.mark.parametrize('bad', [
    'https://api.example.test@evil.example/a', 'https://evil.example@api.example.test/a',
    'https://api.example.test:evil/a', 'https://api.example.test:99999/a',
    'https://api.example.test.evil.example/a', 'https://[2001:db8::2]/a',
    'https://[2001:db8::1/a', 'javascript://api.example.test/a',
    'https://api.example.test\\@evil.example/a', 'https://api.example.test/\nx',
    'https:///a',
])
def test_invalid_or_foreign_inputs_never_reach_generated_file(bad):
    calls = []
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn(calls)):
        ah.run_arjun_discovery([URL, bad], **OPTIONS)
    assert calls[0]['inputs'] == [URL]


@pytest.mark.parametrize('rc,timed_out', [(-9, False), (-15, True)])
def test_partial_output_salvage_keeps_complete_records_only(rc, timed_out):
    payload = ('{"' + URL + '": {"params": ["hidden"], "method": "POST"}, '
               '"https://api.example.test/unfinished": {"params": ["fabricated')
    calls = []
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn(calls, payload, rc, timed_out)):
        results, meta = ah.run_arjun_discovery([URL], **OPTIONS)
    assert [(r['url'], r['params'], r['method']) for r in results] == [(URL, ['hidden'], 'GET')]
    assert meta['status'] == 'partial'
    assert meta['execution'][0]['return_code'] == rc
    assert meta['execution'][0]['output_state'] == 'salvaged'
    assert results[0]['execution_status'] == 'partial'
    assert not Path(calls[0]['cmd'][calls[0]['cmd'].index('-i') + 1]).exists()


def test_scope_empty_is_not_permission_for_every_host():
    with mock.patch.object(ah.subprocess, 'Popen') as spawn:
        rows, _ = ah.run_arjun_discovery([URL], **{**OPTIONS, 'allowed_hosts': set()})
    assert rows == []
    spawn.assert_not_called()


def test_output_method_cannot_fabricate_post_evidence():
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn([], json.dumps({URL: {'params': ['x'], 'method': 'POST'}}))):
        rows, _ = ah.run_arjun_discovery([URL], **OPTIONS)
    by, _ = ah.merge_arjun_into_by_base_url(rows, {})
    ep = by['https://api.example.test']['endpoints']['/api/users']
    assert ep['methods'] == ['GET']
    assert ep['parameters']['body'] == []
    assert ep['parameters']['query'][0]['name'] == 'x'


@pytest.mark.parametrize('mode', ['kill', 'timeout'])
def test_real_local_subprocess_partial_results(tmp_path, monkeypatch, mode):
    executable = tmp_path / 'arjun'
    # No network imports/calls. Process writes valid output before termination.
    executable.write_text('#!' + sys.executable + '\nimport sys,json,os,signal,time\n'
                          'out=sys.argv[sys.argv.index("-oJ")+1]\n'
                          'with open(out,"w") as f: json.dump({' + repr(URL) + ': {"params":["real_partial"],"method":"GET"}},f)\n'
                          + ('os.kill(os.getpid(),signal.SIGKILL)\n' if mode == 'kill' else 'time.sleep(30)\n'))
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
    rows, meta = ah.run_arjun_discovery([URL], **{**OPTIONS, 'scan_timeout': -59.5 if mode == 'timeout' else 5})
    assert rows[0]['params'] == ['real_partial']
    assert meta['status'] == 'partial'
    assert meta['execution'][0]['timed_out'] == (mode == 'timeout')


def test_merge_reconciles_schema_not_stale_counters():
    by = {'https://api.example.test': {'endpoints': {'/api/users': {
        'methods': ['GET'], 'sources': ['katana'], 'parameters': {
            'query': [], 'body': [], 'path': [{'name': 'id'}]},
        'parameter_count': {'total': 999}, 'category': 'api'}},
        'summary': {'total_endpoints': 8, 'total_parameters': 999, 'methods': {}, 'categories': {}}}}
    rows = [{'url': URL, 'params': ['debug', 'debug'], 'method': 'JSON'}]
    by, stats = ah.merge_arjun_into_by_base_url(rows, by)
    ep = by['https://api.example.test']['endpoints']['/api/users']
    assert ep['parameter_count'] == {'query': 0, 'body': 1, 'path': 1, 'total': 2}
    assert by['https://api.example.test']['summary']['total_parameters'] == 2
    assert by['https://api.example.test']['summary']['total_endpoints'] == 1
    assert ep['methods'] == ['GET', 'POST']
    assert ep['parameters']['body'][0]['arjun_modes'] == ['JSON']
    assert stats['arjun_params_discovered'] == 1


def _graph_write(data):
    from graph_db.mixins.recon.resource_mixin import ResourceMixin
    writer = ResourceMixin()
    writer.driver = mock.MagicMock()
    session = writer.driver.session.return_value.__enter__.return_value
    session.run.return_value.single.return_value = {'linked': 0}
    stats = writer.update_graph_from_resource_enum(data, 'u', 'p')
    assert stats['errors'] == []
    return [(c.args[0], c.kwargs) for c in session.run.call_args_list]


def test_artifact_graph_retains_json_body_method_and_partial_state():
    by, _ = ah.merge_arjun_into_by_base_url([
        {'url': URL, 'params': ['q'], 'method': 'GET', 'execution_status': 'complete'},
        {'url': URL, 'params': ['secret'], 'method': 'JSON', 'execution_status': 'partial'},
    ], {})
    data = json.loads(json.dumps({'domain': 'example.test', 'metadata': {'root_domain': 'example.test'},
        'subdomains': ['api.example.test'], 'resource_enum': {'by_base_url': by,
        'scan_metadata': {'arjun_execution': {'status': 'partial'}}}}))
    calls = _graph_write(data)
    eps = {p['method']: p for q, p in calls if 'MERGE (e:Endpoint' in q}
    assert eps['GET']['body_count'] == 0
    assert eps['POST']['body_count'] == 1
    assert eps['POST']['query_count'] == 0
    body = [p for q, p in calls if 'MERGE (p:Parameter' in q and p['position'] == 'body']
    assert body[0]['arjun_modes'] == ['JSON']
    assert data['resource_enum']['scan_metadata']['arjun_execution']['status'] == 'partial'
    query_links = [p for q, p in calls if 'MERGE (e)-[:HAS_PARAMETER]' in q and p.get('position') == 'query']
    assert [p['method'] for p in query_links] == ['GET']


def test_actual_full_partial_callers_same_explicit_contract_and_coverage(tmp_path, recon_main, graph):
    from recon.tests.test_jev_resource_enum_flow import _run, CRAWLED
    from recon.main_recon_modules import resource_enum as full
    from recon.partial_recon_modules import parameter_discovery as partial
    from recon.helpers import circuit_breaker as cb
    settings = {'ARJUN_ENABLED': True, 'ARJUN_METHODS': ['GET', 'JSON'], 'ARJUN_THREADS': 3,
                'ARJUN_TIMEOUT': 7, 'ARJUN_SCAN_TIMEOUT': 5, 'ARJUN_CHUNK_SIZE': 31,
                'ARJUN_MAX_ENDPOINTS': 2, 'ARJUN_RATE_LIMIT': 1, 'ARJUN_DISABLE_REDIRECTS': True,
                'ARJUN_CUSTOM_HEADERS': ['X-Identity: test']}
    captures = []
    out = tmp_path / 'artifact.json'
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn(captures, rc=-9)), \
         mock.patch.object(full, 'arjun_binary_check', return_value=True):
        result = _run(settings, output_file=out)
    full_calls = captures[:]
    saved = json.loads(out.read_text())
    meta = saved['resource_enum']['scan_metadata']['arjun_execution']
    assert meta['status'] == 'partial'
    assert len(meta['unexecuted_urls']) == len(CRAWLED) - 2
    assert saved['resource_enum']['summary']['total_parameters'] == 4
    assert any(g['source'] == 'arjun' for g in cb.coverage_report().gaps)
    assert recon_main._write_coverage_record('example.test') is True
    assert any(g['source'] == 'arjun' for g in json.loads(graph.coverage[0]['gaps_json']))
    recon_main._prune_recon_findings()
    assert graph.prunes and all('arjun' not in p['sources'] for p in graph.prunes)
    # Existing prune only removes findings (not Endpoint/Parameter assets). A
    # resource-enum gap must not pretend a successful empty scan; no new prune.
    graph_payloads = []
    client = mock.MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.update_graph_from_resource_enum.side_effect = lambda **kw: graph_payloads.append(copy.deepcopy(kw['recon_data'])) or {}
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn(captures, rc=-9)), \
         mock.patch.object(ah, 'arjun_binary_check', return_value=True), \
         mock.patch.object(partial, 'partial_settings', return_value=dict(settings)), \
         mock.patch('graph_db.Neo4jClient', return_value=client):
        partial.run_arjun({'domain': 'example.test', 'include_graph_targets': False,
                          'user_targets': {'urls': CRAWLED}})
    def contract(rows):
        return sorted((r['method'], sorted(r['inputs']), tuple(r['cmd'][r['cmd'].index('-m'):])) for r in rows)
    assert contract(full_calls) == contract(captures[len(full_calls):])
    assert graph_payloads[0]['resource_enum']['scan_metadata']['arjun_execution'] == meta
    assert graph_payloads[0]['resource_enum']['summary']['total_parameters'] == 4
    assert _graph_write(saved)



def test_merge_keeps_raw_query_path_and_enforces_supplied_scope():
    raw = 'https://api.example.test/api;x=1?q=a%26b&q='
    by, _ = ah.merge_arjun_into_by_base_url([
        {'url': raw, 'params': ['q'], 'method': 'GET'},
        {'url': 'https://evil.example/admin', 'params': ['q'], 'method': 'GET'},
    ], {}, allowed_hosts={'api.example.test'})
    assert set(by) == {'https://api.example.test'}
    ep = by['https://api.example.test']['endpoints']['/api;x=1']
    assert ep['arjun_evidence'][0]['url'] == raw


def test_existing_multi_source_param_keeps_legacy_applicability_not_fake_execution():
    # Legacy schema did not carry per-param methods; don't erase other-source
    # evidence on the strength of one GET probe. Arjun execution is separate.
    by = {'https://api.example.test': {'endpoints': {'/api/users': {
        'methods': ['GET', 'POST'], 'parameters': {'query': [{'name': 'q'}], 'body': [], 'path': []},
        'sources': ['katana'], 'category': 'api'}}}}
    by, _ = ah.merge_arjun_into_by_base_url([{'url': URL, 'params': ['q'], 'method': 'GET'}], by)
    ep = by['https://api.example.test']['endpoints']['/api/users']
    assert ep['parameters']['query'][0]['arjun_methods'] == ['GET']
    assert not ep['parameters']['query'][0].get('arjun_only')
    assert ep['arjun_evidence'][0]['method'] == 'GET'
    calls = _graph_write({'domain': 'example.test', 'subdomains': ['api.example.test'],
                          'resource_enum': {'by_base_url': by}})
    params = [p for q, p in calls if 'MERGE (p:Parameter' in q]
    assert params[0]['arjun_methods'] == ['GET']


def test_partial_ipv6_host_survives_input_and_graph_link():
    from recon.partial_recon_modules import parameter_discovery as partial
    captures, payloads = [], []
    client = mock.MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.update_graph_from_resource_enum.side_effect = lambda **kw: payloads.append(kw['recon_data']) or {}
    with mock.patch.object(ah.subprocess, 'Popen', side_effect=fake_spawn(captures)), \
         mock.patch.object(ah, 'arjun_binary_check', return_value=True), \
         mock.patch('graph_db.Neo4jClient', return_value=client):
        partial.run_arjun({'domain': '2001:db8::1', 'include_graph_targets': False,
                          '_settings': {'ARJUN_METHODS': ['GET']},
                          'user_targets': {'urls': ['https://[2001:db8::1]:8443/a']}})
    assert captures[0]['inputs'] == ['https://[2001:db8::1]:8443/a']
    assert '2001:db8::1' in payloads[0]['subdomains']
    session = client.driver.session.return_value.__enter__.return_value
    hosts = [c.kwargs['host'] for c in session.run.call_args_list if 'host' in c.kwargs]
    assert hosts == ['2001:db8::1']


def test_resolved_settings_default_and_saved_cap_not_raised():
    from recon.helpers.resource_enum.arjun_contract import arjun_settings
    from recon.project_settings import DEFAULT_SETTINGS, get_settings
    from recon.partial_recon_modules import helpers
    # Real loaders, offline DEFAULT_SETTINGS; no project API/DB contact.
    with mock.patch.dict(os.environ, {'PROJECT_ID': 'fixture', 'WEBAPP_API_URL': 'http://not-called'}), \
         mock.patch('recon.project_settings.fetch_project_settings', return_value=dict(DEFAULT_SETTINGS)):
        loaded = get_settings()
    partial_loaded = helpers.partial_settings({'_settings': loaded})
    assert arjun_settings(partial_loaded) == arjun_settings(loaded)
    assert arjun_settings(loaded)['ARJUN_MAX_ENDPOINTS'] == DEFAULT_SETTINGS['ARJUN_MAX_ENDPOINTS'] == 50000
    assert arjun_settings({'ARJUN_MAX_ENDPOINTS': 3})['ARJUN_MAX_ENDPOINTS'] == 3
    assert arjun_settings({})['ARJUN_MAX_ENDPOINTS'] == 50
    assert arjun_settings({})['ARJUN_METHODS'] == ['GET']
