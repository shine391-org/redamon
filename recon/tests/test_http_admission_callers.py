"""F01: offline HTTP admission at actual consumer files and subprocess argv.

Only external tool / DB boundaries are mocked; no target traffic or Docker socket.
"""
import copy
import json
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import target_helpers as th

BAD = [
    'tel:+123?q=1', 'javascript:alert(1)?q=1', 'mailto:a@example.test?q=1',
    'ftp://app.example.test/?q=1', 'https:///a?q=1', 'https://:443/a?q=1',
    'https://app.example.test:bad/a?q=1', 'https://app.example.test:65536/?q=1',
    'https://[::1/a?q=1', 'https://[::1]garbage/a?q=1',
    'https://app.example.test:/a?q=1', 'https://app.example.test:0/a?q=1',
    'https://user:pass@app.example.test/a?q=1',
    'https://app.example.test\\@other.test/a?q=1',
    'https://app.example.test/a\n?q=1', '\thttps://app.example.test/a?q=1',
    'https://app.example.test/a?q=1\r', 'https://app.example.test/a\x00?q=1',
]
GOOD = [
    'https://App.example.test:8443/App/A%2fb/?q=%2B&q=two+words',
    'http://192.0.2.1:8080/API?q=1',
    'https://[2001:db8::1]:8443/App/A%2fb/?q=1',
]


@pytest.mark.parametrize('url', BAD)
def test_invalid_uri_is_rejected_in_every_builder_source_without_mutation(url, capsys):
    data = {'http_probe': {'by_url': {url: {'status_code': 200}}},
            'resource_enum': {'by_base_url': {url: {'endpoints': {'/ok': {}}}}}}
    before = copy.deepcopy(data)
    assert th.build_target_urls(set(), set(), data) == []
    assert data == before  # raw observations remain exactly as received
    report = capsys.readouterr().out
    assert 'httpx_or_supplied' in report and 'resource_enum_base' in report
    # Reports contain reasons/source, not harvested values or credentials.
    assert url not in report


@pytest.mark.parametrize('url', GOOD)
def test_good_uri_keeps_exact_fidelity(url):
    assert th.http_url_rejection(url) is None
    assert th.build_target_urls_from_httpx({'by_url': {url: {'status_code': 403}}}) == [url]


def test_endpoint_and_fallback_admission(capsys):
    eps = {p: {} for p in ['tel:+123', 'javascript:bad', 'mailto:a@b.test', '//foreign.test/x', '/a\n/z']}
    eps['/App/%2fX'] = {'status_codes': [404]}
    data = {'resource_enum': {'by_base_url': {'https://app.example.test': {'endpoints': eps}}}}
    before = copy.deepcopy(data)
    urls = th.build_target_urls({'bad.test/path', 'bad.test\n', 'next.example.test'},
                               {'192.0.2.3', '2001:db8::3', 'javascript:x'}, data, True)
    assert set(urls) == {'https://app.example.test', 'https://app.example.test/App/%2fX',
                         'http://next.example.test', 'https://next.example.test',
                         'http://192.0.2.3', 'https://192.0.2.3',
                         'http://[2001:db8::3]', 'https://[2001:db8::3]'}
    assert data == before
    text = capsys.readouterr().out
    assert 'resource_enum_path' in text and 'not_relative_path' in text
    assert 'fallback_hostname' in text and 'fallback_ip' in text


@pytest.mark.parametrize('status', [401, 403, 404, 405])
def test_not_global_response_status_policy(status):
    url = 'https://app.example.test/Path?q=1'
    assert th.build_target_urls_from_httpx({'by_url': {url: {'status_code': status}}}) == [url]


def test_detection_and_dast_generated_files_reject_malformed_raw_inputs(monkeypatch):
    # Reuse the executable P0 caller harness; keep the REAL shared builder and
    # command builder, inspect target files from the generated Docker argv.
    from recon.tests.test_no_b_large_inputs import _run_pipeline
    resource = {'by_base_url': {'https://a.example.com': {'endpoints': {'/App': {}}}},
                'discovered_urls': BAD + GOOD + ['https://a.example.com/#?q=1']}
    resource['by_base_url'].update({u: {'endpoints': {'/x': {}}} for u in BAD})
    before = copy.deepcopy(resource)
    state, result = _run_pipeline(monkeypatch, resource, True)
    detection, dast = state['passes']
    assert detection['targets'] == ['https://a.example.com', 'https://a.example.com/App']
    assert dast['targets'] == GOOD
    assert resource == before
    report = result['vuln_scan']['scan_metadata']['http_admission']['resource_enum_dast']
    assert sum(report['rejected'].values()) == len(BAD)
    # The scan result survives the public isolated-return contract, JSON artifact
    # serialization, and retains dispositions independently of raw observations.
    from recon.main_recon_modules.vuln_scan import _VULN_SCAN_RESULT_KEYS
    assert 'vuln_scan' in _VULN_SCAN_RESULT_KEYS
    assert json.loads(json.dumps(result))['vuln_scan']['scan_metadata']['http_admission']


def test_dast_nonhttp_filter_is_independent_of_detection_admission(monkeypatch):
    from recon.tests.test_no_b_large_inputs import _run_pipeline
    resource = {'by_base_url': {'https://a.example.com': {'endpoints': {'/ok': {}}}},
                'discovered_urls': BAD[:3] + GOOD}
    state, result = _run_pipeline(monkeypatch, resource, True)
    assert state['passes'][1]['targets'] == GOOD
    disposition = result['vuln_scan']['scan_metadata']['http_admission']['resource_enum_dast']
    assert disposition['rejected'] == {'non_http_scheme': 3}


def test_ffuf_actual_argv_has_path_placeholder_and_keeps_identity(monkeypatch):
    from recon.helpers.resource_enum import ffuf_helpers as ff
    from helpers import proxy_routing
    monkeypatch.setattr(proxy_routing, 'get_capture_routing', lambda tool: (None, None))
    seen = []

    def execute(cmd, **kwargs):
        seen.append(cmd)
        Path(cmd[cmd.index('-o') + 1]).write_text('{"results": []}')
        return mock.Mock(returncode=0, stderr='')

    monkeypatch.setattr(ff, 'run_with_heartbeat', execute)
    ff.run_ffuf_discovery(
        ['https://app.example.test:8443/api?q=1', 'https://app.example.test/App%2fX?q=2'] + BAD,
        wordlist='/wordlist', threads=1, rate=1, timeout=1, max_time=1,
        match_codes=[200, 403], filter_codes=[], filter_size='', extensions=[],
        recursion=False, recursion_depth=1, auto_calibrate=True,
        custom_headers=['X-Bug-Bounty: fixture'], follow_redirects=False,
        allowed_hosts={'app.example.test'}, discovered_base_paths=['v1'], parallelism=1)
    targets = [cmd[cmd.index('-u') + 1] for cmd in seen]
    assert targets == ['https://app.example.test:8443/api/FUZZ?q=1',
                       'https://app.example.test/App%2fX/FUZZ?q=2',
                       'https://app.example.test:8443/api/v1/FUZZ?q=1',
                       'https://app.example.test/App%2fX/v1/FUZZ?q=2']
    assert all('-r' not in cmd and '-ac' in cmd and 'X-Bug-Bounty: fixture' in cmd for cmd in seen)


class StopAtTool(BaseException):
    pass


@pytest.mark.parametrize('runner,tool,pull', [
    ('run_katana', 'run_katana_crawler', 'pull_katana_docker_image'),
    ('run_hakrawler', 'run_hakrawler_crawler', 'pull_hakrawler_docker_image'),
    ('run_ffuf', 'run_ffuf_discovery', 'pull_ffuf_binary_check'),
])
def test_partial_caller_keeps_deep_supplied_seeds_without_fake_status(monkeypatch, runner, tool, pull):
    from recon.partial_recon_modules import web_crawling as wc
    from recon.helpers import resource_enum as re
    seed = GOOD[0]
    seen = {}
    real_builder = wc.build_target_urls

    def builder(hosts, ips, data, **kwargs):
        entry = data['http_probe']['by_url'][seed]
        assert entry['status_code'] is None and entry['provenance'] == 'supplied'
        urls = real_builder(hosts, ips, data, **kwargs)
        seen['targets'] = urls
        return urls

    def boundary(urls, *args, **kwargs):
        assert urls == [seed]
        raise StopAtTool

    monkeypatch.setattr(wc, 'build_target_urls', builder)
    monkeypatch.setattr(re, pull, lambda *a, **k: True)
    monkeypatch.setattr(re, tool, boundary)
    cfg = {'domain': 'example.test', 'domains': ['example.test'], '_settings': {},
           'include_graph_targets': False, 'user_targets': {'urls': [seed] + BAD}}
    with pytest.raises(StopAtTool):
        getattr(wc, runner)(cfg)
    assert seen['targets'] == [seed]


def test_cache_consumer_retains_query_and_status_unknown(monkeypatch):
    from recon.cache_scan.scanner import _collect_target_urls
    data = {'http_probe': {'by_url': {}}}
    th.add_supplied_http_targets(data, GOOD + BAD)
    before = copy.deepcopy(data)
    assert _collect_target_urls(data, {}) == sorted(GOOD)
    assert data == before
    assert all(data['http_probe']['by_url'][u]['status_code'] is None for u in GOOD)


@pytest.mark.parametrize('url', ['https://éxample.test/App?q=1', 'https://app_internal.test/App?q=1'])
def test_http_host_compatibility_is_not_dns_injection_policy(url):
    assert th.http_url_rejection(url) is None
    assert th.build_target_urls_from_httpx({'by_url': {url: {'status_code': 200}}}) == [url]


def test_later_measured_server_error_is_admitted_not_overridden():
    assert th.build_target_urls_from_httpx({'by_url': {GOOD[0]: {
        'status_code': 503, 'provenance': 'supplied'}}}) == [GOOD[0]]


def test_ffuf_identical_generated_directory_tasks_are_not_repeated():
    from recon.helpers.resource_enum.ffuf_helpers import _build_fuzz_targets
    assert _build_fuzz_targets(['https://app.test/api?q=1', 'https://app.test/api?q=2',
                                'https://app.test/api?q=1']) == [
        'https://app.test/api/FUZZ?q=1', 'https://app.test/api/FUZZ?q=2']


def test_raw_controls_do_not_get_normalized_by_partial_scope_guard():
    from recon.partial_recon_modules.helpers import filter_partial_user_input

    config = {'domain': 'example.test', 'domains': ['example.test'],
              'domain_groups': [{'rootDomain': 'example.test', 'prefixes': ['app'], 'batch': True}],
              'user_targets': {'urls': ['\nhttps://app.example.test/a',
                                        'https://app.example.test/a?q=1',
                                        'https://other.example.test/a?q=1']}}
    refused = filter_partial_user_input(config, {'SUBDOMAIN_LIST': ['app']})
    assert refused
    assert config['user_targets']['urls'] == ['https://app.example.test/a?q=1']


def test_invalid_composed_declared_urls_do_not_consume_the_500_valid_slots():
    eps = {'/000': {'declared_only': True, 'methods': ['GET'], 'parameters': {
        'query': [{'name': 'q', 'sample_values': ['x\ny']}]}}}
    eps.update({f'/d{i:04}': {'declared_only': True, 'methods': ['GET']} for i in range(500)})
    report = {}
    _, urls = th.build_target_urls_from_resource_enum({
        'by_base_url': {'https://app.test': {'endpoints': eps}}}, report)
    assert len(urls) == 500
    assert report['resource_enum_endpoint']['rejected'] == {'control_or_whitespace': 1}


def test_full_resource_caller_uses_http_admission_without_nuclei_policy(monkeypatch, tmp_path):
    from recon.main_recon_modules import resource_enum as re
    from recon.tests.test_jev_resource_enum_flow import BASE
    seed = GOOD[0]
    data = {'domain': 'example.test', 'http_probe': {'by_url': {
        u: {'status_code': 200, 'host': 'app.example.test'} for u in [seed] + BAD}}}
    seen = []
    monkeypatch.setattr(re, 'is_docker_installed', lambda: True)
    monkeypatch.setattr(re, 'is_docker_running', lambda: True)
    monkeypatch.setattr(re, 'pull_hakrawler_docker_image', lambda *a: True)

    def crawl(urls, *a, **k):
        seen.extend(urls)
        return [seed], {'external_domains': [], 'failed': False, 'failed_seeds': 0}

    monkeypatch.setattr(re, 'run_hakrawler_crawler', crawl)
    output = tmp_path / 'resource.json'
    re.run_resource_enum(data, output_file=output, settings=BASE)
    assert seen == [seed]
    saved = json.loads(output.read_text())
    assert saved['http_probe'] == data['http_probe']
    assert seed in saved['resource_enum']['discovered_urls']


def test_partial_parameter_discovery_receives_deep_supplied_seed(monkeypatch):
    from recon.partial_recon_modules import parameter_discovery as pd

    from recon.helpers import resource_enum as re

    def boundary(urls, *a, **k):
        assert urls == [GOOD[0]]
        raise StopAtTool

    monkeypatch.setattr(re, 'ensure_kiterunner_binary', lambda *a: ('/kr', '/wordlist'))
    monkeypatch.setattr(re, 'run_kiterunner_discovery', boundary)
    cfg = {'domain': 'example.test', '_settings': {}, 'include_graph_targets': False,
           'user_targets': {'urls': [GOOD[0]] + BAD}}
    with pytest.raises(StopAtTool):
        pd.run_kiterunner(cfg)


def test_partial_discovery_graph_observed_inputs_have_no_shared_nuclei_budget(monkeypatch):
    from recon.partial_recon_modules import web_crawling as wc
    from recon.helpers import resource_enum as re
    from recon.tests.test_no_b_large_inputs import _observed_data
    data = {'domain': 'example.com', 'subdomains': [], 'http_probe': {'by_url': {}},
            'resource_enum': _observed_data(3001)}
    monkeypatch.setattr(wc, '_build_http_probe_data_from_graph', lambda *a, **k: data)
    monkeypatch.setattr(re, 'pull_katana_docker_image', lambda *a: True)

    def boundary(urls, *a, **k):
        assert len(urls) == 3002
        assert 'https://a.example.com/p03000?q=1' in urls
        raise StopAtTool

    monkeypatch.setattr(re, 'run_katana_crawler', boundary)
    with pytest.raises(StopAtTool):
        wc.run_katana({'domain': 'example.com', '_settings': {}, 'include_graph_targets': True})
