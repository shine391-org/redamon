"""F02: actual producer -> writer payload -> selected graph fields -> caller files.

No Neo4j/scanner/network is contacted. RecordingGraph models only fields the
real writer SETs and the real reader RETURNs, never fabricated provenance.
Revision controls are run by docs/recon-quality/f02/revision_controls.py.
"""
import copy
import json
import re
from urllib.parse import parse_qsl, urlsplit

import pytest

from recon.helpers import target_helpers as th
from recon.helpers.resource_enum import endpoint_helpers as eh, openapi_helpers as oh
from recon.partial_recon_modules import graph_builders as gb
from graph_db.mixins.recon.resource_mixin import ResourceMixin

BASE = "https://a.example.com"


class Result(list):
    def single(self):
        return self[0] if self else None


class RecordingGraph:
    """Persist only literal SET property=$argument fields, project RETURN fields.

    This intentionally does NOT return kwargs wholesale: a payload argument is
    not persisted unless Cypher writes it. Likewise an unselected field cannot
    leak into a row. It is a query-contract fake, not a Neo4j integration test.
    """
    def __init__(self):
        self.nodes = {}
        self.params = {}
        self.calls = []
        self.result_artifact = None
        self.driver = self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def session(self):
        return self

    def verify_connection(self):
        return True

    def update_graph_from_vuln_scan(self, recon_data, **kwargs):
        self.result_artifact = json.loads(json.dumps(recon_data))
        return {}

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "MERGE (e:Endpoint {path: $path" in query:
            key = (kwargs['baseurl'], kwargs['path'], kwargs['method'])
            node = self.nodes.setdefault(key, {})
            for prop, arg in re.findall(r'e\.(\w+)\s*=\s*\$(\w+)', query):
                node[prop] = copy.deepcopy(kwargs[arg])
        elif "MERGE (p:Parameter {name:" in query:
            key = (kwargs['baseurl'], kwargs['endpoint_path'], kwargs['name'], kwargs['position'])
            node = self.params.setdefault(key, {'name': kwargs['name'], 'position': kwargs['position']})
            for prop, arg in re.findall(r'p\.(\w+)\s*=\s*\$(\w+)', query):
                node[prop] = copy.deepcopy(kwargs[arg])
        elif 'RETURN count(*) AS linked' in query:
            return Result([{'linked': 0}])
        elif "RETURN d.name AS name" in query:
            return Result([{'name': 'example.com'}])
        elif "AS status_code" in query and "MATCH (b:BaseURL" in query:
            return Result([{'url': BASE, 'host': 'a.example.com', 'status_code': 200,
                            'content_type': 'text/html', 'is_cdn': False, 'cdn': None, 'asn': None}])
        elif 'AS params' in query and 'HAS_PARAMETER' in query:
            rows = Result()
            fields = re.search(r'collect\(DISTINCT \{(.*?)\}\) AS params', query, re.S)
            for (base, path, method), node in self.nodes.items():
                row = {'base': base, 'baseurl': base, 'path': path, 'host': 'a.example.com',
                       'method': method, 'archive_only': False}
                row['params'] = []
                for (pb, pp, _, _), param in self.params.items():
                    if (pb, pp) != (base, path):
                        continue
                    if "WHERE p.position = 'query'" in query and param['position'] != 'query':
                        continue
                    if fields:
                        # All map fields derive from selected properties, including
                        # coalesce(p.sample_values, []). No missing field is invented.
                        selected = {alias: copy.deepcopy(param.get(prop)) for alias, prop in
                                    re.findall(r'(\w+):\s*(?:coalesce\()?p\.(\w+)', fields[1])}
                        row['params'].append(selected)
                    else:  # actual old reader's [name, head(sample_values)] projection
                        row['params'].append([param['name'], (param.get('sample_values') or ['1'])[0]])
                if 'e.request_fidelity_json AS request_fidelity_json' in query:
                    row['request_fidelity_json'] = node.get('request_fidelity_json')
                rows.append(row)
            return rows
        return Result()


def _record(monkeypatch, endpoint):
    graph = RecordingGraph()
    writer = ResourceMixin()
    writer.driver = graph
    resource = {'by_base_url': {BASE: {'endpoints': {'/search': endpoint}}}}
    data = {'domain': 'example.com', 'subdomains': ['a.example.com'], 'resource_enum': resource}
    stats = writer.update_graph_from_resource_enum(data, 'u', 'p')
    assert not stats['errors']
    import graph_db
    monkeypatch.setattr(graph_db, 'Neo4jClient', lambda: graph)
    return graph, resource


def _param(value, encoding='decoded-observation', name='q'):
    return {'name': name, 'sample_values': [value], 'sample_values_encoding': encoding}


@pytest.mark.parametrize('value', ['&', '=', '#', 'a b', '%', '+', '雪', '', 'a&b=# %+雪'])
def test_decoded_observation_round_trip(value):
    endpoint = {'parameters': {'query': [_param(value)]}}
    url = th._endpoint_url(BASE, '/search', endpoint)
    assert parse_qsl(urlsplit(url).query, keep_blank_values=True) == [('q', value)]


def test_order_duplicate_empty_case_and_raw_encoding_survive_real_graph_boundary(monkeypatch):
    raw = BASE + '/search?k=1&k=2&empty=&K=%2b+%25&u=%E9%9B%AA'
    monkeypatch.setattr(eh, 'fetch_forms_from_urls', lambda *a, **k: [])
    endpoint = eh.organize_endpoints([raw])['by_base_url'][BASE]['endpoints']['/search']
    graph, resource = _record(monkeypatch, endpoint)
    projected = gb._build_serialized_data_from_graph('example.com', 'u', 'p', settings={})
    ep = projected['resource_enum']['by_base_url'][BASE]['endpoints']['/search']
    assert th._endpoint_url(BASE, '/search', ep) == raw
    assert parse_qsl(urlsplit(raw).query, keep_blank_values=True) == [
        ('k', '1'), ('k', '2'), ('empty', ''), ('K', '+ %'), ('u', '雪')]
    assert not ep.get('fidelity_unknown')
    assert any('request_fidelity_json' in n for n in graph.nodes.values())


def test_openapi_producer_writer_selected_projection_not_double_encoded(monkeypatch):
    param = oh._parameter('q', {'schema': {'type': 'string', 'example': 'a b'}}, required=False)
    assert param['sample_values'] == ['a%20b']
    assert param['sample_values_encoding'] == 'percent-encoded'
    graph, _ = _record(monkeypatch, {'methods': ['GET'], 'parameters': {'query': [param]}})
    assert next(iter(graph.params.values()))['sample_values_encoding'] == 'percent-encoded'
    projected = gb._build_serialized_data_from_graph('example.com', 'u', 'p', settings={})
    ep = projected['resource_enum']['by_base_url'][BASE]['endpoints']['/search']
    assert ep['parameters']['query'][0]['sample_values_encoding'] == 'percent-encoded'
    assert th._endpoint_url(BASE, '/search', ep) == BASE + '/search?q=a%20b'


@pytest.mark.parametrize('kind', ['raw', 'openapi'])
def test_full_and_actual_partial_callers_generate_same_target_files(monkeypatch, kind):
    from recon.tests.test_no_b_large_inputs import _run_pipeline
    from recon.partial_recon_modules import vulnerability_scanning as partial
    if kind == 'raw':
        raw = BASE + '/search?k=1&k=2&empty=&K=%2B+%25&u=%E9%9B%AA'
        monkeypatch.setattr(eh, 'fetch_forms_from_urls', lambda *a, **k: [])
        endpoint = eh.organize_endpoints([raw])['by_base_url'][BASE]['endpoints']['/search']
    else:
        param = oh._parameter('q', {'schema': {'type': 'string', 'example': 'a b'}}, required=False)
        endpoint = {'methods': ['GET'], 'parameters': {'query': [param]}}
        raw = BASE + '/search?q=a%20b'
    graph, resource = _record(monkeypatch, endpoint)
    resource['discovered_urls'] = [raw]
    # This runs the real full caller, real command builder, and reads the files
    # identified by Docker argv. Only tool execution/network are mocked.
    state, result = _run_pipeline(monkeypatch, resource, True)
    full = copy.deepcopy(state['passes'])
    partial.run_nuclei({'domain': 'example.com', 'domains': ['example.com'],
                        'include_graph_targets': True, '_settings': {
                            'NUCLEI_TAGS': ['cve'], 'NUCLEI_DAST_MODE': True,
                            'NUCLEI_AUTO_UPDATE_TEMPLATES': False, 'CVE_LOOKUP_ENABLED': False,
                            'SECURITY_CHECK_ENABLED': False, 'MITRE_ENABLED': False,
                            'NUCLEI_SCAN_ALL_IPS': False, 'NUCLEI_MAX_RUNTIME': 0}})
    assert state['passes'][len(full):] == full
    assert full[1]['targets'] == [raw]
    assert graph.result_artifact['resource_enum']['discovered_urls'] == [raw]
    assert graph.result_artifact['vuln_scan']['scan_metadata']['dast_pass_executed']


def test_graph_position_and_post_method_are_not_promoted(monkeypatch):
    graph, _ = _record(monkeypatch, {'methods': ['POST'], 'parameters': {
        'body': [_param('secret', name='token')], 'path': [_param('7', name='id')], 'query': []}})
    data = gb._build_serialized_data_from_graph('example.com', 'u', 'p', settings={})
    ep = data['resource_enum']['by_base_url'][BASE]['endpoints']['/search']
    assert ep['methods'] == ['POST'] and ep['method'] == 'POST'
    assert ep['parameters']['query'] == []
    assert [p['name'] for p in ep['parameters']['body']] == ['token']
    assert [p['name'] for p in ep['parameters']['path']] == ['id']
    assert th._endpoint_url(BASE, '/search', ep) == BASE + '/search'
    vuln = gb._build_vuln_scan_data_from_graph('example.com', 'u', 'p')
    assert not vuln['resource_enum']['discovered_urls']
    assert vuln['resource_enum']['by_base_url'][BASE]['endpoints']['/search']['methods'] == ['POST']


def test_legacy_graph_and_name_keyed_losses_mark_unknown_without_preseed(monkeypatch):
    graph, _ = _record(monkeypatch, {'methods': ['GET'], 'parameters': {'query': [_param('a%20b')]}})
    for node in graph.nodes.values():
        node.pop('request_fidelity_json', None)
    for node in graph.params.values():
        node.pop('sample_values_encoding', None)
    data = gb._build_serialized_data_from_graph('example.com', 'u', 'p', settings={})
    ep = data['resource_enum']['by_base_url'][BASE]['endpoints']['/search']
    assert ep['fidelity_unknown']
    assert 'sample_values_encoding' not in ep['parameters']['query'][0]
    th._endpoint_url(BASE, '/search', ep)
    assert 'fidelity_unknown' in ep['fidelity']
    legacy = {'parameters': {'q': {'sample_values': ['a%20b']}}}
    assert th._endpoint_url(BASE, '/search', legacy) == BASE + '/search?q=a%20b'
    assert legacy['fidelity_unknown'] and 'fidelity_unknown' in legacy['fidelity']


def test_raw_controls_still_rejected():
    assert th._endpoint_url(BASE, '/search', {'parameters': {'query': [_param('x\ny')]}}) is None


def test_aggregated_observation_without_raw_cannot_claim_order_or_duplicates(monkeypatch):
    raw = BASE + '/search?k=1&k=2&empty='
    monkeypatch.setattr(eh, 'fetch_forms_from_urls', lambda *a, **k: [])
    endpoint = eh.organize_endpoints([raw])['by_base_url'][BASE]['endpoints']['/search']
    endpoint.pop('sample_urls')
    assert not endpoint.get('fidelity_unknown')
    graph, _ = _record(monkeypatch, endpoint)
    data = gb._build_serialized_data_from_graph('example.com', 'u', 'p', settings={})
    ep = data['resource_enum']['by_base_url'][BASE]['endpoints']['/search']
    assert ep['fidelity_unknown']
    th._endpoint_url(BASE, '/search', ep)
    assert 'fidelity_unknown' in ep['fidelity']


def test_method_specific_examples_survive_graph_without_last_row_wins(monkeypatch):
    payload = {'operations': [{'baseurl': BASE, 'path': '/search', 'method': m, 'operation': {
        'parameters': [{'name': 'q', 'in': 'query', 'schema': {'type': 'string', 'example': v}}]}}
        for m, v in [('POST', 'post value'), ('GET', 'get value')]]}
    by_base, _ = oh.merge_openapi_into_by_base_url(payload, {})
    endpoint = by_base[BASE]['endpoints']['/search']
    _record(monkeypatch, endpoint)
    data = gb._build_serialized_data_from_graph('example.com', 'u', 'p', settings={})
    ep = data['resource_enum']['by_base_url'][BASE]['endpoints']['/search']
    assert ep['methods'] == ['GET', 'POST']
    variants = {v['method']: v for v in ep['request_variants']}
    assert th._endpoint_url(BASE, '/search', variants['POST']) == BASE + '/search?q=post%20value'
    assert th._endpoint_url(BASE, '/search', ep) == th._endpoint_url(BASE, '/search', endpoint) == BASE + '/search?q=get%20value'
