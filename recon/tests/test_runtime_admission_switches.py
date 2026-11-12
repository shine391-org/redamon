"""Real full/partial JS consumer and late-Arjun caller toggle tests (offline)."""
import copy
from contextlib import ExitStack
from unittest.mock import patch, MagicMock

import pytest

from recon.tests import test_js_recon_coverage as js_fixture
from recon.main_recon_modules import js_recon
from recon.helpers.js_recon.fetch_admission import classify_candidate


@pytest.mark.parametrize('admission', [False, True])
@pytest.mark.parametrize('partial', [False, True])
def test_js_switch_drives_actual_download_consumer(admission, partial, monkeypatch):
    from recon.partial_recon_modules import js_analysis
    urls = ['https://example.test/app.js', 'https://example.test/merely-a-string.js']
    candidates = [classify_candidate(urls[0], observed_app_js=True, source_ref='crawler'),
                  classify_candidate(urls[1], source_ref='js-string')]
    opts = dict(js_fixture.SETTINGS, JS_RECON_FETCH_ADMISSION=admission,
                USER_ID='owner-test', PROJECT_ID='project-test')
    downloaded = []
    def download(selected, *args, **kwargs):
        downloaded.extend(selected)
        return js_fixture._download_ok(selected, *args, **kwargs)
    with ExitStack() as stack:
        stack.enter_context(patch.object(js_recon, '_collect_js_candidates', return_value=candidates))
        stack.enter_context(patch.object(js_recon, '_download_js_files', side_effect=download))
        stack.enter_context(patch.object(js_recon, '_run_analysis', return_value=js_fixture._analysis()))
        if partial:
            monkeypatch.setenv('USER_ID', 'owner-test')
            monkeypatch.setenv('PROJECT_ID', 'project-test')
            stack.enter_context(patch.object(js_analysis, 'partial_settings', return_value=opts))
            client = MagicMock()
            client.__enter__.return_value.verify_connection.return_value = False
            stack.enter_context(patch('graph_db.Neo4jClient', return_value=client))
            js_analysis.run_jsrecon({'domain': 'example.test', 'include_graph_targets': False,
                                    'user_targets': {'urls': urls}})
        else:
            js_recon.run_js_recon({'domain': 'example.test', 'metadata': {},
                                  'resource_enum': {'js_urls': urls}}, opts)
    assert set(downloaded) == ({urls[0]} if admission else set(urls))


def test_js_actual_cache_context_partitions_owner_project_auth():
    seen = []
    real = js_recon.context_key
    def context(**kwargs):
        result = real(**kwargs)
        seen.append(result)
        return result
    for owner, project, profile in [('a', 'p', {}), ('b', 'p', {}), ('a', 'q', {}),
                                     ('a', 'p', {'extraHeaders': {'X-Test': 'synthetic-value'}})]:
        with patch.object(js_recon, 'context_key', side_effect=context), \
             patch.object(js_recon, '_collect_js_candidates', return_value=[]), \
             patch.object(js_recon, '_collect_js_urls', return_value=[]):
            js_recon.run_js_recon({'metadata': {}, 'resource_enum': {}},
                dict(js_fixture.SETTINGS, USER_ID=owner, PROJECT_ID=project, AUTH_PROFILE=profile))
    assert len(set(seen)) == 4


@pytest.mark.parametrize('enabled', [False, True])
def test_late_arjun_switch_real_resource_caller_respects_configured_methods(enabled):
    from recon.tests.test_jev_resource_enum_flow import _run
    from recon.main_recon_modules import resource_enum
    calls = []
    def arjun(urls, methods, *args):
        calls.append((list(urls), list(methods)))
        return [], {'status': 'complete', 'execution': []}
    def merge(_urls, by_base, *args, **kwargs):
        # GAU arrives after the early Arjun pass; known late method evidence
        # must not be unioned into unauthorized requests on another URL.
        by_base = copy.deepcopy(by_base)
        by_base.setdefault('https://a.example.test', {'endpoints': {}})['endpoints'].update({
            '/late-get': {'sources': ['gau'], 'methods': ['GET'], 'parameters': {}},
            '/late-post': {'sources': ['gau'], 'methods': ['POST'], 'parameters': {}},
        })
        return by_base, {'gau_total': 2, 'gau_new': 2, 'gau_overlap': 0, 'gau_parsed': 2, 'gau_out_of_scope': 0}
    with patch.object(resource_enum, 'pull_gau_docker_image', return_value=True), \
         patch.object(resource_enum, 'arjun_binary_check', return_value=True), \
         patch.object(resource_enum, 'run_arjun_discovery', side_effect=arjun), \
         patch.object(resource_enum, 'run_gau_discovery', return_value=(['https://a.example.test/late-get'], {})), \
         patch.object(resource_enum, 'merge_gau_into_by_base_url', side_effect=merge):
        result = _run({'ARJUN_ENABLED': True, 'ARJUN_LATE_SOURCES': enabled,
                       'ARJUN_METHODS': ['GET'], 'ARJUN_MAX_ENDPOINTS': 50,
                       'GAU_ENABLED': True, 'GAU_VERIFY_URLS': False, 'GAU_DETECT_METHODS': False})
    assert calls[0][1] == ['GET']
    if enabled:
        assert calls[1:] == [(['https://a.example.test/late-get'], ['GET'])]
        late = result['resource_enum']['scan_metadata']['arjun_late_summary']
        assert late['deferred_reasons']['configured_method_excluded'] == 1
    else:
        assert len(calls) == 1
