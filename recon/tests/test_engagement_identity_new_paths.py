"""Runtime identity tests for the paths the first review missed.

Each test invokes the real function with a locally-scoped mock at the
exact HTTP call site and asserts on the headers actually passed, plus a
negative control (no identity settings -> header absent, not merely an
ImportError). Third-party LLM/enrichment POSTs must NOT receive it.

Run inside the recon image; host pytest mis-collects.
"""

from unittest import mock

IDENTITY = 'X-Bug-Bounty: researcher-7f3'
SETTINGS = {'ENGAGEMENT_IDENTITY_HEADER': IDENTITY}
EMPTY = {'ENGAGEMENT_IDENTITY_HEADER': ''}


def _headers_of(call):
    h = call.kwargs.get('headers') or {}
    return h if isinstance(h, dict) else {}


# ---------------------------------------------------------------- takeover

class TestTakeoverProbe:
    def _run_apply(self, settings):
        from recon.main_recon_modules import subdomain_takeover as st
        resp = mock.Mock(status_code=200, text='hello')
        resp.headers = {'x-vercel-id': '1'}  # vendor token -> skip AI
        findings = [{'hostname': 'example.test', 'takeover_provider': 'x'}]
        with mock.patch('requests.get', return_value=resp) as get:
            st._apply_ai_waf_disambiguation(
                findings, model='m', user_id='u', project_id='p',
                settings=settings)
        return get

    def test_apply_ai_pass_sends_identity_on_probe(self):
        get = self._run_apply(SETTINGS)
        assert get.call_args_list, 'probe made no request'
        for call in get.call_args_list:
            assert _headers_of(call).get('X-Bug-Bounty') == 'researcher-7f3', call
            assert _headers_of(call).get('User-Agent'), call

    def test_apply_ai_pass_no_identity_when_unset(self):
        get = self._run_apply(EMPTY)
        assert get.call_args_list
        for call in get.call_args_list:
            assert 'X-Bug-Bounty' not in _headers_of(call), call

    def test_direct_probe_existing_wins(self):
        # Identity line named User-Agent must not overwrite the probe's UA.
        from recon.main_recon_modules import subdomain_takeover as st
        resp = mock.Mock(status_code=200, text='')
        resp.headers = {}
        with mock.patch('requests.get', return_value=resp) as get:
            st._probe_for_ai_disambiguation(
                'example.test', settings={'ENGAGEMENT_IDENTITY_HEADER': 'User-Agent: evil'})
        sent = _headers_of(get.call_args_list[0])
        assert sent.get('User-Agent') == 'Mozilla/5.0 (compatible; RedAmon/4.7)'
        assert 'evil' not in sent.values()


# ---------------------------------------------------------------- ffuf AI

class TestFfufAiExtensions:
    def _run(self, settings, post=False):
        from recon.helpers.ai_planner import ffuf_extensions as fx
        head = mock.Mock(status_code=200)
        head.headers = {'Server': 'nginx', 'X-Powered-By': 'PHP/8.1'}
        gate = mock.Mock()
        gate.allowed = True if post else False
        captured = {}
        with mock.patch.object(fx.requests, 'head', return_value=head) as h, \
             mock.patch.object(fx.requests, 'post') as p, \
             mock.patch.object(fx, 'agent_llm_gate', return_value=gate):
            if post:
                r = mock.Mock(status_code=200)
                r.json.return_value = {'extensions': ['.php']}
                p.return_value = r
            out = fx.get_ai_extensions('https://example.test/FUZZ', 'm',
                                       settings=settings)
        captured['head'] = h
        captured['post'] = p
        captured['out'] = out
        return captured

    def test_head_probe_carries_identity(self):
        c = self._run(SETTINGS)
        assert c['head'].call_args_list
        for call in c['head'].call_args_list:
            assert _headers_of(call).get('X-Bug-Bounty') == 'researcher-7f3', call

    def test_head_probe_no_identity_when_unset(self):
        c = self._run(EMPTY)
        assert c['head'].call_args_list
        for call in c['head'].call_args_list:
            assert 'X-Bug-Bounty' not in _headers_of(call), call

    def test_llm_post_does_not_receive_identity(self):
        c = self._run(SETTINGS, post=True)
        assert c['post'].call_args_list, 'LLM post never made'
        for call in c['post'].call_args_list:
            assert 'X-Bug-Bounty' not in _headers_of(call), call
        assert c['out'] == ['.php']


# ---------------------------------------------------------------- nuclei AI

class TestNucleiAiTags:
    def _run(self, settings, post=False):
        from recon.helpers.ai_planner import nuclei_tags as nt
        head = mock.Mock(status_code=200)
        head.headers = {'Server': 'Apache/2.4', 'X-Powered-By': 'PHP'}
        gate = mock.Mock()
        gate.allowed = True if post else False
        with mock.patch.object(nt.requests, 'head', return_value=head) as h, \
             mock.patch.object(nt.requests, 'post') as p, \
             mock.patch.object(nt, 'agent_llm_gate', return_value=gate), \
             mock.patch.object(nt, '_load_candidates', return_value=['cve']):
            if post:
                r = mock.Mock(status_code=200)
                r.json.return_value = {'tags': ['cve']}
                p.return_value = r
            out = nt.get_ai_tags({}, ['cve'], 'm',
                                 fallback_urls=['https://example.test/'],
                                 settings=settings)
        return h, p, out

    def test_fallback_head_carries_identity(self):
        h, p, out = self._run(SETTINGS)
        assert h.call_args_list
        for call in h.call_args_list:
            assert _headers_of(call).get('X-Bug-Bounty') == 'researcher-7f3', call

    def test_fallback_head_no_identity_when_unset(self):
        h, p, out = self._run(EMPTY)
        assert h.call_args_list
        for call in h.call_args_list:
            assert 'X-Bug-Bounty' not in _headers_of(call), call

    def test_llm_post_does_not_receive_identity(self):
        h, p, out = self._run(SETTINGS, post=True)
        assert p.call_args_list, 'LLM post never made'
        for call in p.call_args_list:
            assert 'X-Bug-Bounty' not in _headers_of(call), call
        assert out == ['cve']


# ---------------------------------------------------------------- katana forms

class TestFetchForms:
    def _run(self, settings):
        from recon.helpers.resource_enum import katana_helpers as kh
        seen = []

        class _Req:
            def __init__(self, url, headers=None):
                seen.append(headers or {})

        class _Resp:
            status = 200
            headers = {'Content-Type': 'text/html'}

            def read(self):
                return b'<html></html>'

        opener = mock.Mock()
        opener.open.return_value = _Resp()
        with mock.patch.object(kh.urllib.request, 'Request', _Req), \
             mock.patch.object(kh.urllib.request, 'build_opener', return_value=opener):
            kh.fetch_forms_from_urls(['https://example.test/'], settings=settings)
        return seen

    def test_urllib_fetch_carries_identity(self):
        seen = self._run(SETTINGS)
        assert seen
        for headers in seen:
            assert headers.get('X-Bug-Bounty') == 'researcher-7f3', headers
            assert headers.get('User-Agent'), headers

    def test_urllib_fetch_no_identity_when_unset(self):
        seen = self._run(EMPTY)
        assert seen
        for headers in seen:
            assert 'X-Bug-Bounty' not in headers, headers

    def test_existing_user_agent_wins_over_identity(self):
        seen = self._run({'ENGAGEMENT_IDENTITY_HEADER': 'User-Agent: evil'})
        assert seen
        for headers in seen:
            assert headers.get('User-Agent') != 'evil', headers
            assert 'evil' not in headers.values()


class TestOrganizeEndpointsPlumbing:
    def test_organize_passes_settings_to_fetch_forms(self):
        from recon.helpers.resource_enum import endpoint_helpers as eh
        captured = {}

        def fake_fetch(urls, max_urls=50, settings=None):
            captured['settings'] = settings
            return []

        with mock.patch.object(eh, 'fetch_forms_from_urls', side_effect=fake_fetch):
            eh.organize_endpoints(['https://example.test/a'], settings=SETTINGS)
        assert captured.get('settings') == SETTINGS, captured

    def test_organize_without_settings_passes_none(self):
        from recon.helpers.resource_enum import endpoint_helpers as eh
        captured = {}

        def fake_fetch(urls, max_urls=50, settings=None):
            captured['settings'] = settings
            return []

        with mock.patch.object(eh, 'fetch_forms_from_urls', side_effect=fake_fetch):
            eh.organize_endpoints(['https://example.test/a'])
        assert captured.get('settings') is None, captured
