"""Engagement identity header on the missed active-target HTTP paths.

Follow-up to test_engagement_identity_header.py: the first fix covered the
CLI-tool -H paths (httpx/nuclei/katana/...). These tests pin the *Python*
request paths the prior child missed, per the parent's gap list:

* jsluice download_js_files (urllib, hard-coded headers) — full + partial
* JS recon _download_js_files (requests, redirect-following GET)
* JS recon endpoint validation probes (JS_RECON_ENDPOINT_CUSTOM_HEADERS)
* sourcemap fetches (probe/comment/header + 403 missing-key control)
* AI surface recon sessions (chat/MCP/OpenAPI/vector-DB + Julius packs)
* OpenAPI discovery document fetches

Third-party enrichment (npm registry / GitHub key validation in
recon/helpers/js_recon/validators.py) is deliberately NOT patched; a source
grep pins that no identity leaks into it.

No global monkeypatch: every request is captured via a locally-scoped
mock.patch of the single call site the module actually invokes. Fixtures use
example.test only. Run inside the recon image (README.TESTING.md); host pytest
mis-collects.
"""

from unittest import mock

from recon.main_recon_modules import js_recon, ai_surface_recon
from recon.helpers.resource_enum import jsluice_helpers
from recon.helpers.js_recon import sourcemap as sm
from recon.helpers.openapi import discovery as openapi_discovery
from recon.helpers.auth_profile import engagement_identity_header

IDENTITY = 'X-Bug-Bounty: researcher-7f3'
SETTINGS = {'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': ['.'],
            'IP_MODE': False, 'ENGAGEMENT_IDENTITY_HEADER': IDENTITY}
NO_IDENTITY_SETTINGS = {'ENGAGEMENT_IDENTITY_HEADER': ''}


def _captured_headers(call):
    """The headers kwarg actually passed to requests.get/urllib Request."""
    kwargs = call.kwargs
    if 'headers' in kwargs:
        return kwargs['headers']
    # urllib Request(url, headers=...) positional in some call shapes
    for arg in call.args:
        if isinstance(arg, dict) and 'User-Agent' in str(arg):
            return arg
    return {}


class TestJsluiceDownload:
    def test_urllib_request_carries_identity(self):
        seen = {}

        class _Req:
            def __init__(self, url, headers=None):
                seen['headers'] = headers or {}
                seen['url'] = url

        class _Resp:
            status = 404
            headers = {}
            def read(self):
                return b''

        opener = mock.Mock()
        opener.open.return_value = _Resp()
        with mock.patch.object(jsluice_helpers.urllib.request, 'Request', _Req), \
             mock.patch.object(jsluice_helpers.urllib.request, 'build_opener',
                               return_value=opener), \
             mock.patch.object(jsluice_helpers, '_jsl_alive', lambda u: None), \
             mock.patch.object(jsluice_helpers, '_jsl_skip', lambda u: False):
            jsluice_helpers._download_js_files(
                ['https://example.test/app.js'], mock.Mock(),
                settings=SETTINGS)
        assert seen['headers'].get('X-Bug-Bounty') == 'researcher-7f3'

    def test_no_identity_when_unset(self):
        seen = {}

        class _Req:
            def __init__(self, url, headers=None):
                seen['headers'] = headers or {}

        class _Resp:
            status = 404
            headers = {}
            def read(self):
                return b''

        opener = mock.Mock()
        opener.open.return_value = _Resp()
        with mock.patch.object(jsluice_helpers.urllib.request, 'Request', _Req), \
             mock.patch.object(jsluice_helpers.urllib.request, 'build_opener',
                               return_value=opener), \
             mock.patch.object(jsluice_helpers, '_jsl_alive', lambda u: None), \
             mock.patch.object(jsluice_helpers, '_jsl_skip', lambda u: False):
            jsluice_helpers._download_js_files(
                ['https://example.test/app.js'], mock.Mock(),
                settings=NO_IDENTITY_SETTINGS)
        assert 'X-Bug-Bounty' not in seen['headers']


class TestJsReconDownload:
    def test_download_get_carries_identity_on_every_hop(self):
        resp = mock.Mock(status_code=200)
        resp.headers = {'Content-Type': 'application/javascript',
                        'Content-Length': '10'}
        resp.text = 'var x = 1;'
        with mock.patch.object(js_recon.requests, 'get', return_value=resp) as get:
            js_recon._download_js_files(
                ['https://example.test/a.js'], mock.Mock(),
                max_files=1, concurrency=1, timeout=100,
                settings=SETTINGS)
        for call in get.call_args_list:
            h = call.kwargs.get('headers') or {}
            assert h.get('X-Bug-Bounty') == 'researcher-7f3', call

    def test_no_identity_without_settings(self):
        resp = mock.Mock(status_code=200)
        resp.headers = {'Content-Type': 'application/javascript',
                        'Content-Length': '10'}
        resp.text = 'var x = 1;'
        with mock.patch.object(js_recon.requests, 'get', return_value=resp) as get:
            js_recon._download_js_files(
                ['https://example.test/a.js'], mock.Mock(),
                max_files=1, concurrency=1, timeout=100)
        for call in get.call_args_list:
            h = call.kwargs.get('headers') or {}
            assert 'X-Bug-Bounty' not in h


class TestJsReconEndpointValidation:
    def test_identity_in_same_origin_probe_headers(self):
        # Line-level: the identity line, appended to the operator's custom
        # lines, survives _endpoint_probe_headers' own parse for a same-origin
        # probe. _endpoint_probe_headers takes LINES (not a parsed dict) — it
        # parses them itself.
        from recon.helpers.auth_profile import append_engagement_identity
        ep = {'full_url': 'https://example.test/api/v1/x',
              'method': 'GET', 'source_js': 'https://example.test/app.js'}
        lines = append_engagement_identity(
            [], dict(SETTINGS, JS_RECON_ENDPOINT_CUSTOM_HEADERS=[]))
        headers = js_recon._endpoint_probe_headers(
            ep, 'https://example.test/api/v1/x', lines)
        assert headers.get('X-Bug-Bounty') == 'researcher-7f3'

    def test_identity_absent_for_cross_origin_probe(self):
        # Cross-origin probes (a CDN host) must NOT carry the identity,
        # matching _endpoint_probe_headers' same-origin rule.
        from recon.helpers.auth_profile import append_engagement_identity
        ep = {'full_url': 'https://example.test/api/v1/x',
              'method': 'GET', 'source_js': 'https://cdn.other.test/app.js'}
        lines = append_engagement_identity(
            [], dict(SETTINGS, JS_RECON_ENDPOINT_CUSTOM_HEADERS=[]))
        headers = js_recon._endpoint_probe_headers(
            ep, 'https://example.test/api/v1/x', lines)
        assert 'X-Bug-Bounty' not in headers

    def test_validate_extracted_endpoints_appends_identity_to_lines(self):
        # The wiring: custom_header_lines get the identity appended before
        # _parse_endpoint_validation_headers, in that module's settings flow.
        src = __import__('inspect').getsource(
            js_recon._validate_extracted_endpoints)
        assert 'append_engagement_identity' in src


class TestSourcemapFetches:
    def test_fetch_sourcemap_get_and_head_carry_identity(self):
        head = mock.Mock(status_code=200)
        get = mock.Mock(status_code=200)
        get.content = b'{"version": 3, "sources": [], "names": []}'
        get.text = '{"version": 3}'
        with mock.patch.object(sm.requests, 'head', return_value=head) as h, \
             mock.patch.object(sm.requests, 'get', return_value=get) as g, \
             mock.patch.object(sm, 'is_url_safe_to_probe', return_value=True):
            sm._fetch_sourcemap('https://example.test/app.js.map', timeout=5,
                                identity_headers={'X-Bug-Bounty': 'researcher-7f3'})
        assert h.call_args.kwargs['headers']['X-Bug-Bounty'] == 'researcher-7f3'
        assert g.call_args.kwargs['headers']['X-Bug-Bounty'] == 'researcher-7f3'

    def test_missing_key_control_carries_identity(self):
        resp = mock.Mock(status_code=403)
        with mock.patch.object(sm.requests, 'get', return_value=resp) as g, \
             mock.patch.object(sm, 'is_url_safe_to_probe', return_value=True):
            sm._missing_key_control('https://example.test/a.map', 5,
                                    identity_headers={'X-Bug-Bounty': 'researcher-7f3'})
        assert g.call_args.kwargs['headers']['X-Bug-Bounty'] == 'researcher-7f3'

    def test_discovery_computes_identity_once_from_settings(self):
        src = __import__('inspect').getsource(
            sm.discover_and_analyze_sourcemaps)
        assert '_identity_request_headers(settings)' in src


class TestAiSurfaceRecon:
    def test_sessions_and_julius_receive_identity(self):
        # The wiring points: run_ai_surface_recon computes identity_headers
        # from settings and updates both sessions + passes it to Julius.
        src = __import__('inspect').getsource(ai_surface_recon.run_ai_surface_recon)
        assert 'engagement_identity_header' in src
        assert src.count('session.headers.update(identity_headers)') == 2
        assert '_probe_julius(base_url, timeout, ua, identity_headers)' in src

    def test_probe_pack_session_carries_extra_headers(self):
        # A real probe (not an empty pack) so the session actually requests:
        # the identity must ride the probe request headers.
        from recon.helpers.probe_pack_engine import (
            MatchRule, Probe, ProbeRequest, run_probe_packs,
        )
        probe = Probe(name='p', category='c', port_hint=0,
                      requests=[ProbeRequest(method='GET', path='/x',
                                             match=[MatchRule(type='status', value=200)])])
        sent = []

        class _Resp:
            status_code = 404
            text = ''
            headers = {}

        def fake_request(self, method, url, **kw):
            sent.append((url, dict(self.headers), dict(kw.get('headers') or {})))
            return _Resp()

        with mock.patch('requests.Session.request', fake_request):
            run_probe_packs('https://example.test', [probe], timeout=1,
                            extra_headers={'X-Bug-Bounty': 'researcher-7f3'},
                            extract_models=False)
        assert sent, 'probe pack made no request'
        for url, session_headers, req_headers in sent:
            merged = {**session_headers, **req_headers}
            assert merged.get('X-Bug-Bounty') == 'researcher-7f3', (url, merged)


class TestOpenapiDiscovery:
    def test_enqueue_headers_include_identity(self):
        headers = openapi_discovery.parse_headers(
            __import__('recon.helpers.auth_profile', fromlist=['x'])
            .append_engagement_identity(['Accept: application/json'], SETTINGS))
        assert headers.get('X-Bug-Bounty') == 'researcher-7f3'
        assert headers.get('Accept') == 'application/json'

    def test_discovery_source_wires_identity(self):
        src = __import__('inspect').getsource(openapi_discovery)
        assert 'append_engagement_identity(' in src


class TestThirdPartyUncovered:
    def test_no_identity_in_secret_validators(self):
        # npm registry / GitHub / Slack / Stripe etc. key validation is
        # third-party enrichment: the identity header must NOT be attached.
        import pathlib
        src = pathlib.Path(
            js_recon.__file__).parent.parent / 'helpers' / 'js_recon' / 'validators.py'
        assert 'engagement_identity' not in src.read_text()
