"""Engagement identity header: GraphQL/cache/route-exposure/origin/security
paths plus a controlled loopback receiver.

These close the gaps the first identity patch left: GraphQL's own auth
builder, the cache-poison native engine's session, route-exposure's Prober,
origin-discovery's target fetches, and security_checks' _hh_* wrappers.
The receiver test is the behavioural end-to-end check: real HTTP requests
from those callers (session/prober/wrapper) to a throwaway server on
127.0.0.1, asserting the header actually arrives on the wire — not merely
that a dict was built. No external network; example.test is never contacted.

WCVS (cache_scan/wcvs_runner.py) is deliberately NOT covered: it is an
external Docker tool with no custom-header flag. See identity-result.md.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import pytest
import requests

from recon.helpers.auth_profile import identity_header_dict

IDENTITY = 'X-Bug-Bounty: researcher-7f3'
SETTINGS = {'ENGAGEMENT_IDENTITY_HEADER': IDENTITY}


class _Receiver:
    def __init__(self):
        self.seen = []

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self):
                outer.seen.append((self.command, self.path, dict(self.headers)))
                body = b'ok'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = _record
            do_POST = _record

            def log_message(self, *args):  # silence
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f'http://127.0.0.1:{self.port}/probe'

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def last_headers(self):
        assert self.seen, 'receiver saw no request'
        return self.seen[-1][2]


@pytest.fixture
def receiver():
    r = _Receiver()
    yield r
    r.close()


class TestControlledReceiver:
    def test_plain_requests_with_identity_dict(self, receiver):
        requests.get(receiver.url, headers=identity_header_dict(SETTINGS), timeout=5)
        assert receiver.last_headers().get('X-Bug-Bounty') == 'researcher-7f3'

    def test_no_header_when_unset(self, receiver):
        requests.get(receiver.url, headers=identity_header_dict({}), timeout=5)
        assert 'X-Bug-Bounty' not in receiver.last_headers()

    def test_cache_session_carries_it_on_the_wire(self, receiver):
        from recon.cache_scan.scanner import _build_retry_session
        session = _build_retry_session(settings=SETTINGS)
        session.get(receiver.url, timeout=5)
        assert receiver.last_headers().get('X-Bug-Bounty') == 'researcher-7f3'

    def test_cache_session_silent_when_unset(self, receiver):
        from recon.cache_scan.scanner import _build_retry_session
        _build_retry_session(settings={'ENGAGEMENT_IDENTITY_HEADER': ''}).get(
            receiver.url, timeout=5)
        assert 'X-Bug-Bounty' not in receiver.last_headers()

    def test_route_exposure_prober_carries_it_on_the_wire(self, receiver):
        from recon.route_exposure.prober import Prober
        prober = Prober(SETTINGS, guard=lambda url: True, timeout=5, rps=0)
        answer = prober.send('GET', receiver.url)
        assert answer is not None and answer.status_code == 200
        assert receiver.last_headers().get('X-Bug-Bounty') == 'researcher-7f3'

    def test_security_checks_wrapper_carries_it_on_the_wire(self, receiver):
        from recon.helpers import security_checks as sc
        token = sc._IDENTITY_HEADERS.set(identity_header_dict(SETTINGS))
        try:
            resp = sc._hh_get(receiver.url, timeout=5)
        finally:
            sc._IDENTITY_HEADERS.reset(token)
        assert resp.status_code == 200
        assert receiver.last_headers().get('X-Bug-Bounty') == 'researcher-7f3'

    def test_graphql_headers_used_on_the_wire(self, receiver):
        from recon.graphql_scan.auth import build_auth_headers
        requests.post(receiver.url, json={'query': '{__typename}'},
                      headers=build_auth_headers(SETTINGS), timeout=5)
        assert receiver.last_headers().get('X-Bug-Bounty') == 'researcher-7f3'


class TestGraphQLAuth:
    def test_identity_merged_without_auth(self):
        from recon.graphql_scan.auth import build_auth_headers
        assert build_auth_headers(SETTINGS) == {'X-Bug-Bounty': 'researcher-7f3'}

    def test_auth_header_of_same_name_wins_case_insensitive(self):
        from recon.graphql_scan.auth import build_auth_headers
        settings = dict(SETTINGS, GRAPHQL_AUTH_TYPE='header',
                        GRAPHQL_AUTH_VALUE='mine', GRAPHQL_AUTH_HEADER='x-bug-bounty')
        headers = build_auth_headers(settings)
        assert headers == {'x-bug-bounty': 'mine'}

    def test_invalid_identity_not_merged(self):
        from recon.graphql_scan.auth import build_auth_headers
        assert build_auth_headers(
            {'ENGAGEMENT_IDENTITY_HEADER': 'Host: evil'}) == {}


class TestOriginDiscovery:
    def test_fetch_carries_identity(self):
        from recon.main_recon_modules import origin_discovery as od
        ctx = mock.Mock()
        ctx.settings = SETTINGS
        ctx.rate.wait.return_value = None
        ctx.timeout = 5
        resp = mock.Mock(status_code=200)
        resp.headers = {}
        resp.raw.read.return_value = b'<html></html>'
        resp.raw.headers.get_all.return_value = []
        resp.close.return_value = None
        with mock.patch.object(od.requests, 'get', return_value=resp) as get:
            od._fetch('https://example.test/', None, ctx)
        assert get.call_args.kwargs['headers']['X-Bug-Bounty'] == 'researcher-7f3'

    def test_favicon_fetch_carries_identity(self):
        from recon.main_recon_modules import origin_discovery as od
        ctx = mock.Mock()
        ctx.settings = SETTINGS
        ctx.rate.wait.return_value = None
        ctx.timeout = 5
        resp = mock.Mock(status_code=404)
        resp.close.return_value = None
        with mock.patch.object(od.requests, 'get', return_value=resp) as get, \
                mock.patch.object(od, 'is_url_safe_to_probe', return_value=True):
            od._favicon_hash_for_host('example.test', None, ctx)
        assert get.call_args.kwargs['headers']['X-Bug-Bounty'] == 'researcher-7f3'

    def test_third_party_censys_not_touched(self):
        # The Censys/OTX/SecurityTrails/ViewDNS producers in this module are
        # third-party API calls: identity must not leak into them.
        import inspect
        from recon.main_recon_modules import origin_discovery as od
        src = inspect.getsource(od._discover_via_censys)
        assert 'identity' not in src.lower()


class TestSecurityChecksWiring:
    def test_with_identity_caller_wins(self):
        from recon.helpers import security_checks as sc
        token = sc._IDENTITY_HEADERS.set({'X-Bug-Bounty': 'researcher-7f3'})
        try:
            out = sc._with_identity({'headers': {'X-Bug-Bounty': 'mine'}})
            assert out['headers'] == {'X-Bug-Bounty': 'mine'}
            out = sc._with_identity({})
            assert out['headers'] == {'X-Bug-Bounty': 'researcher-7f3'}
        finally:
            sc._IDENTITY_HEADERS.reset(token)

    def test_run_security_checks_accepts_settings(self):
        import inspect
        from recon.helpers.security_checks import run_security_checks
        assert 'settings' in inspect.signature(run_security_checks).parameters

    def test_vuln_scan_passes_settings_to_ai_tags(self):
        # Runtime invocation: deleting settings=settings at the get_ai_tags
        # call in run_vuln_scan must fail this test (source grep would not).
        from recon.main_recon_modules import vuln_scan
        captured = {}

        def fake_get_ai_tags(**kwargs):
            captured.update(kwargs)
            return []  # empty tags -> detection pass skipped, no nuclei run

        settings = dict(SETTINGS,
                        NUCLEI_ENABLED=True,
                        NUCLEI_AI_TAGS=True,
                        NUCLEI_TAGS=['cve'],
                        CVE_LOOKUP_ENABLED=False,
                        SECURITY_CHECK_ENABLED=False)
        recon_data = {'domain': 'example.test',
                      'subdomains': ['example.test'],
                      'http_probe': {},
                      'resource_enum': {}}
        with mock.patch.object(vuln_scan, 'is_docker_installed', return_value=True), \
             mock.patch.object(vuln_scan, 'is_docker_running', return_value=True), \
             mock.patch.object(vuln_scan, 'pull_nuclei_docker_image', return_value=None), \
             mock.patch.object(vuln_scan, 'ensure_templates_volume', return_value=True), \
             mock.patch.object(vuln_scan, 'extract_targets_from_recon',
                               return_value=([], ['example.test'], {})), \
             mock.patch.object(vuln_scan, 'build_target_urls',
                               return_value=['https://example.test/']), \
             mock.patch('recon.helpers.ai_planner.nuclei_tags.get_ai_tags',
                        side_effect=fake_get_ai_tags):
            vuln_scan.run_vuln_scan(recon_data, settings=settings)
        assert captured.get('settings') == settings, captured
        assert captured.get('fallback_urls'), captured


class TestRouteExposureProber:
    def test_caller_header_of_same_name_wins(self):
        from recon.route_exposure.prober import Prober
        prober = Prober(SETTINGS, guard=lambda url: True, timeout=5, rps=0)
        session = mock.Mock()
        resp = mock.Mock(status_code=200, headers={}, content=b'')
        resp.iter_content.return_value = []
        session.request.return_value = resp
        prober._local.session = session
        answer = prober.send('GET', 'https://example.test/x',
                             headers={'X-Bug-Bounty': 'mine'})
        assert answer is not None
        sent = session.request.call_args.kwargs.get('headers') or \
            session.request.call_args[1].get('headers')
        assert sent.get('X-Bug-Bounty') == 'mine'


class TestValidationRepairs:
    def test_overlong_line_refused(self):
        from recon.helpers.auth_profile import engagement_identity_header
        long_value = 'X-BB: ' + 'a' * 5000
        assert engagement_identity_header(
            {'ENGAGEMENT_IDENTITY_HEADER': long_value}) is None

    def test_connection_and_framing_refused(self):
        from recon.helpers.auth_profile import engagement_identity_header
        for bad in ('Connection: keep-alive', 'Content-Length: 3',
                    'Transfer-Encoding: chunked'):
            assert engagement_identity_header(
                {'ENGAGEMENT_IDENTITY_HEADER': bad}) is None, bad

    def test_proxy_family_refused_case_insensitive(self):
        from recon.helpers.auth_profile import engagement_identity_header
        for bad in ('Proxy-Connection: x', 'PROXY-AUTHENTICATE: x',
                    'proxy-anything: x'):
            assert engagement_identity_header(
                {'ENGAGEMENT_IDENTITY_HEADER': bad}) is None, bad

    def test_identity_header_dict(self):
        assert identity_header_dict(SETTINGS) == {'X-Bug-Bounty': 'researcher-7f3'}
        assert identity_header_dict({}) == {}
        assert identity_header_dict(None) == {}
        assert identity_header_dict(
            {'ENGAGEMENT_IDENTITY_HEADER': 'Host: x'}) == {}
