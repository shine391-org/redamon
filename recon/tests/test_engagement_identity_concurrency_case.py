"""Engagement identity: run-scoped security checks + case-insensitive merging.

(A) security_checks identity must be run-scoped, not a process global: two
parallel run_security_checks calls with distinct settings must never mix
headers, including through their ThreadPoolExecutor workers (executor
threads do not inherit contextvars on their own, so submissions go through
_submit_scoped).

(B) Every dict/session merge path honours "existing header wins" without
duplicate names, case-insensitively (HTTP names are case-insensitive): a
plain setdefault/update would send e.g. both 'X-Bug-Bounty' and
'x-bug-bounty'. Each path is exercised with a lower-case and an upper-case
custom name.
"""

import threading
from unittest import mock

import pytest
import requests

from recon.helpers.auth_profile import (
    add_identity_headers,
    merge_identity_headers,
)

IDENTITY = 'X-Bug-Bounty: researcher-7f3'
IDENTITY_DICT = {'X-Bug-Bounty': 'researcher-7f3'}


def _one_key_case_insensitive(headers, name):
    keys = [k for k in headers if k.lower() == name.lower()]
    assert len(keys) == 1, f'{name!r} sent {len(keys)} times in {dict(headers)!r}'
    return headers[keys[0]]


class TestMergeHelpers:
    @pytest.mark.parametrize('existing_name', ['x-bug-bounty', 'X-BUG-BOUNTY'])
    def test_existing_lower_or_upper_wins_without_duplicates(self, existing_name):
        out = merge_identity_headers({existing_name: 'mine'}, IDENTITY_DICT)
        assert _one_key_case_insensitive(out, 'X-Bug-Bounty') == 'mine'
        assert out == {existing_name: 'mine'}

    def test_identity_fills_gaps_and_inputs_are_not_mutated(self):
        existing = {'Accept': '*/*'}
        out = merge_identity_headers(existing, IDENTITY_DICT)
        assert out == {'Accept': '*/*', 'X-Bug-Bounty': 'researcher-7f3'}
        assert existing == {'Accept': '*/*'}

    @pytest.mark.parametrize('existing_name', ['user-agent', 'USER-AGENT'])
    def test_session_headers_existing_wins(self, existing_name):
        # requests session headers are a CaseInsensitiveDict whose update()
        # would replace the existing entry; add_identity_headers must not.
        session = requests.Session()
        session.headers[existing_name] = 'mine'
        add_identity_headers(session.headers, {'User-Agent': 'identity-ua'})
        keys = [k for k in session.headers if k.lower() == 'user-agent']
        assert len(keys) == 1
        assert session.headers['User-Agent'] == 'mine'


class TestPathCaseInsensitivity:
    @pytest.mark.parametrize('caller_name', ['x-bug-bounty', 'X-BUG-BOUNTY'])
    def test_security_checks_with_identity_caller_wins(self, caller_name):
        from recon.helpers import security_checks as sc
        token = sc._IDENTITY_HEADERS.set(IDENTITY_DICT)
        try:
            out = sc._with_identity({'headers': {caller_name: 'mine'}})
        finally:
            sc._IDENTITY_HEADERS.reset(token)
        assert _one_key_case_insensitive(out['headers'], 'X-Bug-Bounty') == 'mine'

    @pytest.mark.parametrize('caller_name', ['x-bug-bounty', 'X-BUG-BOUNTY'])
    def test_route_prober_caller_wins_without_duplicates(self, caller_name):
        from recon.route_exposure.prober import Prober
        prober = Prober({'ENGAGEMENT_IDENTITY_HEADER': IDENTITY},
                        guard=lambda url: True, timeout=5, rps=0)
        session = mock.Mock()
        resp = mock.Mock(status_code=200, headers={}, content=b'')
        resp.iter_content.return_value = []
        session.request.return_value = resp
        prober._local.session = session
        answer = prober.send('GET', 'https://example.test/x',
                             headers={caller_name: 'mine'})
        assert answer is not None
        sent = session.request.call_args.kwargs.get('headers') or \
            session.request.call_args[1].get('headers')
        assert _one_key_case_insensitive(sent, 'X-Bug-Bounty') == 'mine'

    @pytest.mark.parametrize('identity_name', ['user-agent', 'USER-AGENT'])
    def test_cache_session_keeps_its_user_agent(self, identity_name):
        from recon.cache_scan.scanner import _build_retry_session
        session = _build_retry_session(
            settings={'ENGAGEMENT_IDENTITY_HEADER': f'{identity_name}: evil'})
        keys = [k for k in session.headers if k.lower() == 'user-agent']
        assert len(keys) == 1
        assert session.headers['User-Agent'] == 'RedAmon-CachePoison/1.0'

    @pytest.mark.parametrize('identity_name', ['user-agent', 'USER-AGENT'])
    def test_origin_target_headers_keep_module_user_agent(self, identity_name):
        from recon.main_recon_modules import origin_discovery as od
        ctx = mock.Mock()
        ctx.settings = {'ENGAGEMENT_IDENTITY_HEADER': f'{identity_name}: evil'}
        headers = od._target_headers(ctx)
        assert _one_key_case_insensitive(headers, 'User-Agent') == od._UA

    def test_origin_upper_case_identity_name_still_attributed(self):
        from recon.main_recon_modules import origin_discovery as od
        ctx = mock.Mock()
        ctx.settings = {'ENGAGEMENT_IDENTITY_HEADER': 'X-BUG-BOUNTY: researcher-7f3'}
        headers = od._target_headers(ctx)
        assert _one_key_case_insensitive(headers, 'X-Bug-Bounty') == 'researcher-7f3'

    @pytest.mark.parametrize('identity_name', ['user-agent', 'USER-AGENT'])
    def test_sourcemap_missing_key_control_keeps_default_ua(self, identity_name):
        from recon.helpers.js_recon import sourcemap
        resp = mock.Mock(status_code=404)
        with mock.patch.object(sourcemap.requests, 'get', return_value=resp) as get, \
                mock.patch.object(sourcemap, 'is_url_safe_to_probe', return_value=True):
            sourcemap._missing_key_control(
                'https://example.test/app.js.map', timeout=5,
                identity_headers={identity_name: 'evil'})
        sent = get.call_args.kwargs['headers']
        assert _one_key_case_insensitive(sent, 'User-Agent') == sourcemap.DEFAULT_BROWSER_UA

    @pytest.mark.parametrize('caller_name', ['x-bug-bounty', 'X-BUG-BOUNTY'])
    def test_js_recon_redirect_get_caller_wins(self, caller_name):
        from recon.main_recon_modules import js_recon
        resp = mock.Mock(status_code=200, headers={}, content=b'x')
        with mock.patch.object(js_recon.requests, 'get', return_value=resp) as get, \
                mock.patch.object(js_recon, '_download_allowed', return_value=True):
            js_recon._safe_redirect_get(
                'https://example.test/app.js', timeout=5,
                headers={caller_name: 'mine'}, extra_headers=IDENTITY_DICT)
        sent = get.call_args.kwargs['headers']
        assert _one_key_case_insensitive(sent, 'X-Bug-Bounty') == 'mine'

    def test_graphql_upper_case_auth_wins(self):
        from recon.graphql_scan.auth import build_auth_headers
        settings = {'ENGAGEMENT_IDENTITY_HEADER': IDENTITY,
                    'GRAPHQL_AUTH_TYPE': 'header', 'GRAPHQL_AUTH_VALUE': 'mine',
                    'GRAPHQL_AUTH_HEADER': 'X-BUG-BOUNTY'}
        assert build_auth_headers(settings) == {'X-BUG-BOUNTY': 'mine'}


class TestSecurityChecksRunScope:
    def test_submit_scoped_propagates_identity_to_worker_threads(self):
        import concurrent.futures
        from recon.helpers import security_checks as sc
        token = sc._IDENTITY_HEADERS.set(IDENTITY_DICT)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = sc._submit_scoped(
                    executor, lambda: sc._with_identity({})['headers'])
                assert future.result(timeout=10) == IDENTITY_DICT
        finally:
            sc._IDENTITY_HEADERS.reset(token)

    def test_two_parallel_runs_never_mix_headers(self):
        from recon.helpers import security_checks as sc

        def _resp():
            r = mock.MagicMock()
            r.status_code = 200
            r.headers = {}
            r.text = ''
            r.content = b''
            r.cookies = []
            r.url = 'https://example.test/'
            r.history = []
            return r

        seen = []  # (url, headers-copy)
        lock = threading.Lock()
        barrier = threading.Barrier(2)
        calls = {'n': 0}

        def fake_get(url, *args, **kwargs):
            with lock:
                seen.append((url, dict(kwargs.get('headers') or {})))
                calls['n'] += 1
                first_two = calls['n'] <= 2
            if first_two:
                # Force both runs to be inside requests.get at once: any
                # process-global identity would already have been
                # overwritten by the second run before the first proceeds.
                barrier.wait(timeout=10)
            return _resp()

        def recon(host):
            return {'domain': 'example.test', 'dns': {
                'domain': {},
                'subdomains': {host: {'has_records': True,
                                      'ips': {'ipv4': [], 'ipv6': []}}}}}

        results = {}
        errors = {}

        def run(tag, host, value):
            # The identity headers are ContextVar-scoped per run. The older
            # _HH_SCOPE/_CONTROL_CACHE globals still assume one scan per
            # process (pre-existing, untouched here), so a run may lose that
            # race in its finally block; the assertion below is about the
            # headers captured on the wire, which must never mix.
            try:
                results[tag] = sc.run_security_checks(
                    recon(host), {'missing_referrer_policy': True},
                    timeout=1, max_workers=2,
                    settings={'ENGAGEMENT_IDENTITY_HEADER': f'X-Bug-Bounty: {value}'})
            except Exception as exc:  # noqa: BLE001 - recorded, asserted below
                errors[tag] = exc

        with mock.patch.object(sc.requests, 'get', side_effect=fake_get):
            threads = [
                threading.Thread(target=run, args=('a', 'a.example.test', 'run-a')),
                threading.Thread(target=run, args=('b', 'b.example.test', 'run-b')),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        assert not any(t.is_alive() for t in threads), 'a run deadlocked'
        assert seen, 'no request was captured'
        hosts_seen = set()
        for url, headers in seen:
            if 'a.example.test' in url:
                hosts_seen.add('a')
                assert _one_key_case_insensitive(
                    headers, 'X-Bug-Bounty') == 'run-a', (url, headers)
            elif 'b.example.test' in url:
                hosts_seen.add('b')
                assert _one_key_case_insensitive(
                    headers, 'X-Bug-Bounty') == 'run-b', (url, headers)
        # The barrier guarantees both runs had a request in flight at once.
        assert hosts_seen == {'a', 'b'}, (hosts_seen, seen)

    def test_no_identity_outside_a_run(self):
        from recon.helpers import security_checks as sc
        assert sc._with_identity({}) == {}
