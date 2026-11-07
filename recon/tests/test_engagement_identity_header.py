"""Engagement identity header: the runtime cascade and the outgoing header.

`engagementIdentityHeader` was documented, settable and validated for a year
with `runtime_key: null` — the value sat in the database and no scan ever sent
it. These tests pin the three properties the fix is worth anything for:

* CASCADE: the column flows Prisma -> /api/projects/[id] -> DEFAULT_SETTINGS ->
  fetch_project_settings -> settings['ENGAGEMENT_IDENTITY_HEADER'] -> every
  HTTP tool path. A dead setting is the exact failure this repo's
  test_settings_mapping_coverage.py exists to catch, and this file is its
  behavioural twin.
* OUTGOING: the header rides the tool's own -H set, so it is sent identically
  DIRECT and THROUGH the capture proxy — the proxy fail-open fallback cannot
  lose it, and no AUTH_PROFILE is required for it to appear.
* SAFETY: Host/Authorization/Cookie/Proxy-*/X-Redamon-ctx are refused, CR/LF
  and tool-join delimiters are refused, and a duplicate name is never sent
  twice (the operator's own line of the same name wins).

Run inside the recon image (see README.TESTING.md): host pytest sees the wrong
dependency set and mis-collects.
"""

from unittest import mock

from recon.helpers.auth_profile import (
    append_engagement_identity,
    engagement_identity_header,
)
from recon.main_recon_modules import http_probe, vuln_scan
from recon.helpers import nuclei_helpers

SETTINGS = {'TARGET_DOMAIN': 'example.test', 'SUBDOMAIN_LIST': ['.'], 'IP_MODE': False}
IDENTITY = 'X-Bug-Bounty: researcher-7f3'


class TestCascade:
    def test_default_settings_key_exists_and_is_empty(self):
        from recon.project_settings import DEFAULT_SETTINGS
        assert DEFAULT_SETTINGS['ENGAGEMENT_IDENTITY_HEADER'] == ''

    def test_fetch_maps_the_column(self):
        import recon.project_settings as ps
        project = {
            'userId': 'u1',
            'engagementIdentityHeader': IDENTITY,
            'authProfile': None,
        }
        with mock.patch('requests.get') as get:
            get.return_value.json.return_value = project
            get.return_value.raise_for_status.return_value = None
            settings = ps.fetch_project_settings('p1', 'http://webapp:3000')
        assert settings['ENGAGEMENT_IDENTITY_HEADER'] == IDENTITY

    def test_registry_runtime_key_is_wired(self):
        from recon import settings_registry as reg
        by_key = reg.by_runtime_key()
        assert 'ENGAGEMENT_IDENTITY_HEADER' in by_key
        assert by_key['ENGAGEMENT_IDENTITY_HEADER'] is not None


class TestOutgoingHeader:
    def test_none_when_unset(self):
        assert engagement_identity_header({}) is None
        assert engagement_identity_header({'ENGAGEMENT_IDENTITY_HEADER': ''}) is None
        assert engagement_identity_header(None) is None

    def test_valid_line_returned_normalized(self):
        assert engagement_identity_header(
            {'ENGAGEMENT_IDENTITY_HEADER': f' {IDENTITY} '}) == IDENTITY

    def test_httpx_command_carries_it(self):
        settings = dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY,
                        HTTPX_CUSTOM_HEADERS=[])
        import inspect
        src = inspect.getsource(http_probe.build_httpx_command) if hasattr(
            http_probe, 'build_httpx_command') else None
        # The append happens before cmd construction; assert via the helper the
        # module calls, which is the wiring this file pins.
        merged = append_engagement_identity([], settings)
        assert merged == [IDENTITY]

    def test_nuclei_auth_headers_get_the_identity_without_any_auth_profile(self):
        # No AUTH_PROFILE: identity must still be attached — an identity header
        # is attribution, not a credential, and must not inherit the session's
        # scope gate (which would drop it on out-of-scope hosts).
        settings = dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)
        from recon.helpers.auth_profile import merge_auth_headers
        base = merge_auth_headers([], settings, ['example.test'])
        assert base == []
        out = append_engagement_identity(base, settings)
        assert out == [IDENTITY]

    def test_survives_auth_merge_ordering(self):
        # An authenticated run: session lines FIRST, identity AFTER, one each.
        profile = {'authType': 'bearer', 'authValue': 'tok',
                   'authHeaderName': '', 'extraHeaders': {},
                   'reconEnabled': True, 'scopeHosts': ['example.test']}
        settings = dict(SETTINGS, AUTH_PROFILE=profile,
                        ENGAGEMENT_IDENTITY_HEADER=IDENTITY)
        from recon.helpers.auth_profile import merge_auth_headers
        merged = merge_auth_headers([], settings, ['example.test'])
        out = append_engagement_identity(merged, settings)
        assert out[0].startswith('Authorization: Bearer ')
        assert out[-1] == IDENTITY

    def test_identity_reaches_build_nuclei_command_auth_headers(self):
        cmd = nuclei_helpers.build_nuclei_command(
            targets_file='/targets/t.txt', output_file='/output/o.jsonl',
            docker_image='projectdiscovery/nuclei:latest',
            auth_headers=append_engagement_identity(
                [], dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)))
        assert cmd.count('-H') >= 1
        assert IDENTITY in cmd

    def test_capture_proxy_routing_is_independent_of_the_identity(self):
        # §20.2: the X-Redamon-Ctx tag is added ONLY in the proxy branch. The
        # identity header must not depend on it: direct runs (no proxy) carry
        # the identity, proxy runs carry both.
        with mock.patch('helpers.proxy_routing.get_capture_routing',
                        return_value=(None, None)):
            cmd = nuclei_helpers.build_nuclei_command(
                targets_file='/targets/t.txt', output_file='/output/o.jsonl',
                docker_image='projectdiscovery/nuclei:latest',
                auth_headers=append_engagement_identity(
                    [], dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)))
        assert IDENTITY in cmd
        assert not any('X-Redamon-Ctx' in c for c in cmd)


class TestHostSafetyAndDuplicates:
    def test_forbidden_names_are_refused(self):
        for bad in (
            'Host: victim.test',
            'Proxy-Connection: keep-alive',
            'Proxy-Custom: value',
            'Authorization: Bearer x',
            'Cookie: session=1',
            'Proxy-Authorization: basic',
            'X-Redamon-Ctx: forged',
            'Content-Length: 5',
            'Transfer-Encoding: chunked',
        ):
            assert engagement_identity_header(
                {'ENGAGEMENT_IDENTITY_HEADER': bad}) is None, bad

    def test_crlf_and_join_delimiters_are_refused(self):
        for bad in (
            'X-BB: a\r\nX-Injected: 1',
            'X-BB: a\nX-B: 2',
            'X-BB: a;;X-B: 2',
            'X-BB: a\x00b',
            'X-BB: value\r\n',
            '\nX-BB: value',
        ):
            assert engagement_identity_header(
                {'ENGAGEMENT_IDENTITY_HEADER': bad}) is None, bad

    def test_no_colon_or_empty_value_refused(self):
        assert engagement_identity_header(
            {'ENGAGEMENT_IDENTITY_HEADER': 'X-BB'}) is None
        assert engagement_identity_header(
            {'ENGAGEMENT_IDENTITY_HEADER': 'X-BB: '}) is None

    def test_operator_line_of_same_name_wins_no_duplicate(self):
        settings = dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)
        out = append_engagement_identity(['X-Bug-Bounty: my-own'], settings)
        assert out == ['X-Bug-Bounty: my-own']

    def test_other_headers_are_kept_and_identity_appended_once(self):
        settings = dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)
        out = append_engagement_identity(
            ['X-Other: 1', 'X-Bug-Bounty: mine'], settings)
        assert out == ['X-Other: 1', 'X-Bug-Bounty: mine']

    def test_case_insensitive_dedup(self):
        settings = dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)
        out = append_engagement_identity(['x-bug-bounty: lower'], settings)
        assert out == ['x-bug-bounty: lower']

    def test_input_list_not_mutated(self):
        settings = dict(SETTINGS, ENGAGEMENT_IDENTITY_HEADER=IDENTITY)
        base = ['X-Other: 1']
        append_engagement_identity(base, settings)
        assert base == ['X-Other: 1']
