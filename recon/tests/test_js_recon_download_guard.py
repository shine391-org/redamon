"""The address rule js_recon applies to a JS download.

A bundle on one of the run's own hosts is read whatever the host resolves to,
as katana and httpx already read it, so an internal engagement's bundles reach
the analysers. Any other host, and any redirect hop off the run, keeps the
attacker-influenced rule that refuses every private address. Cloud metadata
stays refused either way.
"""
from __future__ import annotations

import ipaddress
from unittest import mock

import pytest

from recon.main_recon_modules import js_recon as jr


@pytest.fixture
def run_hosts():
    def install(hosts, networks=()):
        jr._OWN_HOSTS = jr._OwnHosts(frozenset(hosts), frozenset(), tuple(networks))
    yield install
    jr._OWN_HOSTS = None


def _resp(status=200, location=None):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = {"Location": location} if location else {}
    return r


class TestDownloadAllowed:
    def test_outside_a_run_a_private_host_is_refused(self):
        assert jr._OWN_HOSTS is None
        assert jr._download_allowed("http://10.20.0.5/static/app.js") is False

    def test_a_run_host_on_a_private_address_is_read(self, run_hosts):
        run_hosts({"10.20.0.5"})
        assert jr._download_allowed("http://10.20.0.5/static/app.js") is True

    def test_a_private_host_off_the_run_is_refused(self, run_hosts):
        run_hosts({"10.20.0.5"})
        assert jr._download_allowed("http://10.20.0.6/static/app.js") is False

    def test_metadata_is_refused_even_as_a_run_host(self, run_hosts):
        run_hosts({"169.254.169.254"})
        assert jr._download_allowed("http://169.254.169.254/latest/meta-data/") is False

    def test_an_operator_network_admits_its_own_address(self, run_hosts):
        run_hosts({"127.0.0.1"}, [ipaddress.ip_network("127.0.0.1/32")])
        assert jr._download_allowed("http://127.0.0.1:8080/app.js") is True

    def test_a_non_http_scheme_takes_the_strict_rule(self, run_hosts):
        run_hosts({"10.20.0.5"})
        assert jr._download_allowed("ftp://10.20.0.5/app.js") is False


class TestRedirectHops:
    def test_a_redirect_off_the_run_into_metadata_is_refused(self, run_hosts):
        run_hosts({"10.20.0.5"})
        hops = [_resp(302, "http://169.254.169.254/latest/meta-data/")]
        with mock.patch.object(jr.requests, "get", side_effect=hops) as get:
            assert jr._safe_redirect_get("http://10.20.0.5/app.js", timeout=5, headers={}) is None
        assert get.call_count == 1

    def test_a_redirect_within_the_run_is_followed(self, run_hosts):
        run_hosts({"10.20.0.5"})
        hops = [_resp(302, "/static/app.1234.js"), _resp(200)]
        with mock.patch.object(jr.requests, "get", side_effect=hops) as get:
            assert jr._safe_redirect_get("http://10.20.0.5/app.js", timeout=5, headers={}).status_code == 200
        assert get.call_args.args[0] == "http://10.20.0.5/static/app.1234.js"


class TestOwnHosts:
    def test_target_list_ip_targets_and_reached_hosts_are_the_run(self):
        combined = {
            "subdomains": ["app.lab.invalid"],
            "metadata": {"expanded_ips": ["10.20.0.5"]},
            "http_probe": {"by_url": {"http://10.20.0.7": {"url": "http://10.20.0.7"}}},
        }
        own = jr._own_hosts(combined, {"TARGET_IPS": ["10.20.0.0/24"], "IP_MODE": True})
        assert {"app.lab.invalid", "10.20.0.5", "10.20.0.7"} <= own.hosts
        assert ipaddress.ip_network("10.20.0.0/24") in own.operator_networks

    def test_a_run_resets_the_hosts_when_it_ends(self):
        with mock.patch.object(jr, "_collect_js_urls", return_value=[]), \
                mock.patch.object(jr, "_load_uploaded_files", return_value=[]):
            jr.run_js_recon({"metadata": {"expanded_ips": ["10.20.0.5"]}}, {})
        assert jr._OWN_HOSTS is None
