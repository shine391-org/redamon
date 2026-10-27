"""The canary-gated DNS resolver breaker and per-source subdomain breakers.

domain_recon.py, plan Phase 7 (#2 rdns zones, #3 resolver+canary, #5 sources).
A dead resolver used to make every 80x7 subdomain lookup time out three times;
the canary tells a dead resolver from a dead name so only the former stops the run.
"""
from __future__ import annotations

from unittest import mock

import pytest

import dns.resolver

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import domain_recon as dr


@pytest.fixture(autouse=True)
def _reset_resolver():
    dr.resolver_breaker.reset()
    yield
    dr.resolver_breaker.reset()


def _timeout(*a, **k):
    # dnspython requires both kwargs; this is what resolve() raises on timeout.
    raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])


def _answer(text="1.2.3.4"):
    rr = mock.MagicMock()
    rr.to_text.return_value = text
    return [rr]


class TestDnsLookupSingle:
    def test_nxdomain_is_definitive_no_retry(self):
        with mock.patch.object(dr.dns.resolver, "resolve",
                               side_effect=dns.resolver.NXDOMAIN) as res:
            out = dr.dns_lookup_single("nope.test", "A", max_retries=3)
        assert out is None
        assert res.call_count == 1  # not retried

    def test_transient_with_a_live_canary_does_not_open(self):
        dr.resolver_breaker.set_canary("canary.test")

        def side(hostname, rtype, *a, **k):
            if str(hostname) == "canary.test":
                return _answer()          # resolver is alive
            raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])

        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=side):
            out = dr.dns_lookup_single("slow.test", "A", max_retries=2)
        assert out is None
        assert dr.resolver_breaker.is_open() is False

    def test_transient_with_a_dead_canary_opens_the_resolver(self):
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            out = dr.dns_lookup_single("slow.test", "A", max_retries=3)
        assert out is None
        assert dr.resolver_breaker.is_open() is True
        report = cb.coverage_report()
        assert "dns" in report.degraded_sources

    def test_an_open_resolver_short_circuits(self):
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            dr.dns_lookup_single("slow.test", "A", max_retries=3)  # opens it
        with mock.patch.object(dr.dns.resolver, "resolve") as res:
            out = dr.dns_lookup_single("other.test", "A", max_retries=3)
        assert out is None
        res.assert_not_called()

    def test_the_off_switch_never_opens(self, monkeypatch):
        monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            dr.dns_lookup_single("slow.test", "A", max_retries=1)
        assert dr.resolver_breaker.is_open() is False


class TestReverseZoneBreaker:
    def test_a_zone_that_times_out_is_skipped_after_the_threshold(self):
        # Three PTR timeouts on the same /24 open its rdns breaker; the fourth
        # IP in that zone is skipped without a lookup.
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            for i in range(3):
                dr.reverse_dns_lookup(f"203.0.113.{i}", max_retries=1)
        assert cb.is_open("rdns:203.0.113")
        with mock.patch.object(dr.dns.resolver, "resolve") as res:
            out = dr.reverse_dns_lookup("203.0.113.9", max_retries=1)
        assert out is None
        res.assert_not_called()

    def test_a_definitive_no_ptr_keeps_the_zone_healthy(self):
        with mock.patch.object(dr.dns.resolver, "resolve",
                               side_effect=dns.resolver.NXDOMAIN):
            for i in range(5):
                dr.reverse_dns_lookup(f"198.51.100.{i}", max_retries=1)
        assert not cb.is_open("rdns:198.51.100")


class TestVerifyDomainOwnership:
    def test_resolver_down_is_reported_not_no_txt(self):
        dr.resolver_breaker.set_canary("canary.test")
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=_timeout):
            out = dr.verify_domain_ownership("example.test", "tok")
        assert out["verified"] is False
        assert "resolver down" in out["error"].lower()


class TestSourceBreakers:
    def _resp(self, status=200, text=""):
        r = mock.MagicMock()
        r.status_code = status
        r.text = text
        r.json.return_value = []
        return r

    def test_crtsh_pauses_after_repeated_failures(self):
        with mock.patch.object(dr.requests, "Session") as Sess:
            Sess.return_value.get.return_value = self._resp(502)
            for _ in range(3):
                dr.query_crtsh("a.test", settings={"CRTSH_ENABLED": True})
        assert cb.is_open("subsrc:crtsh")
        # Next group: the source is skipped without another HTTP call.
        with mock.patch.object(dr.requests, "Session") as Sess:
            dr.query_crtsh("b.test", settings={"CRTSH_ENABLED": True})
            Sess.return_value.get.assert_not_called()

    def test_hackertarget_429_pauses_after_two_in_a_row(self):
        # A 429 is classified RATE_LIMIT; the breaker pauses the source after two
        # consecutive rate-limits (never on one stray 429).
        with mock.patch.object(dr.requests, "Session") as Sess:
            Sess.return_value.get.return_value = self._resp(429, text="")
            dr.query_hackertarget("a.test", settings={"HACKERTARGET_ENABLED": True})
            assert not cb.is_open("subsrc:hackertarget")  # one strike, still closed
            dr.query_hackertarget("a2.test", settings={"HACKERTARGET_ENABLED": True})
        assert cb.is_open("subsrc:hackertarget")


# ---------------------------------------------------------------------------
# Plan 12.10: the latch closes again
# ---------------------------------------------------------------------------
# One trip opened it for the rest of the process: later batch groups and later
# partial roots resolved nothing, ownership checks were refused, the
# certificate-name SSRF check passed names unresolved, and groups 2..N
# recorded no DNS gap.

class _Resolver:
    """dns.resolver.resolve with a switch: dead (timeout) or alive (answers)."""

    def __init__(self, alive=False):
        self.alive = alive
        self.calls = []

    def __call__(self, hostname, rtype="A", *a, **k):
        self.calls.append(str(hostname))
        if not self.alive:
            raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])
        return _answer()


def _trip(resolver):
    dr.resolver_breaker.set_canary("example.com")
    with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
        dr.dns_lookup_single("a.example.com", "A", max_retries=1)
    assert dr.resolver_breaker.is_open()


class TestTheLatchRecovers:
    def test_a_recovered_resolver_resolves_again_in_the_next_group(self, capsys):
        resolver = _Resolver(alive=False)
        _trip(resolver)
        resolver.alive = True
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            assert dr.resolver_breaker.recheck() is True
            assert dr.dns_lookup_single("b.example.com", "A", max_retries=1) == ["1.2.3.4"]
        assert dr.resolver_breaker.is_open() is False
        assert "Resolver answering again: lookups resumed" in capsys.readouterr().out

    def test_a_dead_resolver_re_latches_after_one_probe_and_the_group_records_the_gap(self, capsys):
        resolver = _Resolver(alive=False)
        _trip(resolver)
        group2 = cb.group_scope()
        resolver.calls.clear()
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            assert dr.resolver_breaker.recheck() is False
            for host in ("c.example.com", "d.example.com"):
                assert dr.dns_lookup(host, max_retries=2, parallel=False)["has_records"] is False
        assert resolver.calls == ["example.com"]           # the canary, once
        assert "Resolver still down: skipping this group's lookups" in capsys.readouterr().out
        report = group2.report()
        assert any(g["source"] == "dns" for g in report.gaps)
        assert {"c.example.com", "d.example.com"} <= set(report.skipped_hostnames())

    def test_skipped_hosts_keep_their_findings_for_every_source(self):
        resolver = _Resolver(alive=False)
        _trip(resolver)
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            dr.dns_lookup_single("e.example.com", "A", max_retries=1)
        report = cb.coverage_report()
        assert "e.example.com" in report.keep_hostnames("nuclei")
        assert "e.example.com" in report.keep_hostnames("js_recon")

    def test_a_closed_latch_notes_a_new_trip_in_the_current_group(self):
        resolver = _Resolver(alive=False)
        _trip(resolver)
        resolver.alive = True
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            dr.resolver_breaker.recheck()
        group2 = cb.group_scope()
        resolver.alive = False
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            dr.dns_lookup_single("f.example.com", "A", max_retries=1)
        assert any(g["source"] == "dns" for g in group2.report().gaps)

    def test_recheck_is_a_no_op_while_the_latch_is_closed(self):
        with mock.patch.object(dr.dns.resolver, "resolve") as res:
            assert dr.resolver_breaker.recheck() is True
        res.assert_not_called()


class TestTheCanary:
    def test_the_most_recent_answering_root_is_the_canary(self):
        dr.resolver_breaker.set_canary("first.example.com")
        dr.resolver_breaker.set_canary("second.example.org")
        seen = []

        def side(hostname, rtype="A", *a, **k):
            seen.append(str(hostname))
            raise dns.resolver.LifetimeTimeout(timeout=1, errors=[])

        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=side):
            dr.dns_lookup_single("x.example.org", "A", max_retries=1)
        assert seen[-1] == "second.example.org"


class TestTheHalfOpenCooldown:
    def test_one_probe_after_the_cooldown_closes_it(self, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(dr.resolver_breaker, "_clock", lambda: clock[0])
        resolver = _Resolver(alive=False)
        _trip(resolver)
        resolver.calls.clear()
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            assert dr.resolver_breaker.is_open() is True    # inside the cooldown: no probe
            assert resolver.calls == []
            clock[0] += dr.RESOLVER_COOLDOWN_S
            resolver.alive = True
            assert dr.resolver_breaker.is_open() is False   # one probe, it answered
        assert resolver.calls == ["example.com"]

    def test_a_failed_probe_doubles_the_cooldown(self, monkeypatch):
        clock = [1000.0]
        monkeypatch.setattr(dr.resolver_breaker, "_clock", lambda: clock[0])
        resolver = _Resolver(alive=False)
        _trip(resolver)
        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver):
            clock[0] += dr.RESOLVER_COOLDOWN_S
            assert dr.resolver_breaker.is_open() is True
            resolver.calls.clear()
            clock[0] += dr.RESOLVER_COOLDOWN_S              # not yet: the cooldown doubled
            assert dr.resolver_breaker.is_open() is True
            assert resolver.calls == []


class TestCertificateNamesFailClosed:
    def test_with_the_latch_open_a_name_is_not_injected_unresolved(self):
        from recon.helpers import target_helpers as th
        _trip(_Resolver(alive=False))
        with mock.patch("socket.getaddrinfo") as gai:
            assert th._resolves_to_routable("internal.example.com") is False
        gai.assert_not_called()
        assert "internal.example.com" in cb.coverage_report().skipped_hostnames()

    def test_with_the_latch_closed_a_private_answer_is_still_dropped(self):
        from recon.helpers import target_helpers as th
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
            assert th._resolves_to_routable("pivot.example.com") is False


class TestPartialRoots:
    def test_each_root_rechecks_the_resolver(self):
        from recon.partial_recon_modules import helpers
        resolver = _Resolver(alive=False)
        _trip(resolver)
        resolver.alive = True
        seen = []

        def per_root(root):
            seen.append((root, dr.resolver_breaker.is_open()))
            return helpers.STATUS_OK

        with mock.patch.object(dr.dns.resolver, "resolve", side_effect=resolver), \
                mock.patch.object(helpers, "ROOT_PAUSE_S", 0):
            helpers.run_per_root(["example.com", "example.org"], per_root, "SubdomainDiscovery")
        assert seen == [("example.com", False), ("example.org", False)]
