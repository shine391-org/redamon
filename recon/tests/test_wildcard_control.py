"""RedAmon's own wildcard-DNS control (plan 08.3).

A zone with wildcard DNS answers every name, so a guessed name "exists".
puredns filters those at discovery, but it can be skipped (disabled, stealth,
failure) and the names added after it (certificate SANs, tlsx, js_recon,
uncover) never pass through it. The control probes each zone with random
labels and drops a name that answers only with the zone's wildcard addresses.

Every DNS answer here comes from a fake resolver (wildcard_control._query is
the one seam); fixture names are under example.test / example.net, addresses
are RFC 5737.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import wildcard_control as wc  # noqa: E402

ROOT = "example.test"
WILD_IP = "203.0.113.10"
REAL_IP = "198.51.100.7"


class FakeDNS:
    """A resolver over explicit records plus wildcard zones.

    ``wildcards``: zone -> {"A": [...], "AAAA": [...], "CNAME": [...]}, the
    answer every name under the zone gets unless it has explicit records.
    ``records``: name -> the same shape. ``fail``: zones whose names time out.
    """

    def __init__(self, wildcards=None, records=None, fail=()):
        self.wildcards = wildcards or {}
        self.records = records or {}
        self.fail = set(fail)
        self.calls = []

    def __call__(self, name, rtype):
        self.calls.append((name, rtype))
        if any(name == z or name.endswith("." + z) for z in self.fail):
            return "fail", []
        answer = self.records.get(name)
        if answer is None:
            zones = [z for z in self.wildcards if name.endswith("." + z)]
            if not zones:
                return "nx", []
            answer = self.wildcards[max(zones, key=len)]
        values = answer.get(rtype) or []
        return ("ok", list(values)) if values else ("none", [])

    def probed_labels(self, zone=None):
        return {n for n, _ in self.calls
                if n.startswith("rdm-") and (zone is None or n.split(".", 1)[1] == zone)}


@pytest.fixture(autouse=True)
def fresh_run():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _gaps(source="wildcard_control"):
    return [g for g in json.loads(cb.coverage_report().gaps_json()) if g["source"] == source]


def _entry(ip=None, cname=None):
    return {"has_records": bool(ip or cname),
            "ips": {"ipv4": [ip] if ip else [], "ipv6": []},
            "records": {"A": [ip] if ip else None, "CNAME": [cname] if cname else None}}


def _discovered(names_to_entry, sources, guessing=("knockpy",), settings=None, dns=None,
                roots_domain=ROOT):
    dns_result = {"domain": {}, "subdomains": dict(names_to_entry)}
    with patch.object(wc, "_query", dns):
        return wc.filter_discovered(roots_domain, sorted(names_to_entry), dns_result, sources,
                                    settings or {}, guessing=set(guessing))


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #
def test_a_wildcard_root_drops_guessed_names_on_its_ip_and_keeps_a_distinct_one():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    names = {"admin.example.test": _entry(WILD_IP), "dev.example.test": _entry(WILD_IP),
             "real.example.test": _entry(REAL_IP)}
    out = _discovered(names, {n: {"knockpy"} for n in names}, dns=dns)
    assert out.kept == ["real.example.test"]
    assert sorted(out.dropped) == ["admin.example.test", "dev.example.test"]
    assert out.zones == {ROOT: {"is_wildcard": True, "ips": [WILD_IP]}}


def test_a_non_wildcard_root_keeps_everything_after_one_query():
    dns = FakeDNS()
    names = {"admin.example.test": _entry(WILD_IP), "www.example.test": _entry(REAL_IP)}
    out = _discovered(names, {n: {"knockpy"} for n in names}, dns=dns)
    assert sorted(out.kept) == sorted(names) and out.dropped == []
    assert out.zones == {ROOT: {"is_wildcard": False, "ips": []}}
    assert len(dns.calls) == 1, "an NXDOMAIN on the first label settles the zone"


def test_a_name_that_resolved_to_nothing_is_kept():
    """An empty answer is not 'a subset of the wildcard': it is unresolved."""
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    out = _discovered({"gone.example.test": _entry()}, {"gone.example.test": {"knockpy"}}, dns=dns)
    assert out.kept == ["gone.example.test"]


def test_the_scan_root_itself_is_never_checked():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}}, records={ROOT: {"A": [WILD_IP]}})
    out = _discovered({ROOT: _entry(WILD_IP), "x.example.test": _entry(WILD_IP)},
                      {ROOT: {"crt.sh"}, "x.example.test": {"knockpy"}}, dns=dns)
    assert out.kept == [ROOT] and out.dropped == ["x.example.test"]


def test_a_name_partly_off_the_wildcard_set_is_kept():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    entry = {"has_records": True, "ips": {"ipv4": [WILD_IP, REAL_IP], "ipv6": []}, "records": {}}
    out = _discovered({"lb.example.test": entry}, {"lb.example.test": {"knockpy"}}, dns=dns)
    assert out.kept == ["lb.example.test"]


def test_round_robin_wildcard_answers_are_unioned_over_the_probe_labels():
    answers = iter([[WILD_IP], ["203.0.113.11"], ["203.0.113.12"]])

    def rr(name, rtype):
        if rtype == "A" and name.startswith("rdm-"):
            return "ok", next(answers)
        return "none", []

    names = {"a.example.test": _entry("203.0.113.12")}
    with patch.object(wc, "_query", rr):
        out = wc.filter_discovered(ROOT, list(names), {"subdomains": names}, {"a.example.test": {"knockpy"}},
                                   {}, guessing={"knockpy"})
    assert out.dropped == ["a.example.test"]
    assert out.zones[ROOT]["ips"] == [WILD_IP, "203.0.113.11", "203.0.113.12"]


# --------------------------------------------------------------------------- #
# The CNAME exception: a non-guessing source AND a CNAME of its own
# --------------------------------------------------------------------------- #
def test_the_cname_exception():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP], "CNAME": ["edge.example.net."]}})
    names = {
        # seen by a passive source, with its own CNAME: a real record that
        # shares the wildcard's edge
        "shop.example.test": _entry(WILD_IP, "shops.example.net."),
        # guessed: a CNAME of its own never saves a guess
        "guess.example.test": _entry(WILD_IP, "other.example.net."),
        # passive, but its CNAME is the wildcard's own: synthesized
        "old.example.test": _entry(WILD_IP, "edge.example.net."),
        # passive, no CNAME: now answers only through the wildcard
        "www.example.test": _entry(WILD_IP),
    }
    sources = {"shop.example.test": {"crt.sh"}, "guess.example.test": {"knockpy"},
               "old.example.test": {"crt.sh", "knockpy"}, "www.example.test": {"subfinder"}}
    out = _discovered(names, sources, dns=dns)
    assert out.kept == ["shop.example.test"]
    assert sorted(out.dropped) == ["guess.example.test", "old.example.test", "www.example.test"]


def test_a_name_from_both_a_guessing_and_a_passive_source_counts_as_seen():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    out = _discovered({"api.example.test": _entry(WILD_IP, "api.example.net.")},
                      {"api.example.test": {"knockpy", "crt.sh"}}, dns=dns)
    assert out.kept == ["api.example.test"]


# --------------------------------------------------------------------------- #
# Which zones: the scan root, and deeper parents with enough candidates
# --------------------------------------------------------------------------- #
def test_a_deeper_parent_with_five_candidates_is_probed_as_its_own_zone():
    dns = FakeDNS(wildcards={"dev.example.test": {"A": ["203.0.113.20"]}})
    names = {f"h{i}.dev.example.test": _entry("203.0.113.20") for i in range(4)}
    names["app.dev.example.test"] = _entry(REAL_IP)
    names["www.example.test"] = _entry(REAL_IP)
    out = _discovered(names, {n: {"knockpy"} for n in names}, dns=dns)
    assert sorted(out.kept) == ["app.dev.example.test", "www.example.test"]
    assert len(out.dropped) == 4
    assert out.zones["dev.example.test"] == {"is_wildcard": True, "ips": ["203.0.113.20"]}
    assert out.zones[ROOT] == {"is_wildcard": False, "ips": []}


def test_a_deeper_parent_with_fewer_candidates_uses_the_nearest_probed_zone():
    dns = FakeDNS(wildcards={"dev.example.test": {"A": ["203.0.113.20"]}})
    names = {f"h{i}.dev.example.test": _entry("203.0.113.20") for i in range(4)}
    out = _discovered(names, {n: {"knockpy"} for n in names}, dns=dns)
    assert sorted(out.kept) == sorted(names)
    assert not dns.probed_labels("dev.example.test")
    assert set(out.zones) == {ROOT}


# --------------------------------------------------------------------------- #
# Engagement limits
# --------------------------------------------------------------------------- #
def test_at_most_three_labels_per_zone():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP], "AAAA": ["2001:db8::10"]}})
    _discovered({"a.example.test": _entry(WILD_IP)}, {"a.example.test": {"knockpy"}}, dns=dns)
    assert len(dns.probed_labels(ROOT)) == wc.LABELS_PER_ZONE == 3


def test_a_failing_zone_spends_at_most_three_labels_over_the_whole_run():
    dns = FakeDNS(fail={ROOT})
    for _ in range(5):
        _discovered({"a.example.test": _entry(WILD_IP)}, {"a.example.test": {"knockpy"}}, dns=dns)
    assert len(dns.probed_labels(ROOT)) == 3


def test_the_zone_cap_holds_and_the_cut_is_reported(monkeypatch):
    monkeypatch.setattr(wc, "MAX_ZONES_PER_RUN", 2)
    dns = FakeDNS(wildcards={z: {"A": [WILD_IP]} for z in ("a.test", "b.test", "c.test")})
    with patch.object(wc, "_query", dns):
        out = wc.filter_late_names(["x.a.test", "x.b.test", "x.c.test"],
                                   ["a.test", "b.test", "c.test"], {})
    probed = {n.split(".", 1)[1] for n in dns.probed_labels()}
    assert len(probed) == 2
    unchecked = ({"a.test", "b.test", "c.test"} - probed).pop()
    assert f"x.{unchecked}" in out.kept
    gaps = _gaps()
    assert len(gaps) == 1 and gaps[0]["skipped"] == 1 and "cap" in gaps[0]["reason"]


def test_an_roe_excluded_zone_is_never_queried():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    names = {f"h{i}.dev.example.test": _entry(WILD_IP) for i in range(5)}
    names["www.example.test"] = _entry(REAL_IP)
    settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["dev.example.test"]}
    out = _discovered(names, {n: {"knockpy"} for n in names}, dns=dns, settings=settings)
    assert not any(n.endswith("dev.example.test") for n, _ in dns.calls)
    assert all(n in out.kept for n in names if n.endswith(".dev.example.test"))
    assert _gaps() == [], "an RoE exclusion is a decision, not a cut"


def test_queries_are_paced_to_the_roe_ceiling(monkeypatch):
    sleeps = []
    monkeypatch.setattr(wc.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(wc.time, "sleep", lambda s: sleeps.append(round(s, 3)))
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    _discovered({"a.example.test": _entry(WILD_IP)}, {"a.example.test": {"knockpy"}},
                dns=dns, settings={"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 4})
    assert len(dns.calls) >= 3
    assert sleeps == [round(0.25 * i, 3) for i in range(1, len(dns.calls))]


@pytest.mark.parametrize("settings", [{}, {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 4}])
def test_no_pacing_without_an_active_ceiling(monkeypatch, settings):
    """The same rule as the RoE capper: the ceiling holds only with RoE on."""
    sleeps = []
    monkeypatch.setattr(wc.time, "sleep", lambda s: sleeps.append(s))
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    _discovered({"a.example.test": _entry(WILD_IP)}, {"a.example.test": {"knockpy"}},
                dns=dns, settings=settings)
    assert sleeps == []


# --------------------------------------------------------------------------- #
# A failed check is never evidence; a skipped one is reported
# --------------------------------------------------------------------------- #
def test_a_failed_probe_drops_nothing_and_is_reported():
    dns = FakeDNS(fail={ROOT})
    names = {"admin.example.test": _entry(WILD_IP), "dev.example.test": _entry(WILD_IP)}
    out = _discovered(names, {n: {"knockpy"} for n in names}, dns=dns)
    assert sorted(out.kept) == sorted(names) and out.dropped == []
    assert out.zones == {}, "an unknown zone is never stamped"
    gaps = _gaps()
    assert len(gaps) == 1 and gaps[0]["skipped"] == 2 and "failed" in gaps[0]["reason"]


def test_zone_answers_are_cached_for_the_run():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    names = {"a.example.test": _entry(WILD_IP)}
    _discovered(names, {"a.example.test": {"knockpy"}}, dns=dns)
    first = len(dns.calls)
    _discovered(names, {"a.example.test": {"knockpy"}}, dns=dns)
    assert len(dns.calls) == first


def test_dns_off_skips_the_late_control_and_records_the_note():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    with patch.object(wc, "_query", dns):
        out = wc.filter_late_names(["a.example.test", "b.example.test"], [ROOT],
                                   {"DNS_ENABLED": False})
    assert out.kept == ["a.example.test", "b.example.test"]
    assert dns.calls == []
    gaps = _gaps()
    assert len(gaps) == 1 and gaps[0]["skipped"] == 2 and "DNS resolution off" in gaps[0]["reason"]


def test_stealth_mode_keeps_the_control_on_while_puredns_is_off():
    """Stealth turns puredns off but not DNS resolution, so the control is
    exactly what stands in for puredns there."""
    from recon.project_settings import DEFAULT_SETTINGS, apply_stealth_overrides
    settings = apply_stealth_overrides({**DEFAULT_SETTINGS, "STEALTH_MODE": True})
    assert settings["PUREDNS_ENABLED"] is False and settings["DNS_ENABLED"] is True
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    with patch.object(wc, "_query", dns):
        out = wc.filter_late_names(["a.example.test"], [ROOT], settings)
    assert out.dropped == ["a.example.test"]


@pytest.mark.parametrize("max_zones, settings, reason", [
    (0, {}, "zone cap (0) reached"),
    (50, {"DNS_ENABLED": False}, "DNS resolution off"),
    (50, {}, "wildcard probe failed"),
])
def test_every_note_is_a_valid_coverage_token_with_an_uncut_reason(monkeypatch, max_zones,
                                                                   settings, reason):
    """The Recon Delta rejects a run's whole gap list when one source breaks
    [a-z0-9_]{1,64}; a reason over 80 characters is cut mid-word."""
    monkeypatch.setattr(wc, "MAX_ZONES_PER_RUN", max_zones)
    with patch.object(wc, "_query", FakeDNS(fail={ROOT})):
        wc.filter_late_names(["a.example.test"], [ROOT], settings)
    gaps = json.loads(cb.coverage_report().gaps_json())
    assert len(gaps) == 1
    assert re.fullmatch(r"[a-z0-9_]{1,64}", gaps[0]["source"])
    assert gaps[0]["reason"].startswith(reason)
    assert gaps[0]["reason"].endswith("names not checked for wildcard DNS")
    assert len(gaps[0]["reason"]) <= 80


# --------------------------------------------------------------------------- #
# The resolver seam
# --------------------------------------------------------------------------- #
def test_query_classifies_answers_and_failures():
    import dns.resolver
    rr = MagicMock()
    rr.to_text.return_value = WILD_IP
    with patch.object(dns.resolver, "resolve", return_value=[rr]):
        assert wc._query("a.example.test", "A") == ("ok", [WILD_IP])
    with patch.object(dns.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
        assert wc._query("a.example.test", "A") == ("nx", [])
    with patch.object(dns.resolver, "resolve", side_effect=dns.resolver.NoAnswer):
        assert wc._query("a.example.test", "A") == ("none", [])
    with patch.object(dns.resolver, "resolve",
                      side_effect=dns.resolver.LifetimeTimeout(timeout=1, errors=[])):
        assert wc._query("a.example.test", "A") == ("fail", [])


def test_query_skips_a_resolver_already_known_down():
    import dns.resolver
    from recon.main_recon_modules import domain_recon as dr
    with patch.object(dr.resolver_breaker, "is_open", return_value=True), \
         patch.object(dns.resolver, "resolve") as res:
        assert wc._query("a.example.test", "A") == ("fail", [])
    res.assert_not_called()


# --------------------------------------------------------------------------- #
# Names added after puredns: SAN feedback, tlsx, js_recon, uncover
# --------------------------------------------------------------------------- #
def _routable():
    """Step 5 (resolve-and-check) is pinned elsewhere; RFC 5737 fixture
    addresses are non-routable on purpose, so it is stubbed here."""
    from recon.helpers import target_helpers
    return patch.object(target_helpers, "_resolves_to_routable", return_value=True)


@pytest.mark.parametrize("source", ["certificate_san", "tlsx", "js_recon", "uncover"])
def test_late_names_go_through_the_same_check(source):
    from recon.helpers.target_helpers import merge_discovered_hostnames
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}},
                  records={"api.example.test": {"A": [REAL_IP]},
                           "cdn.example.test": {"A": [WILD_IP], "CNAME": ["cdn.example.net."]}})
    combined = {"dns": {"subdomains": {}}}
    with _routable(), patch.object(wc, "_query", dns):
        merge_discovered_hostnames(combined, ["api.example.test", "ghost.example.test",
                                              "cdn.example.test"],
                                   source=source, root_domain=ROOT, settings={})
    assert sorted(combined["dns"]["subdomains"]) == ["api.example.test", "cdn.example.test"]
    assert combined["wildcard_zones"] == {ROOT: {"is_wildcard": True, "ips": [WILD_IP]}}


def test_late_names_under_a_plain_zone_cost_one_query_and_no_lookups():
    from recon.helpers.target_helpers import merge_discovered_hostnames
    dns = FakeDNS()
    combined = {"dns": {"subdomains": {}}}
    with _routable(), patch.object(wc, "_query", dns):
        merge_discovered_hostnames(combined, ["api.example.test", "www.example.test"],
                                   source="tlsx", root_domain=ROOT, settings={})
    assert sorted(combined["dns"]["subdomains"]) == ["api.example.test", "www.example.test"]
    assert [c for c in dns.calls if not c[0].startswith("rdm-")] == []
    assert len(dns.calls) == 1


def _tlsx_run(combined, dns, settings=None):
    from recon.main_recon_modules import tls_scan
    line = {"host": "192.0.2.10", "ip": "192.0.2.10", "port": "443", "probe_status": True,
            "subject_cn": "api.example.test",
            "subject_an": ["api.example.test", "ghost.example.test", "*.example.test"],
            "fingerprint_hash": {"sha256": "a" * 64}, "not_after": "2099-01-01T00:00:00Z"}
    proc = MagicMock(returncode=0)
    proc.communicate.return_value = (json.dumps(line), "")
    with patch.object(tls_scan, "_build_tlsx_targets",
                      return_value=(["192.0.2.10:443"], {"192.0.2.10:443": "192.0.2.10"})), \
         patch("subprocess.Popen", return_value=proc), \
         patch.object(wc, "_query", dns):
        tls_scan.run_tlsx_enrichment(combined, settings or {})
    return combined["tlsx"]


def test_tlsx_sans_go_through_the_same_check_in_full_and_partial_runs():
    """run_tlsx_enrichment is the one call both paths make: the names the
    control drops leave discovered_hostnames (nothing to merge) and are listed
    for the writer, which links no Subdomain to them."""
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}}, records={"api.example.test": {"A": [REAL_IP]}})
    combined = {"domain": ROOT, "metadata": {},
                "port_scan": {"by_ip": {"192.0.2.10": {"ip": "192.0.2.10", "ports": [443]}},
                              "by_host": {}}}
    tlsx = _tlsx_run(combined, dns)
    assert tlsx["wildcard_dropped"] == ["ghost.example.test"]
    assert "ghost.example.test" not in tlsx["discovered_hostnames"]
    assert "api.example.test" in tlsx["discovered_hostnames"]
    assert combined["wildcard_zones"] == {ROOT: {"is_wildcard": True, "ips": [WILD_IP]}}


def test_tlsx_without_a_root_checks_nothing():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    combined = {"metadata": {},
                "port_scan": {"by_ip": {"192.0.2.10": {"ip": "192.0.2.10", "ports": [443]}},
                              "by_host": {}}}
    tlsx = _tlsx_run(combined, dns)
    assert tlsx["wildcard_dropped"] == [] and dns.calls == []


def test_uncover_drops_a_wildcard_name_from_its_payload_too():
    from recon.main_recon_modules.uncover_enrich import merge_uncover_into_pipeline
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}}, records={"api.example.test": {"A": [REAL_IP]}})
    combined = {"dns": {"subdomains": {}}, "metadata": {}}
    uncover = {"hosts": ["api.example.test", "ghost.example.test"], "ips": [], "ip_ports": {}, "urls": []}
    with _routable(), patch.object(wc, "_query", dns):
        merge_uncover_into_pipeline(combined, uncover, ROOT, settings={})
    assert uncover["hosts"] == ["api.example.test"]


# --------------------------------------------------------------------------- #
# Discovery wiring (full pipeline and partial recon share discover_subdomains)
# --------------------------------------------------------------------------- #
from recon.main_recon_modules import domain_recon as dr  # noqa: E402


def _discover(dns, *, resolve=True, puredns_status="filtered", settings=None, bruteforce=True):
    guessed = ["admin.example.test", "dev.example.test"]
    passive = {"real.example.test": {"crt.sh"}, ROOT: {"crt.sh"}}

    def resolver(domain, subs, **kw):
        out = {}
        for s in subs:
            status, ips = dns(s, "A")
            out[s] = _entry(ips[0] if ips else None)
        return {"domain": _entry(REAL_IP), "subdomains": out}

    with patch.object(dr, "query_crtsh", return_value=passive), \
         patch.object(dr, "query_hackertarget", return_value={}), \
         patch.object(dr, "run_subfinder", return_value=set()), \
         patch.object(dr, "run_amass", return_value=set()), \
         patch.object(dr, "run_knockpy", return_value=set(guessed)), \
         patch.object(dr, "run_puredns_resolve", side_effect=lambda s, d, st: (s, puredns_status)), \
         patch.object(dr, "resolve_all_dns", side_effect=resolver), \
         patch.object(wc, "_query", dns):
        return dr.discover_subdomains(ROOT, bruteforce=bruteforce, resolve=resolve,
                                      save_output=False, settings=settings or {})


def test_discovery_drops_wildcard_guesses_from_every_part_of_its_result():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}}, records={"real.example.test": {"A": [REAL_IP]}})
    result = _discover(dns, puredns_status="skipped:timeout")
    assert result["subdomains"] == [ROOT, "real.example.test"]
    assert result["subdomain_count"] == 2
    assert set(result["dns"]["subdomains"]) == {ROOT, "real.example.test"}
    assert set(result["subdomain_status_map"]) == {ROOT, "real.example.test"}
    assert result["wildcard_zones"] == {ROOT: {"is_wildcard": True, "ips": [WILD_IP]}}
    assert result["metadata"]["wildcard_dropped"] == 2


def test_discovery_with_puredns_filtered_still_runs_the_control():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}}, records={"real.example.test": {"A": [REAL_IP]}})
    result = _discover(dns, puredns_status="filtered")
    assert "admin.example.test" not in result["subdomains"]
    assert result["wildcard_zones"][ROOT]["is_wildcard"] is True


def test_discovery_without_bruteforce_counts_knockpy_as_a_passive_source():
    """knockpy --recon alone reads passive sources; only --bruteforce guesses."""
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP], "CNAME": ["edge.example.net."]}},
                  records={"admin.example.test": {"A": [WILD_IP], "CNAME": ["admin.example.net."]}})

    def resolver(domain, subs, **kw):
        return {"domain": {}, "subdomains": {
            s: _entry(*((WILD_IP, "admin.example.net.") if s == "admin.example.test" else (WILD_IP, None)))
            for s in subs}}

    with patch.object(dr, "query_crtsh", return_value={}), \
         patch.object(dr, "query_hackertarget", return_value={}), \
         patch.object(dr, "run_subfinder", return_value=set()), \
         patch.object(dr, "run_amass", return_value=set()), \
         patch.object(dr, "run_knockpy", return_value={"admin.example.test", "dev.example.test"}), \
         patch.object(dr, "run_puredns_resolve", side_effect=lambda s, d, st: (s, "filtered")), \
         patch.object(dr, "resolve_all_dns", side_effect=resolver), \
         patch.object(wc, "_query", dns):
        result = dr.discover_subdomains(ROOT, bruteforce=False, resolve=True,
                                        save_output=False, settings={})
    assert result["subdomains"] == ["admin.example.test"]


def test_amass_brute_is_a_guessing_source():
    assert dr._guessing_sources(False, {"AMASS_ENABLED": True, "AMASS_BRUTE": True}) == {"amass"}
    assert dr._guessing_sources(True, {"AMASS_ENABLED": True, "AMASS_BRUTE": False}) == {"knockpy"}
    assert dr._guessing_sources(False, {}) == set()


def test_discovery_with_dns_off_and_puredns_skipped_records_the_note():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    result = _discover(dns, resolve=False, puredns_status="skipped:disabled")
    assert dns.calls == []
    assert "wildcard_zones" not in result or result["wildcard_zones"] == {}
    gaps = _gaps()
    assert len(gaps) == 1 and "DNS resolution off" in gaps[0]["reason"]
    assert gaps[0]["skipped"] == len(result["subdomains"])


def test_discovery_with_dns_off_after_puredns_filtered_records_nothing():
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}})
    _discover(dns, resolve=False, puredns_status="filtered")
    assert _gaps() == []


def test_the_pipeline_merge_carries_the_zones_to_the_domain_writer():
    from recon.main import merge_group_hosts
    zones = {ROOT: {"is_wildcard": True, "ips": [WILD_IP]}}
    merged = merge_group_hosts({"subdomains": ["real.example.test"], "dns": {},
                                "subdomain_status_map": {}, "wildcard_zones": zones},
                               {"include_root_domain": False, "full_subdomains": []}, ROOT, {}, False)
    assert merged["wildcard_zones"] == zones
    assert merge_group_hosts(None, {"include_root_domain": False, "full_subdomains": []},
                             ROOT, {}, False)["wildcard_zones"] == {}


def test_the_end_of_a_group_stamps_every_zone_the_run_checked():
    from recon import main as recon_main
    with patch.object(recon_main, "_graph_update_bg") as bg:
        recon_main._stamp_wildcard_zones({"wildcard_zones": {ROOT: {"is_wildcard": False, "ips": []}}})
        recon_main._stamp_wildcard_zones({"wildcard_zones": {}})
        recon_main._stamp_wildcard_zones({})
    assert bg.call_count == 1
    assert bg.call_args.args[0] == "update_graph_wildcard_zones"


# --------------------------------------------------------------------------- #
# Partial subdomain discovery: same control, typed names never checked
# --------------------------------------------------------------------------- #
@pytest.fixture
def graph(monkeypatch):
    from recon.partial_recon_modules import helpers
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_partial_discovery.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    return client


def test_partial_discovery_runs_the_control_and_never_checks_typed_names(graph):
    from recon.partial_recon_modules import subdomain_discovery
    dns = FakeDNS(wildcards={ROOT: {"A": [WILD_IP]}}, records={"real.example.test": {"A": [REAL_IP]}})

    def resolver(domain, subs, **kw):
        return {"domain": {}, "subdomains": {
            s: _entry((dns(s, "A")[1] or [None])[0]) for s in subs}}

    cfg = {"_settings": {}, "domains": [ROOT], "domain": ROOT, "batch_mode": False,
           "domain_groups": [{"rootDomain": ROOT, "prefixes": ["*"], "batch": False}],
           "user_inputs": ["typed.example.test"]}
    with patch.object(dr, "query_crtsh", return_value={"real.example.test": {"crt.sh"}}), \
         patch.object(dr, "query_hackertarget", return_value={}), \
         patch.object(dr, "run_subfinder", return_value=set()), \
         patch.object(dr, "run_amass", return_value=set()), \
         patch.object(dr, "run_knockpy", return_value={"admin.example.test"}), \
         patch.object(dr, "run_puredns_resolve", side_effect=lambda s, d, st: (s, "skipped:timeout")), \
         patch.object(dr, "resolve_all_dns", side_effect=resolver), \
         patch.object(wc, "_query", dns):
        subdomain_discovery.run_subdomain_discovery(cfg)
    written = graph.update_graph_from_partial_discovery.call_args.kwargs["recon_data"]
    assert "admin.example.test" not in written["subdomains"]
    assert {"real.example.test", "typed.example.test"} <= set(written["subdomains"])
    assert written["wildcard_zones"] == {ROOT: {"is_wildcard": True, "ips": [WILD_IP]}}
