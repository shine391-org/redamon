"""recon/helpers/cve_helpers.py: a CVE is linked to a technology only when it is about that product.

The httpx label "HTTP/3" (a protocol) was parsed as the product "http" at
version 3. "http" has no CPE mapping, so NVD was asked keywordSearch="http 3"
and the first 20 of its thousands of answers were linked to the HTTP/3 node: 1998-2001
CVEs in InterScan VirusWall 3.6, WinVNC 3.3.3, Tivoli 3.7.1... (CVSS 10 on the
Blast Radius). Two independent guards are covered here: httpx labels are read
in their own "Name:version" format, and a keyword hit is kept only when NVD's
configuration of the CVE names the product at the version. The cases they must
NOT drop come from a live audit of real detector strings: a vendor's own product
line, a version NVD spells longer, nmap's descriptor words, and a CVE NVD never
analysed whose text names the product at the version.

The configurations below are the real ones of those CVEs, trimmed.
`requests.get` is patched; nothing reaches NVD.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers import cve_helpers
from recon.helpers.cve_helpers import lookup_cves_nvd, parse_httpx_technology, run_cve_lookup


def _cve(cve_id, *matches, text=None):
    """An NVD 2.0 record whose configuration holds the given cpeMatch entries."""
    record = {
        "id": cve_id,
        "descriptions": [{"lang": "en",
                          "value": text or f"{cve_id} via a long HTTP GET request"}],
        "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 10.0}, "baseSeverity": "HIGH"}]},
    }
    if matches:
        record["configurations"] = [{"nodes": [{"operator": "OR", "negate": False,
                                                "cpeMatch": list(matches)}]}]
    return {"cve": record}


def _match(criteria, vulnerable=True, **bounds):
    return {"vulnerable": vulnerable, "criteria": criteria, **bounds}


def _scored(cve_id, score, metric="cvssMetricV31"):
    """An NVD 2.0 record with one CVSS metric and no configuration."""
    return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": cve_id}],
                    "metrics": {metric: [{"cvssData": {"baseScore": score,
                                                       "baseSeverity": "CRITICAL"}}]}}}


def _nvd_answer(*vulns, total=None):
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.headers = {}
    resp.json.return_value = {"vulnerabilities": list(vulns),
                              "totalResults": len(vulns) if total is None else total}
    resp.text = ""
    return resp


def _params(get):
    return [c.kwargs["params"] for c in get.call_args_list]


# Three of the 20 CVEs NVD returns for keywordSearch="http 3".
VIRUSWALL = _cve("CVE-2001-0133", _match(
    "cpe:2.3:a:trend_micro:interscan_viruswall:*:*:*:*:*:*:*:*", versionEndIncluding="3.6"))
WINVNC = _cve("CVE-2001-0168", _match("cpe:2.3:a:att:winvnc:*:*:*:*:*:*:*:*"))
IBM_HTTP_SERVER = _cve("CVE-2001-0122", _match(
    "cpe:2.3:a:ibm:http_server:1.3.12.2:*:*:*:*:*:*:*"))


@pytest.fixture
def nvd():
    cb.reset_registry()
    with mock.patch.object(cve_helpers.requests, "get") as get, \
            mock.patch.object(cve_helpers.time, "sleep"):
        yield get
    cb.reset_registry()


# --------------------------------------------------------------------------- #
# Guard 1: an httpx label carries a version only after a colon
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("label, parsed", [
    ("HTTP/3", ("http/3", None)),
    ("HTTP/2", ("http/2", None)),
    ("Microsoft 365", ("microsoft 365", None)),
    ("Nginx:1.19.0", ("nginx", "1.19.0")),
    ("PHP:8.1.2-1ubuntu2.14", ("php", "8.1.2")),
    ("Apache HTTP Server:2.4.49", ("apache http server", "2.4.49")),
    ("jQuery", ("jquery", None)),
])
def test_an_httpx_label_keeps_a_slash_or_a_number_in_its_name(label, parsed):
    assert parse_httpx_technology(label) == parsed


def test_protocol_labels_from_httpx_are_never_looked_up_and_server_headers_still_are(nvd):
    recon = {"http_probe": {"by_url": {"https://www.example.test": {
        "technologies": ["Cloudflare", "Cloudflare Bot Management", "HSTS", "HTTP/3",
                         "HTTP/2", "Microsoft 365", "Nginx:1.19.0"],
        "server": "Apache/2.4.49 (Unix)",
    }}}}
    queried = []

    def fake_nvd(name, version, max_results, keys, admitted=False, cpe_hint=None):
        queried.append((name, version))
        return SimpleNamespace(data=[], answered=True, outcome=None, detail="")

    with mock.patch.object(cve_helpers, "_nvd_query", side_effect=fake_nvd):
        out = run_cve_lookup(recon, source="nvd", nvd_api_key="")

    assert sorted(queried) == [("apache", "2.4.49"), ("nginx", "1.19.0")]
    assert out["technology_cves"]["technologies_checked"] == 2


# --------------------------------------------------------------------------- #
# Guard 2: a keyword hit must name the product in its NVD configuration
# --------------------------------------------------------------------------- #
def test_keyword_hits_about_other_products_are_dropped(nvd):
    nvd.return_value = _nvd_answer(VIRUSWALL, WINVNC, IBM_HTTP_SERVER)
    assert lookup_cves_nvd("http", "3") == []
    assert nvd.call_args.kwargs["params"]["keywordSearch"] == "http"


@pytest.mark.parametrize("product, version, match, kept", [
    # The product must be the whole CPE product, alone or after its vendor.
    ("http", "1.3.12.2", _match("cpe:2.3:a:ibm:http_server:1.3.12.2:*:*:*:*:*:*:*"), False),
    ("ibm http server", "1.3.12.2",
     _match("cpe:2.3:a:ibm:http_server:1.3.12.2:*:*:*:*:*:*:*"), True),
    ("jquery ui", "1.12.1", _match("cpe:2.3:a:jqueryui:jquery_ui:*:*:*:*:*:*:*:*",
                                   versionEndExcluding="1.13.0"), True),
    # The version must fall inside the bounds, or equal a pinned version.
    ("jquery ui", "1.13.2", _match("cpe:2.3:a:jqueryui:jquery_ui:*:*:*:*:*:*:*:*",
                                   versionEndExcluding="1.13.0"), False),
    ("jquery ui", "1.8", _match("cpe:2.3:a:jqueryui:jquery_ui:*:*:*:*:*:*:*:*",
                                versionStartIncluding="1.10.0", versionEndExcluding="1.13.0"),
     False),
    ("phorum", "3.0.7", _match("cpe:2.3:a:phorum:phorum:3.0.7:*:*:*:*:*:*:*"), True),
    ("phorum", "5.2.1", _match("cpe:2.3:a:phorum:phorum:3.0.7:*:*:*:*:*:*:*"), False),
    ("winvnc", "3.3.3", _match("cpe:2.3:a:att:winvnc:*:*:*:*:*:*:*:*"), True),
    # A version one side states further: Boa/0.94.14rc21 is NVD's 0.94.14.21,
    # Wappalyzer's "5.2" may be 5.2.3.
    ("boa", "0.94.14", _match("cpe:2.3:a:boa:boa:0.94.14.21:*:*:*:*:*:*:*"), True),
    ("plone", "5.2", _match("cpe:2.3:a:plone:plone:5.2.3:*:*:*:*:*:*:*"), True),
    ("plone", "5.2.1", _match("cpe:2.3:a:plone:plone:5.2.3:*:*:*:*:*:*:*"), False),
    # A name that is the vendor reaches its own product line, not another one.
    ("liferay", "7.0", _match("cpe:2.3:a:liferay:liferay_portal:*:*:*:*:*:*:*:*",
                              versionEndIncluding="7.0"), True),
    ("liferay", "7.0",
     _match("cpe:2.3:a:liferay:digital_experience_platform:7.0:*:*:*:*:*:*:*"), False),
    ("dropbear", "2019.78", _match(
        "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*",
        versionEndExcluding="2020.79"), True),
    ("datatables", "1.10.21", _match("cpe:2.3:a:datatables:datatables.net:*:*:*:*:*:*:*:*",
                                     versionEndExcluding="1.10.22"), True),
    ("elementor", "3.0.0", _match("cpe:2.3:a:elementor:hello_elementor:*:*:*:*:*:*:*:*",
                                  versionEndIncluding="3.0.0"), False),
    # An edition is the product; a companion product of the vendor is not.
    ("elementor", "3.0.0", _match(
        "cpe:2.3:a:elementor:elementor_website_builder:*:*:*:*:*:*:*:*",
        versionEndExcluding="3.1.0"), True),
    ("elementor", "3.0.0", _match("cpe:2.3:a:elementor:elementor_pro:*:*:*:*:*:*:*:*",
                                  versionEndIncluding="3.0.5"), False),
    ("zabbix", "5.0", _match("cpe:2.3:a:zabbix:zabbix-agent2:*:*:*:*:*:*:*:*",
                             versionEndExcluding="5.0.46"), False),
    ("nextcloud", "20.0.0", _match("cpe:2.3:a:nextcloud:nextcloud_desktop:*:*:*:*:*:*:*:*",
                                   versionEndExcluding="20.0.1"), False),
    # The same project spelled with or without ".js", when its vendor is too.
    ("angularjs", "1.5.8", _match("cpe:2.3:a:angularjs:angular.js:*:*:*:*:*:*:*:*",
                                  versionEndExcluding="1.6.0"), True),
    ("underscore.js", "1.8.3", _match("cpe:2.3:a:underscorejs:underscore:*:*:*:*:*:*:*:*",
                                      versionEndExcluding="1.12.1"), True),
    ("chart.js", "2.9.3", _match("cpe:2.3:a:otherco:chart:*:*:*:*:*:*:*:*"), False),
    ("font awesome", "4.7.0", _match("cpe:2.3:a:newnine:font_awesome_4_menus:*:*:*:*:*:*:*:*",
                                     versionEndIncluding="4.7.0"), False),
    # nmap's descriptor words are not part of the product.
    ("samba smbd", "3.0.20", _match("cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*",
                                    versionStartIncluding="3.0.0",
                                    versionEndIncluding="3.0.25"), True),
    # A platform the vulnerable app runs on is not itself affected.
    ("linux kernel", "5.10",
     _match("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", vulnerable=False), False),
])
def test_a_keyword_hit_is_kept_only_for_its_own_product_and_version(
        nvd, product, version, match, kept):
    nvd.return_value = _nvd_answer(_cve("CVE-2099-0001", match))
    found = [c["id"] for c in lookup_cves_nvd(product, version)]
    assert found == (["CVE-2099-0001"] if kept else [])


@pytest.mark.parametrize("product, version, text, kept", [
    ("mini_httpd", "1.30", "An issue in ACME mini_httpd 1.30 and prior allows a remote "
                           "attacker to cause a denial of service", True),
    ("zabbix", "5.0", "Zabbix Agent 2 smartctl plugin does not properly sanitize "
                      "parameters. In Zabbix 5.0 this allows for remote code execution.", True),
    ("mini_httpd", "1.3", "An issue in ACME mini_httpd 1.30 and prior", False),
    ("jquery migrate", "1.4.1", "The Enable jQuery Migrate Helper plugin for WordPress is "
                                "vulnerable in all versions up to, and including, 1.4.1.", False),
    ("elementor", "3.0.0", "Missing Authorization vulnerability in Rashid Slider Path for "
                           "Elementor. This issue affects Slider Path for Elementor: from n/a "
                           "through <= 3.0.0.", False),
    ("http", "3", "The web administration interface for Interscan VirusWall 3.6.x does not "
                  "use encryption, via the setpasswd.cgi program or other HTTP GET requests.",
     False),
])
def test_a_keyword_hit_nvd_never_analysed_needs_its_text_to_name_the_version(
        nvd, product, version, text, kept):
    nvd.return_value = _nvd_answer(_cve("CVE-2099-0002", text=text))
    found = [c["id"] for c in lookup_cves_nvd(product, version)]
    assert found == (["CVE-2099-0002"] if kept else [])


def test_a_cpe_name_lookup_is_trusted_as_nvd_matched_it(nvd):
    nvd.return_value = _nvd_answer(_cve("CVE-2021-23017"))
    found = [c["id"] for c in lookup_cves_nvd("nginx", "1.19.0")]
    assert found == ["CVE-2021-23017"]
    assert nvd.call_args.kwargs["params"]["cpeName"] == \
        "cpe:2.3:a:f5:nginx:1.19.0:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------- #
# nmap names reach the exact CPE query instead of the keyword search
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name, normalized", [
    ("Exim smtpd", "exim"),
    ("PostgreSQL DB", "postgresql"),
    ("Squid http proxy", "squid"),
    ("Elasticsearch REST API", "elasticsearch"),
    ("Redis key-value store", "redis"),
    ("Microsoft IIS httpd", "iis"),
    ("ISC BIND", "bind"),
    ("Node.js Express framework", "express"),
    ("TYPO3 CMS", "typo3"),
    ("OpenResty web app server", "openresty"),
    # not a known product once shortened, or another product: unchanged
    ("Django REST framework", "django rest framework"),
    ("IBM HTTP Server", "ibm http server"),
    ("Mongo Express", "mongo express"),
    ("Samba smbd", "samba smbd"),
    ("jQuery UI", "jquery ui"),
    ("HTTP/3", "http/3"),
])
def test_a_product_name_loses_only_words_that_make_it_a_known_product(name, normalized):
    assert cve_helpers.normalize_product_name(name) == normalized


def test_nmap_services_are_queried_by_their_exact_cpe(nvd):
    nvd.return_value = _nvd_answer()
    recon = {"nmap_scan": {"services_detected": [
        {"product": "Exim smtpd", "version": "4.92"},
        {"product": "ISC BIND", "version": "9.4.2"},
        {"product": "PostgreSQL DB", "version": "9.6.0"},
    ]}}
    run_cve_lookup(recon, source="nvd", nvd_api_key="")
    assert sorted(c.kwargs["params"].get("cpeName") for c in nvd.call_args_list) == [
        "cpe:2.3:a:exim:exim:4.92:*:*:*:*:*:*:*",
        "cpe:2.3:a:isc:bind:9.4.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:postgresql:postgresql:9.6.0:*:*:*:*:*:*:*",
    ]


# --------------------------------------------------------------------------- #
# Every answer is read; the most severe CVEs are kept, not the oldest
# --------------------------------------------------------------------------- #
def test_the_kept_cves_are_the_most_severe_of_the_whole_answer(nvd):
    # NVD lists the oldest first; here the two newest are the most severe.
    oldest = [_scored(f"CVE-2010-{i:04d}", 5.0) for i in range(46)]
    nvd.return_value = _nvd_answer(*oldest, _scored("CVE-2020-28024", 9.8),
                                   _scored("CVE-2020-28026", 9.8))
    ids = [c["id"] for c in lookup_cves_nvd("exim", "4.92", max_results=20)]
    assert len(ids) == 20
    assert ids[:2] == ["CVE-2020-28024", "CVE-2020-28026"]
    assert nvd.call_args.kwargs["params"]["resultsPerPage"] == cve_helpers.NVD_PAGE_SIZE


def test_a_cve_scored_only_in_cvss_3_0_keeps_its_score(nvd):
    nvd.return_value = _nvd_answer(_scored("CVE-2018-0001", 9.8, "cvssMetricV30"),
                                   _scored("CVE-2018-0002", 5.0))
    found = lookup_cves_nvd("exim", "4.92", max_results=1)
    assert [(c["id"], c["cvss"]) for c in found] == [("CVE-2018-0001", 9.8)]


def test_every_page_is_read_up_to_the_cap_with_pacing_between(nvd, monkeypatch):
    monkeypatch.setattr(cve_helpers, "NVD_PAGE_SIZE", 2)
    monkeypatch.setattr(cve_helpers, "NVD_MAX_PAGES", 2)
    nvd.side_effect = [
        _nvd_answer(_scored("CVE-2001-0001", 1.0), _scored("CVE-2001-0002", 2.0), total=5),
        _nvd_answer(_scored("CVE-2001-0003", 3.0), _scored("CVE-2001-0004", 4.0), total=5),
    ]
    with mock.patch.object(cve_helpers.time, "sleep") as sleep:
        found = lookup_cves_nvd("exim", "4.92")
    assert [p["startIndex"] for p in _params(nvd)] == [0, 2]
    assert {c["id"] for c in found} == {"CVE-2001-0001", "CVE-2001-0002",
                                        "CVE-2001-0003", "CVE-2001-0004"}
    sleep.assert_called_once_with(6.0)


def test_a_failed_later_page_keeps_the_pages_already_read(nvd, monkeypatch):
    monkeypatch.setattr(cve_helpers, "NVD_PAGE_SIZE", 1)
    nvd.side_effect = [_nvd_answer(_scored("CVE-2001-0001", 1.0), total=3),
                       requests.exceptions.ReadTimeout("read timeout=60")]
    assert [c["id"] for c in lookup_cves_nvd("exim", "4.92")] == ["CVE-2001-0001"]


# --------------------------------------------------------------------------- #
# A product without a CPE is searched by name; the filter places the version
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("product, keyword", [
    ("jquery ui", "jquery ui"),
    ("dropbear sshd", "dropbear"),
    ("samba smbd", "samba"),
    # "http server" is part of the name a CVE's text uses
    ("ibm http server", "ibm http server"),
])
def test_a_product_without_a_cpe_is_searched_by_name_alone(nvd, product, keyword):
    nvd.return_value = _nvd_answer()
    lookup_cves_nvd(product, "1.0")
    assert _params(nvd)[0]["keywordSearch"] == keyword


def test_the_name_search_keeps_only_the_cves_at_the_version_found(nvd):
    nvd.return_value = _nvd_answer(
        _cve("CVE-2021-41182", _match("cpe:2.3:a:jqueryui:jquery_ui:*:*:*:*:*:*:*:*",
                                      versionEndExcluding="1.13.0")),
        _cve("CVE-2010-5312", _match("cpe:2.3:a:jqueryui:jquery_ui:*:*:*:*:*:*:*:*",
                                     versionEndExcluding="1.10.0")),
        _cve("CVE-2017-15719", _match(
            "cpe:2.3:a:wicket-jquery-ui_project:wicket-jquery-ui:*:*:*:*:*:*:*:*")),
    )
    assert [c["id"] for c in lookup_cves_nvd("jquery ui", "1.12.1")] == ["CVE-2021-41182"]


# --------------------------------------------------------------------------- #
# nmap's CPE: matched by NVD under any vendor, besides the name search
# --------------------------------------------------------------------------- #
WEBMIN_BACKDOOR = _cve("CVE-2019-15107", _match("cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
                                                versionEndIncluding="1.920"))


@pytest.mark.parametrize("cpe, product", [
    ("cpe:/a:webmin:webmin:1.890", "webmin"),
    ("cpe:/a:samba:samba", "samba"),
    ("cpe:2.3:a:samba:samba:3.0.20:*:*:*:*:*:*:*", "samba"),
    ("cpe:/o:linux:linux_kernel", None),
    ("", None),
    (None, None),
])
def test_the_cpe_product_is_read_from_nmap_application_cpes_only(cpe, product):
    assert cve_helpers._nmap_cpe_product(cpe) == product


def test_an_nmap_service_is_matched_by_its_cpe_and_its_name_and_both_are_kept(nvd):
    nvd.side_effect = [_nvd_answer(WEBMIN_BACKDOOR),
                       _nvd_answer(VIRUSWALL, _cve("CVE-2099-0003", text="MiniServ 1.890 crashes"))]
    recon = {
        "http_probe": {"by_url": {"https://h.example.test:10000": {"server": "MiniServ/1.890"}}},
        "nmap_scan": {"services_detected": [
            {"product": "MiniServ", "version": "1.890", "cpe": "cpe:/a:webmin:webmin:1.890"}]},
    }
    with mock.patch.object(cve_helpers.time, "sleep") as sleep:
        out = run_cve_lookup(recon, source="nvd", nvd_api_key="")

    # The Server header and nmap name one service: one lookup, with nmap's CPE.
    assert [(p.get("virtualMatchString"), p.get("keywordSearch")) for p in _params(nvd)] == [
        ("cpe:2.3:a:*:webmin:1.890", None), (None, "miniserv")]
    assert sleep.call_args_list[0].args == (6.0,)
    by_tech = out["technology_cves"]["by_technology"]
    assert list(by_tech) == ["MiniServ/1.890"]
    assert sorted(c["id"] for c in by_tech["MiniServ/1.890"]["cves"]) == [
        "CVE-2019-15107", "CVE-2099-0003"]


# --------------------------------------------------------------------------- #
# A CPE match must name the product as the vulnerable one, not its platform
# --------------------------------------------------------------------------- #
def test_a_plugin_cve_is_not_attached_to_the_platform_it_runs_on(nvd):
    plugin = _cve("CVE-2009-2396",
                  _match("cpe:2.3:a:dutchmonkey:dm_album:1.9.2:*:*:*:*:*:*:*"),
                  _match("cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", vulnerable=False))
    core = _cve("CVE-2022-21661", _match("cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
                                         versionEndExcluding="5.8.3"))
    nvd.return_value = _nvd_answer(plugin, core)
    assert [c["id"] for c in lookup_cves_nvd("wordpress", "5.8.1")] == ["CVE-2022-21661"]
    assert "cpeName" in _params(nvd)[0]


def test_nvd_places_the_version_of_a_cpe_match_itself(nvd):
    # NVD returned it for nginx 1.19.0; its own version logic is not second-guessed.
    nvd.return_value = _nvd_answer(_cve("CVE-2021-23017", _match(
        "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionStartIncluding="0.6.18",
        versionEndExcluding="1.21.0")), _cve("CVE-2099-0004", _match(
            "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", versionEndExcluding="1.2.0")))
    assert sorted(c["id"] for c in lookup_cves_nvd("nginx", "1.19.0")) == [
        "CVE-2021-23017", "CVE-2099-0004"]


def test_a_known_product_ignores_nmap_cpe_and_asks_its_exact_cpe(nvd):
    nvd.return_value = _nvd_answer()
    recon = {"nmap_scan": {"services_detected": [
        {"product": "OpenSSH", "version": "8.9p1 Ubuntu 3", "cpe": "cpe:/a:openbsd:openssh:8.9p1"}]}}
    run_cve_lookup(recon, source="nvd", nvd_api_key="")
    assert [p.get("cpeName") for p in _params(nvd)] == ["cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*"]


def test_one_failed_search_of_two_keeps_the_other(nvd):
    nvd.side_effect = [requests.exceptions.ReadTimeout("read timeout=60"),
                       _nvd_answer(WEBMIN_BACKDOOR)]
    res = cve_helpers._nvd_query("miniserv", "1.890", 20, cb.KeyPool(None, "", label="t"),
                                 cpe_hint="webmin")
    # nmap's CPE product also counts for the name search's filter.
    assert res.answered and [c["id"] for c in res.data] == ["CVE-2019-15107"]
    nvd.side_effect = [requests.exceptions.ReadTimeout("read timeout=60")] * 2
    cb.reset_registry()
    res = cve_helpers._nvd_query("miniserv", "1.890", 20, cb.KeyPool(None, "", label="t"),
                                 cpe_hint="webmin")
    assert not res.answered


def test_an_unscored_cve_does_not_crash_the_severity_summary(nvd):
    # A CVE NVD has not scored has no metric, so its severity is None.
    nvd.return_value = _nvd_answer({"cve": {"id": "CVE-2099-0005", "metrics": {},
                                            "descriptions": [{"lang": "en", "value": "x"}]}},
                                   _scored("CVE-2021-23017", 7.7))
    recon = {"http_probe": {"by_url": {"https://www.example.test": {
        "technologies": ["Nginx:1.19.0"]}}}}
    out = run_cve_lookup(recon, source="nvd", nvd_api_key="")["technology_cves"]
    assert [c["id"] for c in out["by_technology"]["Nginx:1.19.0"]["cves"]] == [
        "CVE-2021-23017", "CVE-2099-0005"]
    assert out["summary"]["total_unique_cves"] == 2 and out["summary"]["high"] == 0
