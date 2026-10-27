"""httpx follows redirects (-fr): an in-scope host that redirects off-scope.

httpx's `url` is the URL it was asked for and `final_url` the last hop, while
the title, technologies, server, favicon and body hash describe the LAST page.
The scope check used to test `url` only, so it always passed for in-scope
inputs: a third-party login page's title and technologies were stored on the
target's own Endpoint and credited to the target. The entry is kept (the host
is live and redirects away), its foreign fingerprint is dropped, and the
foreign host is recorded as an external domain.
"""
from __future__ import annotations

import json
from unittest import mock

from recon.main_recon_modules import http_probe as hp

IN_SCOPE = "http://old.example.com"
FOREIGN = "https://idp.example.net/saml/login"


def _line(url, final_url=None, chain=None, **extra):
    entry = {
        "url": url, "input": url, "host": "192.0.2.10", "port": "80", "scheme": "http",
        "status_code": 200, "title": "SAML Login", "webserver": "SAP NetWeaver Application Server",
        "tech": ["SAP NetWeaver"], "favicon": "-1170867023", "content_type": "text/html",
        "content_length": 5120, "words": 312, "lines": 40,
        "hash": {"body_sha256": "a" * 64, "header_sha256": "b" * 64},
        "header": {"server": "SAP NetWeaver Application Server", "set_cookie": "SAPSSO=1"},
        "body": "<html><title>SAML Login</title></html>",
        "tls": {"subject_cn": "idp.example.net", "issuer_cn": "Example CA", "tls_version": "tls13"},
        "jarm": "29d29d00029d29d00042d42d000000",
        "a": ["192.0.2.10"], "cdn_name": None,
    }
    if final_url:
        entry["final_url"] = final_url
    if chain is not None:
        entry["chain_status_codes"] = chain
    entry.update(extra)
    return entry


def _parse(tmp_path, *entries, **kw):
    out = tmp_path / "httpx.jsonl"
    out.write_text("".join(json.dumps(e) + "\n" for e in entries))
    return hp.parse_httpx_output(str(out), root_domain=kw.pop("root", "example.com"), **kw)


class TestAnInScopeHostRedirectingAway:
    def test_the_entry_is_kept_without_the_foreign_fingerprint(self, tmp_path):
        res = _parse(tmp_path, _line(IN_SCOPE, FOREIGN, [302, 200]))
        entry = res["by_url"][IN_SCOPE]
        assert entry["host"] == "old.example.com"
        for field in ("title", "server", "content_type", "word_count", "line_count", "content_length"):
            assert entry.get(field) is None, field
        assert entry["technologies"] == []
        for field in ("favicon_hash", "body_hash", "headers", "body", "tls"):
            assert field not in entry, field

    def test_the_target_host_keeps_what_was_measured_on_it(self, tmp_path):
        """The JARM, IP and CDN data come from the requested host, not the last hop."""
        entry = _parse(tmp_path, _line(IN_SCOPE, FOREIGN, [302, 200]))["by_url"][IN_SCOPE]
        assert entry["jarm"] == "29d29d00029d29d00042d42d000000"
        assert entry["ip"] == "192.0.2.10"
        assert entry["status_code"] == 200

    def test_nothing_foreign_is_credited_to_the_target(self, tmp_path):
        res = _parse(tmp_path, _line(IN_SCOPE, FOREIGN, [302, 200]))
        assert "SAP NetWeaver" not in res["technologies_found"]
        assert res["servers_found"] == {}
        host = res["by_host"]["old.example.com"]
        assert host["technologies"] == [] and host["servers"] == []
        assert res["summary"]["unique_technologies"] == []

    def test_the_foreign_host_is_an_external_domain(self, tmp_path):
        res = _parse(tmp_path, _line(IN_SCOPE, FOREIGN, [302, 200]))
        ext = res["external_domains"]
        assert len(ext) == 1
        assert ext[0]["domain"] == "idp.example.net"
        assert ext[0]["source"] == "http_probe_redirect"
        assert ext[0]["url"] == FOREIGN
        assert ext[0]["redirect_from_url"] == IN_SCOPE
        assert ext[0]["title"] == "SAML Login"
        assert ext[0]["status_code"] == 200

    def test_a_foreign_title_never_reaches_the_ai_annotation(self, tmp_path):
        settings = {"HTTP_PROBE_AI_HEADER_SCAN_ENABLED": True, "HTTP_PROBE_AI_TITLE_DETECTION_ENABLED": True,
                    "HTTP_PROBE_AI_FAVICON_HASH_ENABLED": True, "HTTP_PROBE_AI_WAPPALYZER_ENABLED": True}
        line = _line(IN_SCOPE, FOREIGN, [302, 200], title="Open WebUI",
                     header={"x-vllm-cache-hit": "1"}, body="<gradio-app></gradio-app>")
        entry = _parse(tmp_path, line, settings=settings)["by_url"][IN_SCOPE]
        assert not entry.get("is_ai_framework_detected")
        assert "ai_framework_name" not in entry and "ai_frontend_product_guess" not in entry

    def test_in_filtered_mode_the_allowed_list_decides(self, tmp_path):
        """IP mode: the target list is the scope, so another IP is foreign."""
        line = _line("http://192.0.2.23", "http://198.51.100.21/saml/login", [302, 200])
        res = _parse(tmp_path, line, root="ip-targets.abc123", allowed_hosts=["192.0.2.23"])
        entry = res["by_url"]["http://192.0.2.23"]
        assert entry.get("title") is None and entry["technologies"] == []
        assert [e["domain"] for e in res["external_domains"]] == ["198.51.100.21"]


class TestRedirectsThatStayInScope:
    def test_an_in_scope_to_in_scope_redirect_keeps_everything(self, tmp_path):
        url = "http://www.example.com"
        res = _parse(tmp_path, _line(url, "https://www.example.com/home", [301, 200]))
        entry = res["by_url"][url]
        assert entry["title"] == "SAML Login"
        assert entry["technologies"] == ["SAP NetWeaver"]
        assert entry["favicon_hash"] == "-1170867023"
        assert entry["body_hash"]["body_sha256"] == "a" * 64
        assert entry["tls"]["certificate"]["subject_cn"] == "idp.example.net"
        assert res["external_domains"] == []

    def test_no_redirect_keeps_everything(self, tmp_path):
        url = "http://www.example.com"
        entry = _parse(tmp_path, _line(url))["by_url"][url]
        assert entry["title"] == "SAML Login" and entry["technologies"] == ["SAP NetWeaver"]


class TestNeitherHostInScope:
    def test_the_entry_is_dropped_and_recorded(self, tmp_path):
        line = _line("http://cdn.example.org", "https://idp.example.net/", [302, 200])
        res = _parse(tmp_path, line)
        assert res["by_url"] == {}
        assert res["summary"]["filtered_out_of_scope"] == 1
        assert [e["domain"] for e in res["external_domains"]] == ["cdn.example.org"]


class TestTheRedirectChain:
    """The pre-redirect answer is kept: a host that answers 302 is not a 200 page."""

    def test_an_off_host_redirect_records_its_chain(self, tmp_path):
        entry = _parse(tmp_path, _line(IN_SCOPE, FOREIGN, [302, 200]))["by_url"][IN_SCOPE]
        assert entry["final_url"] == FOREIGN
        assert entry["first_status_code"] == 302
        assert entry["redirect_chain_codes"] == [302, 200]
        assert entry["redirected_off_host"] is True

    def test_a_same_host_redirect_is_not_off_host(self, tmp_path):
        url = "http://www.example.com"
        entry = _parse(tmp_path, _line(url, "https://www.example.com/home", [301, 302, 200]))["by_url"][url]
        assert entry["first_status_code"] == 301
        assert entry["redirect_chain_codes"] == [301, 302, 200]
        assert entry["redirected_off_host"] is False

    def test_an_in_scope_host_change_is_off_host(self, tmp_path):
        url = "http://example.com"
        entry = _parse(tmp_path, _line(url, "https://www.example.com/", [301, 200]))["by_url"][url]
        assert entry["redirected_off_host"] is True
        assert entry["title"] == "SAML Login"

    def test_no_redirect_is_a_one_hop_chain(self, tmp_path):
        url = "http://www.example.com"
        entry = _parse(tmp_path, _line(url, status_code=404))["by_url"][url]
        assert entry["final_url"] == url
        assert entry["first_status_code"] == 404
        assert entry["redirect_chain_codes"] == [404]
        assert entry["redirected_off_host"] is False

    def test_chain_codes_are_ints(self, tmp_path):
        url = "http://www.example.com"
        line = _line(url, "http://www.example.com/a", ["302", 200, "junk"])
        entry = _parse(tmp_path, line)["by_url"][url]
        assert entry["redirect_chain_codes"] == [302, 200]
        assert entry["first_status_code"] == 302

    def test_no_status_at_all_writes_no_chain(self, tmp_path):
        url = "http://www.example.com"
        line = _line(url)
        del line["status_code"]
        entry = _parse(tmp_path, line)["by_url"][url]
        assert entry["first_status_code"] is None
        assert entry["redirect_chain_codes"] is None


class _Proc:
    returncode = 0

    def communicate(self, timeout=None):
        return "", ""


def _run_with_httpx_lines(lines):
    """run_http_probe end to end, with httpx replaced by a fake that writes `lines`."""
    def fake_popen(cmd, **_kw):
        mounts = {}
        for i, tok in enumerate(cmd):
            if tok == "-v":
                host, container = cmd[i + 1].split(":")[:2]
                mounts[container] = host
        out = cmd[cmd.index("-o") + 1].replace("/output", mounts["/output"], 1)
        with open(out, "w") as f:
            f.writelines(json.dumps(e) + "\n" for e in lines)
        return _Proc()

    recon = {"domain": "example.com",
             "dns": {"domain": {}, "subdomains": {"old.example.com": {
                 "has_records": True, "ips": {"ipv4": ["192.0.2.10"], "ipv6": []}}}}}
    with mock.patch.object(hp, "is_docker_installed", return_value=True), \
         mock.patch.object(hp, "is_docker_running", return_value=True), \
         mock.patch.object(hp, "pull_httpx_docker_image", return_value=True), \
         mock.patch.object(hp, "enhance_with_wappalyzer", side_effect=lambda r, s: r), \
         mock.patch.object(hp.subprocess, "Popen", side_effect=fake_popen):
        return hp.run_http_probe(recon, output_file=None, settings={"BANNER_GRAB_ENABLED": False})


class TestTheRunForwardsTheExternalDomains:
    def test_the_redirect_entry_reaches_the_pipeline(self):
        """main._aggregate_external_domains reads http_probe.external_domains."""
        result = _run_with_httpx_lines([_line(IN_SCOPE, FOREIGN, [302, 200])])
        ext = result["http_probe"]["external_domains"]
        assert [(e["domain"], e["source"], e["redirect_from_url"]) for e in ext] == \
            [("idp.example.net", "http_probe_redirect", IN_SCOPE)]
        from recon.main import _aggregate_external_domains
        agg = _aggregate_external_domains(result)
        assert [a["domain"] for a in agg] == ["idp.example.net"]
        assert agg[0]["redirect_from_urls"] == [IN_SCOPE]
