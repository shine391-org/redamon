"""Banner grabbing skips web ports and tells SMTP from FTP (plan 12.11).

HTTP_PORTS was defined twice in http_probe.py; the second definition (for URL
building) shadowed the banner grab's skip set, so 443, 8443, 9090 and 8800 were
banner-grabbed: a plaintext connect that waits up to 3 s per port and leaves a
`service: unknown` row. And the generic FTP pattern `220[- ]` came before the
SMTP ones, so every SMTP greeting (Postfix, Exim, Sendmail, Exchange) was
labelled `ftp`, and an Exim version never reached the CVE lookup.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import http_probe as hp  # noqa: E402


class TestTheSkipSet:
    @pytest.mark.parametrize("port", [80, 443, 8080, 8443, 9090, 8800, 4443, 9443, 8843])
    def test_web_ports_are_skipped(self, port):
        assert port in hp.BANNER_GRAB_SKIP_PORTS

    @pytest.mark.parametrize("port", [21, 22, 25, 110, 143, 465, 587, 3306, 6379])
    def test_service_ports_are_grabbed(self, port):
        assert port not in hp.BANNER_GRAB_SKIP_PORTS

    def test_the_url_constants_are_unchanged(self):
        # They drive the URLs httpx gets; test_custom_port_scope pins them apart.
        assert hp.HTTPS_PORTS == {443, 8443, 4443, 9443, 8843}
        assert hp.HTTP_PORTS == {80, 8080, 8000, 8888, 8008, 3000, 5000, 9000}

    def test_run_banner_grab_targets_only_non_web_ports(self):
        recon = {"port_scan": {"by_host": {"a.example.com": {
            "ip": "192.0.2.10", "ports": [22, 443, 8443, 9090, 8800, 25, 80]}}}}
        grabbed = []

        def fake(target, timeout, max_length):
            grabbed.append(target[1])
            return {"host": target[2], "ip": target[0], "port": target[1], "banner": None,
                    "service": "unknown", "version": None, "confidence": "none"}

        with mock.patch.object(hp, "grab_banner_for_target", side_effect=fake):
            hp.run_banner_grab(recon, {"BANNER_GRAB_ENABLED": True})
        assert sorted(grabbed) == [22, 25]


class TestIdentifyService:
    @pytest.mark.parametrize("banner, version", [
        ("220 mx.example.com ESMTP Exim 4.94.2 Mon, 26 Oct 2026 12:00:00 +0000", "Exim 4.94.2"),
        ("220 mail.example.com ESMTP Postfix (Ubuntu)", "Postfix"),
        ("220 mail.example.com ESMTP Sendmail 8.15.2/8.15.2", "Sendmail"),
        ("220 mail.example.com Microsoft ESMTP MAIL Service ready", "Microsoft Exchange"),
        ("220 smtp.example.com ESMTP ready", "SMTP"),
    ])
    def test_smtp_greetings_are_smtp(self, banner, version):
        out = hp.identify_service(banner, 25)
        assert out["service"] == "smtp"
        assert out["version"] == version

    def test_an_smtp_greeting_on_another_port_is_still_smtp(self):
        assert hp.identify_service("220 mx.example.com ESMTP Exim 4.94.2", 2525)["service"] == "smtp"

    @pytest.mark.parametrize("banner, version", [
        ("220 (vsFTPd 3.0.3)", "vsFTPd 3.0.3"),
        ("220 ProFTPD 1.3.5 Server ready.", "ProFTPD 1.3.5"),
        ("220---------- Welcome to Pure-FTPd [privsep] ----------", "Pure-FTPd"),
        ("220 Microsoft FTP Service", "Microsoft FTP"),
    ])
    def test_ftp_greetings_are_ftp(self, banner, version):
        out = hp.identify_service(banner, 21)
        assert out["service"] == "ftp"
        assert out["version"] == version

    @pytest.mark.parametrize("port, service", [
        (25, "smtp"), (465, "smtp"), (587, "smtp"), (2525, "smtp"),
        (21, "ftp"), (990, "ftp"),
        (8021, "unknown"),
    ])
    def test_a_bare_220_falls_back_by_port(self, port, service):
        assert hp.identify_service("220 ready", port)["service"] == service

    def test_a_bare_220_that_says_ftp_is_ftp_on_any_port(self):
        assert hp.identify_service("220 example FTP server ready", 8021)["service"] == "ftp"

    def test_a_220_inside_a_banner_is_not_a_greeting(self):
        # Unanchored, `220[- ]` matched a code in the middle of any text.
        assert hp.identify_service("HTTP/1.1 400 Bad Request at offset 220 ", 8021)["service"] == "unknown"

    def test_ssh_is_unaffected(self):
        assert hp.identify_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu", 22)["service"] == "ssh"
