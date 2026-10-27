"""tlsx payload: the CDN the certificate issuer names travels with the payload.

In a full run the port graph write happens before tlsx, so the CDN tag tlsx puts
on port_scan.by_ip never reached IP.is_cdn. run_tlsx_enrichment now lists the
IPs it attributed under ``tlsx.cdn_by_ip``, which the tlsx graph writer reads
(tests/test_tlsx_writer_cdn.py covers the writer side).

The tlsx binary is mocked; target selection is patched so the RFC 5737 fixture
addresses survive the module's SSRF filter.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import tls_scan

EDGE_IP = "192.0.2.10"
NAABU_IP = "192.0.2.12"
PLAIN_IP = "192.0.2.11"


def _line(ip, issuer_dn):
    return {
        "host": ip, "ip": ip, "port": "993", "probe_status": True,
        "subject_cn": "mail.example.com", "subject_an": ["mail.example.com"],
        "issuer_cn": issuer_dn.split(",")[0][3:], "issuer_dn": issuer_dn,
        "fingerprint_hash": {"sha256": ip.replace(".", "") * 4},
        "not_after": "2099-01-01T00:00:00Z",
    }


def _run(by_ip):
    combined = {"port_scan": {"by_ip": by_ip, "by_host": {}}}
    stdout = "\n".join(json.dumps(x) for x in (
        _line(EDGE_IP, "CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc."),
        _line(NAABU_IP, "CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc."),
        _line(PLAIN_IP, "CN=R11, O=Let's Encrypt"),
    ))
    meta = {f"{ip}:993": ip for ip in (EDGE_IP, NAABU_IP, PLAIN_IP)}
    proc = MagicMock(returncode=0)
    proc.communicate.return_value = (stdout, "")
    with patch.object(tls_scan, "_build_tlsx_targets",
                      return_value=([f"{ip}:993" for ip in meta.values()], meta)), \
         patch("subprocess.Popen", return_value=proc):
        tls_scan.run_tlsx_enrichment(combined, {})
    return combined


def _by_ip():
    return {
        EDGE_IP: {"ip": EDGE_IP, "ports": [993], "cdn": None, "is_cdn": False},
        NAABU_IP: {"ip": NAABU_IP, "ports": [993], "cdn": "fastly", "is_cdn": True},
        PLAIN_IP: {"ip": PLAIN_IP, "ports": [993], "cdn": None, "is_cdn": False},
    }


def test_the_payload_names_each_ip_tlsx_attributed():
    out = _run(_by_ip())
    assert out["tlsx"]["cdn_by_ip"] == {EDGE_IP: "cloudflare"}


def test_naabus_own_attribution_is_not_claimed_by_tlsx():
    out = _run(_by_ip())
    assert NAABU_IP not in out["tlsx"]["cdn_by_ip"]
    assert out["port_scan"]["by_ip"][NAABU_IP]["cdn"] == "fastly"


def test_an_ordinary_issuer_attributes_nothing():
    out = _run(_by_ip())
    assert PLAIN_IP not in out["tlsx"]["cdn_by_ip"]
    assert out["port_scan"]["by_ip"][PLAIN_IP]["is_cdn"] is False


def test_the_isolated_wrapper_returns_the_same_attribution():
    combined = {"port_scan": {"by_ip": _by_ip(), "by_host": {}}}
    proc = MagicMock(returncode=0)
    proc.communicate.return_value = (json.dumps(_line(EDGE_IP, "CN=Cloudflare Inc ECC CA-3")), "")
    meta = {f"{EDGE_IP}:993": EDGE_IP}
    with patch.object(tls_scan, "_build_tlsx_targets", return_value=([f"{EDGE_IP}:993"], meta)), \
         patch("subprocess.Popen", return_value=proc):
        payload = tls_scan.run_tlsx_enrichment_isolated(combined, {})
    assert payload["cdn_by_ip"] == {EDGE_IP: "cloudflare"}


def test_no_targets_still_carries_an_empty_attribution():
    combined = {"port_scan": {"by_ip": {}, "by_host": {}}}
    tls_scan.run_tlsx_enrichment(combined, {})
    assert combined["tlsx"]["cdn_by_ip"] == {}
