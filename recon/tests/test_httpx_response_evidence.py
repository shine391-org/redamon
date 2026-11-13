"""httpx evidence: bounded raw-body decode and real response headers.

No network. These tests exercise the parser against the JSON shapes the tool
actually emits; native transport/fingerprint checks are recorded separately.
"""
import base64
import gzip

from recon.main_recon_modules import http_probe


def test_base64_gzip_body_is_decoded_for_evidence():
    body = gzip.compress(b"<title>LOCAL_403_ERROR_TITLE</title>")
    entry = {"body": base64.b64encode(body).decode(), "content_encoding": "gzip",
             "raw_header": "HTTP/1.1 403 Forbidden\r\nContent-Encoding: gzip\r\n\r\n"}
    text, source = http_probe._text_from_httpx_fields(entry)
    assert text == "<title>LOCAL_403_ERROR_TITLE</title>"
    assert source == "body_gzip_decoded"
    assert http_probe._body_title(text) == "LOCAL_403_ERROR_TITLE"


def test_already_decoded_text_is_preserved():
    text, source = http_probe._text_from_httpx_fields({"body": "<html>app</html>"})
    assert text == "<html>app</html>"
    assert source == "body_text"


def test_corrupt_gzip_is_evidence_not_a_clean_page():
    entry = {"body": base64.b64encode(b"\x1f\x8bnot-a-gzip-stream").decode()}
    text, source = http_probe._text_from_httpx_fields(entry)
    assert text is not None
    assert "not-a-gzip-stream" in text
    assert source == "body_base64"


def test_oversized_body_is_not_kept_as_evidence():
    assert http_probe._text_from_httpx_fields(
        {"body": b"x" * (http_probe._HTTP_BODY_EVIDENCE_CAP + 1)}) == (None, "too_large")


def test_raw_response_block_contributes_response_headers_only():
    url_entry = {}
    raw = "HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nCF-RAY: abc\r\n\r\nbody"
    http_probe._record_response_headers(url_entry, {"raw_response": raw})
    assert url_entry["headers"] == {"Server": "cloudflare", "CF-RAY": "abc"}
    assert "request" not in str(url_entry).lower()


def test_builder_omits_only_accept_encoding_and_keeps_identity_headers():
    settings = {
        "HTTPX_DOCKER_IMAGE": "projectdiscovery/httpx:latest", "HTTPX_THREADS": 1,
        "HTTPX_TIMEOUT": 1, "HTTPX_PROBE_STATUS_CODE": True, "HTTPX_PROBE_TITLE": True,
        "HTTPX_CUSTOM_HEADERS": [
            "Accept-Encoding: gzip, deflate",
            "X-Bug-Bounty: fixture-identity",
            "Authorization: Bearer fixture",
        ],
        "HTTPX_PROBE_TECH_DETECT": False, "HTTPX_PROBE_TLS_INFO": False,
        "HTTPX_INCLUDE_RESPONSE": False, "HTTPX_INCLUDE_RESPONSE_HEADERS": True,
        "HTTPX_PROBE_IP": False, "HTTPX_PROBE_CNAME": False,
        "HTTPX_PROBE_FAVICON": False, "HTTPX_PROBE_JARM": False,
        "HTTPX_PROBE_ASN": False, "HTTPX_PROBE_CDN": False,
        "HTTPX_PROBE_CONTENT_LENGTH": False, "HTTPX_PROBE_CONTENT_TYPE": False,
        "HTTPX_PROBE_SERVER": False, "HTTPX_PROBE_RESPONSE_TIME": False,
        "HTTPX_PROBE_WORD_COUNT": False, "HTTPX_PROBE_LINE_COUNT": False,
        "HTTPX_FOLLOW_REDIRECTS": False, "HTTPX_PATHS": [],
        "HTTPX_MATCH_CODES": [], "HTTPX_FILTER_CODES": [],
    }
    cmd = http_probe.build_httpx_command("/tmp/targets.txt", "/tmp/out.json",
                                         settings, probe_hosts=["app.example.test"])
    assert "Accept-Encoding: gzip, deflate" not in cmd
    assert "X-Bug-Bounty: fixture-identity" in cmd
    assert "Authorization: Bearer fixture" in cmd
