"""httpx evidence: exact -irr text, bounded binary decode, response-only headers.

No network. Field names follow projectdiscovery/httpx v1.12: default ``-irr``
puts plain text in ``body`` / ``raw_header`` and the request block in
``request``; only ``-irrb`` base64-encodes them, and that shape carries no
per-entry marker. Therefore plain alphabet strings are never "decoded".
"""
import base64
import gzip
import json
import zlib

from recon.main_recon_modules import http_probe

CAP = http_probe._HTTP_BODY_EVIDENCE_CAP


# ---------------------------------------------------------------------------
# Body decoding
# ---------------------------------------------------------------------------

def test_default_irr_text_body_is_preserved_exactly():
    body = "<html><head><title>LOCAL</title></head><body>hello</body></html>"
    text, source = http_probe._text_from_httpx_fields(
        {"body": body, "content_type": "text/html"})
    assert text == body
    assert source == "body_text"


def test_alphabet_only_text_is_never_guessed_as_base64():
    body = "deadbeefcafebabe0123456789abcdefABCDEF"
    text, source = http_probe._text_from_httpx_fields({"body": body})
    assert text == body
    assert source == "body_text"


def test_content_encoding_alone_does_not_permit_base64_decode():
    encoded = base64.b64encode(
        b"<html><head><title>X</title></head></html>").decode()
    text, source = http_probe._text_from_httpx_fields({
        "body": encoded, "content_encoding": "gzip",
        "raw_header": "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
    })
    assert text == encoded
    assert source == "body_text"


def test_explicit_base64_key_decodes_without_compression():
    raw = b"<html><head><title>Explicit</title></head></html>"
    text, source = http_probe._text_from_httpx_fields({
        "body_base64": base64.b64encode(raw).decode(),
        "content_type": "text/html",
    })
    assert text == raw.decode()
    assert source == "body_base64"


def test_explicit_base64_metadata_with_gzip_decompresses_bounded():
    raw = b"<html><head><title>Gzip</title></head></html>"
    text, source = http_probe._text_from_httpx_fields({
        "body": base64.b64encode(gzip.compress(raw)).decode(),
        "body_encoding": "base64",
        "content_encoding": "gzip",
    })
    assert text == raw.decode()
    assert source == "body_gzip_decoded"


def test_malformed_explicit_base64_stays_evidence():
    encoded = base64.b64encode(b"\x1f\x8bnot-a-gzip-stream").decode()
    text, source = http_probe._text_from_httpx_fields(
        {"body": encoded, "body_encoding": "base64"})
    assert text is not None
    assert "not-a-gzip-stream" in text
    assert source == "body_base64"


def test_gzip_bomb_is_marked_truncated_not_silently_prefixed():
    bomb = gzip.compress(b"x" * (CAP * 4))
    assert http_probe._text_from_httpx_fields({
        "body": base64.b64encode(bomb).decode(),
        "body_encoding": "base64",
    }) == (None, "truncated")


def test_zlib_bomb_is_bounded_by_decompressobj():
    bomb = zlib.compress(b"y" * (CAP * 4))
    assert http_probe._text_from_httpx_fields({
        "body": base64.b64encode(bomb).decode(),
        "body_encoding": "base64",
    }) == (None, "truncated")


def test_oversized_plain_body_is_capped_before_allocation():
    assert http_probe._text_from_httpx_fields(
        {"body": "x" * (CAP + 1)}) == (None, "too_large")


def test_oversized_binary_body_is_capped_before_allocation():
    assert http_probe._text_from_httpx_fields(
        {"body": b"x" * (CAP + 1)}) == (None, "too_large")


def test_oversized_base64_body_is_rejected_before_allocation():
    encoded = base64.b64encode(b"z" * (CAP * 2)).decode()
    assert http_probe._text_from_httpx_fields({
        "body": encoded, "body_encoding": "base64"}) == (None, "too_large")


def test_body_at_the_cap_is_kept():
    body = "a" * CAP
    assert http_probe._text_from_httpx_fields({"body": body}) == (body, "body_text")


# ---------------------------------------------------------------------------
# Response-header fallback
# ---------------------------------------------------------------------------

RAW_TRANSACTION = (
    "GET / HTTP/1.1\r\n"
    "Host: app.example.test\r\n"
    "Authorization: Bearer ***\r\n"
    "\r\n"
    "HTTP/1.1 403 Forbidden\r\n"
    "Server: cloudflare\r\n"
    "Content-Type: text/html\r\n"
    "\r\n"
    "{\"note\": \"body: pseudoheader\", \"n\": 1}"
)


def test_header_fallback_parses_response_block_only_and_stops_at_blank_line():
    url_entry = {}
    http_probe._record_response_headers(url_entry, {"raw_response": RAW_TRANSACTION})
    assert url_entry["headers"] == {"Server": "cloudflare", "Content-Type": "text/html"}


def test_raw_header_field_is_parsed_when_no_header_dict():
    url_entry = {}
    http_probe._record_response_headers(
        url_entry, {"raw_header": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"})
    assert url_entry["headers"] == {"Server": "nginx"}


def test_request_only_raw_block_yields_no_response_headers():
    url_entry = {}
    http_probe._record_response_headers(
        url_entry,
        {"raw_response": "GET / HTTP/1.1\r\nAuthorization: Bearer ***\r\n\r\n"})
    assert "headers" not in url_entry


def test_named_header_dict_wins_over_raw_block():
    url_entry = {}
    http_probe._record_response_headers(
        url_entry, {"header": {"Server": "nginx"}, "raw_response": RAW_TRANSACTION})
    assert url_entry["headers"] == {"Server": "nginx"}


# ---------------------------------------------------------------------------
# HTML title fallback gate
# ---------------------------------------------------------------------------

def _parse_records(tmp_path, records):
    path = tmp_path / "httpx-out.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    return http_probe.parse_httpx_output(str(path))


def _entry(index, body, content_type=None, title=None):
    record = {"url": f"https://app.example.test/{index}",
              "status_code": 200, "body": body}
    if content_type is not None:
        record["content_type"] = content_type
    if title is not None:
        record["title"] = title
    return record


def test_html_title_fallback_requires_confirmed_html_document(tmp_path):
    doc = "<html><head><title>Doc Title</title></head><body>x</body></html>"
    parsed = _parse_records(tmp_path, [
        _entry(0, doc, "text/html"),
        _entry(1, doc, "application/json"),
        _entry(2, doc, "text/plain"),
        _entry(3, doc, "application/xhtml+xml"),
        _entry(4, doc),
        _entry(5, "<title>Fragment</title>", "text/html"),
        _entry(6, base64.b64encode(doc.encode()).decode(), "text/html"),
    ])
    titles = {key: value.get("title") for key, value in parsed["by_url"].items()}
    assert titles["https://app.example.test/0"] == "Doc Title"
    assert titles["https://app.example.test/1"] is None       # JSON is not HTML
    assert titles["https://app.example.test/2"] is None       # text/plain
    assert titles["https://app.example.test/3"] == "Doc Title"
    assert titles["https://app.example.test/4"] is None       # unconfirmed type
    assert titles["https://app.example.test/5"] is None       # fragment, not document
    assert titles["https://app.example.test/6"] is None       # base64, never decoded


def test_supplied_httpx_title_wins_over_body_fallback(tmp_path):
    doc = "<html><head><title>Body Title</title></head></html>"
    parsed = _parse_records(
        tmp_path, [_entry(0, doc, "text/html", title="Supplied Title")])
    assert parsed["by_url"]["https://app.example.test/0"]["title"] == "Supplied Title"


def test_title_fallback_reads_content_type_from_response_header(tmp_path):
    doc = "<html><head><title>Header CT</title></head></html>"
    parsed = _parse_records(tmp_path, [{
        "url": "https://app.example.test/", "status_code": 200, "body": doc,
        "raw_response": ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                         "Server: nginx\r\n\r\n"),
    }])
    assert parsed["by_url"]["https://app.example.test/"]["title"] == "Header CT"
