"""A 403 on a referenced source map is no proof the map exists (plan 06.5).

S3 without ListBucket, and CloudFront in front of it with OAC, answer 403
AccessDenied for keys that do not exist, so a script naming a map that was
never uploaded still produced an info source_map_reference row. A 403 now
needs corroboration: storage markers on the answer (``<Code>AccessDenied</Code>``,
``Server: AmazonS3``, ``x-amz-*``) drop the row with no extra request;
otherwise a sibling control (``<map_url>.<nonce>``) is fetched, and a 403 there
too drops it. A control that errors is no evidence: the row stays, marked.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import sourcemap as sm  # noqa: E402

JS = "https://app.example.com/static/js/main.4f2a9c.js"
MAP = JS + ".map"
JS_FILE = {"url": JS, "content": "x;\n//# sourceMappingURL=main.4f2a9c.js.map", "headers": {}}
SETTINGS = {"JS_RECON_SOURCE_MAPS": True, "JS_RECON_TIMEOUT": 60}

S3_DENIED = ('<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>AccessDenied</Code>'
             '<Message>Access Denied</Message><RequestId>EXAMPLE</RequestId></Error>')


def _resp(status, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.headers = requests.structures.CaseInsensitiveDict(headers or {})
    r.text = body
    r.content = body.encode()
    return r


def _discover(map_answer, control_answer=None, settings=None):
    """Run discovery for one script whose map answers `map_answer`; the
    sibling control (any other URL) answers `control_answer`."""
    requested = []

    def fake_get(url, **kw):
        requested.append(url)
        if url == MAP:
            return map_answer
        if isinstance(control_answer, Exception):
            raise control_answer
        return control_answer

    with patch.object(sm, "is_url_safe_to_probe", return_value=True), \
            patch.object(sm.requests, "head", return_value=_resp(403)), \
            patch.object(sm.requests, "get", side_effect=fake_get):
        rows = sm.discover_and_analyze_sourcemaps([dict(JS_FILE)], dict(SETTINGS, **(settings or {})))
    return rows, requested


def test_a_403_whose_control_is_also_403_is_dropped():
    rows, requested = _discover(_resp(403, "Forbidden"), _resp(403, "Forbidden"))
    assert rows == []
    [control] = [u for u in requested if u != MAP]
    assert control.startswith(MAP + ".") and len(control) > len(MAP) + 4


def test_a_403_whose_control_is_404_is_a_referenced_map():
    rows, _ = _discover(_resp(403, "Forbidden"), _resp(404, "Not Found"))
    [row] = rows
    assert (row["finding_type"], row["fetch_result"], row["control_check"]) == (
        "source_map_reference", "http_403", "passed")


def test_the_control_nonce_differs_each_time():
    _, first = _discover(_resp(403), _resp(404))
    _, second = _discover(_resp(403), _resp(404))
    assert [u for u in first if u != MAP] != [u for u in second if u != MAP]


def test_an_s3_access_denied_body_drops_the_row_without_a_control():
    rows, requested = _discover(_resp(403, S3_DENIED, {"Content-Type": "application/xml"}))
    assert rows == []
    assert requested == [MAP]


def test_an_s3_server_header_drops_the_row_without_a_control():
    rows, requested = _discover(_resp(403, "", {"Server": "AmazonS3"}))
    assert (rows, requested) == ([], [MAP])


def test_an_x_amz_header_drops_the_row_without_a_control():
    rows, requested = _discover(_resp(403, "", {"x-amz-request-id": "EXAMPLE", "X-Cache": "Error from cloudfront"}))
    assert (rows, requested) == ([], [MAP])


def test_a_control_that_errors_is_no_evidence_and_the_row_stays_marked():
    rows, _ = _discover(_resp(403, "Forbidden"), requests.ConnectionError("reset"))
    [row] = rows
    assert (row["fetch_result"], row["control_check"]) == ("http_403", "failed")


def test_a_401_is_still_reported_with_no_control():
    rows, requested = _discover(_resp(401, "Unauthorized"))
    [row] = rows
    assert row["fetch_result"] == "http_401"
    assert requested == [MAP]


def test_no_request_reaches_an_roe_excluded_map_host():
    js_file = {"url": JS, "content": "x;\n//# sourceMappingURL=https://legacy.example.com/m.js.map", "headers": {}}
    with patch.object(sm, "is_url_safe_to_probe", return_value=True), \
            patch.object(sm.requests, "head") as head, patch.object(sm.requests, "get") as get:
        rows = sm.discover_and_analyze_sourcemaps(
            [js_file], dict(SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["legacy.example.com"]))
    assert rows == []
    head.assert_not_called()
    get.assert_not_called()


def test_with_source_maps_off_nothing_is_requested():
    """Stealth and the operator switch the check off as a whole; the control
    never runs without it."""
    with patch.object(sm.requests, "head") as head, patch.object(sm.requests, "get") as get:
        assert sm.discover_and_analyze_sourcemaps([dict(JS_FILE)], {"JS_RECON_SOURCE_MAPS": False}) == []
    head.assert_not_called()
    get.assert_not_called()


def test_the_control_goes_through_the_ssrf_guard():
    checked = []

    def guard(url):
        checked.append(url)
        return url == MAP

    with patch.object(sm, "is_url_safe_to_probe", side_effect=guard), \
            patch.object(sm.requests, "head", return_value=_resp(403)), \
            patch.object(sm.requests, "get", return_value=_resp(403, "Forbidden")) as get:
        rows = sm.discover_and_analyze_sourcemaps([dict(JS_FILE)], dict(SETTINGS))
    assert any(u.startswith(MAP + ".") for u in checked)
    # The guard refused the control: no request, no evidence, the row stays.
    assert [c.args[0] for c in get.call_args_list] == [MAP]
    assert rows[0]["control_check"] == "failed"
