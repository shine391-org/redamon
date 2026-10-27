"""The sensitive-comment check is linear in the line's length (plan 06.2 measurement).

Measuring the file volume plan 06.1 hands js_recon showed one analyzer taking
29 s per MB of minified JS, more than all the others together: the
sensitive-comment regex ``(?://|/\\*|\\*)\\s*.*(keyword).*`` ran ``.*`` to the end
of the line from every ``*`` on it (multiplication included) and backtracked,
so a minified bundle (one long line) cost the square of its length. A 520-chunk
site came within seconds of JS_RECON_TIMEOUT. The match it reports is unchanged.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import patterns  # noqa: E402

# The expression as it was, kept here as the reference for what a match is.
OLD = re.compile(r'(?://|/\*|\*)\s*.*(?:' + '|'.join(patterns.DEV_COMMENT_SENSITIVE_KEYWORDS) + r').*',
                 re.IGNORECASE)

LINES = [
    "// the admin password is in the vault",
    "/* temporary bypass for QA */",
    " * @param {string} token the session token",
    "var a=b*c; // no keyword here",
    "x = y * z + secretValue;",
    "const area = w*h;",
    "/*! license */ var Key = 1;",
    "return a**2 // DEBUG",
    "no marker but a password word",
    "",
    "*",
    "// KEY",
    "/* */ token",
    "url = 'http://example.com/a/*/b?token=1'",
    "a*b*c*d*e*f credential",
    "credential * before the marker",
    "\tcomment // Hardcoded value\r",
]


@pytest.mark.parametrize("line", LINES)
def test_the_reported_match_is_unchanged(line):
    old = OLD.search(line)
    assert patterns._sensitive_comment(line) == (old.group(0) if old else None)


def test_a_long_minified_line_is_checked_in_linear_time():
    line = "".join(f"function f{i}(a,b){{var c=a+b*{i % 97};return c>{i}?c:a}}" for i in range(6000))
    assert len(line) > 250_000
    start = time.monotonic()
    assert patterns._sensitive_comment(line) is None
    assert time.monotonic() - start < 1.0


def test_the_scan_still_reports_a_sensitive_comment():
    [finding] = patterns.scan_dev_comments("var a=1;\n// the admin password is in the vault\n", "https://example.com/a.js")
    assert (finding["type"], finding["line"]) == ("sensitive_comment", 2)
    assert finding["content"] == "// the admin password is in the vault"
