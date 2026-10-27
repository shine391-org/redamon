"""JS Recon endpoint extraction: an endpoint's HTTP method comes from its own call.

The method was guessed from the whole line: the first method pattern anywhere
on it, else any substring "post", "put" or "delete". A minified bundle is one
line, so one `postMessage` made every endpoint on it POST. Endpoint identity
includes the method, and non-GET endpoints are probed with OPTIONS, so both
the graph nodes and the probes were wrong.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon.endpoints import extract_endpoints  # noqa: E402


def methods(js: str) -> dict:
    found = extract_endpoints([{"url": "https://app.example.com/main.js", "content": js}], {})
    out: dict = {}
    for ep in found:
        if ep.get("type") == "rest":
            out.setdefault(ep["path"], set()).add(ep["method"])
    return {path: sorted(m) for path, m in out.items()}


def test_regression_postmessage_on_a_minified_line_made_every_endpoint_post():
    got = methods('window.postMessage(1);fetch("/api/read");api.get("/api/list")')
    assert got == {"/api/read": ["GET"], "/api/list": ["GET"]}


def test_a_verb_in_the_call_names_the_method():
    assert methods('axios.post("/api/x",d)') == {"/api/x": ["POST"]}
    assert methods('client.put("/api/p",d)') == {"/api/p": ["PUT"]}
    assert methods('superagent.del("/api/v")') == {"/api/v": ["DELETE"]}
    assert methods('xhr.open("PATCH", "/api/w")') == {"/api/w": ["PATCH"]}


def test_the_calls_own_options_name_the_method():
    assert methods('fetch("/api/y",{method:"DELETE"})') == {"/api/y": ["DELETE"]}
    assert methods("fetch('/api/n', {headers: {'X-A': '1'}, method: 'patch'})") == {"/api/n": ["PATCH"]}
    assert methods('$.ajax({type:"POST",url:"/api/z"})') == {"/api/z": ["POST"]}


def test_options_far_down_the_line_belong_to_another_call():
    js = 'fetch("/a");' + "var pad=1;" * 200 + '{method:"PUT"}'
    assert len(js) > 2000
    assert methods(js) == {"/a": ["GET"]}


def test_a_neighbouring_calls_options_do_not_leak():
    assert methods('fetch("/a");fetch("/b",{method:"POST"})') == {"/a": ["GET"], "/b": ["POST"]}
    assert methods('axios.post("/save",d);fetch("/load")') == {"/save": ["POST"], "/load": ["GET"]}


def test_words_that_merely_contain_a_verb_are_not_a_method():
    js = 'var output="deleted";fetch("/api/posts");request("/api/input");api.get("/api/putaway")'
    assert methods(js) == {"/api/posts": ["GET"], "/api/input": ["GET"], "/api/putaway": ["GET"]}


def test_an_unknown_method_word_defaults_to_get():
    assert methods('fetch("/api/q",{method:someVar})') == {"/api/q": ["GET"]}
    assert methods('fetch("/api/r",{method:"BREW"})') == {"/api/r": ["GET"]}
