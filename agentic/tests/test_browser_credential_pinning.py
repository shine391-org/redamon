"""Host-pinned credentials in the proxy_brain browser (plan §23.8 item 2).

The session used to ride extra_http_headers, which Playwright sends on every
request, a third-party script or image included. Now a cookie profile is
scoped to the pinned origin and every other auth header is added per request,
only when the request's host is the pinned host. The decisions are pure
functions, tested here; the endpoint returns no session in anonymous mode.
"""
import asyncio
import json
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "mcp", "servers"))

KEY = "test-internal-key-pin"
os.environ["INTERNAL_API_KEY"] = KEY

import redamon  # noqa: E402
from redamon_ctx import sign_tag  # noqa: E402

AUTH = {"Authorization": "Bearer tok", "X-Tenant": "t1"}


def test_the_pinned_host_gets_the_session():
    assert redamon._pinned_auth("http://10.0.0.5/profile", "10.0.0.5", AUTH) == AUTH
    assert redamon._pinned_auth("https://App.Lab.Invalid:8443/x", "app.lab.invalid", AUTH) == AUTH


def test_a_cross_origin_sub_resource_gets_nothing():
    assert redamon._pinned_auth("http://10.0.0.96/widget.js", "10.0.0.5", AUTH) == {}
    assert redamon._pinned_auth("https://cdn.example/lib.js", "app.lab.invalid", AUTH) == {}
    assert redamon._pinned_auth("http://[bad", "10.0.0.5", AUTH) == {}
    assert redamon._pinned_auth("data:text/plain,x", "10.0.0.5", AUTH) == {}


def test_a_cookie_profile_becomes_cookies_scoped_to_the_origin():
    cookies, headers = redamon._split_auth({"Cookie": "sid=lab-user-1; theme=dark; junk", "X-K": "v"})
    assert cookies == [("sid", "lab-user-1"), ("theme", "dark")]
    assert headers == {"X-K": "v"}
    assert redamon._split_auth({}) == ([], {})


def test_the_browser_never_puts_the_session_in_extra_http_headers():
    src = open(redamon.__file__).read()
    init = src[src.index("    def __init__(self, origin_id: str, anonymous: bool = False):"):src.index("    def _checkin(")]
    assert "**auth_headers" not in init
    assert "self._context.route(\"**/*\", _attach)" in init
    assert "add_cookies" in init


def _tag():
    return sign_tag({"source": "agent", "user_id": "u1", "project_id": "p1", "session_id": "s-pin",
                     "tool": "proxy_brain", "phase": "exploitation"}, KEY)


def _open(anonymous):
    import api
    api._TRAFFIC_BROWSER_ACTIONS.clear()
    txn = {"host": "10.0.0.5", "scheme": "http", "port": 80, "path": "/", "query": "", "method": "GET",
           "req_headers": {}, "req_body": None}
    with mock.patch("traffic_tools.fetch_transaction", new=mock.AsyncMock(return_value=txn)), \
         mock.patch.object(api, "_profile_auth_base", new=mock.AsyncMock(return_value=AUTH)):
        resp = asyncio.new_event_loop().run_until_complete(api.traffic_browser(
            api.TrafficBrowserRequest(ctx=_tag(), action="open", origin_id="t1", anonymous=anonymous)))
    return json.loads(resp.body)


def test_an_anonymous_browser_gets_no_session():
    assert _open(True)["auth_headers"] == {} and _open(True)["identity"] == "anonymous"
    opened = _open(False)
    assert opened["auth_headers"] == AUTH and opened["identity"] == "session"
