"""proxy_brain anonymous mode (plan §23.8 item 1).

An anonymous replay, batch or fuzz carries no credential at all: no profile is
seeded, and the origin request's Cookie, Authorization, Proxy-Authorization,
every header name the project's profile sets (header, apikey, extraHeaders) and
every redacted header are stripped, whoever set them. A non-anonymous replay is
unchanged. Handlers are called directly with the DB and webapp stubbed.
"""
import asyncio
import os
import shlex
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

KEY = "test-internal-key-anon"
os.environ["INTERNAL_API_KEY"] = KEY

from redamon_ctx import sign_tag  # noqa: E402

PROFILES = {
    "bearer": ({"authType": "bearer", "authValue": "tok"}, "authorization"),
    "basic": ({"authType": "basic", "authValue": "u:p"}, "authorization"),
    "cookie": ({"authType": "cookie", "authValue": "sid=1"}, "cookie"),
    "header": ({"authType": "header", "authValue": "k", "authHeaderName": "X-Lab-Key"}, "x-lab-key"),
    "apikey": ({"authType": "apikey", "authValue": "k"}, "x-api-key"),
    "extra": ({"authType": "none", "authValue": "", "extraHeaders": {"X-Tenant-Token": "t"}}, "x-tenant-token"),
}


def _tag():
    return sign_tag({"source": "agent", "user_id": "u1", "project_id": "p1", "session_id": "s-anon",
                     "tool": "proxy_brain", "phase": "exploitation"}, KEY)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _txn(headers):
    return {"host": "10.0.0.5", "scheme": "http", "port": 80, "path": "/api/export", "query": "",
            "method": "GET", "req_headers": headers, "req_body": None}


def _headers(curl_args: str) -> dict:
    parts = shlex.split(curl_args)
    out = {}
    for i, p in enumerate(parts):
        if p == "-H":
            name, _, value = parts[i + 1].partition(":")
            out[name.strip().lower()] = value.strip()
    return out


def _send(profile, origin_headers, anonymous, op="replay", mutate=None):
    import api
    api._TRAFFIC_REPLAY_SENDS.clear()
    api._AUTH_PROFILE_CACHE.clear()
    project = {"authProfile": profile, "ipMode": True, "targetIps": ["10.0.0.5"], "updatedAt": "x"}
    body = {"ctx": _tag(), "op": op, "id": "t1", "anonymous": anonymous, "mutate": mutate or {}}
    if op == "fuzz":
        body.update(insertion_point="q", payloads=["a", "b"])
    with mock.patch("traffic_tools.fetch_transaction", new=mock.AsyncMock(return_value=_txn(origin_headers))), \
         mock.patch.object(api, "_cached_project", new=mock.AsyncMock(return_value=project)):
        resp = _run(api.traffic_replay(api.TrafficReplayRequest(**body)))
    assert resp.status_code == 200, resp.body
    import json
    return json.loads(resp.body)


ORIGIN = {"Accept": "application/json", "Cookie": "[redacted:abcd]",
          "Authorization": "Bearer captured", "X-Trace": "keep-me"}


@pytest.mark.parametrize("name", sorted(PROFILES))
@pytest.mark.parametrize("op", ["replay", "fuzz"])
def test_an_anonymous_send_carries_no_credential(name, op):
    profile, header = PROFILES[name]
    origin = dict(ORIGIN, **{header: "captured-value"})
    data = _send(profile, origin, True, op=op,
                 mutate={"headers": {"Proxy-Authorization": "Basic x", header: "mutated"}})
    assert data["identity"] == "anonymous"
    for send in data["sends"]:
        sent = _headers(send["curl_args"])
        assert not {"cookie", "authorization", "proxy-authorization", header} & set(sent), sent
        assert not any(v.startswith("[redacted:") for v in sent.values())
        assert sent.get("x-trace") == "keep-me" and sent.get("accept") == "application/json"


def test_a_session_replay_is_unchanged():
    profile, _ = PROFILES["bearer"]
    import api
    from traffic_tools import build_replay_curl
    data = _send(profile, ORIGIN, False)
    assert data["identity"] == "session"
    sent = _headers(data["sends"][0]["curl_args"])
    # The captured Authorization outranks the profile; the redacted cookie is dropped.
    assert sent["authorization"] == "Bearer captured" and "cookie" not in sent
    assert data["sends"][0]["curl_args"] == build_replay_curl(_txn(ORIGIN), {}, auth_base={"Authorization": "Bearer tok"})
    assert api._CREDENTIAL_HEADERS == {"cookie", "authorization", "proxy-authorization"}


def test_strip_names_survive_a_webapp_failure():
    import api
    api._AUTH_PROFILE_CACHE.clear()
    with mock.patch.object(api, "_cached_project", new=mock.AsyncMock(side_effect=RuntimeError("down"))):
        names = _run(api._anonymous_strip_names("p1"))
    assert names == {"cookie", "authorization", "proxy-authorization"}


def test_the_sdk_tags_each_response_with_its_identity(monkeypatch):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                    "mcp", "servers"))
    import redamon
    posted = []
    monkeypatch.setattr(redamon, "_post", lambda path, payload: (posted.append(payload) or
                        {"sends": [{"curl_args": "-s http://h/x", "payload": None}], "ctx": "", "identity":
                         "anonymous" if payload.get("anonymous") else "session"}))
    monkeypatch.setattr(redamon, "_run", lambda args, ctx, payload=None, identity="session":
                        redamon.Response(200, {}, "", payload, identity))
    assert redamon.replay("t1", anonymous=True).identity == "anonymous"
    assert redamon.replay("t1").identity == "session"
    assert [r.identity for r in redamon.fuzz("t1", "q", ["a"], anonymous=True)] == ["anonymous"]
    assert [r.identity for r in redamon.batch("t1", [{}, {}], anonymous=True)] == ["anonymous", "anonymous"]
    assert posted[0]["anonymous"] is True and posted[1]["anonymous"] is False
    assert "anonymous" in repr(redamon.Response(200, {}, "", identity="anonymous"))
