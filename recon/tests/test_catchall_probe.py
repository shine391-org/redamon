"""The shared catch-all control probe (recon/helpers/catchall.py).

A server that answers every path alike (an SPA shell, `200 {"code":"NOT_FOUND"}`,
a login redirect for everything) makes a status-only check report paths that
do not exist. The control asks for a path that cannot exist next to the hit;
the same answer means the hit means nothing. An error is never evidence either
way: the verdict is None and the caller keeps its finding.
"""
from __future__ import annotations

import threading
from unittest import mock

from recon.helpers import catchall
from recon.helpers import circuit_breaker as cb


def _resp(status=200, body="", headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.content = body.encode() if isinstance(body, str) else body
    r.text = body if isinstance(body, str) else body.decode()
    r.headers = headers or {}
    return r


class _Fake:
    """A fake requester: answers by path, records every URL it was sent."""

    def __init__(self, answer):
        self.answer = answer
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        path = url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else ""
        return self.answer("/" + path)


NOT_FOUND_JSON = '{"code":"NOT_FOUND"}'


class TestTheVerdict:
    def test_catch_all_json_200_on_both_is_catch_all(self):
        fetch = _Fake(lambda path: _resp(200, NOT_FOUND_JSON, {"Content-Type": "application/json"}))
        hit = _resp(200, NOT_FOUND_JSON, {"Content-Type": "application/json"})
        v = catchall.control_probe(fetch, "http://192.0.2.10/api/v1", hit)
        assert v.catch_all is True
        assert v.control_check == "catch_all"
        assert "same status and body" in v.reason
        assert len(fetch.urls) == 1
        assert fetch.urls[0].startswith("http://192.0.2.10/api/rdm-")

    def test_real_path_against_a_404_control_is_not_catch_all(self):
        fetch = _Fake(lambda path: _resp(404, NOT_FOUND_JSON))
        v = catchall.control_probe(fetch, "http://192.0.2.10/api/v1",
                                   _resp(200, '{"service":"orders","version":"2.1"}'))
        assert v.catch_all is False
        assert v.control_check == "passed"
        assert "404" in v.reason

    def test_a_body_that_echoes_the_path_is_catch_all_after_normalising(self):
        def answer(path):
            return _resp(200, f'{{"error":"no route for {path}","request_id":"9f8e7d6c5b4a39281706"}}')
        fetch = _Fake(answer)
        hit = _resp(200, '{"error":"no route for /api/v1","request_id":"0a1b2c3d4e5f60718293"}')
        assert catchall.control_probe(fetch, "http://192.0.2.10/api/v1", hit).catch_all is True

    def test_two_different_short_json_bodies_are_not_one_page(self):
        """Both are within 64 bytes of each other: the token ratio decides."""
        fetch = _Fake(lambda path: _resp(200, NOT_FOUND_JSON))
        hit = _resp(200, '{"name":"inventory","v":"1.4"}')
        assert catchall.control_probe(fetch, "http://192.0.2.10/v1", hit).catch_all is False

    def test_a_401_hit_against_a_404_control_is_a_real_path(self):
        fetch = _Fake(lambda path: _resp(404, '{"error":"Not Found"}'))
        v = catchall.control_probe(fetch, "https://app.example.com/admin", _resp(401, '{"error":"Unauthorized"}'))
        assert v.catch_all is False

    def test_a_login_redirect_for_everything_is_catch_all(self):
        def answer(path):
            return _resp(302, "", {"Location": f"/login?next={path.replace('/', '%2F')}"})
        hit = _resp(302, "", {"Location": "/login?next=%2Fapi%2Fusers"})
        v = catchall.control_probe(_Fake(answer), "https://app.example.com/api/users", hit)
        assert v.catch_all is True

    def test_a_redirect_to_a_different_place_is_not_catch_all(self):
        fetch = _Fake(lambda path: _resp(302, "", {"Location": "/login"}))
        hit = _resp(302, "", {"Location": "/admin/"})
        assert catchall.control_probe(fetch, "https://app.example.com/admin", hit).catch_all is False

    def test_the_control_raising_is_no_conclusion(self):
        def boom(url):
            raise ConnectionError("reset")
        v = catchall.control_probe(boom, "http://192.0.2.10/api", _resp(200, NOT_FOUND_JSON))
        assert v.catch_all is None
        assert v.control_check == "failed"
        assert "ConnectionError" in v.reason

    def test_a_control_with_no_status_is_no_conclusion(self):
        v = catchall.control_probe(lambda u: object(), "http://192.0.2.10/api", _resp(200, "x"))
        assert v.catch_all is None

    def test_a_hit_with_no_status_is_no_conclusion(self):
        hit = _resp(200, "x")
        hit.status_code = None
        v = catchall.control_probe(_Fake(lambda p: _resp(200, "x")), "http://192.0.2.10/api", hit)
        assert v.catch_all is None

    def test_an_unparsable_url_is_no_conclusion_and_sends_nothing(self):
        fetch = _Fake(lambda p: _resp(200))
        assert catchall.control_probe(fetch, "not a url", _resp(200)).catch_all is None
        assert fetch.urls == []

    def test_it_never_raises(self):
        v = catchall.control_probe(None, "http://192.0.2.10/api", _resp(200, "x"))
        assert v.catch_all is None


class TestTheControlUrl:
    def test_same_scheme_host_and_port_with_the_parent_prefix(self):
        fetch = _Fake(lambda p: _resp(404))
        catchall.control_probe(fetch, "https://app.example.com:8443/api/v1?x=1", _resp(200, "x"))
        url = fetch.urls[0]
        assert url.startswith("https://app.example.com:8443/api/rdm-")
        nonce = url.rsplit("/", 1)[1]
        assert len(nonce) == len("rdm-") + 12 and "?" not in url

    def test_a_top_level_path_is_controlled_at_the_root(self):
        fetch = _Fake(lambda p: _resp(404))
        catchall.control_probe(fetch, "http://192.0.2.10/graphql", _resp(200, "x"))
        assert fetch.urls[0].startswith("http://192.0.2.10/rdm-")

    def test_parent_prefix(self):
        assert catchall._parent_prefix("/api/v1") == "/api/"
        assert catchall._parent_prefix("/api/v1/") == "/api/"
        assert catchall._parent_prefix("/graphql") == "/"
        assert catchall._parent_prefix("/") == "/"
        assert catchall._parent_prefix("") == "/"


class TestTheCache:
    def test_one_control_per_host_and_prefix(self):
        fetch = _Fake(lambda p: _resp(404))
        cache = catchall.ControlCache()
        for path in ("/api/v1", "/api/v2"):
            catchall.control_probe(fetch, f"http://192.0.2.10{path}", _resp(200, "x"), cache=cache)
        catchall.control_probe(fetch, "http://192.0.2.10/graphql", _resp(200, "x"), cache=cache)
        catchall.control_probe(fetch, "http://192.0.2.11/api/v1", _resp(200, "x"), cache=cache)
        prefixes = sorted(u.rsplit("/", 1)[0] for u in fetch.urls)
        assert prefixes == ["http://192.0.2.10", "http://192.0.2.10/api", "http://192.0.2.11/api"]
        assert cache.requests == 3 and len(cache) == 3

    def test_a_cached_control_still_judges_each_hit(self):
        cache = catchall.ControlCache()
        fetch = _Fake(lambda p: _resp(200, NOT_FOUND_JSON))
        a = catchall.control_probe(fetch, "http://192.0.2.10/api/v1", _resp(200, NOT_FOUND_JSON), cache=cache)
        b = catchall.control_probe(fetch, "http://192.0.2.10/api/v2", _resp(200, '{"orders":[1,2,3],"n":3}'),
                                   cache=cache)
        assert (a.catch_all, b.catch_all) == (True, False)
        assert len(fetch.urls) == 1

    def test_a_failed_control_is_cached_too(self):
        calls = []

        def boom(url):
            calls.append(url)
            raise TimeoutError("slow")
        cache = catchall.ControlCache()
        for path in ("/api/v1", "/api/v2"):
            assert catchall.control_probe(boom, f"http://192.0.2.10{path}", _resp(200), cache=cache).catch_all is None
        assert len(calls) == 1

    def test_threads_share_one_control(self):
        gate = threading.Event()
        fetch_calls = []

        def slow(url):
            fetch_calls.append(url)
            gate.wait(1)
            return _resp(404)
        cache = catchall.ControlCache()
        threads = [threading.Thread(target=catchall.control_probe,
                                    args=(slow, f"http://192.0.2.10/api/v{i}", _resp(200, "x")),
                                    kwargs={"cache": cache}) for i in range(5)]
        for t in threads:
            t.start()
        gate.set()
        for t in threads:
            t.join()
        assert len(fetch_calls) == 1


class TestEngagementLimits:
    def test_an_roe_excluded_host_is_never_requested(self):
        fetch = _Fake(lambda p: _resp(200))
        v = catchall.control_probe(fetch, "https://admin.example.com/api", _resp(200, "x"),
                                   roe_excluded=["admin.example.com"])
        assert v.catch_all is None and "rules of engagement" in v.reason
        assert fetch.urls == []

    def test_an_roe_excluded_cidr_is_never_requested(self):
        fetch = _Fake(lambda p: _resp(200))
        catchall.control_probe(fetch, "http://192.0.2.10/api", _resp(200), roe_excluded=["192.0.2.0/24"])
        assert fetch.urls == []

    def test_a_guard_that_refuses_sends_nothing(self):
        fetch = _Fake(lambda p: _resp(200))
        seen = []
        v = catchall.control_probe(fetch, "http://169.254.169.254/latest", _resp(200),
                                   url_guard=lambda u: seen.append(u) or False)
        assert v.catch_all is None and "SSRF" in v.reason
        assert fetch.urls == [] and seen and seen[0].startswith("http://169.254.169.254/rdm-")

    def test_a_guard_that_raises_fails_closed(self):
        fetch = _Fake(lambda p: _resp(200))

        def guard(u):
            raise OSError("dns")
        assert catchall.control_probe(fetch, "http://192.0.2.10/api", _resp(200), url_guard=guard).catch_all is None
        assert fetch.urls == []

    def test_a_guard_that_allows_lets_the_control_go(self):
        fetch = _Fake(lambda p: _resp(404))
        v = catchall.control_probe(fetch, "http://192.0.2.10/api", _resp(200, "x"), url_guard=lambda u: True)
        assert v.catch_all is False and len(fetch.urls) == 1


CF_CHALLENGE = ('<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>'
                '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script></body></html>')
AKAMAI_DENY = ('<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>'
               'You don\'t have permission to access this server.<P>Reference&#32;&#35;18&#46;6bd3c917&#46;'
               '1696512345&#46;1a2b3c4d</BODY></HTML>')


class TestIsChallenge:
    def test_cf_mitigated_header(self):
        assert catchall.is_challenge(_resp(403, "", {"cf-mitigated": "challenge"}))

    def test_header_names_are_case_blind(self):
        assert catchall.is_challenge(_resp(403, "", {"CF-Mitigated": "challenge"}))

    def test_challenge_platform_in_the_body(self):
        assert catchall.is_challenge(_resp(403, CF_CHALLENGE))

    def test_just_a_moment_title(self):
        assert catchall.is_challenge(_resp(503, "<title>Just a moment...</title>"))

    def test_akamai_access_denied_with_a_reference(self):
        assert catchall.is_challenge(_resp(403, AKAMAI_DENY))

    def test_access_denied_without_a_reference_is_an_ordinary_page(self):
        assert not catchall.is_challenge(_resp(403, "<h1>Access Denied</h1><p>Login required</p>"))

    def test_a_cloudflare_block_page_without_a_challenge_is_not_one(self):
        """A plain block page (no cf-mitigated, no challenge platform) is the
        edge's answer, and other checks already read it as such."""
        assert not catchall.is_challenge(_resp(403, "<title>Attention Required! | Cloudflare</title>",
                                              {"cf-ray": "8a1b2c3d4e5f6a7b-FRA"}))

    def test_an_ordinary_page(self):
        assert not catchall.is_challenge(_resp(200, "<html><title>Shop</title></html>"))

    def test_only_the_first_64_kb_are_read(self):
        assert not catchall.is_challenge(_resp(200, "a" * (64 * 1024) + "challenge-platform"))
        assert catchall.is_challenge(_resp(200, "a" * (60 * 1024) + "challenge-platform"))

    def test_a_mock_header_object_is_not_a_challenge(self):
        """A non-str header value (a mock, a list) is never read as the marker."""
        r = mock.MagicMock()
        r.status_code = 200
        assert not catchall.is_challenge(r)


class TestChallengeInTheProbe:
    def test_a_challenged_hit_is_no_conclusion_and_sends_no_control(self):
        fetch = _Fake(lambda p: _resp(200))
        v = catchall.control_probe(fetch, "http://192.0.2.10/api", _resp(403, CF_CHALLENGE), note_module="vuln_scan")
        assert v.catch_all is None and v.reason == "challenge page"
        assert fetch.urls == []

    def test_a_challenged_control_is_no_conclusion(self):
        fetch = _Fake(lambda p: _resp(403, CF_CHALLENGE))
        v = catchall.control_probe(fetch, "http://192.0.2.10/api", _resp(200, "{}"))
        assert v.catch_all is None and v.reason == "challenge page"

    def test_a_challenged_host_is_one_coverage_gap(self):
        fetch = _Fake(lambda p: _resp(403, CF_CHALLENGE))
        for path in ("/api", "/v1", "/v2"):
            catchall.control_probe(fetch, f"http://192.0.2.10{path}", _resp(403, AKAMAI_DENY), note_module="vuln_scan")
        gaps = [g for g in cb.coverage_report().gaps if g["source"] == "challenge_blocked"]
        assert len(gaps) == 1
        assert gaps[0]["module"] == "vuln_scan" and gaps[0]["skipped"] == 1
        assert gaps[0]["reason"] == "192.0.2.10"

    def test_the_gap_has_no_prune_effect(self):
        catchall.note_challenge("vuln_scan", "192.0.2.10")
        report = cb.coverage_report()
        assert not report.degraded_sources and not report.skipped_hostnames()

    def test_no_note_module_records_nothing(self):
        catchall.control_probe(_Fake(lambda p: _resp(200)), "http://192.0.2.10/api", _resp(403, CF_CHALLENGE))
        assert not [g for g in cb.coverage_report().gaps if g["source"] == "challenge_blocked"]


class TestNormalising:
    def test_volatile_tokens_are_stripped(self):
        a = catchall.canonical_bytes(b"ray 8a1b2c3d4e5f6a7b at 2026-10-23T10:00:00Z id 3f2a1b4c-0000-4000-8000-123456789abc")
        b = catchall.canonical_bytes(b"ray 0f9e8d7c6b5a4938 at 2026-10-24 11:12:13 UTC id 11111111-2222-4333-8444-555555555555")
        assert a == b

    def test_hostnames_are_replaced(self):
        assert catchall.replace_hostnames(b"Unknown host shop.example.com", ["shop.example.com"]) == b"Unknown host {HOST}"

    def test_url_encoded_and_json_escaped_echoes(self):
        echoes = ["/api/v1"]
        assert catchall.normalise_body(b"next=%2Fapi%2Fv1", echoes=echoes) == b"next={ECHO}"
        assert catchall.normalise_body(b'"path":"\\/api\\/v1"', echoes=echoes) == b'"path":"{ECHO}"'

    def test_same_page_tolerates_a_small_change(self):
        page = b"<html><body>" + b"<p>Welcome to the shop, browse our catalogue.</p>" * 40
        assert catchall.same_page(page, page.replace(b"Welcome", b"Welcome!", 1))

    def test_same_page_rejects_a_length_far_apart(self):
        assert not catchall.same_page(b"x " * 100, b"x " * 400)

    def test_similarity_bounds(self):
        assert catchall.similarity(b"", b"") == 1.0
        assert catchall.similarity(b"a b c", b"a b c") == 1.0
        assert catchall.similarity(b"alpha beta", b"gamma delta") == 0.0
