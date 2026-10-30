"""The triage run's heartbeat: what it sends, and when.

A caller that is not the run's own tab (an MCP agent polling
get_triage_status, another tab) learns the run's phase only from the
heartbeat, so a phase change must reach the webapp without waiting a full
HEARTBEAT_SECONDS, or a short phase is never seen at all.
"""
import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import run_client  # noqa: E402


class _Response:
    def __init__(self, body):
        self.content = b"x"
        self._body = body

    def json(self):
        return self._body


class _FakeClient:
    """Stands in for httpx.AsyncClient and records every heartbeat body."""

    calls: list = []
    reply: dict = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeClient.calls.append((url, dict(json or {})))
        return _Response(_FakeClient.reply)


class TestHeartbeat(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        _FakeClient.calls = []
        _FakeClient.reply = {}
        patches = [
            mock.patch.object(run_client.httpx, "AsyncClient", _FakeClient),
            mock.patch.object(run_client, "HEARTBEAT_SECONDS", 30),
            mock.patch.object(run_client, "PHASE_HEARTBEAT_MIN_GAP", 0),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = run_client.TriageRunClient("p1", "u1")
        self.client.run_id = "run-1"

    async def asyncTearDown(self):
        await self.client.stop_heartbeat()

    async def _settle(self):
        for _ in range(20):
            await asyncio.sleep(0)

    async def test_a_phase_change_heartbeats_at_once_with_the_phase(self):
        self.client.start_heartbeat()
        self.client.set_progress("scoring", 10)
        await self._settle()
        self.assertEqual(len(_FakeClient.calls), 1)
        url, body = _FakeClient.calls[0]
        self.assertTrue(url.endswith("/api/internal/triage-runs/run-1/heartbeat"))
        self.assertEqual(body, {"phase": "scoring", "progress": 10})

    async def test_the_first_phase_beat_is_not_held_by_the_gap(self):
        """A run can finish in two seconds; its first phase must still get out."""
        with mock.patch.object(run_client, "PHASE_HEARTBEAT_MIN_GAP", 60):
            self.client.start_heartbeat()
            self.client.set_progress("scoring", 10)
            await self._settle()
            self.assertEqual(len(_FakeClient.calls), 1)
            self.client.set_progress("grouping", 20)
            await self._settle()
            self.assertEqual(len(_FakeClient.calls), 1, "the second beat waits out the gap")

    async def test_progress_within_one_phase_waits_for_the_interval(self):
        self.client.set_progress("reviewing", 40)
        self.client.start_heartbeat()
        await self._settle()
        _FakeClient.calls = []
        self.client._phase_changed.clear()
        self.client.set_progress("reviewing", 55)
        await self._settle()
        self.assertEqual(_FakeClient.calls, [])

    async def test_an_abort_reply_is_honoured(self):
        _FakeClient.reply = {"abort": True, "reason": "stopped from another tab"}
        self.client.start_heartbeat()
        self.client.set_progress("grouping", 20)
        await self._settle()
        self.assertTrue(self.client.aborted)
        with self.assertRaises(run_client.TriageRunAborted):
            self.client.check_abort()

    async def test_the_phase_is_bounded(self):
        self.client.set_progress("x" * 100, 250)
        self.assertEqual(len(self.client.phase), 40)
        self.assertEqual(self.client.progress, 100)


if __name__ == "__main__":
    unittest.main()


class _StatusResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.content = b"x"

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class _AnsweringClient(_FakeClient):
    answer = None

    async def post(self, url, json=None, headers=None):
        if isinstance(_AnsweringClient.answer, Exception):
            raise _AnsweringClient.answer
        return _AnsweringClient.answer


class TestARefusalCarriesTheWebappsOwnReason(unittest.IsolatedAsyncioTestCase):
    """G-33: the tab used to get one fixed sentence for every refusal."""

    def setUp(self):
        patcher = mock.patch.object(run_client.httpx, "AsyncClient", _AnsweringClient)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = run_client.TriageRunClient("p1", "u1")

    async def _refusal(self):
        with self.assertRaises(run_client.TriageRunAborted) as raised:
            await self.client.authorize("m", "v")
        return raised.exception

    async def test_a_409_keeps_the_webapps_sentence_and_the_status(self):
        _AnsweringClient.answer = _StatusResponse(
            409, {"error": "A version activation is in progress for this project."})
        refusal = await self._refusal()
        self.assertEqual(refusal.error_class, "authorize_failed")
        self.assertEqual(refusal.public_reason,
                         "A version activation is in progress for this project.")
        self.assertEqual(refusal.details, {"upstream_status": 409})

    async def test_a_5xx_body_is_never_shown(self):
        _AnsweringClient.answer = _StatusResponse(500, {"error": "Prisma said P2024 for x"})
        refusal = await self._refusal()
        self.assertEqual(refusal.public_reason, "")
        self.assertEqual(refusal.details, {"upstream_status": 500})

    async def test_an_unreachable_webapp_names_the_class_not_the_message(self):
        _AnsweringClient.answer = ConnectionError("connect to http://webapp:3000 failed")
        refusal = await self._refusal()
        self.assertEqual(refusal.public_reason, "The webapp could not be reached.")
        self.assertEqual(refusal.details, {"error_class": "ConnectionError"})

    async def test_a_publish_refusal_keeps_its_class_and_reason(self):
        self.client.run_id = "r1"
        _AnsweringClient.answer = _StatusResponse(
            409, {"error": "The run stopped checking in.", "errorClass": "agent_lost"})
        with self.assertRaises(run_client.TriageRunAborted) as raised:
            await self.client.claim_publish()
        self.assertEqual(raised.exception.error_class, "agent_lost")
        self.assertEqual(raised.exception.public_reason, "The run stopped checking in.")
