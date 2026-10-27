"""tool_finished: the UI learns a standalone tool returned BEFORE the next turn.

Regression for session 071a0c7d of the "agent stuck" incident: tradecraft_lookup
returned in 12s and its raw output reached the UI, but the card kept "Running"
for minutes, because tool_complete is only emitted after the NEXT think turn
(LLM analysis + ChainStep write) and that turn stalled. The step now emits
tool_finished as soon as execute_tool_node returns, and every root tool event
carries the step_id the frontend pairs cards by.

Run: ./agentic/run_tests.sh tests/test_tool_finished_streaming.py
"""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import websocket_api  # noqa: E402
from orchestrator_helpers.member_streaming import MemberScopedCallback  # noqa: E402
from orchestrator_helpers.streaming import emit_streaming_events  # noqa: E402
from websocket_api import StreamingCallback, WebSocketConnection  # noqa: E402


class _FakeWS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


def _callback():
    conn = WebSocketConnection(_FakeWS())
    conn.user_id, conn.project_id, conn.session_id = "u", "p", "s"
    conn.authenticated = True
    return StreamingCallback(conn), conn.websocket


def _types(ws):
    return [m["type"] for m in ws.sent]


def _of(ws, msg_type):
    return [m["payload"] for m in ws.sent if m["type"] == msg_type]


STEP_ID = "a1b2c3d4"
PLANNED = {
    "step_id": STEP_ID, "iteration": 1, "phase": "informational",
    "thought": "lookup the PoC", "reasoning": "user asked",
    "tool_name": "tradecraft_lookup",
    "tool_args": {"resource_id": "php2shell-poc", "cve_id": "CVE-2026-109618"},
    "tool_output": None, "success": True,
}
RETURNED = {**PLANNED, "tool_output": "PoC not found for CVE-2026-109618 in resource 'php2shell-poc'.",
            "duration_ms": 12000}


class ToolFinishedTimeline(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.saved = []

        async def fake_save(**kw):
            self.saved.append((kw["msg_type"], kw["data"]))

        p = patch.object(websocket_api, "save_chat_message", side_effect=fake_save)
        p.start()
        self.addCleanup(p.stop)
        self.cb, self.ws = _callback()

    async def _persisted(self):
        await self.cb.flush_persist_queue(timeout=5)
        return self.saved

    async def test_incident_timeline(self):
        # think node yields: the step is planned, the tool has not run.
        await emit_streaming_events({"current_phase": "informational", "_current_step": PLANNED}, self.cb)
        self.assertIn("tool_start", _types(self.ws))
        self.assertNotIn("tool_finished", _types(self.ws), "finished before the tool ran")

        # execute_tool_node yields: the tool returned in 12s.
        returned_state = {"current_phase": "informational", "_current_step": RETURNED}
        await emit_streaming_events(returned_state, self.cb)
        chunk = _of(self.ws, "tool_output_chunk")
        self.assertEqual(len(chunk), 1)
        self.assertEqual(chunk[0]["step_id"], STEP_ID)
        finished = _of(self.ws, "tool_finished")
        self.assertEqual(finished, [{"tool_name": "tradecraft_lookup", "success": True,
                                     "duration_ms": 12000, "step_id": STEP_ID}])
        self.assertNotIn("tool_complete", _types(self.ws))

        # LangGraph can yield the same state again: no duplicates.
        await emit_streaming_events(returned_state, self.cb)
        self.assertEqual(len(_of(self.ws, "tool_finished")), 1)
        self.assertEqual(len(_of(self.ws, "tool_output_chunk")), 1)

        # The next think turn completes: tool_complete pairs by the same step_id.
        await emit_streaming_events({
            "current_phase": "informational",
            "_completed_step": {**RETURNED, "output_analysis": "no PoC indexed"},
            "_current_step": {**PLANNED, "step_id": "next0001", "tool_args": {"q": 2}},
        }, self.cb)
        complete = _of(self.ws, "tool_complete")
        self.assertEqual(len(complete), 1)
        self.assertEqual(complete[0]["step_id"], STEP_ID)
        order = [t for t in _types(self.ws) if t.startswith("tool_")]
        self.assertEqual(order[:4], ["tool_start", "tool_output_chunk", "tool_finished", "tool_complete"])

        persisted = [t for t, _ in await self._persisted()]
        self.assertIn("tool_finished", persisted)
        self.assertLess(persisted.index("tool_start"), persisted.index("tool_finished"))
        self.assertLess(persisted.index("tool_finished"), persisted.index("tool_complete"))

    async def test_empty_output_still_finishes_without_a_chunk(self):
        await emit_streaming_events({"_current_step": {**RETURNED, "tool_output": ""}}, self.cb)
        self.assertEqual(_of(self.ws, "tool_output_chunk"), [])
        self.assertEqual(len(_of(self.ws, "tool_finished")), 1)

    async def test_failed_tool_reports_failure(self):
        await emit_streaming_events({"_current_step": {**RETURNED, "success": False}}, self.cb)
        self.assertIs(_of(self.ws, "tool_finished")[0]["success"], False)

    async def test_rejected_tool_and_pending_confirmation_emit_nothing(self):
        await emit_streaming_events({"_current_step": {**RETURNED, "tool_name": "tool_rejection"}}, self.cb)
        await emit_streaming_events({"_current_step": RETURNED, "awaiting_tool_confirmation": True}, self.cb)
        self.assertEqual(_of(self.ws, "tool_finished"), [])


class MemberAndLegacyCallbacks(unittest.IsolatedAsyncioTestCase):
    async def test_member_steps_never_reach_root_tool_cards(self):
        real = MagicMock()
        real.on_fireteam_tool_start = AsyncMock()
        real.on_fireteam_tool_output_chunk = AsyncMock()
        real.on_tool_finished = AsyncMock()
        real.on_tool_output_chunk = AsyncMock()
        member = MemberScopedCallback(real, fireteam_id="ft", member_id="m0", member_name="Web")
        await emit_streaming_events({"_current_step": RETURNED}, member)
        real.on_tool_finished.assert_not_called()
        real.on_tool_output_chunk.assert_not_called()
        real.on_fireteam_tool_output_chunk.assert_awaited_once()
        self.assertEqual(real.on_fireteam_tool_output_chunk.await_args.kwargs["chunk"], RETURNED["tool_output"])

    async def test_a_callback_without_the_event_still_gets_the_rest(self):
        """Mock-style callbacks (no tool_finished set) must not abort emission."""
        cb = MagicMock()
        for name in ("on_phase_update", "on_todo_update", "on_tool_start", "on_tool_output_chunk",
                     "on_thinking", "on_task_complete", "on_tool_complete", "on_execution_step"):
            setattr(cb, name, AsyncMock())
        for name in ("_emitted_tool_start_ids", "_emitted_tool_output_ids",
                     "_emitted_tool_complete_ids", "_emitted_thinking_ids"):
            setattr(cb, name, set())
        cb._emitted_approval_key = cb._emitted_question_key = cb._emitted_tool_confirmation_key = None
        await emit_streaming_events({
            "_current_step": RETURNED, "task_complete": True, "_report_generated": True,
        }, cb)
        cb.on_tool_output_chunk.assert_awaited_once()
        cb.on_task_complete.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
