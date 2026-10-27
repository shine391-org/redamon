"""Chain-graph writes can no longer stall the agent.

Regression for the "agent stuck" incident (Neo4j at 300% CPU / 98.6% memory):
- every chain write used to run on asyncio's DEFAULT executor, the same pool
  that runs each Bedrock LLM call (sync boto3) and the DNS lookup behind every
  new outbound connection (asyncio getaddrinfo). Stalled writes filled it, so
  the LLM and new tool connections waited too, and the agent idled at ~0% CPU;
- each write first took a global lock and ran verify_connectivity();
- the think node awaited the ChainStep write with no bound, and the step's
  tool_complete only reaches the UI after that node returns, so the tool card
  stayed "Running" while the agent waited on Neo4j.

Run: ./agentic/run_tests.sh tests/test_chain_writer_isolation.py
"""
import asyncio
import importlib
import inspect
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from neo4j import Query  # noqa: E402
from neo4j.exceptions import ServiceUnavailable  # noqa: E402

import orchestrator_helpers.chain_graph_writer as cg  # noqa: E402


def _drain_writer(timeout: float = 10.0) -> None:
    """Wait until the shared writer thread has nothing queued."""
    end = time.monotonic() + timeout
    while cg.pending_writes() and time.monotonic() < end:
        time.sleep(0.01)
    assert cg.pending_writes() == 0, "writer thread still busy after test"


class _BlockedNeo4j:
    """Stands in for a write stuck on an overloaded Neo4j until released."""

    def __init__(self):
        self.release = threading.Event()
        self.entered = threading.Event()
        self.calls = []

    def write(self, label="w"):
        self.entered.set()
        self.release.wait(timeout=30)
        self.calls.append(label)


class DefaultExecutorStaysFree(unittest.IsolatedAsyncioTestCase):
    """The starvation mechanism, then proof the writer no longer causes it.

    A 4-thread default executor makes the effect deterministic (production
    gets min(32, cpus + 4) threads, so it takes more stalled writes, not fewer
    effects)."""

    async def asyncSetUp(self):
        self.loop = asyncio.get_running_loop()
        self.small_default = ThreadPoolExecutor(max_workers=4)
        self.loop.set_default_executor(self.small_default)
        self.neo4j = _BlockedNeo4j()

    async def asyncTearDown(self):
        self.neo4j.release.set()
        await asyncio.to_thread(_drain_writer)
        self.small_default.shutdown(wait=False, cancel_futures=True)

    async def _llm_call_and_dns_finish(self, within: float) -> bool:
        llm_call = self.loop.run_in_executor(None, lambda: "llm-response")
        dns = asyncio.ensure_future(self.loop.getaddrinfo("localhost", 80))
        done, pending = await asyncio.wait({llm_call, dns}, timeout=within)
        for p in pending:
            p.cancel()
        return not pending

    async def test_old_design_writes_on_the_default_executor_starve_llm_and_dns(self):
        # What every chain write used to do: run_in_executor(None, write).
        for i in range(4):
            self.loop.run_in_executor(None, self.neo4j.write, f"old-{i}")
        self.assertFalse(await self._llm_call_and_dns_finish(within=1.0),
                         "the starvation mechanism did not reproduce")

    async def test_new_design_stalled_writes_leave_llm_and_dns_untouched(self):
        for i in range(50):
            cg._fire_and_forget(self.neo4j.write, f"new-{i}", max_retries=0)
        self.assertTrue(await asyncio.to_thread(self.neo4j.entered.wait, 5))
        self.assertGreaterEqual(cg.pending_writes(), 50)
        self.assertTrue(await self._llm_call_and_dns_finish(within=1.0))


class BoundedAwaitedWrite(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await asyncio.to_thread(_drain_writer)

    async def test_fast_write_returns_true(self):
        ran = []
        ok = await cg.run_bounded_write(lambda: ran.append(1), wait_s=5)
        self.assertTrue(ok)
        self.assertEqual(ran, [1])

    async def test_stalled_write_stops_the_wait_but_still_lands_later(self):
        neo4j = _BlockedNeo4j()
        t0 = time.monotonic()
        ok = await cg.run_bounded_write(lambda: neo4j.write("step"), wait_s=0.3, label="t")
        self.assertFalse(ok)
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertEqual(neo4j.calls, [])
        neo4j.release.set()
        await asyncio.to_thread(_drain_writer)
        self.assertEqual(neo4j.calls, ["step"], "a timed-out wait must not cancel the write")

    async def test_a_stalled_writer_charges_the_wait_once_not_per_write(self):
        """A plan wave writes one ChainStep per tool. Behind one stuck write,
        each of them used to wait the full bound again."""
        neo4j = _BlockedNeo4j()
        first = await cg.run_bounded_write(lambda: neo4j.write("t1"), wait_s=0.3)
        self.assertFalse(first)
        t0 = time.monotonic()
        rest = [await cg.run_bounded_write(lambda i=i: neo4j.write(f"t{i}"), wait_s=0.3)
                for i in range(2, 7)]
        self.assertEqual(rest, [False] * 5, "queued, still to land")
        self.assertLess(time.monotonic() - t0, 0.2)
        neo4j.release.set()
        await asyncio.to_thread(_drain_writer)
        self.assertEqual(neo4j.calls, [f"t{i}" for i in range(1, 7)], "every write lands, in order")
        # Drained: the next awaited write is waited on normally again.
        self.assertTrue(await cg.run_bounded_write(lambda: None, wait_s=5))

    async def test_errors_raised_by_the_write_propagate(self):
        def boom():
            raise ValueError("cypher syntax")
        with self.assertRaises(ValueError):
            await cg.run_bounded_write(boom, wait_s=5)

    async def test_writes_keep_submission_order(self):
        order = []
        gate = _BlockedNeo4j()
        cg._fire_and_forget(gate.write, "first", max_retries=0)
        for i in range(20):
            cg._fire_and_forget(order.append, i, max_retries=0)
        gate.release.set()
        await asyncio.to_thread(_drain_writer)
        self.assertEqual(order, list(range(20)))


class BacklogCap(unittest.IsolatedAsyncioTestCase):
    async def test_writes_beyond_the_cap_are_dropped_and_counted(self):
        neo4j = _BlockedNeo4j()
        before = cg._failed_write_count
        with mock.patch.object(cg, "MAX_PENDING_WRITES", 3):
            for i in range(3):
                cg._fire_and_forget(neo4j.write, f"w{i}", max_retries=0)
            cg._fire_and_forget(neo4j.write, "dropped", max_retries=0)
            ok = await cg.run_bounded_write(lambda: None, wait_s=1)
            self.assertIsNone(ok, "a dropped write must say it will never exist")
            self.assertEqual(cg._failed_write_count, before + 2)
        neo4j.release.set()
        await asyncio.to_thread(_drain_writer)
        self.assertEqual(neo4j.calls, ["w0", "w1", "w2"])


class DriverAndSession(unittest.TestCase):
    def setUp(self):
        cg._discard_driver()

    def tearDown(self):
        cg._discard_driver()

    def test_driver_is_built_once_with_timeouts_and_never_pinged_per_write(self):
        fake = MagicMock()
        with mock.patch.object(cg.GraphDatabase, "driver", return_value=fake) as factory:
            for _ in range(5):
                self.assertIs(cg._get_driver("bolt://n:7687", "neo4j", "pw"), fake)
        factory.assert_called_once()
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["auth"], ("neo4j", "pw"))
        for key in ("connection_timeout", "connection_acquisition_timeout", "liveness_check_timeout"):
            self.assertIn(key, kwargs)
        fake.verify_connectivity.assert_not_called()

    def test_every_run_carries_a_server_side_transaction_timeout(self):
        driver = MagicMock()
        inner = driver.session.return_value.__enter__.return_value
        with cg._session(driver) as session:
            session.run("MERGE (s:ChainStep {step_id: $id})", {"id": "x"})
            prebuilt = Query("RETURN 1", timeout=5)
            session.run(prebuilt)
        first, second = inner.run.call_args_list
        q = first.args[0]
        self.assertIsInstance(q, Query)
        self.assertEqual(q.text, "MERGE (s:ChainStep {step_id: $id})")
        self.assertEqual(q.timeout, cg.CHAIN_TX_TIMEOUT_S)
        self.assertEqual(first.args[1], {"id": "x"})
        self.assertIs(second.args[0], prebuilt, "an explicit Query keeps its own timeout")

    def test_all_writer_sessions_use_the_bounded_session(self):
        src = inspect.getsource(cg)
        # Exactly one raw session: the one _session() wraps.
        self.assertEqual(src.count("driver.session()"), 1)
        self.assertIn("with driver.session() as session:\n        yield _BoundedSession(session)", src)
        self.assertGreaterEqual(src.count("with _session(driver) as session:"), 10)

    def test_connectivity_error_rebuilds_the_driver_then_retries(self):
        first, second = MagicMock(name="d1"), MagicMock(name="d2")
        attempts = []

        def write():
            drv = cg._get_driver("bolt://n", "u", "p")
            attempts.append(drv)
            if len(attempts) == 1:
                raise ServiceUnavailable("neo4j restarted")

        with mock.patch.object(cg.GraphDatabase, "driver", side_effect=[first, second]), \
                mock.patch.object(cg.time, "sleep"):
            cg._run_with_retry(write, (), {}, max_retries=1, retry_delay=0, sync=False)
        self.assertEqual(attempts, [first, second])
        first.close.assert_called_once()


class AwaitedWriteCallSites(unittest.TestCase):
    """Every awaited ChainStep write goes through run_bounded_write."""

    def test_no_awaited_write_uses_the_default_executor(self):
        from orchestrator_helpers.nodes import fireteam_member_think_node, think_node
        for mod in (think_node, fireteam_member_think_node):
            src = inspect.getsource(mod)
            with self.subTest(module=mod.__name__):
                self.assertNotIn("run_in_executor(", src)
                self.assertIn("chain_graph.run_bounded_write(", src)

    def test_prior_chains_read_is_off_the_event_loop_and_bounded(self):
        # The package re-exports the function under the module's name.
        mod = importlib.import_module("orchestrator_helpers.nodes.initialize_node")
        src = inspect.getsource(mod)
        self.assertIn("run_neo4j_read(", src)
        self.assertIn("chain_graph.query_prior_chains", src)
        self.assertIn("timeout=PRIOR_CHAINS_WAIT_S", src)


class GraphReadsHaveTheirOwnPool(unittest.IsolatedAsyncioTestCase):
    """query_graph, graph_summary and the prior-chains read are blocking
    Neo4j calls; a stalled read must not hold a default-executor thread."""

    async def test_reads_run_on_the_read_pool_and_leave_llm_and_dns_free(self):
        from neo4j_read_pool import run_neo4j_read

        loop = asyncio.get_running_loop()
        small_default = ThreadPoolExecutor(max_workers=2)
        loop.set_default_executor(small_default)
        stuck = threading.Event()
        names = []

        def stalled_read():
            names.append(threading.current_thread().name)
            stuck.wait(30)

        reads = [asyncio.ensure_future(run_neo4j_read(stalled_read)) for _ in range(4)]
        try:
            await asyncio.sleep(0.2)
            self.assertTrue(names and all(n.startswith("neo4j-read") for n in names), names)
            llm = loop.run_in_executor(None, lambda: "llm")
            dns = asyncio.ensure_future(loop.getaddrinfo("localhost", 80))
            done, pending = await asyncio.wait({llm, dns}, timeout=1.0)
            self.assertFalse(pending)
        finally:
            stuck.set()
            await asyncio.gather(*reads)
            small_default.shutdown(wait=False)

    def test_graph_tools_use_the_read_pool(self):
        import tools as tools_mod
        src = inspect.getsource(tools_mod)
        self.assertNotIn("asyncio.to_thread(manager.graph.query", src)
        # query_graph, and graph_summary's node, relationship and coverage reads.
        self.assertEqual(src.count("await run_neo4j_read("), 4)


class MemberNodeFinishesWhileNeo4jIsStuck(unittest.IsolatedAsyncioTestCase):
    """End-to-end through fireteam_member_think_node's plan-wave writes: with
    every ChainStep write stuck, the node still returns its analysis promptly
    instead of hanging until Neo4j recovers."""

    async def asyncTearDown(self):
        self.neo4j.release.set()
        await asyncio.to_thread(_drain_writer)

    async def test_node_returns_within_the_bounded_wait(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        self.neo4j = _BlockedNeo4j()
        analysis_json = '''
        {"thought":"t","reasoning":"r","action":"complete","completion_reason":"done",
         "output_analysis":{
           "interpretation":"two-tool recon wave",
           "extracted_info":{"primary_target":"10.0.0.1","ports":[22],"services":[],"technologies":[],"vulnerabilities":[],"credentials":[],"sessions":[]},
           "actionable_findings":[],"recommended_next_steps":[],
           "exploit_succeeded":false,"exploit_details":null,"chain_findings":[]
         }}'''
        llm = MagicMock()
        llm.ainvoke = AsyncMock(return_value=MagicMock(content=analysis_json))
        state = {
            "messages": [], "current_iteration": 1, "max_iterations": 10,
            "task_complete": False, "completion_reason": None,
            "current_phase": "informational", "attack_path_type": "cve_exploit",
            "user_id": "u", "project_id": "p", "session_id": "s",
            "parent_target_info": {}, "member_name": "Web Tester",
            "member_id": "member-0-abc", "fireteam_id": "fteam-1",
            "tools": ["xss"], "task": "scan target", "execution_trace": [],
            "target_info": {}, "chain_findings_memory": [], "chain_failures_memory": [],
            "_pending_confirmation": None, "tokens_used": 0, "_decision": None,
            "_current_step": None, "_last_chain_step_id": None, "_guardrail_blocked": False,
            "_current_plan": {
                "steps": [
                    {"tool_name": "execute_nmap", "tool_args": {}, "tool_output": "open 22",
                     "success": True, "iteration": 1},
                    {"tool_name": "execute_httpx", "tool_args": {}, "tool_output": "nginx",
                     "success": True, "iteration": 1},
                ],
                "wave_id": "wave-abc",
            },
        }
        with mock.patch.object(cg, "STEP_WRITE_WAIT_S", 0.3), \
                mock.patch.object(cg, "sync_record_step",
                                  side_effect=lambda *a, **kw: self.neo4j.write(kw["step_id"])), \
                mock.patch.object(cg, "fire_record_failure"), \
                mock.patch.object(cg, "fire_record_finding"):
            t0 = time.monotonic()
            update = await asyncio.wait_for(
                fireteam_member_think_node(state, None, llm=llm,
                                           neo4j_creds=("bolt://x", "u", "p"),
                                           streaming_callbacks=None),
                timeout=10,
            )
            elapsed = time.monotonic() - t0
            self.assertEqual(self.neo4j.calls, [], "nothing was written while Neo4j was stuck")
            # Neo4j recovers: the queued writes land, in order, while still patched.
            self.neo4j.release.set()
            await asyncio.to_thread(_drain_writer)
        self.assertLess(elapsed, 1.0, "the member paid the wait per step instead of once")
        self.assertEqual(len(update.get("execution_trace") or []), 2)
        self.assertEqual(len(self.neo4j.calls), 2, "the shielded writes were lost")


if __name__ == "__main__":
    unittest.main()
