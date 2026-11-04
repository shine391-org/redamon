"""A scan container that dies says how: an OOM kill is named, not left as "code 137".

The webapp shows ``state.error`` as the run's reason (log drawer, Other Scans,
AI Gauntlet). Before this, every non-zero exit read "Container exited with code
N", so a scanner the kernel killed for memory looked like any other crash.

    ./redamon.sh test unit   (recon_orchestrator section)
"""
import unittest
from unittest.mock import MagicMock, patch

import container_manager as cm
from container_manager import ContainerManager, container_exit_reason
from models import AiAttackSurfaceState, AiAttackSurfaceStatus


class TestContainerExitReason(unittest.TestCase):
    def test_plain_failure_keeps_the_exit_code(self):
        self.assertEqual(container_exit_reason(1), "Container exited with code 1")

    def test_oom_flag_names_out_of_memory(self):
        self.assertEqual(
            container_exit_reason(137, oom_killed=True),
            "Container exited with code 137: killed (out of memory)",
        )

    def test_137_without_the_flag_is_likely_memory_not_certain(self):
        self.assertEqual(
            container_exit_reason(137),
            "Container exited with code 137: killed (SIGKILL, likely out of memory)",
        )

    def test_oom_flag_wins_whatever_the_code(self):
        # A process can catch the OOM kill of a child and exit with its own code.
        self.assertEqual(
            container_exit_reason(1, oom_killed=True),
            "Container exited with code 1: killed (out of memory)",
        )

    def test_reads_the_state_docker_reported(self):
        container = MagicMock()
        container.attrs = {"State": {"ExitCode": 137, "OOMKilled": True}}
        self.assertEqual(cm._exit_reason_of(container), "Container exited with code 137: killed (out of memory)")

    def test_a_missing_state_is_still_a_sentence(self):
        container = MagicMock()
        container.attrs = {}
        self.assertEqual(cm._exit_reason_of(container), "Container exited with code -1")

    def test_only_a_real_true_counts_as_oom(self):
        container = MagicMock()
        container.attrs = {"State": {"ExitCode": 2, "OOMKilled": "false"}}
        self.assertEqual(cm._exit_reason_of(container), "Container exited with code 2")


def _manager():
    with patch("container_manager.docker") as md:
        md.from_env.return_value = MagicMock()
        mgr = ContainerManager()
    mgr.client = MagicMock()
    mgr.local_llm_manager = MagicMock()
    return mgr


class TestStateErrorAtTheRefreshSites(unittest.TestCase):
    """Two refresh sites end to end; the other five share the same one-line call."""

    def test_ai_attack_run_killed_for_memory(self):
        mgr = _manager()
        dead = MagicMock(status="exited", attrs={"State": {"ExitCode": 137, "OOMKilled": True}})
        mgr.client.containers.get.return_value = dead
        state = AiAttackSurfaceState(
            project_id="p1", run_id="r1", status=AiAttackSurfaceStatus.RUNNING, container_id="c1",
        )
        with patch.object(mgr, "_release_llm"):
            mgr._refresh_ai_attack_state(state)
        self.assertEqual(state.status, AiAttackSurfaceStatus.ERROR)
        self.assertEqual(state.error, "Container exited with code 137: killed (out of memory)")

    def test_supply_chain_run_with_a_plain_failure(self):
        mgr = _manager()
        mgr.client.containers.get.return_value = MagicMock(
            status="exited", attrs={"State": {"ExitCode": 3, "OOMKilled": False}},
        )
        from models import SupplyChainState, SupplyChainStatus
        mgr.supply_chain_states["p1"] = SupplyChainState(
            project_id="p1", status=SupplyChainStatus.RUNNING, container_id="c1",
        )
        state = mgr._get_supply_chain_status_sync("p1")
        self.assertEqual(state.status, SupplyChainStatus.ERROR)
        self.assertEqual(state.error, "Container exited with code 3")


if __name__ == "__main__":
    unittest.main()
