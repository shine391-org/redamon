"""The route-exposure parts end to end inside the agent (plan §23.12, integration).

- get_phase_tools renders each skill's new part in the informational and the
  exploitation phase, and the exploitation-only recipes say so in the text;
- a think turn whose output_analysis carries a `vulnerability_confirmed` entry
  with an id and an `exploit_success` entry hands the id to the graph writer for
  the first and never writes the second, which is why RECORD_CONTRACT forbids
  ids on the exploit types (mocked writer, no Neo4j);
- the prompt's forbidden list is exactly the set both think nodes drop;
- a switch_skill decision to path_traversal validates.
"""

import ast
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))


def _load_recorder():
    spec = importlib.util.spec_from_file_location("record_skill_golden", _HERE / "tools" / "record_skill_golden.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recorder = _load_recorder()

SETTINGS = {
    "ROUTE_EXPOSURE_ENABLED": True,
    "PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True,
    "PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": True,
    "RCE_HEAPDUMP_ANALYSIS_ENABLED": True,
    "ROE_ALLOW_DATA_EXFILTRATION": True,
    "ROE_SENSITIVE_DATA_HANDLING": "limited_collection",
}
MARKERS = {
    "access_control": "ROUTE EXPOSURE LEADS",
    "path_traversal": "EXPOSED FILES RECON FOUND",
    "rce": "DEBUG CONSOLES AND ENDPOINTS RECON FOUND",
}
CANDIDATE_ID = "rex-0123456789abcdef"


class PhaseToolsRenderTheParts(unittest.TestCase):
    def _render(self, phase, skill, settings=SETTINGS):
        return recorder.render_phase_tools(phase, skill, settings, recorder.ALL_TOOLS, False, [])

    def test_each_part_renders_in_both_phases(self):
        for skill, marker in MARKERS.items():
            for phase in ("informational", "exploitation"):
                with self.subTest(skill=skill, phase=phase):
                    self.assertIn(marker, self._render(phase, skill))

    def test_off_renders_no_part(self):
        for skill, marker in MARKERS.items():
            with self.subTest(skill=skill):
                self.assertNotIn(marker, self._render("exploitation", skill, {}))

    def test_informational_phase_marks_the_exploitation_only_steps(self):
        # A built-in skill renders the same text in every phase, so the steps
        # that need exploitation must say so themselves.
        text = self._render("informational", "access_control")
        self.assertIn("EXPLOITATION phase only", text)
        pt = self._render("informational", "path_traversal")
        self.assertIn("RECONSTRUCT AN EXPOSED .git", pt)
        self.assertIn("EXPLOITATION phase", pt[pt.index("RECONSTRUCT AN EXPOSED .git"):])
        rce = self._render("informational", "rce")
        self.assertIn("EXPLOITATION phase", rce[rce.index("ANALYSE AN EXPOSED HEAP DUMP"):])


def _overlap_sets():
    """The exploit-type sets each think node skips when an exploit succeeded."""
    found = {}
    for rel in ("orchestrator_helpers/nodes/think_node.py", "orchestrator_helpers/nodes/fireteam_member_think_node.py"):
        tree = ast.parse((_HERE.parent / rel).read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in ("_EXPLOIT_OVERLAP_TYPES", "_EXPLOIT_OVERLAP")):
                found.setdefault(rel, []).append(frozenset(ast.literal_eval(node.value)))
    return found


class TheRecordContractMatchesTheCode(unittest.TestCase):
    def test_the_forbidden_types_are_the_dropped_ones(self):
        from prompts.route_exposure_shared import RECORD_CONTRACT
        sets = _overlap_sets()
        self.assertEqual(set(sets), {"orchestrator_helpers/nodes/think_node.py",
                                     "orchestrator_helpers/nodes/fireteam_member_think_node.py"})
        dropped = {s for group in sets.values() for s in group}
        self.assertEqual(len(dropped), 1, "the think nodes disagree on what they drop")
        line = next(ln for ln in RECORD_CONTRACT.splitlines() if "NEVER put ids on" in ln)
        named = {t for t in ("exploit_success", "access_gained", "credential_found") if f"`{t}`" in line}
        self.assertEqual(frozenset(named), next(iter(dropped)))


class AThinkTurnRecordsTheProof(unittest.IsolatedAsyncioTestCase):
    def _state(self):
        return {
            "messages": [], "current_iteration": 3, "max_iterations": 20,
            "task_complete": False, "completion_reason": None,
            "current_phase": "exploitation", "attack_path_type": "access_control",
            "user_id": "u", "project_id": "p", "session_id": "s",
            "parent_target_info": {},
            "member_name": "Route Checker", "member_id": "member-0-rex", "fireteam_id": "fteam-rex",
            "tools": ["execute_curl", "execute_code"], "task": "confirm the route exposure leads",
            "execution_trace": [], "target_info": {}, "chain_findings_memory": [], "chain_failures_memory": [],
            "_pending_confirmation": None, "_current_plan": None, "tokens_used": 0, "_decision": None,
            "_current_step": {
                "tool_name": "execute_code", "tool_args": {"code": "print('derived facts only')"},
                "tool_output": "anon=200 authed=200 records=12 keys=email,name owner_match=0", "success": True,
                "iteration": 3, "thought": "read the body file", "reasoning": "counts only",
                "error_message": None,
            },
            "_last_chain_step_id": None, "_guardrail_blocked": False,
        }

    async def test_the_id_rides_only_on_the_proof_type(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node
        decision = '''
        {"thought": "t", "reasoning": "r", "action": "complete", "completion_reason": "confirmed",
         "output_analysis": {
           "interpretation": "the export serves other users' records to anyone",
           "extracted_info": {"primary_target": "", "ports": [], "services": [], "technologies": [],
                              "vulnerabilities": [], "credentials": [], "sessions": []},
           "actionable_findings": [], "recommended_next_steps": [],
           "exploit_succeeded": true,
           "exploit_details": {"attack_type": "access_control", "target_ip": "192.0.2.10", "target_port": 80,
                               "cve_ids": [], "evidence": "12 records, 0 owned by the caller"},
           "chain_findings": [
             {"finding_type": "vulnerability_confirmed", "severity": "high",
              "title": "Unauthenticated export of user records", "evidence": "anon 200, 12 records, keys email,name",
              "related_cves": [], "related_ips": [], "related_finding_ids": ["''' + CANDIDATE_ID + '''"],
              "confidence": 90},
             {"finding_type": "exploit_success", "severity": "high",
              "title": "Read another user's records", "evidence": "owner_match=0",
              "related_cves": [], "related_ips": [], "related_finding_ids": ["rex-should-be-lost"],
              "confidence": 90}
           ]}}'''
        llm = MagicMock()
        llm.ainvoke = AsyncMock(return_value=MagicMock(content=decision))
        findings, exploits = [], []
        base = "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph."
        with patch(base + "fire_record_step", side_effect=lambda *a, **kw: None), \
                patch(base + "fire_resolve_step_bridges", side_effect=lambda *a, **kw: None), \
                patch(base + "fire_record_exploit_success", side_effect=lambda *a, **kw: exploits.append(kw)), \
                patch(base + "fire_record_finding", side_effect=lambda *a, **kw: findings.append(kw)):
            await fireteam_member_think_node(self._state(), None, llm=llm,
                                             neo4j_creds=("bolt://x", "u", "p"), streaming_callbacks=None)
        self.assertEqual([f["finding_type"] for f in findings], ["vulnerability_confirmed"])
        self.assertEqual(findings[0]["related_finding_ids"], [CANDIDATE_ID])
        self.assertEqual(len(exploits), 1)
        self.assertNotIn("related_finding_ids", exploits[0])
        self.assertNotIn("rex-should-be-lost", repr(findings) + repr(exploits))


class TheHandoffValidates(unittest.TestCase):
    def test_switch_to_path_traversal_and_rce(self):
        from state import LLMDecision, SkillSwitchDecision
        for target in ("path_traversal", "rce"):
            with self.subTest(target=target):
                switch = SkillSwitchDecision(to_skill=target, reason="recon flagged an exposed file")
                decision = LLMDecision(thought="t", reasoning="r", action="switch_skill", skill_switch=switch)
                self.assertEqual(decision.skill_switch.to_skill, target)


if __name__ == "__main__":
    unittest.main()
