"""finding_guard: a confirmation the model wrote as an actionable line.

The route exposure agent campaign (AG1, deepseek-v4-pro) lost proven leads:
the model wrote "Record vulnerability_confirmed for <id>" under
actionable_findings, which keeps a note without an id and writes no CONFIRMS
edge. The guard names those lines in the next prompt and writes nothing itself.

Run: ./agentic/run_tests.sh tests/test_finding_guard.py
"""

from pathlib import Path

from orchestrator_helpers.finding_guard import unrecorded_confirmations, unrecorded_note
from state import ChainFindingExtract, OutputAnalysisInline

AGENTIC = Path(__file__).resolve().parents[1]


def _analysis(actionable, chain=()):
    return OutputAnalysisInline(actionable_findings=list(actionable), chain_findings=list(chain))


def test_the_campaign_lines_are_caught():
    lines = [
        "Record vulnerability_confirmed for old_version lead route_exposure_3f35a1998555d8eca376c1b7",
        "Record /api/admin/export as a confirmed function-level authorization bypass.",
        "Seven leads are recorded as vulnerability_confirmed in this response.",
    ]
    assert unrecorded_confirmations(_analysis(lines)) == lines


def test_a_recorded_chain_finding_silences_the_guard():
    chain = [ChainFindingExtract(finding_type="vulnerability_confirmed", related_finding_ids=["route_exposure_x"])]
    assert unrecorded_confirmations(_analysis(["Record the rest next."], chain)) is None


def test_ordinary_actionable_lines_are_not_flagged():
    lines = ["Issue anonymous vs authenticated GET pairs for all 8 leads",
             "The recorder service on port 8080 is exposed", "Re-run the query with a smaller page"]
    assert unrecorded_confirmations(_analysis(lines)) is None
    assert unrecorded_confirmations(None) is None


def test_the_note_is_bounded():
    many = [f"Record lead {i} " + "x" * 400 for i in range(9)]
    lines = unrecorded_confirmations(_analysis(many))
    assert len(lines) == 5 and all(len(line) == 200 for line in lines)


def test_the_note_says_where_a_confirmation_goes():
    note = unrecorded_note(["Record /api/admin/export as confirmed"])
    assert "- Record /api/admin/export as confirmed" in note
    assert "That records NOTHING" in note
    assert "`output_analysis.chain_findings`" in note and "related_finding_ids" in note


def test_the_think_node_sets_it_after_every_analysis_and_shows_it_next_turn():
    src = (AGENTIC / "orchestrator_helpers" / "nodes" / "think_node.py").read_text()
    # Set once, before the single-tool and the plan-wave branches, from the same analysis.
    pre = src.index('updates["_unrecorded_confirmation"] = unrecorded_confirmations(decision.output_analysis)')
    assert src.rindex("if has_pending_output or has_pending_plan_outputs:", 0, pre) > 0
    assert pre < src.index("    # Process output analysis if we had pending tool output")
    # Rendered from state into the next system prompt.
    assert 'system_prompt += unrecorded_note(_unrecorded)' in src


def test_the_state_carries_the_key():
    from state import AgentState
    assert "_unrecorded_confirmation" in AgentState.__annotations__
    state_src = (AGENTIC / "state.py").read_text()
    assert '"_unrecorded_confirmation": None' in state_src
