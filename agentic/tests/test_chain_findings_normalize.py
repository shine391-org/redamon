"""chain_findings normalisation: a confirmation is its ids.

The route exposure agent campaign (AG1, deepseek-v4-pro) re-recorded proven
leads as entries carrying finding_type, related_finding_ids and confidence but no
title or evidence, which the normaliser dropped as meaningless; the model kept
believing they were written. An entry that names the recon finding it proves is
kept; one that names nothing is still dropped.

The same campaign's real loss was elsewhere: analysing a single tool's output,
the model wrote a well-formed `chain_findings` beside `output_analysis` instead of
inside it, and the parser ignored the unknown top-level key. It is moved in.

Run: ./agentic/run_tests.sh tests/test_chain_findings_normalize.py
"""

import json

from orchestrator_helpers.parsing import try_parse_llm_decision


def _decision(chain_findings):
    return json.dumps({
        "thought": "t", "reasoning": "r", "action": "use_tool", "tool_name": "query_graph",
        "tool_args": {"question": "MATCH (n) RETURN n LIMIT 1"},
        "output_analysis": {"interpretation": "i", "chain_findings": chain_findings},
    })


def _findings(chain_findings):
    decision, error = try_parse_llm_decision(_decision(chain_findings))
    assert error is None, error
    return decision.output_analysis.chain_findings


def test_an_entry_with_ids_and_no_title_is_kept():
    [f] = _findings([{"finding_type": "vulnerability_confirmed",
                      "related_finding_ids": ["route_exposure_b37ac20e1becd5e443e974cf"], "confidence": 90}])
    assert f.related_finding_ids == ["route_exposure_b37ac20e1becd5e443e974cf"]
    assert f.title == "vulnerability_confirmed: route_exposure_b37ac20e1becd5e443e974cf"
    assert f.confidence == 90


def test_an_entry_naming_nothing_is_still_dropped():
    assert _findings([{"finding_type": "custom", "confidence": 60},
                      {"finding_type": "custom", "title": " ", "related_finding_ids": [" "]}]) == []


def test_one_id_as_a_bare_string_does_not_fail_the_decision():
    [f] = _findings([{"finding_type": "vulnerability_confirmed", "title": "t",
                      "related_finding_ids": "route_exposure_x", "confidence": 85}])
    assert f.related_finding_ids == ["route_exposure_x"]


def test_a_null_title_does_not_fail_the_decision():
    [f] = _findings([{"finding_type": "vulnerability_confirmed", "title": None, "evidence": "200/200 sha 1a2b",
                      "related_finding_ids": ["route_exposure_y"]}])
    assert f.related_finding_ids == ["route_exposure_y"]


def _parse(data):
    decision, error = try_parse_llm_decision(json.dumps({
        "thought": "t", "reasoning": "r", "action": "use_tool", "tool_name": "query_graph",
        "tool_args": {"question": "MATCH (n) RETURN n LIMIT 1"}, **data}))
    assert error is None, error
    return decision


PROOF = {"finding_type": "vulnerability_confirmed", "title": "t", "evidence": "200/200",
         "related_finding_ids": ["route_exposure_z"], "confidence": 90}


def test_top_level_chain_findings_move_into_output_analysis():
    decision = _parse({"output_analysis": {"interpretation": "i"}, "chain_findings": [PROOF]})
    [f] = decision.output_analysis.chain_findings
    assert f.related_finding_ids == ["route_exposure_z"]
    assert decision.output_analysis.interpretation == "i"


def test_top_level_chain_findings_join_the_nested_ones():
    nested = {**PROOF, "related_finding_ids": ["route_exposure_n"]}
    decision = _parse({"output_analysis": {"interpretation": "i", "chain_findings": [nested]},
                       "chain_findings": [PROOF]})
    ids = [f.related_finding_ids[0] for f in decision.output_analysis.chain_findings]
    assert ids == ["route_exposure_n", "route_exposure_z"]


def test_top_level_chain_findings_without_output_analysis_are_kept():
    decision = _parse({"chain_findings": [PROOF]})
    [f] = decision.output_analysis.chain_findings
    assert f.related_finding_ids == ["route_exposure_z"]


def test_an_empty_top_level_list_changes_nothing():
    assert _parse({"chain_findings": []}).output_analysis is None
