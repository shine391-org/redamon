"""The pipeline prints a GROUP header for every phase, in order (plan 12.8).

The orchestrator takes a full scan's progress label from these headers only
(PIPELINE_HEADER_PHASES in recon_orchestrator/container_manager.py): tool
output can no longer move it. So every phase must start with a header the
table maps, and within one pipeline the mapped phases must never go down, or
the label would rewind. Read as source: the recon image does not carry the
orchestrator, and the order is the property under test.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
MAIN = (REPO / "recon" / "main.py").read_text()

# Helpers that print a header themselves, at the place they are called.
HELPER_HEADERS = {
    "_maybe_run_ai_surface(": "[*][Pipeline] GROUP 4.5: AI Surface Recon",
    "_maybe_run_supply_chain(": "[*][Pipeline] GROUP 5.5: Supply-Chain Recon",
    "_run_phase_a_fan_out(": "[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning",
}


def _header_table():
    source = (REPO / "recon_orchestrator" / "container_manager.py").read_text()
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", None) == "PIPELINE_HEADER_PHASES" for t in node.targets):
            return [(re.compile(p), number) for p, _name, number in ast.literal_eval(node.value)]
    raise AssertionError("PIPELINE_HEADER_PHASES not found in container_manager.py")


TABLE = _header_table()


def _phase(line: str):
    hits = [number for regex, number in TABLE if regex.search(line)]
    assert len(hits) <= 1, line
    return hits[0] if hits else None


def _function(name: str) -> str:
    tree = ast.parse(MAIN)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(MAIN, node)


def _phases_in_order(body: str) -> list:
    """The phase of every header a pipeline prints, in source order."""
    events = []
    for m in re.finditer(r'print\(f?"\\n\[\*\]\[Pipeline\] GROUP [^"]*"', body):
        events.append((m.start(), m.group(0).split('"', 1)[1].replace("\\n", "")))
    for call, header in HELPER_HEADERS.items():
        for m in re.finditer(re.escape(call), body):
            events.append((m.start(), header))
    return [_phase(line) for _pos, line in sorted(events)]


def test_every_header_the_pipeline_prints_is_mapped():
    headers = re.findall(r'\[\*\]\[Pipeline\] GROUP [^"]*', MAIN)
    assert headers
    unmapped = [h for h in headers if _phase(h) is None]
    assert unmapped == []


@pytest.mark.parametrize("pipeline, first, last", [
    ("run_domain_recon", 1, 5),
    ("run_ip_recon", 1, 5),
])
def test_each_pipeline_starts_every_phase_with_a_header_in_order(pipeline, first, last):
    phases = _phases_in_order(_function(pipeline))
    assert None not in phases
    assert phases == sorted(phases), phases
    assert phases[0] == first
    assert {2, 3, 4, 4.5, 5} <= set(phases)
    assert phases[-1] >= last


def test_the_domain_pipeline_reaches_mitre():
    assert _phases_in_order(_function("run_domain_recon"))[-1] == 6


def test_the_legacy_branch_keeps_its_phases_in_order():
    body = _function("run_domain_group")
    legacy = body[body.index('if "domain_discovery" in SCAN_MODULES:'):]
    phases = _phases_in_order(legacy)
    assert phases == sorted(phases), phases
    assert {2, 3, 4, 5} <= set(phases)


def test_ip_modes_prelude_reads_as_steps_not_phases():
    # Its PHASE 1..3 lines used to map to pipeline phases 1, 2 and 1 again.
    assert not re.search(r"\]\s*PHASE \d", MAIN)
    for step in re.findall(r"\[(?:DNS|WHOIS)\] IP STEP \d[^\"]*", MAIN):
        assert _phase(step) is None
