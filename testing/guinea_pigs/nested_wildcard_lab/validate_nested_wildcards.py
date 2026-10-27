#!/usr/bin/env python3
"""Assert expected_results.yaml for one scenario project, through the MCP server.

    validate_nested_wildcards.py <scenario> <projectId>      # e.g. U3 cmabc...

Prints PASS/FAIL per check and exits 1 on any FAIL. Every check is a read-only
Cypher run through query_graph (the token needs graph:cypher; the server scopes
it to the project). The token comes from MCP_SERVER_TOKEN_LAB (see nwlab_mcp.py).
A check with `recon_json: <dotted.path>` reads the run's recon JSON
(recon/output/recon_<projectId>.json) instead of the graph.
Needs PyYAML (present on the host and in the recon image).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nwlab_mcp  # noqa: E402

EXPECTED = Path(__file__).resolve().parent / "expected_results.yaml"
RECON_OUTPUT = Path(__file__).resolve().parents[3] / "recon" / "output"


def _values(project_id: str, cypher: str) -> list:
    return [row.get("v") for row in nwlab_mcp.cypher_rows(project_id, cypher)]


def _recon_json_values(project_id: str, path: str) -> list:
    """The keys (a dict) or items (a list) at a dotted path of the run's recon
    JSON. What the run TARGETED is there and nowhere in the graph when no
    writer turns a name into a node (a certificate SAN merged after httpx)."""
    node = json.loads((RECON_OUTPUT / f"recon_{project_id}.json").read_text())
    for key in path.split("."):
        node = (node or {}).get(key) if isinstance(node, dict) else None
    if isinstance(node, dict):
        return list(node)
    return list(node) if isinstance(node, list) else []


def values_for(project_id: str, check: dict) -> list:
    if "recon_json" in check:
        return _recon_json_values(project_id, check["recon_json"])
    return _values(project_id, check["cypher"])


def evaluate(check: dict, values: list) -> tuple[bool, str]:
    got = set(map(str, values))
    if "equals" in check:
        want = set(map(str, check["equals"]))
        return got == want, f"missing={sorted(want - got)} extra={sorted(got - want)}"
    if "superset" in check:
        missing = sorted(set(map(str, check["superset"])) - got)
        return not missing, f"missing={missing}"
    if "disjoint" in check:
        present = sorted(set(map(str, check["disjoint"])) & got)
        return not present, f"present={present}"
    if "true" in check:
        return values == [True], f"rows={values}"
    if "count" in check:
        return len(values) == check["count"], f"rows={len(values)} sample={values[:5]}"
    raise ValueError(f"check {check.get('id')} has no assertion")


def checks_for(spec: dict, name: str) -> list[dict]:
    scenario = spec["scenarios"][name]
    if "same_as" in scenario:
        return checks_for(spec, scenario["same_as"])
    checks = list(scenario.get("checks", []))
    if scenario.get("common"):
        checks += spec.get("common_checks", [])
    return checks


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    name, project_id = sys.argv[1], sys.argv[2]
    spec = yaml.safe_load(EXPECTED.read_text())
    if name not in spec["scenarios"]:
        print(f"unknown scenario {name}; known: {sorted(spec['scenarios'])}")
        return 2

    failed = 0
    for check in checks_for(spec, name):
        try:
            ok, detail = evaluate(check, values_for(project_id, check))
        except (nwlab_mcp.ToolError, OSError, ValueError) as e:
            ok, detail = False, f"query failed: {e}"
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}.{check['id']}" + ("" if ok else f"  {detail}"))
    print(f"\n{name}: {'PASS' if not failed else f'{failed} FAIL'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
