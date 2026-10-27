"""The Red Zone "network initial access" table reads the Python constants' ports
and finding types, not a hand copy of them (drift-map #25).

webapp/src/app/api/analytics/redzone/netInitAccess/route.ts keeps PORT_CATEGORY
and NET_VULN_TYPES in TypeScript. When security_checks.py flagged a port the TS
did not list, the finding showed with no category; a finding type it did not
list would not show at all. Both sides are read from source: security_checks.py
by AST (its constants and the "type" literals of the IP-level checks), the route
by regex, so neither list is copied into this test.

Run: ./redamon.sh test unit (recon section; the whole repo is mounted at /repo)
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SECURITY_CHECKS = PROJECT_ROOT / "recon" / "helpers" / "security_checks.py"
ROUTE = (PROJECT_ROOT / "webapp" / "src" / "app" / "api" / "analytics"
         / "redzone" / "netInitAccess" / "route.ts")

#: Python-probed ports the table deliberately leaves uncategorised.
UNCATEGORISED_PORTS = {
    443: "only probed by the Kubernetes check; categorising it lists every HTTPS service",
}

#: IP-level finding types the table deliberately leaves out.
NOT_INITIAL_ACCESS_TYPES = {
    "cache_purge_exposed": (
        "a cache-DoS misconfiguration, not an access vector: it is a finding of "
        "the Vulnerabilities tables, not of network initial access (drift-map #71)"),
}

#: The run_* entry points of the IP-level checks whose findings the table shows.
IP_LEVEL_RUNNERS = ("run_direct_ip_checks", "run_port_service_checks")


def _tree() -> ast.Module:
    return ast.parse(SECURITY_CHECKS.read_text(encoding="utf-8"))


def _constant(name: str):
    for node in _tree().body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is no longer a literal in security_checks.py")


def _functions() -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in _tree().body if isinstance(n, ast.FunctionDef)}


def _called_checks(fn: ast.FunctionDef, functions) -> set[str]:
    """check_* functions a runner reaches, nested helpers included."""
    return {
        n.func.id for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id.startswith("check_") and n.func.id in functions
    }


def _emitted_types(fn: ast.FunctionDef) -> set[str]:
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if (isinstance(k, ast.Constant) and k.value == "type"
                        and isinstance(v, ast.Constant) and isinstance(v.value, str)):
                    out.add(v.value)
    return out


def _ip_level_types() -> set[str]:
    functions = _functions()
    out = set()
    for runner in IP_LEVEL_RUNNERS:
        assert runner in functions, f"{runner} is gone from security_checks.py"
        for check in _called_checks(functions[runner], functions):
            out |= _emitted_types(functions[check])
    return out


def _route() -> str:
    if not (PROJECT_ROOT / "webapp").exists():
        pytest.skip("webapp/ is not in this checkout")
    return ROUTE.read_text(encoding="utf-8")


def _ts_port_category() -> dict[int, str]:
    block = re.search(r"const PORT_CATEGORY[^=]*=\s*\{(.*?)\n\}", _route(), re.S)
    assert block, "PORT_CATEGORY not found in the route"
    return {int(p): c for p, c in re.findall(r"(\d+):\s*'(\w+)'", block.group(1))}


def _ts_net_vuln_types() -> set[str]:
    block = re.search(r"const NET_VULN_TYPES\s*=\s*\[(.*?)\]", _route(), re.S)
    assert block, "NET_VULN_TYPES not found in the route"
    return set(re.findall(r"'(\w+)'", block.group(1)))


def _python_port_categories() -> dict[int, str]:
    """The category each Python-flagged port must carry in the table."""
    expected = {p: name.lower() for p, (name, _desc) in _constant("ADMIN_PORTS").items()}
    expected |= {p: "database" for p in _constant("DATABASE_PORTS")}
    expected |= {p: "k8s" for p in _constant("KUBERNETES_API_PORTS")}
    return {p: c for p, c in expected.items() if p not in UNCATEGORISED_PORTS}


def test_every_python_flagged_port_has_its_category():
    ts = _ts_port_category()
    wrong = {p: (ts.get(p), c) for p, c in _python_port_categories().items()
             if ts.get(p) != c}
    assert not wrong, (
        "ports security_checks.py flags but PORT_CATEGORY gives no or another "
        f"category (port: (ts, expected)): {wrong}")


def test_the_route_parse_is_not_vacuous():
    assert len(_ts_port_category()) >= len(_python_port_categories())
    assert len(_ts_net_vuln_types()) >= 5


def test_every_ip_level_finding_type_is_listed():
    missing = _ip_level_types() - _ts_net_vuln_types() - set(NOT_INITIAL_ACCESS_TYPES)
    assert not missing, (
        f"IP-level finding types security_checks.py emits that NET_VULN_TYPES "
        f"lacks, so the table never shows them: {sorted(missing)}")


def test_net_vuln_types_names_only_emitted_types():
    stale = _ts_net_vuln_types() - _ip_level_types()
    assert not stale, f"NET_VULN_TYPES names types no IP-level check emits: {sorted(stale)}"


def test_the_allowlists_are_still_needed():
    stale_ports = sorted(set(UNCATEGORISED_PORTS) - set(_constant("KUBERNETES_API_PORTS"))
                         - set(_constant("ADMIN_PORTS")) - set(_constant("DATABASE_PORTS")))
    stale_types = sorted(set(NOT_INITIAL_ACCESS_TYPES)
                         - (_ip_level_types() - _ts_net_vuln_types()))
    assert not stale_ports and not stale_types, (stale_ports, stale_types)
