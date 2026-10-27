"""The registry's tools.*.partial_recon_module names the module partial recon runs.

registry.tools.test.ts only checks that the named file exists, so jsluice,
kiterunner, security_check and vhost_sni named a real but wrong module after
their partial-recon code moved (drift-map #63). The truth is recon/partial_recon.py
itself: `_dispatch` calls one function per tool id, and the imports say which
partial_recon_modules file each function comes from.
"""
import ast
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PARTIAL_RECON = REPO / "recon" / "partial_recon.py"
REGISTRY = REPO / "recon_settings" / "registry.json"


def _norm(name: str) -> str:
    return name.lower().replace("_", "").rstrip("s")


def _dispatched_modules() -> dict[str, str]:
    """normalised tool id -> the partial_recon_modules module its run function is from."""
    tree = ast.parse(PARTIAL_RECON.read_text(encoding="utf-8"))
    origin: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("recon.partial_recon_modules."):
            for alias in node.names:
                origin[alias.asname or alias.name] = node.module.rsplit(".", 1)[1]
    dispatch = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_dispatch")
    out: dict[str, str] = {}
    for node in ast.walk(dispatch):
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.comparators[0], ast.Constant)):
            continue
        tool_id = node.test.comparators[0].value
        for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Name) and stmt.func.id in origin:
                out[_norm(tool_id)] = origin[stmt.func.id]
                break
    return out


def test_every_dispatched_tool_names_the_module_it_runs_from():
    tools = json.loads(REGISTRY.read_text(encoding="utf-8"))["tools"]
    dispatched = _dispatched_modules()
    compared, wrong = 0, []
    for tool, spec in sorted(tools.items()):
        module = spec.get("partial_recon_module")
        if not module or _norm(tool) not in dispatched:
            continue
        compared += 1
        if module != dispatched[_norm(tool)]:
            wrong.append(f"{tool}: registry says {module}, partial_recon.py runs {dispatched[_norm(tool)]}")
    # most partial-recon tools share their id with a registry tool; a parse that
    # matched none would pass vacuously
    assert compared >= 20, f"only {compared} registry tools matched a dispatched tool id"
    assert wrong == [], wrong
