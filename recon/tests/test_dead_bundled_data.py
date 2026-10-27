"""Bundled data that nothing reads stays deleted (drift-map #60, #61).

recon/data/mitre_db/ was a second MITRE tree: add_mitre.py reads and refreshes
recon/main_recon_modules/data/mitre_db/, so the copy aged in git, 95 MB of CVE
files whose cwe_*.json already differed from the live ones. A dead copy is
worse than none: the next reader picks it because it is there, which is what
graph_db/cpe_resolver.py did with recon/data/wappalyzer_cache/ while
http_probe.py refreshed the one under main_recon_modules/.

Run: ./redamon.sh test unit (recon section; needs git and the repo at /repo)
"""
from __future__ import annotations

import ast
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
THIS_FILE = str(Path(__file__).resolve().relative_to(PROJECT_ROOT))

DEAD_PATHS = (
    "recon/data/mitre_db",
    "recon/data/wappalyzer_cache",
    "recon/data/wappalyzer_technologies.json",
)
HTTP_PROBE = PROJECT_ROOT / "recon" / "main_recon_modules" / "http_probe.py"
CPE_RESOLVER = PROJECT_ROOT / "graph_db" / "cpe_resolver.py"

#: Tracked files that still name a dead path, each with the reason.
STILL_NAMED = {
    "docs/readmes/README.DRIFT_MAP.md": "the drift map records the deletion",
}


def _git(*args: str) -> str:
    if shutil.which("git") is None or not (PROJECT_ROOT / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    result = subprocess.run(["git", "-C", str(PROJECT_ROOT), *args],
                            capture_output=True, text=True, timeout=60)
    if result.returncode not in (0, 1):  # git grep exits 1 on no match
        pytest.skip(f"git {args[0]} failed: {result.stderr.strip()[:200]}")
    return result.stdout


def test_the_dead_trees_are_not_tracked():
    for path in DEAD_PATHS:
        assert _git("ls-files", "--", path).strip() == "", f"{path} is tracked again"


def test_nothing_names_a_dead_path():
    hits = {}
    for path in DEAD_PATHS:
        for f in _git("grep", "-I", "-l", "-F", path).splitlines():
            if f != THIS_FILE and f not in STILL_NAMED:
                hits.setdefault(path, []).append(f)
    assert not hits, f"tracked files still name a deleted data path: {hits}"


def _http_probe_cache_file() -> Path:
    """The file download_wappalyzer_database refreshes, evaluated from its own
    assignments with http_probe.py as __file__."""
    fn = next(n for n in ast.parse(HTTP_PROBE.read_text(encoding="utf-8")).body
              if isinstance(n, ast.FunctionDef) and n.name == "download_wappalyzer_database")
    scope = {"Path": Path, "__file__": str(HTTP_PROBE)}
    for node in ast.walk(fn):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in ("WAPPALYZER_CACHE_DIR", "WAPPALYZER_CACHE_FILE")):
            scope[node.targets[0].id] = eval(  # noqa: S307 - a Path expression from our own source
                compile(ast.Expression(node.value), str(HTTP_PROBE), "eval"), scope)
    assert "WAPPALYZER_CACHE_FILE" in scope, "http_probe no longer names its cache file"
    return Path(scope["WAPPALYZER_CACHE_FILE"]).resolve()


def test_cpe_resolution_reads_the_cache_http_probe_refreshes():
    spec = importlib.util.spec_from_file_location("_cpe_resolver", CPE_RESOLVER)
    cpe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cpe)
    first = cpe._wappalyzer_cache_candidates()[0].resolve()
    assert first == _http_probe_cache_file(), (first, _http_probe_cache_file())
