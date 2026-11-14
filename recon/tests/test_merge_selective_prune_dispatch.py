"""Merge contract: selective retention reaches every actual prune dispatch."""
import ast
from pathlib import Path


def test_every_prune_dispatch_keeps_unproven_when_the_run_is_selective():
    source = (Path(__file__).resolve().parents[1] / 'main.py').read_text()
    tree = ast.parse(source)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == '_prune_recon_findings')
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute)
             and n.func.attr == 'prune_unseen_findings']
    # Ordinary batches, positive checked hosts, and unrecorded check types.
    assert len(calls) == 3
    for call in calls:
        keep = next((kw.value for kw in call.keywords if kw.arg == 'keep_unproven'), None)
        assert isinstance(keep, ast.Name) and keep.id == 'selective', call.lineno
