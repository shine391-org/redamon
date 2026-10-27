"""Rulesets cite a symbol, never a line number.

`file#L123` in a SKILL.md or AGENTS.md points at whatever line 123 holds after
the next edit; 19 such links pointed at unrelated code before the fix pass
named the function, Cypher or volume instead.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LINE_ANCHOR = re.compile(r"\]\([^)\s]*#L\d+")


def test_no_ruleset_links_a_line_number():
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    files = subprocess.run(["git", "-C", str(REPO), "ls-files", "skills/*/SKILL.md", "*AGENTS.md"],
                           capture_output=True, text=True, check=True).stdout.split()
    assert files, "no SKILL.md or AGENTS.md found"
    hits = [
        f"{name}:{i}: {line.strip()[:120]}"
        for name in files
        for i, line in enumerate((REPO / name).read_text(encoding="utf-8").split("\n"), 1)
        if LINE_ANCHOR.search(line)
    ]
    assert hits == [], "cite the symbol instead of a line number:\n" + "\n".join(hits)
