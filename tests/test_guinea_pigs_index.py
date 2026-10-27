"""Every guinea-pig lab is listed in testing/guinea_pigs/README.md (drift-map #58).

The index described 5 of 19 labs: a lab added without a row is a target nobody
finds, and its fixed IP or host port collides with another lab's unannounced.
Reads the files only. Run: ./redamon.sh test unit (root tests).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LABS = "testing/guinea_pigs"


def _tracked_labs() -> set[str]:
    """Top-level folders under testing/guinea_pigs/ that git tracks.

    Tracked rather than on disk, so a lab somebody is still building locally
    does not fail everyone's gate before it is committed.
    """
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    files = subprocess.run(
        ["git", "-C", str(REPO), "ls-files", "--", LABS],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    prefix = LABS + "/"
    return {f[len(prefix):].split("/")[0] for f in files if f.startswith(prefix) and f.count("/") > 2}


def _linked_labs() -> set[str]:
    text = (REPO / LABS / "README.md").read_text(encoding="utf-8")
    return set(re.findall(r"\]\(([\w.\-]+)/\)", text))


def test_every_lab_has_a_row():
    missing = sorted(_tracked_labs() - _linked_labs())
    assert missing == [], f"labs with no row in {LABS}/README.md: {missing}"


def test_every_row_names_a_lab():
    stale = sorted(_linked_labs() - _tracked_labs())
    assert stale == [], f"{LABS}/README.md links folders that do not exist: {stale}"


def test_the_lab_list_is_read():
    """A broken listing would make both checks above pass on nothing."""
    assert len(_tracked_labs()) > 15
