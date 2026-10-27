"""One version per pinned tool, in every image and every sentence that names it.

The same binary is pinned in several Dockerfiles, and code comments record what
was verified against which release (a parser shape, an exit code, a detector
list). Bumping one copy silently splits the images, and a "verified against
vX" note that does not move with the pin is a claim nobody re-checked
(drift-map section 6 guard #20, 4.11, 4.12). Each site below must name the
version at least once, so a reworded file fails here instead of dropping out.

Reads the files only; no Docker. Run: ./redamon.sh test unit (root tests).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SEMVER = r"(\d+\.\d+\.\d+)"
_ANY_V = r"(?<![\w.])v" + SEMVER          # every vX.Y.Z in a file about one tool

# tool -> [(repo path, regex capturing the version)]. The first site is the pin
# that builds the image; the rest must agree with it.
SITES: dict[str, list[tuple[str, str]]] = {
    "trufflehog": [
        ("scanners/trufflehog_scan/Dockerfile", r"ARG TRUFFLEHOG_VERSION=" + SEMVER),
        # The detector list is parsed out of that exact binary.
        ("webapp/src/lib/trufflehogDetectors.ts", r"TruffleHog " + SEMVER),
        # Each fixture secret was proven to fire against the pinned binary.
        ("testing/e2e/backend/build_github_fixtures.sh", r"TruffleHog " + SEMVER),
        ("testing/e2e/backend/build_github_experimental_fixtures.sh", r"TruffleHog " + SEMVER),
        ("testing/e2e/backend/build_gitlab_fixtures.sh", r"TruffleHog " + SEMVER),
    ],
    "osv-scanner": [
        ("scanners/supply_chain_analyzer/Dockerfile", r"(?i)osv-scanner[@ ]v" + SEMVER),
        ("scanners/supply_chain_scan/Dockerfile", r"(?i)osv-scanner[@ ]v" + SEMVER),
        ("recon/Dockerfile", r"(?i)osv-scanner[@ ]v" + SEMVER),
        ("mcp/kali-sandbox/Dockerfile", r"(?i)osv-scanner[@ ]v" + SEMVER),
        ("scanners/supply_chain_common/__init__.py", r"(?i)osv-scanner v" + SEMVER),
        ("scanners/supply_chain_common/osv_runner.py", _ANY_V),
        ("scanners/supply_chain_common/osv_db_sync.py", r"(?i)osv-scanner v" + SEMVER),
        ("THIRD-PARTY-LICENSES.md", r"\| \*\*OSV-Scanner\*\* \|.*?@v" + SEMVER),
    ],
    "guarddog": [
        ("scanners/supply_chain_analyzer/Dockerfile", r"(?i)guarddog(?:==|\s+)" + SEMVER),
        ("mcp/kali-sandbox/Dockerfile", r"guarddog==" + SEMVER),
        ("scanners/supply_chain_common/__init__.py", r"GuardDog v" + SEMVER),
        ("scanners/supply_chain_common/guarddog_runner.py", r"GuardDog v?" + SEMVER),
        ("THIRD-PARTY-LICENSES.md", r"guarddog==" + SEMVER),
    ],
    "retire.js": [
        ("scanners/supply_chain_analyzer/Dockerfile", r"retire(?:@|\.js\s+)" + SEMVER),
        ("scanners/supply_chain_common/retire_runner.py", _ANY_V),
        ("scanners/supply_chain_common/__init__.py", r"retire\.js v" + SEMVER),
        ("THIRD-PARTY-LICENSES.md", r"retire@" + SEMVER),
    ],
}

# (tool, repo path) -> why that copy may differ from the pin for now. Empty
# today; an entry must still differ, or it is deleted.
ALLOWED_DRIFT: dict[tuple[str, str], str] = {}


def _versions(path: str, pattern: str) -> list[str]:
    return re.findall(pattern, (REPO / path).read_text(encoding="utf-8"))


def _pin(tool: str) -> str:
    path, pattern = SITES[tool][0]
    found = set(_versions(path, pattern))
    assert len(found) == 1, f"{path} must pin exactly one {tool} version, found {sorted(found)}"
    return found.pop()


@pytest.mark.parametrize("tool", sorted(SITES))
def test_every_site_names_the_pinned_version(tool):
    pin = _pin(tool)
    problems = []
    for path, pattern in SITES[tool]:
        if not (REPO / path).is_file():
            problems.append(f"{path}: missing (move the site with the file)")
            continue
        found = _versions(path, pattern)
        if not found:
            problems.append(f"{path}: no {tool} version matched {pattern!r}; the sentence was reworded")
            continue
        wrong = sorted(set(found) - {pin})
        if wrong and (tool, path) not in ALLOWED_DRIFT:
            problems.append(f"{path}: names {tool} {wrong}, the pin is {pin}")
    assert not problems, f"{tool} {pin} is pinned in {SITES[tool][0][0]}:\n" + "\n".join(problems)


def test_allowed_drift_entries_still_drift():
    stale = []
    for (tool, path), why in sorted(ALLOWED_DRIFT.items()):
        pattern = dict(SITES[tool])[path]
        if not why.strip() or set(_versions(path, pattern)) <= {_pin(tool)}:
            stale.append(f"{tool} in {path}")
    assert not stale, f"ALLOWED_DRIFT entries that agree with the pin now (delete them): {stale}"

