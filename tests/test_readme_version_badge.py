"""The README's version badge names the release in VERSION.

The badge is hand-edited while VERSION is what redamon.sh and the webapp read, so
it said v7.2.0 a release after VERSION moved to 7.3.0 (drift-map #51).
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_the_version_badge_names_the_current_release():
    version = (REPO / "VERSION").read_text(encoding="utf-8").strip()
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    badges = re.findall(r"img\.shields\.io/badge/v(\d+\.\d+\.\d+)-release", readme)
    assert badges, "no version badge in README.md"
    assert set(badges) == {version}
    assert set(re.findall(r'alt="Version (\d+\.\d+\.\d+)"', readme)) <= {version}
