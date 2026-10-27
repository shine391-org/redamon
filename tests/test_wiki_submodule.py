"""redamon.wiki is a declared submodule, so a clone can check it out.

The wiki was a gitlink with no .gitmodules: a fresh clone got an empty
redamon.wiki and could not fill it, and every wiki-dependent test skipped or
checked nothing (drift-map 3.3). An empty checkout now fails those tests unless
REDAMON_TEST_ALLOW_MISSING names `wiki` (tooling/scripts/wiki_checkout.py).
"""
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class TestWikiSubmodule(unittest.TestCase):
    def setUp(self):
        if shutil.which("git") is None or not (REPO / ".git").exists():
            self.skipTest("needs git and the repository's .git")

    def _git(self, *args: str) -> str:
        return subprocess.run(["git", "-C", str(REPO), *args],
                              capture_output=True, text=True, check=True).stdout.strip()

    def test_the_wiki_gitlink_is_a_declared_submodule(self):
        self.assertEqual(self._git("ls-files", "-s", "--", "redamon.wiki").split()[0], "160000")
        self.assertEqual(self._git("config", "-f", ".gitmodules", "--get", "submodule.redamon.wiki.path"),
                         "redamon.wiki")
        url = self._git("config", "-f", ".gitmodules", "--get", "submodule.redamon.wiki.url")
        self.assertTrue(url.endswith("/redamon.wiki.git"), url)


if __name__ == "__main__":
    unittest.main()
