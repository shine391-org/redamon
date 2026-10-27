"""`COPY agentic/ ./` must not overwrite what an earlier COPY baked.

agentic/Dockerfile bakes graph_db/, services/knowledge_base/ and
recon_settings/ under /app, then copies agentic/ over /app. A file at
agentic/<dir>/... for one of those dirs therefore replaces the baked one: an
empty, root-owned agentic/knowledge_base/kb_config.yaml did exactly that to the
real KB config (drift-map #19), masked only where compose mounts the real file
back. This checks that no such file is tracked, and that .dockerignore keeps any
local copy (the root-owned one cannot be deleted without sudo) out of the build
context.
"""

import os
import re
import shutil
import subprocess
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKERFILE = os.path.join(REPO, "agentic", "Dockerfile")
DOCKERIGNORE = os.path.join(REPO, ".dockerignore")
SHADOWED_KB_CONFIG = "agentic/knowledge_base/kb_config.yaml"


def _baked_dirs_under_agentic_copy() -> list[str]:
    """Destination dirs of the COPYs that run before `COPY agentic/ ./`."""
    dirs = []
    with open(DOCKERFILE, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^COPY\s+(?!--)(\S+)\s+(\S+)\s*$", line.strip())
            if not m:
                continue
            src, dest = m.groups()
            if src.rstrip("/") == "agentic" and dest == "./":
                return dirs
            if src.startswith("agentic/"):
                continue
            dest = dest.removeprefix("./").strip("/")
            if dest:
                dirs.append(dest)
    raise AssertionError(f"no `COPY agentic/ ./` in {DOCKERFILE}")


def _pattern_regex(pattern: str) -> re.Pattern:
    """A .dockerignore pattern as a regex over a slash path (Docker's
    patternmatcher: `**` spans directories, `*` and `?` stay within one)."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def _dockerignored(path: str) -> bool:
    """True when the build context drops `path`: the last matching pattern
    decides, and a pattern matching a parent directory covers its contents."""
    parts = path.split("/")
    candidates = ["/".join(parts[: n + 1]) for n in range(len(parts))]
    ignored = False
    with open(DOCKERIGNORE, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            negate = line.startswith("!")
            pat = line[1:] if negate else line
            pat = pat.strip().lstrip("/").rstrip("/")
            rx = _pattern_regex(pat)
            if any(rx.match(c) for c in candidates):
                ignored = not negate
    return ignored


class TestAgentImageNoShadowedCopy(unittest.TestCase):
    def test_the_baked_dirs_are_parsed(self):
        # A broken parser must fail here, not leave nothing to check.
        self.assertIn("knowledge_base", _baked_dirs_under_agentic_copy())

    def test_matcher_follows_docker_semantics(self):
        rx = _pattern_regex("**/__pycache__")
        self.assertTrue(rx.match("a/b/__pycache__"))
        self.assertTrue(rx.match("__pycache__"))
        self.assertFalse(_pattern_regex("agentic/*.txt").match("agentic/x/y.txt"))

    def test_no_tracked_file_shadows_a_baked_dir(self):
        if not shutil.which("git") or not os.path.isdir(os.path.join(REPO, ".git")):
            self.skipTest("needs git and a git checkout")
        tracked = []
        for d in _baked_dirs_under_agentic_copy():
            out = subprocess.run(
                ["git", "-C", REPO, "ls-files", "--", f"agentic/{d}"],
                capture_output=True, text=True, check=True,
            ).stdout.split()
            tracked.extend(out)
        self.assertEqual(
            tracked, [],
            "tracked under agentic/ where `COPY agentic/ ./` would overwrite a "
            "file an earlier COPY baked; delete it from git",
        )

    def test_dockerignore_drops_the_empty_kb_config(self):
        self.assertTrue(
            _dockerignored(SHADOWED_KB_CONFIG),
            f".dockerignore must exclude {SHADOWED_KB_CONFIG}: a local copy "
            "(root-owned on some hosts) would replace the real KB config baked "
            "from services/knowledge_base/",
        )

    def test_no_local_file_reaches_a_baked_dir(self):
        leaking = []
        for d in _baked_dirs_under_agentic_copy():
            root = os.path.join(REPO, "agentic", d)
            for dirpath, _dirs, files in os.walk(root):
                for name in files:
                    rel = os.path.relpath(os.path.join(dirpath, name), REPO)
                    if not _dockerignored(rel.replace(os.sep, "/")):
                        leaking.append(rel)
        self.assertEqual(leaking, [], "these would overwrite baked files in the agent image")


if __name__ == "__main__":
    unittest.main()
