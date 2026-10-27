"""`recon_settings/build.py --check` runs in the gate.

The other registry tests compare the generated artifacts with each other (the two
registry.json copies, the RoE prompt against the JSON, the JSON against Prisma),
so a YAML-only edit (a meaning, a bound) that was never rebuilt passed all of
them (drift-map #26). Only the generator itself can tell that registry.yaml and
its outputs disagree.
"""
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "recon_settings"))

import build  # noqa: E402


class TestRegistryBuildCheck(unittest.TestCase):
    def test_the_generated_artifacts_are_built_from_the_yaml(self):
        self.assertEqual(
            build.main(["--check"]), 0,
            "registry.yaml and its generated files disagree: run python3 recon_settings/build.py",
        )


if __name__ == "__main__":
    unittest.main()
