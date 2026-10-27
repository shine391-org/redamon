"""The proxy_brain tool docstring teaches the BOLA check the manual teaches.

The agent reads this docstring as the tool's description. Its access-control
recipe flagged BOLA on `r.status == 200` alone, so a public page, a login
page served with 200, or any endpoint that answers everyone became a "high"
finding. The manual's authz section requires the owner's baseline: same status
AND the same body back for the weaker identity.

Read through `ast`, so the MCP server's dependencies are not needed.
"""
import ast
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "mcp/servers/network_recon_server.py"


def _docstring() -> str:
    tree = ast.parse(SERVER.read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "proxy_brain")
    return ast.get_docstring(fn) or ""


class TestTheBolaRecipe(unittest.TestCase):
    DOC = _docstring()

    def test_the_docstring_was_found(self):
        self.assertIn("RECIPES", self.DOC)

    def test_no_status_only_bola_check_is_left(self):
        self.assertNotIn('if r.status == 200: redamon.finding("bola"', self.DOC)

    def test_the_weaker_identity_is_compared_with_the_owner_baseline(self):
        recipe = self.DOC[self.DOC.index("# Access-control sweep"):self.DOC.index("# JWT forge")]
        self.assertIn("base = redamon.replay(t.id, {})", recipe)
        self.assertIn("if base.status not in (200, 201):", recipe)
        self.assertIn("if r.status == base.status and r.body == base.body:", recipe)
        self.assertIn('redamon.finding("bola", t.id, evidence=r, severity="high")', recipe)


if __name__ == "__main__":
    unittest.main()
