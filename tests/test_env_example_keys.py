"""Every key .env.example documents reaches something that reads it.

No service has an env_file, so a key works only when a compose file forwards it
(`${KEY...}`) or redamon.sh reads it on the host (`_env_knob`). A key in neither
is a documented knob that changes nothing: seven were read by no code at all and
fifteen by container code no compose file forwarded (drift-map #23). Host-only
keys are named in HOST_ONLY_ENV_KEYS in redamon.sh, and each must really be read
there through _env_knob or _pct_env.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = REPO / ".env.example"
REDAMON_SH = REPO / "redamon.sh"


def _documented_keys() -> set[str]:
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    return set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]{2,})=", text, re.M))


def _compose_keys() -> set[str]:
    text = "".join(p.read_text(encoding="utf-8") for p in sorted(REPO.glob("docker-compose*.yml")))
    return set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)[:}?-]", text))


def _host_only_keys(script: str) -> list[str]:
    body = re.search(r"^HOST_ONLY_ENV_KEYS=\((.*?)^\)", script, re.S | re.M)
    assert body, "HOST_ONLY_ENV_KEYS not found in redamon.sh"
    return body.group(1).split()


def _read_by_env_knob(script: str, key: str) -> bool:
    if re.search(r"(_env_knob|_pct_env)\s+\"?" + re.escape(key) + r"\b", script):
        return True
    # a family read as _env_knob "PREFIX_${name}"
    return any(key.startswith(prefix) for prefix in
               re.findall(r"_env_knob\s+\"([A-Z][A-Z0-9_]*)\$\{", script))


@unittest.skipUnless(ENV_EXAMPLE.exists() and REDAMON_SH.exists(), "needs .env.example and redamon.sh")
class TestEnvExampleKeys(unittest.TestCase):
    def setUp(self):
        self.script = REDAMON_SH.read_text(encoding="utf-8")

    def test_every_documented_key_is_forwarded_or_read_on_the_host(self):
        reached = _compose_keys() | set(_host_only_keys(self.script))
        self.assertEqual(
            sorted(_documented_keys() - reached), [],
            "documented in .env.example but forwarded by no compose file and not a "
            "host-only key of redamon.sh: forward it, or delete it",
        )

    def test_every_host_only_key_is_read_from_env(self):
        unread = [k for k in _host_only_keys(self.script) if not _read_by_env_knob(self.script, k)]
        self.assertEqual(unread, [], "HOST_ONLY_ENV_KEYS names keys redamon.sh never reads from .env")

    def test_every_host_only_key_is_documented(self):
        self.assertEqual(sorted(set(_host_only_keys(self.script)) - _documented_keys()), [])


if __name__ == "__main__":
    unittest.main()
