"""The memory-governor knobs reach the recon containers the orchestrator starts.

compose forwards REDAMON_MEM_GOVERNOR, MEM_SCALE_* and the rest to the
orchestrator only, while the ratio model that scales recon's parallelism runs
inside the recon container (graph_db/resource_governor.py, used by
recon/project_settings.py). Setting a knob in .env therefore changed nothing for
recon (drift-map #65). Both recon spawn sites now forward every knob that is set.
"""
import os
import re
from pathlib import Path
from unittest import mock

import container_manager as cm

REPO = Path(__file__).resolve().parents[2]
GOVERNOR = REPO / "graph_db" / "resource_governor.py"
COMPOSE = REPO / "docker-compose.yml"

#: Knobs the governor reads that name a path inside ITS container, so the
#: orchestrator's value would be wrong in a recon container.
NOT_FORWARDED = {"RESOURCE_PROFILE_PATH", "RESOURCE_PROFILE_DEFAULT_PATH"}


def test_only_the_knobs_an_operator_set_are_forwarded():
    env = {"MEM_SCALE_HIGH": "0.6", "MEM_SCALE_LOW": "", "PER_CONTAINER_MAX": "4g"}
    with mock.patch.dict(os.environ, env, clear=True):
        assert cm._governor_overrides() == {"MEM_SCALE_HIGH": "0.6", "PER_CONTAINER_MAX": "4g"}


def test_every_knob_the_governor_reads_is_forwarded():
    src = GOVERNOR.read_text(encoding="utf-8")
    read = set(re.findall(r'(?:_env_float|_env_bool|env_bytes)\("([A-Z_]+)"', src))
    assert read, "parsed no knob from graph_db/resource_governor.py"
    assert sorted(read - set(cm.GOVERNOR_KNOBS) - NOT_FORWARDED) == []
    assert sorted(set(cm.GOVERNOR_KNOBS) - read) == []


def test_both_recon_spawn_sites_forward_them():
    src = Path(cm.__file__).read_text(encoding="utf-8")
    recon_envs = src.count('"RECON_CIRCUIT_BREAKERS": os.environ.get("RECON_CIRCUIT_BREAKERS"')
    assert recon_envs == 2
    assert src.count("**_governor_overrides(),") == recon_envs


def test_compose_hands_every_knob_to_the_orchestrator():
    text = COMPOSE.read_text(encoding="utf-8")
    start = text.index("\n  recon-orchestrator:\n")
    end = re.search(r"\n  [a-z][\w-]*:\n", text[start + 1:]).start() + start + 1
    service = text[start:end]
    missing = [k for k in cm.GOVERNOR_KNOBS if f"{k}: ${{{k}:-}}" not in service]
    assert missing == []
