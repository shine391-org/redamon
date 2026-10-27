"""Each scan state's total_phases is the highest phase its log patterns report.

The webapp drawers render "Phase n/total" from these, and GvmState said 4 while
GVM_PHASE_PATTERNS numbers five phases, so the GVM drawer showed "Phase 5/4"
(drift-map #22). The webapp side is webapp/src/lib/recon-types.phases.test.ts.
"""
import pytest

import container_manager as cm
import models

PAIRS = [
    (models.ReconState, cm.PHASE_PATTERNS),
    (models.GvmState, cm.GVM_PHASE_PATTERNS),
    (models.GithubHuntState, cm.GITHUB_HUNT_PHASE_PATTERNS),
    (models.TrufflehogState, cm.TRUFFLEHOG_PHASE_PATTERNS),
    (models.AiAttackSurfaceState, cm.AI_ATTACK_SURFACE_PHASE_PATTERNS),
]


@pytest.mark.parametrize("state,patterns", PAIRS, ids=[s.__name__ for s, _ in PAIRS])
def test_total_phases_is_the_last_phase_number(state, patterns):
    assert state.model_fields["total_phases"].default == max(n for _, _, n in patterns)
