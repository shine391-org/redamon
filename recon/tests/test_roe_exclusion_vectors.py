"""recon/helpers/roe_scope.py against the vectors the webapp's matcher also reads.

The webapp keeps a TS copy of the RoE excluded-host matcher
(webapp/src/lib/roeScope.ts) for the recording-session scope and the OpenAPI
source status. Both run fixtures/roe_exclusion_vectors.json: a red vector here
means the table and the scan-time matcher disagree; a red one in
webapp/src/lib/roeScope.test.ts means the copy does (drift-map #20).
"""
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from recon.helpers.roe_scope import _is_roe_excluded  # noqa: E402

_VECTORS = json.loads(
    (Path(__file__).parent / 'fixtures' / 'roe_exclusion_vectors.json').read_text())['vectors']


def test_the_table_is_a_real_set():
    assert len(_VECTORS) >= 40
    assert len({v['name'] for v in _VECTORS}) == len(_VECTORS)


@pytest.mark.parametrize('v', _VECTORS, ids=[v['name'] for v in _VECTORS])
def test_vector(v):
    assert _is_roe_excluded(v['host'], v['excluded']) is v['result']


def test_the_webapp_reads_the_same_vectors_file():
    ts = _REPO / 'webapp' / 'src' / 'lib' / 'roeScope.test.ts'
    if not ts.exists():
        pytest.skip('webapp source not mounted in this image')
    assert "'roe_exclusion_vectors.json'" in ts.read_text()
