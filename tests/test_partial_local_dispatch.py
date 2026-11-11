"""Frozen pre-F09 literal controls exercised at actual downstream dispatch.

No target/DB/tool subprocess is used. The scanner boundary aborts with a
BaseException so post-dispatch graph writers cannot run. Inventory data is a
checked-in snapshot, not a list derived from the candidate helper under test.
"""
import contextlib
import io
import json
from pathlib import Path

import pytest

from test_partial_override_contract import (
    _run_caller, _run_nuclei_capturing_settings, vuln_caller, cache_caller,
    graphql_caller, route_caller, serialized_caller, partial_helpers,
)

INVENTORY = json.loads((Path(__file__).parent / 'fixtures' /
                       'partial_override_inventory.json').read_text())['settings']
CALLERS = {
    'cache': (cache_caller, 'run_webcachepoison', 'recon.cache_scan', 'run_cache_scan'),
    'graphql': (graphql_caller, 'run_graphqlscan', 'recon.graphql_scan', 'run_graphql_scan'),
    'route': (route_caller, 'run_route_exposure_partial', 'recon.route_exposure', 'run_route_exposure'),
    'serialized': (serialized_caller, 'run_serialized_scan_partial', 'recon.serialized_scan', 'run_serialized_scan'),
    'takeover': (vuln_caller, 'run_subdomain_takeover_partial', 'recon.main_recon_modules.subdomain_takeover', 'run_subdomain_takeover'),
    'vhost': (vuln_caller, 'run_vhost_sni_partial', 'recon.main_recon_modules.vhost_sni_enum', 'run_vhost_sni_enrichment'),
}


def dispatch(caller, saved, overrides):
    if caller == 'nuclei':
        return _run_nuclei_capturing_settings(overrides, saved)
    extra = [('attach_graph_ownership', lambda *a, **k: None)] if caller == 'vhost' else []
    return _run_caller(*CALLERS[caller], extra_patches=extra, saved=saved,
                       config_extra={'settings_overrides': overrides})


@pytest.mark.parametrize('row', [r for r in INVENTORY if r['disposition'] == 'supported'],
                         ids=lambda r: r['key'])
def test_prior_registered_control_reaches_actual_dispatch(row):
    key, value = row['key'], row['value']
    saved = {key: '__saved_sentinel__', 'UNRELATED': 'keep',
             'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': ['blocked.synthetic.test']}
    effective = dispatch(row['caller'], saved, {key: value})
    assert effective is not None, 'actual dispatch not reached'
    expected = value
    if key == 'GRAPHQL_ENDPOINTS':
        expected = ','.join(filter(None, [value, 'https://synthetic.test/a']))
    assert effective[key] == expected
    assert effective['UNRELATED'] == 'keep'
    assert effective['ROE_ENABLED'] is True
    assert effective['ROE_EXCLUDED_HOSTS'] == ['blocked.synthetic.test']
    assert saved[key] == '__saved_sentinel__'


@pytest.mark.parametrize('row', [r for r in INVENTORY if r['disposition'] == 'protected'],
                         ids=lambda r: r['key'])
def test_inventory_protected_controls_preserved_and_rejected(row):
    seen = []
    saved = {row['key']: 'saved'}
    effective = partial_helpers.apply_settings_overrides(saved, {row['key']: 'replacement'}, log=seen.append)
    assert effective == saved
    assert len(seen) == 1 and row['key'] in seen[0]


@pytest.mark.parametrize('caller,key', [
    ('cache', 'WEB_CACHE_POISON_ENABLED'), ('graphql', 'GRAPHQL_SECURITY_ENABLED'),
    ('route', 'ROUTE_EXPOSURE_ENABLED'), ('serialized', 'SERIALIZED_SCAN_ENABLED'),
    ('vhost', 'VHOST_SNI_ENABLED'), ('takeover', 'SUBDOMAIN_TAKEOVER_ENABLED'),
    ('nuclei', 'NUCLEI_ENABLED'),
])
def test_explicit_false_wins_after_force_enable(caller, key):
    assert dispatch(caller, {key: True}, {key: False})[key] is False


@pytest.mark.parametrize('caller', ['nuclei', *CALLERS])
@pytest.mark.parametrize('invalid', [False, [], '', 1, 'invalid'])
def test_malformed_override_container_is_observable_at_dispatch(caller, invalid):
    stdout = io.StringIO()
    with contextlib.redirect_stdout(stdout):
        # Existing fixture suppresses the normal caller log; replace only its
        # redirect context so diagnostics remain available to this assertion.
        from unittest.mock import patch
        with patch('test_partial_override_contract.contextlib.redirect_stdout',
                   side_effect=lambda stream: contextlib.nullcontext()):
            effective = dispatch(caller, {'PLANNER_MODE': 'shadow'}, invalid)
    assert effective['PLANNER_MODE'] == 'shadow'
    assert 'settings_overrides rejected: expected an object' in stdout.getvalue()


@pytest.mark.parametrize('caller', ['nuclei', *CALLERS])
@pytest.mark.parametrize('key,value', [
    ('PLANNER_MODE', 'invalid'), ('PLANNER_MODE', None),
    ('PLANNER_MANIFEST_ENABLED', 'false'), ('PLANNER_CONSUMER_AI_TAGS', 1),
    ('PLANNER_CONSUMER_TARGET_SELECTION', None), ('PLANNER_CONSUMER_TWO_PASS', 'false'),
])
def test_invalid_planner_controls_preserve_saved_at_actual_dispatch(caller, key, value):
    saved = {key: 'shadow' if key == 'PLANNER_MODE' else False}
    assert dispatch(caller, saved, {key: value})[key] == saved[key]


@pytest.mark.parametrize('mode', ['off', 'shadow', 'enforce'])
@pytest.mark.parametrize('caller', ['nuclei', *CALLERS])
def test_valid_planner_controls_and_false_survive_dispatch(caller, mode):
    overrides = {'PLANNER_MODE': mode, 'PLANNER_MANIFEST_ENABLED': False,
                 'PLANNER_CONSUMER_AI_TAGS': False, 'PLANNER_CONSUMER_TARGET_SELECTION': False,
                 'PLANNER_CONSUMER_TWO_PASS': False}
    effective = dispatch(caller, {}, overrides)
    assert {key: effective[key] for key in overrides} == overrides
