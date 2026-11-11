"""Adversarial helper controls: no raw credentials, silent coercion or guard bypass."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recon.partial_recon_modules.helpers import apply_settings_overrides


@pytest.mark.parametrize('key,value', [
    ('NUCLEI_RATE_LIMIT', '7'), ('NUCLEI_RATE_LIMIT', True),
    ('NUCLEI_RATE_LIMIT', 0), ('NUCLEI_RATE_LIMIT', 100001),
    ('VHOST_SNI_TIMEOUT', 99),
    ('NUCLEI_TAGS', 'cve'), ('NUCLEI_TAGS', [1]),
    ('NUCLEI_SEVERITY', ['not-a-severity']),
    ('CVE_LOOKUP_MIN_CVSS', float('nan')), ('CVE_LOOKUP_MIN_CVSS', float('inf')),
    ('CVE_LOOKUP_MIN_CVSS', 10 ** 1000), ('CVE_LOOKUP_MIN_CVSS', True),
    ('GRAPHQL_AUTH_VALUE', {'Authorization': 'CREDENTIAL_CANARY'}),
    ('NUCLEI_CUSTOM_TEMPLATES', ['/etc/passwd']),
    ('NUCLEI_CUSTOM_TEMPLATES', ['/app/recon/wordlists/other-project/list']),
    ('NUCLEI_CUSTOM_TEMPLATES', ['']),
    ('NUCLEI_SELECTED_CUSTOM_TEMPLATES', ['../secret.yaml']),
    ('NUCLEI_SELECTED_CUSTOM_TEMPLATES', ['']),
])
def test_invalid_tuning_preserves_saved_and_reports_without_values(key, value):
    seen = []
    saved = {key: 'saved', 'PROJECT_ID': 'this-project'}
    assert apply_settings_overrides(saved, {key: value}, log=seen.append) == saved
    assert len(seen) == 1 and key in seen[0]
    assert 'CREDENTIAL_CANARY' not in seen[0]


@pytest.mark.parametrize('key,value', [
    ('NUCLEI_RATE_LIMIT', 7), ('TAKEOVER_RATE_LIMIT', 7),
    ('WEB_CACHE_POISON_MAX_RPS_PER_HOST', 7),
    ('WEB_CACHE_POISON_MAX_RPS_PER_HOST', 0),
])
def test_post_loader_override_cannot_reopen_engagement_rate_ceiling(key, value):
    seen = []
    saved = {'ROE_ENABLED': True, 'ROE_GLOBAL_MAX_RPS': 3, key: 2}
    assert apply_settings_overrides(saved, {key: value}, log=seen.append) == saved
    assert 'engagement ceiling' in seen[0]


@pytest.mark.parametrize('key,value', [
    ('NUCLEI_CUSTOM_TEMPLATES', ['/custom-templates/synthetic.yaml']),
    ('NUCLEI_CUSTOM_TEMPLATES', ['/app/recon/wordlists/this-project/list']),
    ('NUCLEI_SELECTED_CUSTOM_TEMPLATES', ['synthetic.yaml']),
    ('GRAPHQL_AUTH_VALUE', 'CREDENTIAL_CANARY'),
    ('NUCLEI_TAGS', ['cve', 'synthetic']),
])
def test_valid_tuning_is_not_dropped_or_logged(key, value):
    seen = []
    out = apply_settings_overrides({'PROJECT_ID': 'this-project'}, {key: value}, log=seen.append)
    assert out[key] == value
    assert seen == []
    if isinstance(value, list):
        out[key].append('caller-mutation')
        assert value[-1] != 'caller-mutation'


def test_malicious_diagnostic_keys_values_and_flood_are_bounded():
    seen = []
    overrides = {f'UNKNOWN_{i}': 'CREDENTIAL_CANARY' for i in range(40)}
    overrides['Authorization: CREDENTIAL_CANARY\nINJECTED'] = 'CREDENTIAL_CANARY'
    overrides['PLANNER_MODE'] = {'Authorization': 'CREDENTIAL_CANARY'}
    assert apply_settings_overrides({'PLANNER_MODE': 'shadow'}, overrides, log=seen.append) == {'PLANNER_MODE': 'shadow'}
    assert len(seen) == 17
    assert '42 rejected in total' in seen[-1]
    assert all(len(line) < 250 and '\n' not in line for line in seen)
    assert 'CREDENTIAL_CANARY' not in '\n'.join(seen)
    seen.clear()
    apply_settings_overrides({}, {'Authorization: CREDENTIAL_CANARY\nINJECTED': True,
                                  'PLANNER_MODE': 'CREDENTIAL_CANARY', 7: 'CREDENTIAL_CANARY'}, log=seen.append)
    assert len(seen) == 3
    assert '<invalid-key>' in seen[0] and '<invalid-key>' in seen[2]
    assert 'CREDENTIAL_CANARY' not in '\n'.join(seen)


@pytest.mark.parametrize('value', [None, False, 0, 1, 'false', [], {}])
@pytest.mark.parametrize('key', ['PLANNER_MANIFEST_ENABLED', 'PLANNER_CONSUMER_AI_TAGS',
                                'PLANNER_CONSUMER_TARGET_SELECTION', 'PLANNER_CONSUMER_TWO_PASS'])
def test_planner_bool_is_strict_and_observable(key, value):
    seen = []
    out = apply_settings_overrides({key: True}, {key: value}, log=seen.append)
    if value is False:
        assert out[key] is False and seen == []
    else:
        assert out[key] is True and len(seen) == 1


@pytest.mark.parametrize('value', [None, False, 1, [], {}, 'OFF', ' enforce ', 'invalid'])
def test_planner_enum_is_exact_and_preserves_saved(value):
    seen = []
    assert apply_settings_overrides({'PLANNER_MODE': 'shadow'}, {'PLANNER_MODE': value}, log=seen.append) == {'PLANNER_MODE': 'shadow'}
    assert len(seen) == 1


def test_no_overrides_does_not_invent_defaults_or_modify_saved():
    saved = {'UNRELATED': 'keep'}
    for overrides in (None, {}):
        result = apply_settings_overrides(saved, overrides)
        assert result == saved and result is not saved
