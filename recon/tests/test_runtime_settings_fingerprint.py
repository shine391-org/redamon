"""Regression: API-loaded settings contain live, non-JSON KeyRotator objects.

Exercise real loader -> real checkpoint / manifest / planner, offline. Credential
strings below are explicit redacted fixture markers, never real credentials.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from recon import project_settings as ps
from recon.helpers import planner_manifest as pm
from recon.helpers.scan_planner import ScanPlanner


@pytest.fixture
def runtime_settings(monkeypatch):
    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                'userId': 'fixture-user', 'targetDomain': 'example.test',
                'subdomainList': ['.'], 'updateGraphDb': False,
                'urlscanEnabled': True, 'chunkCheckpointEnabled': True,
                'plannerManifestEnabled': True,
            }

    monkeypatch.setenv('PROJECT_ID', 'fixture-project')
    monkeypatch.setenv('WEBAPP_API_URL', 'http://offline.invalid')
    monkeypatch.setenv('REDAMON_MEM_GOVERNOR', '0')
    monkeypatch.setattr('requests.get', lambda *a, **kw: Response())
    monkeypatch.setattr(ps, '_fetch_user_settings_full', lambda *a, **kw: {
        'urlscanApiKey': '[REDACTED-1]',
        'rotationConfigs': {'urlscan': {'extraKeys': ['[REDACTED-2]'], 'rotateEveryN': 1}},
    })
    settings = ps.get_settings()
    assert type(settings['URLSCAN_KEY_ROTATOR']).__name__ == 'KeyRotator'
    return settings


def load_main(settings, monkeypatch):
    monkeypatch.setattr(ps, 'get_settings', lambda: settings)
    path = Path(__file__).resolve().parents[1] / 'main.py'
    spec = importlib.util.spec_from_file_location('runtime_settings_startup_probe', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('mode', ['off', 'shadow', 'enforce'])
def test_api_settings_reach_real_checkpoint(runtime_settings, monkeypatch, tmp_path, mode):
    settings = dict(runtime_settings, PLANNER_MODE=mode)
    main = load_main(settings, monkeypatch)
    monkeypatch.setattr(main, 'OUTPUT_DIR', tmp_path)
    assert main._start_checkpoint(settings, 'fixture-project', 'fixture-run', 'example.test', 'fixture-user') == 'fresh'
    assert main._checkpoint_revision.settings_hash
    assert main._start_checkpoint(settings, 'fixture-project', 'fixture-run', 'example.test', 'fixture-user') == 'resumed'
    text = (tmp_path / '.recon_fixture-project.json.fixture-run.chunk-journal').read_text()
    assert '[REDACTED-1]' not in text and '[REDACTED-2]' not in text
    assert len(main._checkpoint_revision.settings_hash) == 64


@pytest.mark.parametrize('mode', ['off', 'shadow', 'enforce'])
def test_api_settings_build_real_manifest(runtime_settings, mode):
    settings = dict(runtime_settings, PLANNER_MODE=mode)
    manifest = pm.build_manifest(run_id='fixture-run', group_id='example.test',
        tenant='fixture-user', project_id='fixture-project', scope={'roots': ['example.test']},
        settings=settings, template_hashes={}, task_summaries=[])
    assert manifest['settings_hash_prefix'] == manifest['settings_hash'][:16]
    assert '[REDACTED-1]' not in json.dumps(manifest)


@pytest.mark.parametrize('mode', ['off', 'shadow', 'enforce'])
def test_api_settings_reach_real_planner(runtime_settings, mode):
    settings = dict(runtime_settings, PLANNER_MODE=mode)
    planner = ScanPlanner(settings, ['ssl'])
    plan = planner.plan(['https://example.test/'])
    assert plan.manifest['settings_hash_prefix'] == plan.manifest['settings_hash'][:16]
    assert '[REDACTED-1]' not in json.dumps(plan.manifest)


@pytest.mark.parametrize('mode', ['off', 'shadow', 'enforce'])
def test_full_entrypoint_crosses_checkpoint_without_target_calls(runtime_settings, monkeypatch, tmp_path, mode):
    """The actual main() -> domain runner crosses the former crash boundary.

    Stop at the next pure metadata builder, before WHOIS/DNS/scanner dispatch.
    Graph clearing and shutdown sweeps are local fixtures, never live services.
    """
    from recon.main_recon_modules.domain_recon import resolver_breaker

    settings = dict(runtime_settings, PLANNER_MODE=mode)
    main = load_main(settings, monkeypatch)
    monkeypatch.setattr(main, 'OUTPUT_DIR', tmp_path)
    monkeypatch.setenv('RECON_RUN_ID', 'fixture-entrypoint-run')
    monkeypatch.setattr(resolver_breaker, 'recheck', lambda: None)
    monkeypatch.setattr(main, '_clear_recon_graph', lambda: None)
    monkeypatch.setattr(main, '_apply_node_filters', lambda: None)

    class CheckpointCrossed(BaseException):
        pass

    def stop_before_first_scanner():
        assert main._checkpoint_revision is not None
        raise CheckpointCrossed()

    monkeypatch.setattr(main, 'build_scan_type', stop_before_first_scanner)
    with pytest.raises(CheckpointCrossed):
        main.main()
    assert (tmp_path / '.recon_fixture-project.json.fixture-entrypoint-run.chunk-journal').is_file()


def test_plain_json_hash_is_backwards_compatible():
    from recon.helpers.settings_fingerprint import settings_fingerprint
    data = {'PLANNER_MODE': 'off', 'LIST': [1, True, None], 'NESTED': {'x': 'y'}}
    assert settings_fingerprint(data) == hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
    assert settings_fingerprint(data, compact=True) == hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def test_rotation_and_drop_do_not_change_hash_but_configuration_does(runtime_settings):
    from helpers.key_rotation import KeyRotator
    from recon.helpers.settings_fingerprint import settings_fingerprint
    before = settings_fingerprint(runtime_settings)
    rotator = runtime_settings['URLSCAN_KEY_ROTATOR']
    rotator.tick()
    assert settings_fingerprint(runtime_settings) == before
    rotator.mark_bad(0)
    assert settings_fingerprint(runtime_settings) == before
    changed_config = dict(runtime_settings, URLSCAN_KEY_ROTATOR=KeyRotator(['[REDACTED-1]', '[REDACTED-2]'], 2))
    assert settings_fingerprint(changed_config) != before
    changed_keys = dict(runtime_settings, URLSCAN_KEY_ROTATOR=KeyRotator(['[REDACTED-1]', '[REDACTED-3]'], 1))
    assert settings_fingerprint(changed_keys) != before
    assert settings_fingerprint(dict(runtime_settings, NUCLEI_RATE_LIMIT=7)) != before


def test_unknown_objects_fail_closed_without_repr():
    from recon.helpers.settings_fingerprint import settings_fingerprint
    class Unsupported:
        def __str__(self):
            raise AssertionError('must not stringify arbitrary objects')
        __repr__ = __str__
    with pytest.raises(TypeError, match='Unsupported'):
        settings_fingerprint({'unknown': Unsupported()})


def test_both_module_import_paths_share_rotator_semantics():
    from helpers.key_rotation import KeyRotator as LegacyRotator
    from recon.helpers.key_rotation import KeyRotator
    from recon.helpers.settings_fingerprint import settings_fingerprint
    assert settings_fingerprint({'rotator': LegacyRotator(['[REDACTED]'])}) == settings_fingerprint({'rotator': KeyRotator(['[REDACTED]'])})


def test_rotator_config_changes_do_not_change_fingerprint_if_initial_json_config_is_same(runtime_settings):
    from helpers.key_rotation import KeyRotator as LegacyRotator
    from recon.helpers.key_rotation import KeyRotator
    from recon.helpers.settings_fingerprint import settings_fingerprint
    same_config = dict(runtime_settings, URLSCAN_KEY_ROTATOR=KeyRotator(['[REDACTED-1]', '[REDACTED-2]'], 1))
    assert settings_fingerprint(same_config) == settings_fingerprint(runtime_settings)
    assert settings_fingerprint({'rotator': LegacyRotator(['[REDACTED]'])}) == settings_fingerprint({'rotator': KeyRotator(['[REDACTED]'])})


def test_rotator_configuration_fingerprint_survives_live_state():
    from recon.helpers.key_rotation import KeyRotator
    from recon.helpers.settings_fingerprint import settings_fingerprint
    rotator = KeyRotator(['[REDACTED-1]', '[REDACTED-2]'], 1)
    before = settings_fingerprint({'rotator': rotator})
    rotator.tick(); rotator.mark_bad(0)
    assert settings_fingerprint({'rotator': rotator}) == before
    assert KeyRotator(['[REDACTED-1]', '[REDACTED-2]'], 1).configuration_fingerprint == rotator.configuration_fingerprint
    assert KeyRotator(['[REDACTED-1]', '[REDACTED-2]'], 2).configuration_fingerprint != rotator.configuration_fingerprint
    assert KeyRotator(['[REDACTED-1]', '[REDACTED-3]'], 1).configuration_fingerprint != rotator.configuration_fingerprint


def test_only_the_actual_recon_rotator_class_is_allowed_not_a_name_spoof():
    from recon.helpers.settings_fingerprint import settings_fingerprint

    class KeyRotator:
        configuration_fingerprint = '[REDACTED]'

    with pytest.raises(TypeError, match='Unsupported runtime settings value: KeyRotator'):
        settings_fingerprint({'rotator': KeyRotator()})
