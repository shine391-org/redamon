"""
F04 pruning-contract tests: AI pruning never expands the saved selection
and never overrides master flags.

Defects these regressions pin (fail on the pinned base 104f66cc, pass here):
1. get_ai_tags validated the AI response against the candidate universe, so
   the model could ADD tags the user never selected ('wordpress', 'apache',
   'takeover', ...). Fix: the response is validated as a subset of the
   policy-filtered saved selection.
2. Every failure path returned the raw user list, ignoring
   NUCLEI_EXCLUDE_TAGS. Fix: fallback equals the policy-filtered selection.
3. Duplicate tags passed through; no added/removed/effective + reason was
   recorded. Fix: dedupe at validation + scan_metadata accounting.
4. The runtime consumer (run_vuln_scan) passed the helper result straight to
   build_nuclei_command, so a mocked/legacy/planner implementation returning
   an expanded list reached the Nuclei argv. Fix: defensive clamp at the
   consumer + metadata report.

Master-flag precedence is tested through the real loader (get_settings with
a mocked webapp) and through the runtime wiring, not only get_ai_tags.
Identity headers are exercised through the HEAD-probe path. No network, no
Docker, no LLM calls: agent requests are mocked.
"""
import os
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / 'recon'))

import recon.helpers.ai_planner.nuclei_tags as nt
from recon.helpers.ai_planner.nuclei_tags import (
    _validate_tags,
    get_ai_tags,
    policy_filtered_selection,
    selection_report,
)


def _mock_resp(json_data=None, status_code=200):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = ''
    return resp


# ---------- helper: subset validation ----------

def test_validate_tags_drops_unselected_candidates():
    """AI may keep tags only from the saved selection (pruning, not
    selection) -- a valid candidate the user never chose is dropped."""
    out = _validate_tags(
        ['cve', 'wordpress', 'takeover'],
        candidates=['cve', 'wordpress', 'takeover'],
        allowed=['cve', 'xss'],
    )
    assert out == ['cve']
    print("PASS: test_validate_tags_drops_unselected_candidates")


def test_validate_tags_dedupe_and_exclusions():
    out = _validate_tags(
        ['cve', 'cve', 'xss', 'dos', '../../etc', 42, 'T AKE'],
        candidates=['cve', 'xss', 'dos'],
        allowed=['cve', 'xss', 'dos'],
        excluded=['dos'],
    )
    assert out == ['cve', 'xss']
    print("PASS: test_validate_tags_dedupe_and_exclusions")


def test_policy_filtered_selection_removes_exclusions_and_dupes():
    out = policy_filtered_selection(
        ['cve', 'xss', 'cve', 'dos', 'fuzz'], ['dos', 'fuzz'])
    assert out == ['cve', 'xss']
    print("PASS: test_policy_filtered_selection_removes_exclusions_and_dupes")


def test_selection_report_marks_expansion():
    rep = selection_report(['cve', 'xss'], ['cve', 'takeover'])
    assert rep['added_tags'] == ['takeover']
    assert rep['reason'] == 'expansion_detected'
    print("PASS: test_selection_report_marks_expansion")


# ---------- get_ai_tags: pruning contract ----------

def test_get_ai_tags_cannot_add_takeover_or_unselected():
    nt._candidates_cache = ['cve', 'xss', 'sqli', 'takeover', 'wordpress']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={
                        'tags': ['cve', 'takeover', 'wordpress', 'evil-injected']})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['wordpress'], 'servers': []},
            current_tags=['cve', 'xss', 'sqli'],
            model='m',
        )
    assert result == ['cve'], f"expansion leaked: {result}"
    print("PASS: test_get_ai_tags_cannot_add_takeover_or_unselected")


def test_get_ai_tags_exclusions_win_over_ai_and_fallback():
    nt._candidates_cache = ['cve', 'xss', 'dos']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['cve', 'dos']})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss', 'dos'],
            model='m',
            exclude_tags=['dos'],
        )
    assert result == ['cve']
    # Invalid-response fallback also honours the exclusion list (no default-all).
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': 'not-a-list'})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss', 'dos'],
            model='m',
            exclude_tags=['dos'],
        )
    assert result == ['cve', 'xss'], f"fallback must be policy-filtered: {result}"
    print("PASS: test_get_ai_tags_exclusions_win_over_ai_and_fallback")


def test_get_ai_tags_empty_response_is_policy_fallback_not_default_all():
    nt._candidates_cache = ['cve', 'xss']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': []})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve'],
            model='m',
        )
    assert result == ['cve']
    print("PASS: test_get_ai_tags_empty_response_is_policy_fallback_not_default_all")


def test_get_ai_tags_duplicate_ai_tags_are_coalesced():
    nt._candidates_cache = ['cve', 'xss']
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['cve', 'cve', 'xss', 'xss']})):
        result = get_ai_tags(
            tech_fingerprint={'technologies': ['x'], 'servers': []},
            current_tags=['cve', 'xss'],
            model='m',
        )
    assert result == ['cve', 'xss']
    print("PASS: test_get_ai_tags_duplicate_ai_tags_are_coalesced")


def test_get_ai_tags_head_probe_carries_identity_headers():
    """The opportunistic HEAD probe must send the configured identity
    headers; a bare probe would be an unauthenticated fresh request."""
    nt._candidates_cache = ['cve']
    seen = {}
    def _fake_head(url, allow_redirects, timeout, headers=None, **kw):
        seen['headers'] = headers
        r = mock.MagicMock()
        r.headers = {'Server': 'Apache/2.4'}
        return r
    with mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.head',
                    side_effect=_fake_head), \
         mock.patch('recon.helpers.ai_planner.nuclei_tags.requests.post',
                    return_value=_mock_resp(json_data={'tags': ['cve']})):
        get_ai_tags(
            tech_fingerprint={'technologies': [], 'servers': []},
            current_tags=['cve'],
            model='m',
            fallback_urls=['https://example.com/'],
            settings={'ENGAGEMENT_IDENTITY_HEADER': 'X-Bug-Bounty: tester'},
        )
    assert seen.get('headers'), "HEAD probe must carry identity headers"
    print("PASS: test_get_ai_tags_head_probe_carries_identity_headers")


# ---------- loader precedence (real get_settings path) ----------

def _mock_project(**overrides):
    base = {
        "ffufEnabled": True, "nucleiEnabled": True,
        "nucleiAiTags": False, "stealthMode": False,
        "aiInPipeline": False, "aiPipelineModel": "m",
        "nucleiTags": ["cve", "xss"],
    }
    base.update(overrides)
    return base


def _mock_response(project_dict):
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.json.return_value = project_dict
    resp.raise_for_status = mock.MagicMock()
    return resp


def test_loader_master_on_forces_ai_tags_and_keeps_saved_tags():
    from recon import project_settings
    fake = _mock_project(aiInPipeline=True, nucleiAiTags=False)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 't', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake)):
        settings = project_settings.get_settings()
    assert settings['NUCLEI_AI_TAGS'] is True
    assert 'NUCLEI_TAGS' in settings, "saved selection must survive the cascade"
    print("PASS: test_loader_master_on_forces_ai_tags_and_keeps_saved_tags")


def test_loader_master_off_forces_ai_tags_off():
    from recon import project_settings
    fake = _mock_project(aiInPipeline=False, nucleiAiTags=True)
    with mock.patch.dict(os.environ, {'PROJECT_ID': 't', 'WEBAPP_API_URL': 'http://x'}, clear=False), \
         mock.patch('requests.get', return_value=_mock_response(fake)):
        settings = project_settings.get_settings()
    assert settings['NUCLEI_AI_TAGS'] is False
    print("PASS: test_loader_master_off_forces_ai_tags_off")


# ---------- runtime consumer clamp ----------

def _wiring_helpers():
    from recon.tests.test_nuclei_ai_vuln_scan_wiring import (
        _recon_data, _base_settings, _pipeline_patches)
    return _recon_data, _base_settings, _pipeline_patches


def test_runtime_clamps_expanded_ai_result_before_command():
    """A legacy/planner helper that returns unselected/'takeover' tags must
    not reach build_nuclei_command; metadata shows added=[] and the clamp."""
    from recon.main_recon_modules import vuln_scan as vs
    _recon_data, _base_settings, _pipeline_patches = _wiring_helpers()
    rd = _recon_data(with_tech=True)
    settings = _base_settings(NUCLEI_AI_TAGS=True)
    patches = _pipeline_patches()
    for p in patches:
        p.start()
    try:
        with mock.patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
             mock.patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags",
                        return_value=["cve", "takeover", "wordpress", "cve"]), \
             mock.patch.object(vs, "build_nuclei_command",
                               return_value=["docker", "run", "fake"]) as cmd_mock:
            vs.run_vuln_scan(rd, output_file=None, settings=settings)
    finally:
        for p in patches:
            p.stop()
    assert cmd_mock.call_args.kwargs["tags"] == ["cve"]
    md = rd["vuln_scan"]["scan_metadata"]
    assert md["tags_added"] == []
    assert md["tags_effective"] == ["cve"]
    assert "takeover" in md["tags_removed"] or "sqli" in md["tags_removed"]
    assert md["tags_selection_reason"] in ("ai_pruned", "fallback_policy_filtered")
    print("PASS: test_runtime_clamps_expanded_ai_result_before_command")


def test_runtime_preserves_explicit_custom_templates_under_pruning():
    """Explicit NUCLEI_TEMPLATES must reach the command builder untouched
    while AI prunes only the tag list (no selection reset)."""
    from recon.main_recon_modules import vuln_scan as vs
    _recon_data, _base_settings, _pipeline_patches = _wiring_helpers()
    rd = _recon_data(with_tech=True)
    settings = _base_settings(NUCLEI_AI_TAGS=True,
                              NUCLEI_TEMPLATES=["http/exposures/custom.yaml"])
    patches = _pipeline_patches()
    for p in patches:
        p.start()
    try:
        with mock.patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
             mock.patch("recon.helpers.ai_planner.nuclei_tags.get_ai_tags",
                        return_value=["cve", "xss"]), \
             mock.patch.object(vs, "build_nuclei_command",
                               return_value=["docker", "run", "fake"]) as cmd_mock:
            vs.run_vuln_scan(rd, output_file=None, settings=settings)
    finally:
        for p in patches:
            p.stop()
    kwargs = cmd_mock.call_args.kwargs
    assert kwargs["tags"] == ["cve", "xss"]
    assert kwargs.get("templates") == ["http/exposures/custom.yaml"]
    print("PASS: test_runtime_preserves_explicit_custom_templates_under_pruning")


if __name__ == '__main__':
    nt._candidates_cache = None
    test_validate_tags_drops_unselected_candidates()
    test_validate_tags_dedupe_and_exclusions()
    test_policy_filtered_selection_removes_exclusions_and_dupes()
    test_selection_report_marks_expansion()
    test_get_ai_tags_cannot_add_takeover_or_unselected()
    test_get_ai_tags_exclusions_win_over_ai_and_fallback()
    test_get_ai_tags_empty_response_is_policy_fallback_not_default_all()
    test_get_ai_tags_duplicate_ai_tags_are_coalesced()
    test_get_ai_tags_head_probe_carries_identity_headers()
    test_loader_master_on_forces_ai_tags_and_keeps_saved_tags()
    test_loader_master_off_forces_ai_tags_off()
    test_runtime_clamps_expanded_ai_result_before_command()
    test_runtime_preserves_explicit_custom_templates_under_pruning()
    print("\nAll F04 contract tests passed")
