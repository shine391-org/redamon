"""
Unit tests for Arjun late-source parameter discovery (F12).

Tests the classification, planning, and merge of endpoints that appear
from late sources (GAU, ParamSpider, Kiterunner, URLScan, OpenAPI)
after the early Arjun pass has run.
"""

import sys
import json
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.resource_enum.arjun_contract import (
    classify_late_source_endpoint,
    plan_arjun_late_sources,
    select_arjun_targets,
    arjun_url_host,
)


# =============================================================================
# classify_late_source_endpoint tests
# =============================================================================

def _base_endpoint_data(**overrides):
    base = {
        'sources': ['katana'],
        'methods': ['GET'],
        'parameters': {'query': ['id'], 'body': [], 'path': []},
        'declared_only': False,
        'dead': False,
        'unverified_archive': False,
        'status_code': 200,
    }
    base.update(overrides)
    return base


def test_classify_eligible_observed_endpoint():
    """Endpoint with observed source (katana) should be eligible."""
    ep = _base_endpoint_data(sources=['katana'], methods=['GET', 'POST'])
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is True
    assert result['defer_reason'] is None
    assert set(result['methods']) == {'GET', 'POST'}
    assert result['has_known_schema'] is True
    assert result['sources'] == ['katana']


def test_classify_eligible_gau_endpoint():
    """Endpoint from GAU should be eligible."""
    ep = _base_endpoint_data(sources=['gau'], methods=['GET'])
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is True
    assert result['defer_reason'] is None
    assert result['methods'] == ['GET']


def test_classify_declared_only_openapi_uninstantiated():
    """OpenAPI-only endpoint with template params should be deferred."""
    ep = _base_endpoint_data(sources=['openapi'], declared_only=True)
    result = classify_late_source_endpoint('https://example.com', '/api/{id}', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is False
    assert result['defer_reason'] == 'declared_only_uninstantiated'


def test_classify_openapi_with_observed_source():
    """OpenAPI endpoint that ALSO has observed source should be eligible."""
    ep = _base_endpoint_data(sources=['openapi', 'gau'], declared_only=True)
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is True
    assert result['defer_reason'] is None


def test_classify_out_of_scope():
    """Endpoint on different host should be deferred."""
    ep = _base_endpoint_data(sources=['gau'])
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'other.com'})

    assert result['eligible'] is False
    assert result['defer_reason'] == 'out_of_scope'


def test_classify_dead_endpoint():
    """Dead endpoint (404) should be deferred."""
    ep = _base_endpoint_data(sources=['gau'], status_code=404)
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is False
    assert result['defer_reason'] == 'dead_endpoint'


def test_classify_unverified_archive():
    """Unverified archive endpoint should be deferred."""
    ep = _base_endpoint_data(sources=['urlscan'], unverified_archive=True)
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is False
    assert result['defer_reason'] == 'unverified_archive'


def test_classify_retains_methods():
    """Methods should be retained from endpoint data, not blind GET-only."""
    ep = _base_endpoint_data(sources=['gau'], methods=['POST', 'JSON'])
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is True
    assert set(result['methods']) == {'POST', 'JSON'}


def test_classify_unknown_method_defaults_to_get():
    """Unknown methods should default to GET."""
    ep = _base_endpoint_data(sources=['gau'], methods=['INVALID', 'GET'])
    result = classify_late_source_endpoint('https://example.com', '/api/users', ep, allowed_hosts={'example.com'})

    assert result['eligible'] is True
    assert 'GET' in result['methods']
    assert 'INVALID' not in result['methods']


# =============================================================================
# select_arjun_targets tests (fair origin scheduling)
# =============================================================================

def test_select_arjun_targets_fair_origin_scheduling():
    """When cap binds, selection should distribute fairly across origins."""
    urls = [
        'https://api.example.com/v1/users',
        'https://api.example.com/v1/orders',
        'https://api.example.com/v1/products',
        'https://other.com/admin',
        'https://other.com/dashboard',
        'https://third.org/api/data',
    ]
    selected, unselected = select_arjun_targets(urls, maximum=4)

    # Should pick from each origin round-robin
    origins_selected = {arjun_url_host(u) for u in selected}
    assert 'api.example.com' in origins_selected
    assert 'other.com' in origins_selected
    assert 'third.org' in origins_selected
    assert len(selected) == 4


def test_select_arjun_targets_priority_buckets():
    """API paths should be prioritized over dynamic over other."""
    urls = [
        'https://example.com/static/page.html',
        'https://example.com/api/v1/users',
        'https://example.com/dynamic.php',
        'https://example.com/other',
    ]
    selected, unselected = select_arjun_targets(urls, maximum=2)

    # API should be first priority
    assert any('/api/' in u for u in selected)
    assert len(selected) == 2


def test_select_arjun_targets_no_cap_returns_all():
    """When urls <= maximum, all should be returned."""
    urls = ['https://example.com/a', 'https://example.com/b']
    selected, unselected = select_arjun_targets(urls, maximum=10)

    assert selected == urls
    assert unselected == []


# =============================================================================
# plan_arjun_late_sources tests
# =============================================================================

def _make_by_base_url():
    """Create a realistic by_base_url structure with endpoints from various sources."""
    return {
        'https://example.com': {
            'base_url': 'https://example.com',
            'endpoints': {
                '/api/users': {
                    'methods': ['GET'],
                    'parameters': {'query': [], 'body': [], 'path': []},
                    'sources': ['gau'],
                    'category': 'api',
                },
                '/api/orders': {
                    'methods': ['GET', 'POST'],
                    'parameters': {'query': ['id'], 'body': [], 'path': []},
                    'sources': ['paramspider'],
                    'category': 'api',
                },
                '/admin': {
                    'methods': ['GET'],
                    'parameters': {'query': [], 'body': [], 'path': []},
                    'sources': ['kiterunner'],
                    'category': 'admin',
                },
                '/openapi-declared': {
                    'methods': ['GET'],
                    'parameters': {'query': ['filter'], 'body': [], 'path': []},
                    'sources': ['openapi'],
                    'declared_only': True,
                    'category': 'api',
                },
                '/dead': {
                    'methods': ['GET'],
                    'parameters': {'query': [], 'body': [], 'path': []},
                    'sources': ['urlscan'],
                    'status_code': 404,
                    'category': 'other',
                },
            },
            'summary': {'total_endpoints': 5, 'total_parameters': 1, 'methods': {'GET': 4, 'POST': 1}, 'categories': {'api': 3, 'admin': 1, 'other': 1}}
        }
    }


def test_plan_arjun_late_sources_admits_eligible():
    """Eligible late-source endpoints should be admitted."""
    by_base_url = _make_by_base_url()
    already_targeted = {'https://example.com/api/orders'}  # Already done by early Arjun

    admitted, deferred, summary = plan_arjun_late_sources(
        by_base_url,
        already_targeted,
        allowed_hosts={'example.com'},
        remaining_budget=10,
    )

    admitted_urls = {t['url'] for t in admitted}
    assert 'https://example.com/api/users' in admitted_urls
    assert 'https://example.com/admin' in admitted_urls
    # /api/orders already targeted, /openapi-declared deferred, /dead deferred
    assert len(admitted) == 2
    assert summary['admitted_count'] == 2
    # already_targeted is excluded from both admitted and deferred
    assert summary['deferred_count'] == 2


def test_plan_arjun_late_sources_respects_budget():
    """Budget cap should defer excess endpoints."""
    by_base_url = _make_by_base_url()
    already_targeted = set()

    admitted, deferred, summary = plan_arjun_late_sources(
        by_base_url,
        already_targeted,
        allowed_hosts={'example.com'},
        remaining_budget=2,
    )

    assert len(admitted) == 2
    assert summary['admitted_count'] == 2
    # 5 total - 2 admitted = 3 deferred (plus budget cap)
    assert summary['deferred_count'] >= 3
    budget_deferred = [d for d in deferred if d['reason'] == 'budget_cap_exceeded']
    assert len(budget_deferred) >= 1


def test_plan_arjun_late_sources_deferred_reasons_tracked():
    """Deferred endpoints should have correct reasons tracked."""
    by_base_url = _make_by_base_url()
    already_targeted = set()

    admitted, deferred, summary = plan_arjun_late_sources(
        by_base_url,
        already_targeted,
        allowed_hosts={'example.com'},
        remaining_budget=10,
    )

    reasons = {d['reason'] for d in deferred}
    assert 'declared_only_uninstantiated' in reasons
    assert 'dead_endpoint' in reasons
    assert summary['deferred_reasons']['declared_only_uninstantiated'] == 1
    assert summary['deferred_reasons']['dead_endpoint'] == 1


def test_plan_arjun_late_sources_methods_retained():
    """Admitted tasks should retain methods from endpoint."""
    by_base_url = _make_by_base_url()
    already_targeted = set()

    admitted, deferred, summary = plan_arjun_late_sources(
        by_base_url,
        already_targeted,
        allowed_hosts={'example.com'},
        remaining_budget=10,
    )

    # Find the /api/orders task which has GET, POST
    orders_task = next(t for t in admitted if t['path'] == '/api/orders')
    assert set(orders_task['methods']) == {'GET', 'POST'}


def test_plan_arjun_late_sources_zero_budget():
    """Zero budget should defer all eligible candidates."""
    by_base_url = _make_by_base_url()
    already_targeted = set()

    admitted, deferred, summary = plan_arjun_late_sources(
        by_base_url,
        already_targeted,
        allowed_hosts={'example.com'},
        remaining_budget=0,
    )

    assert len(admitted) == 0
    assert summary['admitted_count'] == 0
    # 2 classified-deferred + 3 budget-deferred = 5 total deferred
    assert summary['deferred_count'] == 5
    budget_deferred = [d for d in deferred if d['reason'] == 'budget_cap_exceeded']
    assert len(budget_deferred) == 3


# =============================================================================
# Integration test: merge_arjun_into_by_base_url with late sources
# =============================================================================

def test_merge_late_arjun_results_into_existing():
    """Late Arjun results should merge correctly with existing endpoints."""
    from recon.helpers.resource_enum.arjun_helpers import merge_arjun_into_by_base_url

    # Start with by_base_url that has endpoints from late sources
    by_base_url = _make_by_base_url()

    # Simulate late Arjun results for /api/users (from GAU) and /admin (from kiterunner)
    late_arjun_results = [
        {'url': 'https://example.com/api/users', 'params': ['debug', 'token'], 'method': 'GET'},
        {'url': 'https://example.com/admin', 'params': ['cmd'], 'method': 'POST'},
    ]

    result, stats = merge_arjun_into_by_base_url(late_arjun_results, by_base_url, allowed_hosts={'example.com'})

    # /api/users should be enriched
    users_ep = result['https://example.com']['endpoints']['/api/users']
    assert 'debug' in [p['name'] for p in users_ep['parameters']['query']]
    assert 'token' in [p['name'] for p in users_ep['parameters']['query']]
    assert 'arjun' in users_ep['sources']

    # /admin should get POST method and body param
    admin_ep = result['https://example.com']['endpoints']['/admin']
    assert 'POST' in admin_ep['methods']
    assert 'cmd' in [p['name'] for p in admin_ep['parameters']['body']]

    assert stats['arjun_params_discovered'] == 3
    assert stats['arjun_existing_enriched'] == 2  # both /api/users and /admin existed
    assert stats['arjun_new_endpoints'] == 0  # both existed


# =============================================================================
# Run all tests
# =============================================================================

if __name__ == '__main__':
    # Classification tests
    test_classify_eligible_observed_endpoint()
    test_classify_eligible_gau_endpoint()
    test_classify_declared_only_openapi_uninstantiated()
    test_classify_openapi_with_observed_source()
    test_classify_out_of_scope()
    test_classify_dead_endpoint()
    test_classify_unverified_archive()
    test_classify_retains_methods()
    test_classify_unknown_method_defaults_to_get()

    # Selection tests
    test_select_arjun_targets_fair_origin_scheduling()
    test_select_arjun_targets_priority_buckets()
    test_select_arjun_targets_no_cap_returns_all()

    # Planning tests
    test_plan_arjun_late_sources_admits_eligible()
    test_plan_arjun_late_sources_respects_budget()
    test_plan_arjun_late_sources_deferred_reasons_tracked()
    test_plan_arjun_late_sources_methods_retained()
    test_plan_arjun_late_sources_zero_budget()

    # Integration test
    test_merge_late_arjun_results_into_existing()

    print("\n" + "=" * 50)
    print("ALL ARJUN LATE SOURCES TESTS PASSED")
    print("=" * 50)