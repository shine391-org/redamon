"""Tests for template_classification module."""

import pytest
import sys
from pathlib import Path

# Add the helpers directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "helpers"))

import template_classification as tc


class TestPrefixClassification:
    """Test prefix-based template classification."""

    def test_origin_safe_prefixes(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry.get_category('ssl/tls-version') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('tls/certificate') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('aws/s3') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('technologies/wordpress') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('exposure/config') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('misconfig/security') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('dns/subdomain') == tc.TemplateCategory.ORIGIN_SAFE
        assert registry.get_category('takeover/azure') == tc.TemplateCategory.ORIGIN_SAFE

    def test_app_prefix_prefixes(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry.get_category('wordpress/wp-admin') == tc.TemplateCategory.APP_PREFIX
        assert registry.get_category('default-login/admin') == tc.TemplateCategory.APP_PREFIX
        assert registry.get_category('panel/phpmyadmin') == tc.TemplateCategory.APP_PREFIX
        assert registry.get_category('wp-plugin/akismet') == tc.TemplateCategory.APP_PREFIX
        assert registry.get_category('joomla/com_content') == tc.TemplateCategory.APP_PREFIX

    def test_endpoint_prefixes(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry.get_category('cves/2024/cve-2024-1234') == tc.TemplateCategory.ENDPOINT
        assert registry.get_category('cve/2023-1234') == tc.TemplateCategory.ENDPOINT
        assert registry.get_category('xss/reflected') == tc.TemplateCategory.ENDPOINT
        assert registry.get_category('vulns/sqli') == tc.TemplateCategory.ENDPOINT
        assert registry.get_category('vulnerabilities/rce') == tc.TemplateCategory.ENDPOINT

    def test_body_multipart_prefixes(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry.get_category('file-upload/webshell') == tc.TemplateCategory.BODY_MULTIPART

    def test_multi_request_prefixes(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry.get_category('fuzz/directory') == tc.TemplateCategory.MULTI_REQUEST
        assert registry.get_category('brute/force') == tc.TemplateCategory.MULTI_REQUEST

    def test_unknown_prefixes(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry.get_category('generic/unknown') == tc.TemplateCategory.UNKNOWN
        assert registry.get_category('http/misc') == tc.TemplateCategory.UNKNOWN


class TestTagClassification:
    """Test tag-based heuristic classification."""

    def test_origin_safe_tags(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry._classify_by_tags(('ssl', 'tls')) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('certificate',)) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('dns',)) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('takeover',)) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('tech', 'fingerprint')) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('exposure',)) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('misconfig',)) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('aws',)) == tc.TemplateCategory.ORIGIN_SAFE
        assert registry._classify_by_tags(('kubernetes',)) == tc.TemplateCategory.ORIGIN_SAFE

    def test_app_prefix_tags(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry._classify_by_tags(('wordpress',)) == tc.TemplateCategory.APP_PREFIX
        assert registry._classify_by_tags(('default-login',)) == tc.TemplateCategory.APP_PREFIX
        assert registry._classify_by_tags(('panel',)) == tc.TemplateCategory.APP_PREFIX
        assert registry._classify_by_tags(('wp-plugin',)) == tc.TemplateCategory.APP_PREFIX

    def test_body_multipart_tags(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry._classify_by_tags(('file-upload',)) == tc.TemplateCategory.BODY_MULTIPART
        assert registry._classify_by_tags(('multipart',)) == tc.TemplateCategory.BODY_MULTIPART

    def test_multi_request_tags(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry._classify_by_tags(('fuzz',)) == tc.TemplateCategory.MULTI_REQUEST
        assert registry._classify_by_tags(('brute',)) == tc.TemplateCategory.MULTI_REQUEST

    def test_endpoint_tags(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry._classify_by_tags(('cve', 'xss')) == tc.TemplateCategory.ENDPOINT
        assert registry._classify_by_tags(('vuln',)) == tc.TemplateCategory.ENDPOINT
        assert registry._classify_by_tags(('sqli',)) == tc.TemplateCategory.ENDPOINT
        assert registry._classify_by_tags(('rce',)) == tc.TemplateCategory.ENDPOINT

    def test_unknown_tags(self):
        registry = tc.TemplateClassificationRegistry()
        assert registry._classify_by_tags(('unknown-tag',)) == tc.TemplateCategory.UNKNOWN
        assert registry._classify_by_tags(('http',)) == tc.TemplateCategory.UNKNOWN
        assert registry._classify_by_tags(('misc',)) == tc.TemplateCategory.UNKNOWN
        assert registry._classify_by_tags(('generic',)) == tc.TemplateCategory.UNKNOWN
        assert registry._classify_by_tags(('network',)) == tc.TemplateCategory.UNKNOWN
        assert registry._classify_by_tags(('protocol',)) == tc.TemplateCategory.UNKNOWN


class TestContentPatternClassification:
    """Test content-based pattern classification."""

    def test_multi_request_content(self):
        registry = tc.TemplateClassificationRegistry()
        multi_content = 'requests:\n  - method: GET\n    path: /test1\n'
        assert registry.classify('test/multi', multi_content).category == tc.TemplateCategory.MULTI_REQUEST

    def test_raw_http_content(self):
        registry = tc.TemplateClassificationRegistry()
        raw_content = 'raw: |\n  GET /test HTTP/1.1\n  Host: example.com\n'
        assert registry.classify('test/raw', raw_content).category == tc.TemplateCategory.RAW_HTTP

        raw_quoted = 'raw: "GET /test HTTP/1.1"'
        assert registry.classify('test/rawq', raw_quoted).category == tc.TemplateCategory.RAW_HTTP

    def test_body_multipart_content(self):
        registry = tc.TemplateClassificationRegistry()
        body_content = 'method: POST\nbody: test=1\n'
        assert registry.classify('test/body', body_content).category == tc.TemplateCategory.BODY_MULTIPART

        multipart_content = 'method: POST\ncontent_type: multipart/form-data\n'
        assert registry.classify('test/multipart', multipart_content).category == tc.TemplateCategory.BODY_MULTIPART

    def test_redirect_chain_content(self):
        registry = tc.TemplateClassificationRegistry()
        redirect_content = 'method: GET\nfollow_redirects: true\n'
        assert registry.classify('test/redirect', redirect_content).category == tc.TemplateCategory.MULTI_REQUEST

    def test_flow_logic_content(self):
        registry = tc.TemplateClassificationRegistry()
        flow_content = 'condition: response.status == 200\n'
        assert registry.classify('test/flow', flow_content).category == tc.TemplateCategory.MULTI_REQUEST

    def test_app_prefix_path_content(self):
        registry = tc.TemplateClassificationRegistry()
        app_content = 'path: "/wp-admin/"\n'
        assert registry.classify('test/app', app_content).category == tc.TemplateCategory.APP_PREFIX


class TestBatchByCategory:
    """Test batching templates by category."""

    def test_batch_by_category(self):
        registry = tc.TemplateClassificationRegistry()
        templates = ['ssl/tls', 'xss/reflected', 'wordpress/wp-admin', 'fuzz/dir', 'file-upload/shell', 'generic/unknown']
        batched = registry.batch_by_category(templates)
        assert batched[tc.TemplateCategory.ORIGIN_SAFE] == ['ssl/tls']
        assert batched[tc.TemplateCategory.ENDPOINT] == ['xss/reflected']
        assert batched[tc.TemplateCategory.APP_PREFIX] == ['wordpress/wp-admin']
        assert batched[tc.TemplateCategory.MULTI_REQUEST] == ['fuzz/dir']
        assert batched[tc.TemplateCategory.BODY_MULTIPART] == ['file-upload/shell']
        assert batched[tc.TemplateCategory.UNKNOWN] == ['generic/unknown']

    def test_compatibility_lane(self):
        registry = tc.TemplateClassificationRegistry()
        templates = ['ssl/tls', 'xss/reflected', 'generic/unknown']
        compat = registry.get_compatibility_templates(templates)
        assert 'generic/unknown' in compat
        assert 'ssl/tls' not in compat
        assert 'xss/reflected' not in compat


class TestCapabilityAnalysis:
    """Test request capability analysis."""

    def test_origin_safe_capability(self):
        cap = tc.analyze_template_capability('ssl/tls-version')
        assert cap.method == 'GET'
        assert cap.has_body == False
        assert cap.supported == True

    def test_body_multipart_capability(self):
        cap = tc.analyze_template_capability('file-upload/webshell')
        assert cap.method == 'POST'
        assert cap.has_body == True
        assert cap.supported == True
        registry = tc.TemplateClassificationRegistry()
        classified = registry.classify('file-upload/webshell')
        assert classified.requires_body_support() == True

    def test_post_content_capability(self):
        post_content = 'method: POST\nbody: test=1\ncontent_type: application/x-www-form-urlencoded\n'
        cap = tc.analyze_template_capability('custom/test', post_content)
        assert cap.method == 'POST'
        assert cap.has_body == True
        assert cap.content_type == 'application/x-www-form-urlencoded'

    def test_json_content_capability(self):
        json_content = 'method: POST\ncontent_type: application/json\nbody: {"key": "value"}\n'
        cap = tc.analyze_template_capability('custom/json', json_content)
        assert cap.method == 'POST'
        assert cap.content_type == 'application/json'

    def test_multipart_detection(self):
        multipart_content = 'method: POST\ncontent_type: multipart/form-data\n'
        cap = tc.analyze_template_capability('custom/multipart', multipart_content)
        assert cap.is_multipart == True
        assert cap.content_type == 'multipart/form-data'


class TestAuthBatchSafety:
    """Test auth batch safety validation."""

    def test_safe_batch(self):
        safe, warnings = tc.validate_auth_batch_safety(
            ['ssl/tls-version', 'aws/s3-bucket'],
            auth_headers=['Cookie: ***'],
            target_origins=['https://example.com'],
            scope_hosts=['example.com']
        )
        assert safe == True

    def test_redirect_warning(self):
        redirect_content = 'method: GET\nfollow_redirects: true\n'
        safe, warnings = tc.validate_auth_batch_safety(
            ['custom/redirect'],
            template_contents={'custom/redirect': redirect_content},
            auth_headers=['Cookie: ***'],
            target_origins=['https://example.com'],
            scope_hosts=['example.com']
        )
        assert any('redirect' in w.lower() for w in warnings)

    def test_oast_unsafe(self):
        oast_content = 'interactsh:\n  url: oast.fun\n'
        safe, warnings = tc.validate_auth_batch_safety(
            ['custom/oast'],
            template_contents={'custom/oast': oast_content},
            auth_headers=['Cookie: ***'],
            target_origins=['https://example.com'],
            scope_hosts=['example.com']
        )
        assert safe == False
        assert any('oast' in w.lower() or 'interactsh' in w.lower() for w in warnings)

    def test_raw_http_warning(self):
        raw_content = 'raw: |\n  GET /test HTTP/1.1\n'
        safe, warnings = tc.validate_auth_batch_safety(
            ['custom/raw'],
            template_contents={'custom/raw': raw_content},
            auth_headers=['Cookie: ***'],
            target_origins=['https://example.com'],
            scope_hosts=['example.com']
        )
        assert any('raw' in w.lower() for w in warnings)

    def test_multi_request_warning(self):
        multi_content = 'requests:\n  - method: GET\n    path: /login\n'
        safe, warnings = tc.validate_auth_batch_safety(
            ['custom/multi'],
            template_contents={'custom/multi': multi_content},
            auth_headers=['Cookie: ***'],
            target_origins=['https://example.com'],
            scope_hosts=['example.com']
        )
        assert any('multi' in w.lower() or 'flow' in w.lower() for w in warnings)

    def test_out_of_scope_warning(self):
        safe, warnings = tc.validate_auth_batch_safety(
            ['ssl/tls-version'],
            auth_headers=['Cookie: ***'],
            target_origins=['https://evil.com'],
            scope_hosts=['example.com']
        )
        assert safe == False
        assert any('out of scope' in w.lower() for w in warnings)

    def test_no_scope_hosts_warning(self):
        safe, warnings = tc.validate_auth_batch_safety(
            ['ssl/tls-version'],
            auth_headers=['Cookie: ***'],
            target_origins=['https://example.com'],
            scope_hosts=None
        )
        assert any('scope hosts not provided' in w.lower() for w in warnings)


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_classify_template(self):
        classified = tc.classify_template('ssl/tls-version')
        assert classified.category == tc.TemplateCategory.ORIGIN_SAFE

    def test_batch_templates_by_category(self):
        templates = ['ssl/tls', 'xss/reflected', 'generic/unknown']
        batched = tc.batch_templates_by_category(templates)
        assert 'ssl/tls' in batched[tc.TemplateCategory.ORIGIN_SAFE]

    def test_get_compatibility_lane_templates(self):
        templates = ['ssl/tls', 'xss/reflected', 'generic/unknown']
        compat = tc.get_compatibility_lane_templates(templates)
        assert 'generic/unknown' in compat


class TestRoutingMode:
    """Test routing mode resolution."""

    def test_default_mode_off(self):
        settings = {}
        assert tc.resolve_routing_mode(settings) == tc.MODE_OFF

    def test_explicit_mode_off(self):
        settings = {"NUCLEI_ROUTING_MODE": "off"}
        assert tc.resolve_routing_mode(settings) == tc.MODE_OFF

    def test_mode_shadow(self):
        settings = {"NUCLEI_ROUTING_MODE": "shadow"}
        assert tc.resolve_routing_mode(settings) == tc.MODE_SHADOW

    def test_mode_enforce(self):
        settings = {"NUCLEI_ROUTING_MODE": "enforce"}
        assert tc.resolve_routing_mode(settings) == tc.MODE_ENFORCE

    def test_invalid_mode_defaults_off(self):
        settings = {"NUCLEI_ROUTING_MODE": "invalid"}
        assert tc.resolve_routing_mode(settings) == tc.MODE_OFF

    def test_consumer_enabled_off(self):
        settings = {"NUCLEI_ROUTING_MODE": "off"}
        assert tc.routing_consumer_enabled(settings) == False

    def test_consumer_enabled_shadow(self):
        settings = {"NUCLEI_ROUTING_MODE": "shadow"}
        assert tc.routing_consumer_enabled(settings) == True

    def test_consumer_enabled_enforce(self):
        settings = {"NUCLEI_ROUTING_MODE": "enforce"}
        assert tc.routing_consumer_enabled(settings) == True


class TestClassifiedTemplateProperties:
    """Test ClassifiedTemplate helper properties."""

    def test_is_known(self):
        registry = tc.TemplateClassificationRegistry()
        known = registry.classify('ssl/tls-version')
        unknown = registry.classify('generic/unknown')
        assert known.is_known() == True
        assert unknown.is_known() == False

    def test_requires_body_support(self):
        registry = tc.TemplateClassificationRegistry()
        body_tpl = registry.classify('file-upload/webshell')
        origin_tpl = registry.classify('ssl/tls-version')
        assert body_tpl.requires_body_support() == True
        assert origin_tpl.requires_body_support() == False

    def test_is_multi_request(self):
        registry = tc.TemplateClassificationRegistry()
        multi_tpl = registry.classify('fuzz/directory')
        origin_tpl = registry.classify('ssl/tls-version')
        assert multi_tpl.is_multi_request() == True
        assert origin_tpl.is_multi_request() == False


class TestRoutingFixture:
    """Test the RoutingFixture controlled receiver verification."""

    def test_routing_fixture_verify_routing(self):
        """Test that RoutingFixture correctly verifies template routing."""
        fixture = tc.RoutingFixture()
        
        # Simulate receiving requests for different template categories
        template_contents = {
            'ssl/tls-version': 'id: ssl/tls-version\ninfo:\n  tags: ssl,tls',
            'xss/reflected': 'id: xss/reflected\ninfo:\n  tags: xss',
            'wordpress/wp-admin': 'id: wordpress/wp-admin\ninfo:\n  tags: wordpress',
            'fuzz/directory': 'id: fuzz/directory\ninfo:\n  tags: fuzz',
            'file-upload/webshell': 'id: file-upload/webshell\ninfo:\n  tags: file-upload',
            'generic/unknown': 'id: generic/unknown\ninfo:\n  tags: generic',
        }
        template_ids = list(template_contents.keys())
        
        # Record simulated requests (6 requests: 5 templates, fuzz sends 2)
        fixture.record_request('ssl/tls-version', 'GET', '/', {}, '', 'https://example.com')
        fixture.record_request('xss/reflected', 'GET', '/search?q=test', {}, '', 'https://example.com/search?q=test')
        fixture.record_request('wordpress/wp-admin', 'GET', '/wp-admin/', {}, '', 'https://example.com/wp-admin/')
        fixture.record_request('fuzz/directory', 'GET', '/dir1', {}, '', 'https://example.com/dir1')
        fixture.record_request('fuzz/directory', 'GET', '/dir2', {}, '', 'https://example.com/dir2')  # Duplicate for multi-request
        fixture.record_request('file-upload/webshell', 'POST', '/upload', {'Content-Type': 'multipart/form-data'}, 'file=data', 'https://example.com/upload')
        # generic/unknown not recorded (simulates missing)
        
        results = fixture.verify_routing(template_ids, template_contents)
        
        # Verify results structure
        assert results['total_templates'] == 6
        assert results['received'] == 6  # 5 templates sent requests, fuzz sent 2 = 6 total
        assert 'duplicates' in results
        assert 'missing' in results
        assert 'by_category' in results
        
        # Check duplicates counted
        assert results['duplicates'] == 1  # fuzz/directory sent 2 requests
        
        # Check missing
        assert 'generic/unknown' in results['missing']
        
        # Check by_category counts
        assert results['by_category']['origin_safe']['expected'] == 1
        assert results['by_category']['origin_safe']['received'] == 1
        assert results['by_category']['endpoint']['expected'] == 1
        assert results['by_category']['endpoint']['received'] == 1
        assert results['by_category']['app_prefix']['expected'] == 1
        assert results['by_category']['app_prefix']['received'] == 1
        assert results['by_category']['multi_request']['expected'] == 1
        assert results['by_category']['multi_request']['received'] == 2  # 2 requests for fuzz
        assert results['by_category']['body_multipart']['expected'] == 1
        assert results['by_category']['body_multipart']['received'] == 1
        assert results['by_category']['unknown']['expected'] == 1
        assert results['by_category']['unknown']['received'] == 0

    def test_routing_fixture_no_duplicates(self):
        """Test that RoutingFixture correctly counts no duplicates when each template sends one request."""
        fixture = tc.RoutingFixture()
        
        template_contents = {
            'ssl/tls-version': 'id: ssl/tls-version\ninfo:\n  tags: ssl',
            'xss/reflected': 'id: xss/reflected\ninfo:\n  tags: xss',
        }
        template_ids = list(template_contents.keys())
        
        fixture.record_request('ssl/tls-version', 'GET', '/', {}, '', 'https://example.com')
        fixture.record_request('xss/reflected', 'GET', '/search', {}, '', 'https://example.com/search')
        
        results = fixture.verify_routing(template_ids, template_contents)
        
        assert results['duplicates'] == 0
        assert results['missing'] == []
        assert results['received'] == 2

    def test_routing_fixture_all_missing(self):
        """Test that RoutingFixture handles all templates missing."""
        fixture = tc.RoutingFixture()
        
        template_contents = {
            'ssl/tls-version': 'id: ssl/tls-version\ninfo:\n  tags: ssl',
        }
        template_ids = list(template_contents.keys())
        
        # No requests recorded
        results = fixture.verify_routing(template_ids, template_contents)
        
        assert results['received'] == 0
        assert results['missing'] == ['ssl/tls-version']
        assert results['duplicates'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
