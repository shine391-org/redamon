import sys
sys.path.insert(0, '/data/redamon/workspace/worktrees/recon-quality/f14/recon/helpers')
import template_classification as tc

# Test prefix classification
registry = tc.TemplateClassificationRegistry()

# Origin safe
assert registry.get_category('ssl/tls-version') == tc.TemplateCategory.ORIGIN_SAFE
assert registry.get_category('tls/certificate') == tc.TemplateCategory.ORIGIN_SAFE
assert registry.get_category('aws/s3') == tc.TemplateCategory.ORIGIN_SAFE

# App prefix
assert registry.get_category('wordpress/wp-admin') == tc.TemplateCategory.APP_PREFIX
assert registry.get_category('default-login/admin') == tc.TemplateCategory.APP_PREFIX

# Endpoint
assert registry.get_category('cves/2024/cve-2024-1234') == tc.TemplateCategory.ENDPOINT
assert registry.get_category('xss/reflected') == tc.TemplateCategory.ENDPOINT
assert registry.get_category('vulns/sqli') == tc.TemplateCategory.ENDPOINT

# Body multipart
assert registry.get_category('file-upload/webshell') == tc.TemplateCategory.BODY_MULTIPART

# Multi request
assert registry.get_category('fuzz/directory') == tc.TemplateCategory.MULTI_REQUEST

# Unknown
assert registry.get_category('generic/unknown') == tc.TemplateCategory.UNKNOWN
assert registry.get_category('http/misc') == tc.TemplateCategory.UNKNOWN

print('PASS: prefix classification')

# Test tag classification
assert registry._classify_by_tags(('ssl', 'tls')) == tc.TemplateCategory.ORIGIN_SAFE
assert registry._classify_by_tags(('wordpress',)) == tc.TemplateCategory.APP_PREFIX
assert registry._classify_by_tags(('file-upload',)) == tc.TemplateCategory.BODY_MULTIPART
assert registry._classify_by_tags(('fuzz',)) == tc.TemplateCategory.MULTI_REQUEST
assert registry._classify_by_tags(('cve', 'xss')) == tc.TemplateCategory.ENDPOINT
assert registry._classify_by_tags(('unknown-tag',)) == tc.TemplateCategory.UNKNOWN

print('PASS: tag classification')

# Test content pattern classification
multi_content = 'requests:\n  - method: GET\n    path: /test1\n'
assert registry.classify('test/multi', multi_content).category == tc.TemplateCategory.MULTI_REQUEST

raw_content = '''raw: |
  GET /test HTTP/1.1
  Host: example.com
'''
assert registry.classify('test/raw', raw_content).category == tc.TemplateCategory.RAW_HTTP

raw_quoted = '''raw: "GET /test HTTP/1.1"'''
assert registry.classify('test/rawq', raw_quoted).category == tc.TemplateCategory.RAW_HTTP

body_content = 'method: POST\nbody: test=1\n'
assert registry.classify('test/body', body_content).category == tc.TemplateCategory.BODY_MULTIPART

multipart_content = 'method: POST\ncontent_type: multipart/form-data\n'
assert registry.classify('test/multipart', multipart_content).category == tc.TemplateCategory.BODY_MULTIPART

print('PASS: content pattern classification')

# Test batch by category
templates = ['ssl/tls', 'xss/reflected', 'wordpress/wp-admin', 'fuzz/dir', 'file-upload/shell', 'generic/unknown']
batched = registry.batch_by_category(templates)
assert batched[tc.TemplateCategory.ORIGIN_SAFE] == ['ssl/tls']
assert batched[tc.TemplateCategory.ENDPOINT] == ['xss/reflected']
assert batched[tc.TemplateCategory.APP_PREFIX] == ['wordpress/wp-admin']
assert batched[tc.TemplateCategory.MULTI_REQUEST] == ['fuzz/dir']
assert batched[tc.TemplateCategory.BODY_MULTIPART] == ['file-upload/shell']
assert batched[tc.TemplateCategory.UNKNOWN] == ['generic/unknown']

print('PASS: batch by category')

# Test compatibility lane
compat = registry.get_compatibility_templates(templates)
assert 'generic/unknown' in compat
assert 'ssl/tls' not in compat

print('PASS: compatibility lane')

# Test capability analysis
cap = tc.analyze_template_capability('ssl/tls-version')
assert cap.method == 'GET'
assert cap.has_body == False
assert cap.supported == True

cap = tc.analyze_template_capability('file-upload/webshell')
assert cap.method == 'POST'
assert cap.has_body == True
assert cap.supported == True
# Note: is_multipart is False without content, but requires_body_support() is True
classified = registry.classify('file-upload/webshell')
assert classified.requires_body_support() == True

# Content-based detection
post_content = 'method: POST\nbody: test=1\ncontent_type: application/x-www-form-urlencoded\n'
cap = tc.analyze_template_capability('custom/test', post_content)
assert cap.method == 'POST'
assert cap.has_body == True
assert cap.content_type == 'application/x-www-form-urlencoded'

json_content = 'method: POST\ncontent_type: application/json\nbody: {"key": "value"}\n'
cap = tc.analyze_template_capability('custom/json', json_content)
assert cap.method == 'POST'
assert cap.content_type == 'application/json'

print('PASS: capability analysis')

# Test auth batch safety
safe, warnings = tc.validate_auth_batch_safety(
    ['ssl/tls-version', 'aws/s3-bucket'],
    auth_headers=['Cookie: session=abc'],
    target_origins=['https://example.com']
)
assert safe == True

redirect_content = 'method: GET\nfollow_redirects: true\n'
safe, warnings = tc.validate_auth_batch_safety(
    ['custom/redirect'],
    template_contents={'custom/redirect': redirect_content},
    auth_headers=['Cookie: session=abc'],
    target_origins=['https://example.com']
)
assert any('redirect' in w.lower() for w in warnings)

oast_content = 'interactsh:\n  url: oast.fun\n'
safe, warnings = tc.validate_auth_batch_safety(
    ['custom/oast'],
    template_contents={'custom/oast': oast_content},
    auth_headers=['Cookie: session=abc'],
    target_origins=['https://example.com']
)
assert safe == False
assert any('oast' in w.lower() or 'interactsh' in w.lower() for w in warnings)

raw_content = 'raw: |\n  GET /test HTTP/1.1\n'
safe, warnings = tc.validate_auth_batch_safety(
    ['custom/raw'],
    template_contents={'custom/raw': raw_content},
    auth_headers=['Cookie: session=abc'],
    target_origins=['https://example.com']
)
assert any('raw' in w.lower() for w in warnings)

multi_content = 'requests:\n  - method: GET\n    path: /login\n'
safe, warnings = tc.validate_auth_batch_safety(
    ['custom/multi'],
    template_contents={'custom/multi': multi_content},
    auth_headers=['Cookie: session=abc'],
    target_origins=['https://example.com']
)
assert any('multi' in w.lower() or 'flow' in w.lower() for w in warnings)

print('PASS: auth batch safety')

# Test convenience functions
templates = ['ssl/tls', 'xss/reflected', 'generic/unknown']
classified = tc.classify_template('ssl/tls-version')
assert classified.category == tc.TemplateCategory.ORIGIN_SAFE

batched = tc.batch_templates_by_category(templates)
assert 'ssl/tls' in batched[tc.TemplateCategory.ORIGIN_SAFE]

compat = tc.get_compatibility_lane_templates(templates)
assert 'generic/unknown' in compat

print('PASS: convenience functions')

print('\nAll template_classification tests passed!')