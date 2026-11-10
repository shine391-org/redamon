#!/usr/bin/env python3
"""Run unchanged desired encoding checks against the mounted source revision.

PYTHONPATH must point at the source checkout under test (not this script's tree).
Exit 1 is expected for each demonstrated broken revision, not a missing API.
"""
import json
from urllib.parse import parse_qsl, urlsplit
from recon.helpers.target_helpers import _endpoint_url
from recon.helpers.resource_enum.openapi_helpers import _parameter

base = 'https://api.example.test'
value = 'a&b=# %+雪'
param = {'name': 'q', 'sample_values': [value], 'sample_values_encoding': 'decoded-observation'}
decoded_url = _endpoint_url(base, '/search', {'parameters': {'query': [param]}})
openapi_param = _parameter('q', {'schema': {'type': 'string', 'example': 'a b'}}, required=False)
openapi_url = _endpoint_url(base, '/search', {'parameters': {'query': [openapi_param]}})
checks = []
for name, url, expected in [('decoded_observation', decoded_url, [('q', value)]),
                            ('openapi_sample', openapi_url, [('q', 'a b')])]:
    actual = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    checks.append({'name': name, 'url': url, 'decoded_pairs': actual,
                   'expected_pairs': expected, 'passed': actual == expected})
print(json.dumps({'checks': checks, 'producer_sample_values': openapi_param['sample_values']},
                 ensure_ascii=False, indent=2))
raise SystemExit(0 if all(c['passed'] for c in checks) else 1)
