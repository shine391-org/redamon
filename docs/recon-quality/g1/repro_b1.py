import json
from recon.helpers.target_helpers import build_target_urls_from_resource_enum
from recon.helpers.resource_enum.openapi_helpers import merge_openapi_into_by_base_url

# Real openapi producer shape: encode_value() pre-encodes the spec example.
payload = {'documents': [], 'operations': [{
    'baseurl': 'https://api.example.test', 'path': '/search', 'method': 'GET',
    'operation': {'parameters': [{'name': 'q', 'in': 'query', 'required': False,
                                   'schema': {'type': 'string', 'example': 'a b'}}]}}]}
by, stats = merge_openapi_into_by_base_url(payload, {})
ep = by['https://api.example.test']['endpoints']['/search']
print('openapi sample_values:', ep['parameters']['query'][0]['sample_values'])
print('openapi sample_urls  :', ep.get('sample_urls'))
bases, urls = build_target_urls_from_resource_enum({'by_base_url': by})
print('generated target     :', urls)
from urllib.parse import urlsplit, parse_qsl
print('decoded query        :', parse_qsl(urlsplit(urls[0]).query, keep_blank_values=True))
