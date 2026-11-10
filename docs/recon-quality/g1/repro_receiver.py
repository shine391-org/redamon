"""G1 controlled-receiver check: generated target -> wire path/query/header.

No external target. Loopback receiver only. Uses the pipeline's own URL builder
and the requests session the probe callers use.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qsl

import requests

from recon.helpers.target_helpers import build_target_urls_from_resource_enum

SEEN = []

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append((self.path, dict(self.headers)))
        b = b'ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a):
        pass

srv = ThreadingHTTPServer(('127.0.0.1', 0), H)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{port}'

# The exact observation shape the F01/F02 seam consumes: decoded sample values
# (endpoint_helpers stores parse_qs output) plus a raw sample URL.
row = {'origin': base, 'path': '/api/search',
       'raw_url': f'{base}/api/search?q=a%26b%3D%23%20%25%2B%E9%9B%AA',
       'parameters': {'query': [{'name': 'q', 'sample_values': ['a&b=# %+雪']}]}}
bases, urls = build_target_urls_from_resource_enum({'by_base_url': {
    base: {'endpoints': {'/api/search': {'methods': ['GET'],
                                        'parameters': row['parameters'],
                                        'sample_urls': [row['raw_url']]}}}}})
print('generated target:', urls)
assert urls == [row['raw_url']], urls

r = requests.get(urls[0], headers={'X-Bug-Bounty': 'g1-reviewer'}, timeout=10)
assert r.status_code == 200
path, headers = SEEN[-1]
print('wire request-line:', path)
print('wire identity     :', headers.get('X-Bug-Bounty'))
assert path == '/api/search?q=a%26b%3D%23%20%25%2B%E9%9B%AA', path
assert parse_qsl(urlsplit(path).query, keep_blank_values=True) == [('q', 'a&b=# %+雪')]
assert headers.get('X-Bug-Bounty') == 'g1-reviewer'
print('PASS: generated target preserved verbatim on the wire; query decodes to the original value; identity header present')
