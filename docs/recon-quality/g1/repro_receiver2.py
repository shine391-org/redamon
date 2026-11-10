"""G1 controlled-receiver: rebuilt-tuple path (no sample_urls) round-trips on the wire."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qsl
import requests
from recon.helpers.target_helpers import build_target_urls_from_resource_enum

SEEN = []
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        SEEN.append(self.path); b=b'ok'
        self.send_response(200); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
srv = ThreadingHTTPServer(('127.0.0.1',0), H); port=srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base=f'http://127.0.0.1:{port}'

# Decoded values (endpoint_helpers semantics) rebuilt WITHOUT a raw sample URL.
params={'query':[{'name':'q','sample_values':['a&b=# %+雪']},
                  {'name':'empty','sample_values':['']},
                  {'name':'K','sample_values':['3']}]}
_,urls=build_target_urls_from_resource_enum({'by_base_url':{base:{'endpoints':{
    '/rebuilt':{'methods':['GET'],'parameters':params}}}}})
print('generated target:',urls)
requests.get(urls[0],timeout=10)
print('wire request-line:',SEEN[-1])
got=parse_qsl(urlsplit(SEEN[-1]).query,keep_blank_values=True)
print('decoded on wire  :',got)
assert got==[('q','a&b=# %+雪'),('empty',''),('K','3')], got
print('PASS: rebuilt query round-trips (decoded value, empty value, key case, order)')
