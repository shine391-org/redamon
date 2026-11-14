"""Parent review: new evidence schemas cannot bypass off-scope redirect guard."""
import base64
import json
import pytest
from recon.main_recon_modules import http_probe as hp
from recon.main_recon_modules import js_recon as js

@pytest.mark.parametrize('fields',[
 {'body_base64':base64.b64encode(b'<html><title>Foreign</title></html>').decode()},
 {'response_body':'<html><title>Foreign</title></html>'},
 {'raw_response':'HTTP/1.1 200 OK\r\nX-Vllm-Cache-Hit: true\r\nContent-Type: text/html\r\n\r\n<html><title>Foreign</title></html>'},
 {'raw_header':'HTTP/1.1 200 OK\r\nX-Vllm-Cache-Hit: true\r\n\r\n'}])
def test_alternate_body_header_schemas_do_not_reintroduce_foreign_fingerprint(tmp_path, fields):
    row={'url':'https://app.example.test','input':'https://app.example.test',
         'final_url':'https://outside.invalid','chain_status_codes':[302,200],
         'status_code':200, 'content_type':'text/html', **fields}
    path=tmp_path/'httpx.jsonl';path.write_text(json.dumps(row)+'\n')
    result=hp.parse_httpx_output(str(path),root_domain='example.test')
    entry=result['by_url']['https://app.example.test']
    assert not entry.get('title') and not entry.get('body') and not entry.get('headers')
    assert entry['first_status_code']==302

def test_unknown_canonical_route_never_gets_context(monkeypatch):
    monkeypatch.setattr('helpers.proxy_routing.get_capture_routing',lambda tool:('http://127.0.0.1:8888','fixture'))
    monkeypatch.setattr(js,'_canonical_capture_route',lambda:None)
    session,routed=js._capture_session()
    try:
        assert not routed and not session.trust_env
        assert not session.proxies and 'X-Redamon-Ctx' not in session.headers
    finally:session.close()
