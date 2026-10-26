"""An unmapped product must not fall back to NVD keywordSearch.

keywordSearch is a full-text search over CVE descriptions, so a protocol or
CDN label with no CPE mapping matched the word "http" in 1990s-era records and
imported them as if they applied to the target ("HTTP/3" parses to product
http, version 3; "Cloudflare http proxy/1.0" comes from nmap). Those CVEs
became global CVE nodes (MERGE by id, no project scope) and polluted every
project's exploit view.

The lookup now answers empty for a product with no CPE binding and makes no
request at all. `requests.get`/`time.sleep` are patched; no test waits and no
test touches the network.
"""
from __future__ import annotations

from unittest import mock

import pytest

from recon.helpers import cve_helpers
from recon.helpers.circuit_breaker import Outcome
from recon.helpers.cve_helpers import CPE_MAPPINGS, _nvd_query, run_cve_lookup


def _recon(*techs: str) -> dict:
    return {"http_probe": {"by_url": {
        f"https://h{i}.example.test": {"technologies": [t]}
        for i, t in enumerate(techs)
    }}}


def _resp(status: int, body=None, headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = headers if headers is not None else {}
    r.json.return_value = body if body is not None else {}
    r.text = ""
    return r


@pytest.fixture
def http():
    with mock.patch.object(cve_helpers.requests, "get") as get, \
            mock.patch.object(cve_helpers.time, "sleep") as sleep:
        yield get, sleep


def test_unmapped_products_make_no_request_and_no_cves(http, capsys):
    get, _ = http
    out = run_cve_lookup(_recon("HTTP/3", "Cloudflare http proxy/1.0"),
                         source="nvd", nvd_api_key="")
    assert get.call_count == 0
    assert out["technology_cves"]["by_technology"] == {}
    assert out["technology_cves"]["summary"]["total_unique_cves"] == 0
    printed = capsys.readouterr().out
    assert "no CPE mapping — skipped" in printed
    assert "keywordSearch" not in printed


def test_mapped_product_queries_by_exact_cpe(http):
    get, _ = http
    body = {"vulnerabilities": [{
        "cve": {"id": "CVE-2026-1234", "metrics": {}, "descriptions": [],
                "references": [], "published": None}
    }]}
    get.return_value = _resp(200, body)
    out = run_cve_lookup(_recon("nginx/1.24.0"), source="nvd", nvd_api_key="")
    assert get.call_count == 1
    params = get.call_args.kwargs["params"]
    assert params["cpeName"] == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    assert "keywordSearch" not in params
    assert out["technology_cves"]["by_technology"]["nginx/1.24.0"]["cve_count"] == 1


def test_nvd_query_unmapped_returns_no_data_without_request(http):
    get, _ = http
    res = _nvd_query("http", "3", 20, keys=mock.Mock())
    assert res.outcome is Outcome.NO_DATA
    assert res.answered  # an answer, not a failure: the loop must not retry it
    assert res.data == []
    assert get.call_count == 0


def test_detector_label_aliases_are_mapped():
    # httpx/wapparser/nmap spell these with the vendor prefix; the alias keeps
    # them on the exact-CPE path instead of being skipped as unmapped.
    assert CPE_MAPPINGS["apache tomcat"] == ("apache", "tomcat")
    assert CPE_MAPPINGS["microsoft iis"] == ("microsoft", "internet_information_services")
