"""False-positive regressions for JS Recon source-map discovery.

A field report muted ~95 source-map rows: a single-page app answers the
referenced `.map` URL with its own HTML shell (200 text/html), and vendor
scripts' maps (a marketing loader, a CMS plugin) were reported as the
target's source disclosure. The fetch must prove a v3 source map, an
unreachable reference is reported only when the server refused access, and a
map that holds only library code is low. Every case has a positive twin.
"""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.js_recon import sourcemap as sm
from recon.main_recon_modules import js_recon

JS = "https://app.example.com/static/js/main.4f2a9c.js"
MAP = JS + ".map"

SPA_SHELL = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'
FIRST_PARTY_MAP = {
    "version": 3, "file": "main.js", "mappings": "AAAA,SAASA",
    "sources": ["webpack:///./src/App.tsx", "webpack:///./src/api/client.ts",
                "webpack:///node_modules/react/index.js", "webpack:///webpack/bootstrap"],
    "sourcesContent": ["export const App = () => null;", "const KEY = 'x';",
                       "module.exports = require('./cjs/react.production.min.js');", "(()=>{})()"],
}
VENDOR_ONLY_MAP = {
    "version": 3, "mappings": "AAAA",
    "sources": ["webpack:///node_modules/lodash/lodash.js", "webpack:///webpack/bootstrap",
                "webpack:///(webpack)/buildin/global.js"],
    "sourcesContent": ["/* lodash */", "(()=>{})()", "g = this"],
}


def _resp(status=200, body="", ctype="application/json"):
    r = MagicMock()
    r.status_code = status
    r.headers = {"Content-Type": ctype} if ctype else {}
    r.text = body
    r.content = body.encode("utf-8")
    return r


def _fetch(get_resp, head_status=200, url=MAP):
    outcome = {}
    with patch.object(sm, "is_url_safe_to_probe", return_value=True), \
         patch.object(sm.requests, "head", return_value=_resp(head_status)), \
         patch.object(sm.requests, "get", return_value=get_resp):
        data = sm._fetch_sourcemap(url, timeout=5, outcome=outcome)
    return data, outcome


class TestFetchProvesASourceMap(unittest.TestCase):
    def test_spa_shell_with_200_is_not_a_map(self):
        data, out = _fetch(_resp(200, SPA_SHELL, "text/html; charset=utf-8"))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "html")

    def test_html_body_mislabelled_as_json_is_not_a_map(self):
        data, out = _fetch(_resp(200, "\n  " + SPA_SHELL, "application/json"))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "html")

    def test_json_catch_all_is_not_a_map(self):
        data, out = _fetch(_resp(200, json.dumps({"error": "not found", "status": 404})))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "invalid_schema")

    def test_sources_without_mappings_is_not_a_map(self):
        data, out = _fetch(_resp(200, json.dumps({"version": 3, "sources": ["a.js"]})))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "invalid_schema")

    def test_plain_text_error_is_not_json(self):
        data, out = _fetch(_resp(200, "Not Found", "text/plain"))
        self.assertIsNone(data)
        self.assertEqual(out["reason"], "not_json")

    def test_a_real_map_served_as_octet_stream_is_accepted(self):
        # S3 / CDNs often serve .map files as octet-stream; the old content-type
        # allowlist missed them.
        data, out = _fetch(_resp(200, json.dumps(FIRST_PARTY_MAP), "binary/octet-stream"))
        self.assertEqual(data["sources"], FIRST_PARTY_MAP["sources"])
        self.assertEqual(out["reason"], "ok")

    def test_map_mislabelled_as_html_is_still_a_map(self):
        data, _ = _fetch(_resp(200, json.dumps(FIRST_PARTY_MAP), "text/html"))
        self.assertIsNotNone(data)

    def test_bom_prefixed_map_is_accepted(self):
        data, _ = _fetch(_resp(200, "\ufeff" + json.dumps(FIRST_PARTY_MAP)))
        self.assertIsNotNone(data)

    def test_xssi_prefixed_map_is_accepted(self):
        data, _ = _fetch(_resp(200, ")]}'\n" + json.dumps(FIRST_PARTY_MAP)))
        self.assertIsNotNone(data)

    def test_index_map_is_accepted(self):
        index = {"version": 3, "sections": [{"offset": {"line": 0, "column": 0}, "map": FIRST_PARTY_MAP}]}
        data, _ = _fetch(_resp(200, json.dumps(index)))
        self.assertIsNotNone(data)

    def test_status_outcomes(self):
        self.assertEqual(_fetch(_resp(403, "denied", "text/plain"))[1]["reason"], "http_403")
        self.assertEqual(_fetch(_resp(200), head_status=404)[1]["reason"], "not_found")
        self.assertEqual(_fetch(_resp(404, "", "text/plain"), head_status=405)[1]["reason"], "not_found")

    def test_connection_failure_is_unreachable(self):
        outcome = {}
        with patch.object(sm, "is_url_safe_to_probe", return_value=True), \
             patch.object(sm.requests, "head", side_effect=requests.ConnectionError("x")):
            self.assertIsNone(sm._fetch_sourcemap(MAP, outcome=outcome))
        self.assertEqual(outcome["reason"], "unreachable")

    def test_inline_data_map(self):
        good = "data:application/json;base64," + base64.b64encode(json.dumps(FIRST_PARTY_MAP).encode()).decode()
        self.assertIsNotNone(sm._fetch_sourcemap(good))
        bad = "data:application/json;base64," + base64.b64encode(b"<html>").decode()
        outcome = {}
        self.assertIsNone(sm._fetch_sourcemap(bad, outcome=outcome))
        self.assertEqual(outcome["reason"], "html")

    def test_outcome_is_optional(self):
        data, _ = _fetch(_resp(200, json.dumps(FIRST_PARTY_MAP)))
        self.assertIsNotNone(data)


class TestOwnership(unittest.TestCase):
    def test_vendor_sources(self):
        for s in ("webpack:///node_modules/react/index.js", "webpack:///webpack/bootstrap",
                  "webpack:///(webpack)/buildin/global.js", "../node_modules/core-js/a.js",
                  "webpack:///./node_modules/x/y.js", "external \"React\"", "~/lodash/lodash.js"):
            self.assertTrue(sm._is_vendor_source(s), s)

    def test_first_party_sources(self):
        for s in ("webpack:///./src/App.tsx", "src/api/client.ts", "../../app/models/user.rb.js",
                  "webpack:///./pages/vendor-portal.tsx"):
            self.assertFalse(sm._is_vendor_source(s), s)

    def test_first_party_source_text_is_low(self):
        # Readable source is an exposure, but its impact is what the detectors
        # find in it (plan 06.4): those become Secret and Endpoint findings.
        r = sm.analyze_sourcemap(FIRST_PARTY_MAP, MAP, JS)
        self.assertEqual((r["severity"], r["files_count"], r["first_party_files"]), ("low", 4, 2))
        self.assertTrue(r["has_sources_content"])
        self.assertEqual(r["source_files"], ["webpack:///./src/App.tsx", "webpack:///./src/api/client.ts"])

    def test_first_party_paths_without_text_are_info(self):
        m = dict(FIRST_PARTY_MAP)
        m.pop("sourcesContent")
        self.assertEqual(sm.analyze_sourcemap(m, MAP, JS)["severity"], "info")

    def test_library_only_map_is_low(self):
        r = sm.analyze_sourcemap(VENDOR_ONLY_MAP, MAP, JS)
        self.assertEqual((r["severity"], r["first_party_files"]), ("low", 0))
        self.assertFalse(r["has_sources_content"])

    def test_the_map_itself_no_longer_scans_for_secrets(self):
        r = sm.analyze_sourcemap(FIRST_PARTY_MAP, MAP, JS)
        self.assertEqual(r["secrets_in_source"], 0)
        self.assertNotIn("secrets", r)

    def test_a_null_source_keeps_the_pairing_with_its_text(self):
        m = {"version": 3, "mappings": "AAAA", "sources": [None, "src/a.js"],
             "sourcesContent": [None, "const KEY = 1;"]}
        r = sm.analyze_sourcemap(m, MAP, JS)
        self.assertEqual((r["severity"], r["has_sources_content"], r["first_party_files"]), ("low", True, 1))

    def test_next_js_runtime_is_library_code(self):
        for src in ("webpack://_N_E/webpack/runtime/compat", "webpack://app/(webpack)/buildin/global.js"):
            self.assertTrue(sm._is_vendor_source(src), src)

    def test_index_map_sources_are_counted(self):
        index = {"version": 3, "sections": [
            {"offset": {"line": 0, "column": 0}, "map": FIRST_PARTY_MAP},
            {"offset": {"line": 9, "column": 0}, "map": VENDOR_ONLY_MAP},
        ]}
        r = sm.analyze_sourcemap(index, MAP, JS)
        self.assertEqual((r["files_count"], r["first_party_files"], r["severity"]), (7, 2, "low"))


class TestDiscovery(unittest.TestCase):
    def _discover(self, fetch_result):
        data, reason = fetch_result

        def fake_fetch(url, timeout=10, outcome=None):
            if outcome is not None:
                outcome["reason"] = reason
            return data

        js_files = [{"url": JS, "content": "console.log(1);\n//# sourceMappingURL=main.4f2a9c.js.map", "headers": {}}]
        # A 403's sibling control (plan 06.5) is covered in test_js_recon_sourcemap_403.
        with patch.object(sm, "_fetch_sourcemap", side_effect=fake_fetch), \
                patch.object(sm, "_missing_key_control", return_value="passed"):
            return sm.discover_and_analyze_sourcemaps(js_files, {"JS_RECON_SOURCE_MAPS": True})

    def test_referenced_map_answered_by_the_spa_shell_reports_nothing(self):
        self.assertEqual(self._discover((None, "html")), [])

    def test_referenced_map_404_or_json_error_reports_nothing(self):
        for reason in ("not_found", "invalid_schema", "not_json", "unreachable", "unsafe"):
            self.assertEqual(self._discover((None, reason)), [], reason)

    def test_a_map_on_another_unreachable_host_is_reported(self):
        # `sourceMappingURL=http://build.corp.internal/...` leaks a build host.
        js_files = [{"url": JS, "content": "x;\n//# sourceMappingURL=http://build.example.internal:8080/app.js.map",
                     "headers": {}}]

        def fake_fetch(url, timeout=10, outcome=None):
            outcome["reason"] = "unsafe"
            return None

        with patch.object(sm, "_fetch_sourcemap", side_effect=fake_fetch):
            [row] = sm.discover_and_analyze_sourcemaps(js_files, {"JS_RECON_SOURCE_MAPS": True})
        self.assertEqual((row["finding_type"], row["fetch_result"]), ("source_map_reference", "unsafe"))
        self.assertEqual(row["map_url"], "http://build.example.internal:8080/app.js.map")

    def test_an_unreachable_map_on_the_same_host_reports_nothing(self):
        self.assertEqual(self._discover((None, "unreachable")), [])

    def test_referenced_map_behind_auth_is_an_info_reference(self):
        [row] = self._discover((None, "http_403"))
        self.assertEqual((row["finding_type"], row["severity"], row["fetch_result"]),
                         ("source_map_reference", "info", "http_403"))
        self.assertEqual(row["map_url"], MAP)
        self.assertFalse(row["accessible"])

    def test_served_map_is_an_exposure(self):
        [row] = self._discover((FIRST_PARTY_MAP, "ok"))
        self.assertEqual((row["finding_type"], row["severity"], row["discovery_method"]),
                         ("source_map_exposure", "low", "comment"))


class TestThirdPartyHost(unittest.TestCase):
    def test_a_foreign_hosts_map_with_secret_hits_keeps_its_severity(self):
        results = {"source_maps": [{"js_url": "https://cdn.marketing-vendor.test/a.js", "severity": "high",
                                    "secrets_in_source": 2}]}
        js_recon._downgrade_third_party_findings(results, {"domain": "example.com"})
        self.assertEqual((results["source_maps"][0]["severity"], results["source_maps"][0]["third_party"]),
                         ("high", True))

    def test_map_of_a_script_on_a_foreign_host_is_info(self):
        results = {"source_maps": [
            {"js_url": "https://js.marketing-vendor.test/loader.js", "severity": "high"},
            {"js_url": JS, "severity": "high"},
        ]}
        js_recon._downgrade_third_party_findings(results, {"domain": "example.com"})
        vendor, own = results["source_maps"]
        self.assertEqual((vendor["severity"], vendor["third_party"]), ("info", True))
        self.assertEqual(own["severity"], "high")
        self.assertNotIn("third_party", own)


# ---------------------------------------------------------------------------
# Plan 06.4: a map's own sources go through every detector
# ---------------------------------------------------------------------------

# Synthetic, built by concatenation so no scanner reads it as a real key.
STRIPE_KEY = "sk_live_" + "Zq8RvT3mNc7LpW2xYk5HdB9s"
CONFIG_TS = ('export const PAYMENTS_KEY = "' + STRIPE_KEY + '";\n'
             'export function loadOrders() {\n  return fetch("/api/v2/orders");\n}\n')
APP_MAP = {
    "version": 3, "file": "main.js", "mappings": "AAAA",
    "sources": ["webpack:///./src/config.ts", "webpack:///./src/App.tsx",
                "webpack:///node_modules/react/index.js"],
    "sourcesContent": [CONFIG_TS, "export const App = () => null;\n",
                       'const leaked = "' + "sk_live_" + "LIBRARYEXAMPLE0000000000" + '";\n'],
}
BUNDLE = "(()=>{console.log(1)})();\n//# sourceMappingURL=main.4f2a9c.js.map"


class TestPseudoFiles(unittest.TestCase):
    def test_each_first_party_source_with_text_is_a_pseudo_file(self):
        files = sm.sourcemap_pseudo_files(APP_MAP, MAP, JS)
        self.assertEqual([f["url"] for f in files], [f"{MAP}#src/config.ts", f"{MAP}#src/App.tsx"])
        self.assertTrue(all(f["from_source_map"] for f in files))
        self.assertEqual(files[0]["content"], CONFIG_TS)

    def test_a_map_of_library_sources_only_yields_no_pseudo_file(self):
        self.assertEqual(sm.sourcemap_pseudo_files(VENDOR_ONLY_MAP, MAP, JS), [])

    def test_a_map_without_source_text_yields_no_pseudo_file(self):
        m = dict(APP_MAP)
        m.pop("sourcesContent")
        self.assertEqual(sm.sourcemap_pseudo_files(m, MAP, JS), [])

    def test_a_source_over_the_size_cap_is_skipped(self):
        big = dict(APP_MAP, sourcesContent=["x" * 50, "y" * 10, ""])
        files = sm.sourcemap_pseudo_files(big, MAP, JS, max_chars=20)
        self.assertEqual([f["url"] for f in files], [f"{MAP}#src/App.tsx"])

    def test_an_inline_map_is_named_after_its_script(self):
        inline = "data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="
        files = sm.sourcemap_pseudo_files(APP_MAP, inline, JS)
        self.assertEqual(files[0]["url"], f"{JS}#src/config.ts")

    def test_discovery_hands_the_pseudo_files_to_the_caller(self):
        def fake_fetch(url, timeout=10, outcome=None):
            if outcome is not None:
                outcome["reason"] = "ok"
            return APP_MAP

        pseudo = []
        with patch.object(sm, "_fetch_sourcemap", side_effect=fake_fetch):
            [row] = sm.discover_and_analyze_sourcemaps(
                [{"url": JS, "content": BUNDLE, "headers": {}}], {"JS_RECON_SOURCE_MAPS": True},
                pseudo_files=pseudo)
        self.assertEqual(row["severity"], "low")
        self.assertEqual([f["url"] for f in pseudo], [f"{MAP}#src/config.ts", f"{MAP}#src/App.tsx"])


ANALYSIS = {
    "JS_RECON_MAX_FILES": 50, "JS_RECON_REGEX_PATTERNS": True, "JS_RECON_SOURCE_MAPS": True,
    "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_EXTRACT_ENDPOINTS": True,
    "JS_RECON_FRAMEWORK_DETECT": True, "JS_RECON_DOM_SINKS": True, "JS_RECON_DEV_COMMENTS": True,
    "JS_RECON_AI_SDK_DETECTION_ENABLED": False, "JS_RECON_VALIDATE_KEYS": True,
    "JS_RECON_VALIDATE_ENDPOINTS": False, "JS_RECON_TIMEOUT": 60,
}


class TestSourceMapSourcesFeedTheDetectors(unittest.TestCase):
    def _run(self, source_map=APP_MAP):
        def fake_fetch(url, timeout=10, outcome=None):
            if outcome is not None:
                outcome["reason"] = "ok"
            return source_map

        bundle = {"url": JS, "filepath": "", "content": BUNDLE, "headers": {}, "size": len(BUNDLE)}
        validations = []

        def fake_validate(name, matched_text, validator_ref=None, timeout=5):
            validations.append((name, validator_ref))
            return {"state": "rejected", "info": "test double"}

        # app.example.com is a known subdomain, so the run makes no DNS lookup.
        combined = {"domain": "example.com", "metadata": {}, "http_probe": {"by_url": {}},
                    "dns": {"subdomains": ["app.example.com"]},
                    "resource_enum": {"discovered_urls": []}}
        with patch.object(js_recon, "_collect_js_urls", return_value=[JS]), \
                patch.object(js_recon, "_download_js_files", return_value=[bundle]), \
                patch.object(sm, "_fetch_sourcemap", side_effect=fake_fetch), \
                patch.object(js_recon, "validate_secret", side_effect=fake_validate):
            out = js_recon.run_js_recon(combined, dict(ANALYSIS))
        return out["js_recon"], validations

    def test_a_key_in_the_maps_source_is_a_secret_that_goes_through_validation(self):
        data, validations = self._run()
        [secret] = [s for s in data["secrets"] if s["name"] == "Stripe Secret Key"]
        self.assertTrue(secret["source_url"].endswith("#src/config.ts"))
        self.assertEqual(secret["source_url"], f"{MAP}#src/config.ts")
        self.assertEqual(secret["validation"]["status"], "rejected")
        self.assertIn(("Stripe Secret Key", "validate_stripe"), validations)

    def test_a_library_sources_example_key_is_not_scanned(self):
        data, _ = self._run()
        self.assertFalse(any("LIBRARYEXAMPLE" in s.get("matched_text", "") for s in data["secrets"]))

    def test_an_endpoint_in_the_maps_source_is_extracted(self):
        data, _ = self._run()
        [ep] = [e for e in data["endpoints"] if e["path"] == "/api/v2/orders"]
        self.assertEqual(ep["source_js"], f"{MAP}#src/config.ts")

    def test_the_source_map_finding_is_low_and_counts_its_secret(self):
        data, _ = self._run()
        [row] = data["source_maps"]
        self.assertEqual((row["finding_type"], row["severity"]), ("source_map_exposure", "low"))
        self.assertEqual(row["secrets_in_source"], 1)

    def test_a_map_with_only_node_modules_sources_feeds_nothing(self):
        data, _ = self._run(VENDOR_ONLY_MAP)
        self.assertEqual(data["scan_metadata"]["source_map_files_analyzed"], 0)
        self.assertEqual(data["source_maps"][0]["secrets_in_source"], 0)

    def test_the_pseudo_files_are_counted_in_the_scan_metadata(self):
        data, _ = self._run()
        self.assertEqual(data["scan_metadata"]["source_map_files_analyzed"], 2)
        self.assertEqual(data["scan_metadata"]["js_files_analyzed"], 1)

    def test_a_framework_imported_by_every_source_is_reported_once_per_map(self):
        many = dict(APP_MAP,
                    sources=[f"webpack:///./src/page{i}.tsx" for i in range(5)],
                    sourcesContent=["import { useRouter } from 'next/router';\n"] * 5)
        data, _ = self._run(many)
        nextjs = [f for f in data["frameworks"] if f["name"] == "Next.js"]
        self.assertEqual(len(nextjs), 1)


class TestSecretValidationIsPerKey(unittest.TestCase):
    def test_the_same_key_in_two_files_is_validated_once(self):
        calls = []

        def fake_validate(name, matched_text, validator_ref=None, timeout=5):
            calls.append(matched_text)
            return {"state": "valid", "scope": "account", "info": ""}

        secrets = [
            {"name": "Stripe Secret Key", "matched_text": STRIPE_KEY, "validator_ref": "validate_stripe",
             "confidence": "high", "source_url": JS},
            {"name": "Stripe Secret Key", "matched_text": STRIPE_KEY, "validator_ref": "validate_stripe",
             "confidence": "high", "source_url": f"{MAP}#src/config.ts"},
        ]
        with patch.object(js_recon, "validate_secret", side_effect=fake_validate):
            js_recon._validate_secrets(secrets, {"JS_RECON_VALIDATE_KEYS": True})
        self.assertEqual(calls, [STRIPE_KEY])
        self.assertEqual([s["validation"]["status"] for s in secrets], ["validated", "validated"])
        self.assertIsNot(secrets[0]["validation"], secrets[1]["validation"])


if __name__ == "__main__":
    unittest.main()
