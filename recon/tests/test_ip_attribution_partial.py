"""Partial recon re-tags the graph's IPs (plan 11.5).

IpAttribution reads the graph's IPs (their ports, CDN tag and the names whose
forward-DNS edges point at them), runs the same run_ip_attribution as the full
pipeline, and writes the tags with update_graph_from_ip_attribution. Graph
targets only. An IP-mode placeholder Subdomain ("192-0-2-1") is not a DNS name.

The graph builder, settings, handshake and Neo4j client are stubs; addresses
are RFC 5737.
"""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import recon.partial_recon as partial_recon  # noqa: E402
import recon.partial_recon_modules.ip_attribution as mod  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import ip_attribution as ia  # noqa: E402

OWN = "192.0.2.10"
OTHER = "192.0.2.11"


def _graph_data():
    return {
        "domain": "example.com", "domains": ["example.com"],
        "port_scan": {"by_ip": {
            OWN: {"ip": OWN, "ports": [443], "is_cdn": False, "cdn": None},
            OTHER: {"ip": OTHER, "ports": [80], "is_cdn": True, "cdn": "fastly"},
        }, "by_host": {}},
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {
                    "www.example.com": {"ips": {"ipv4": [OWN], "ipv6": []}, "has_records": True},
                    "cdn.example.com": {"ips": {"ipv4": [OTHER], "ipv6": []}, "has_records": True},
                }},
        "metadata": {},
    }


def _ip_mode_data():
    return {
        "domain": "ip-targets.p1", "domains": ["ip-targets.p1"],
        "port_scan": {"by_ip": {OWN: {"ip": OWN, "ports": [22]}}, "by_host": {}},
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}},
                "subdomains": {"192-0-2-10": {"ips": {"ipv4": [OWN], "ipv6": []}}}},
        "metadata": {},
    }


class TestPartialIpAttribution(unittest.TestCase):
    def _run(self, graph_data, settings=None, connected=True):
        client = MagicMock()
        client.verify_connection.return_value = connected
        client.update_graph_from_ip_attribution.return_value = {"ips_tagged": 2, "errors": []}
        neo4j_cls = MagicMock()
        neo4j_cls.return_value.__enter__ = MagicMock(return_value=client)
        neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)
        fake_graph_db = MagicMock()
        fake_graph_db.Neo4jClient = neo4j_cls
        builder = MagicMock(return_value=graph_data)
        handshake = MagicMock(return_value={"serial": "1", "cn": "www.example.com",
                                            "sans": {"*.example.com"}})
        with patch.dict("sys.modules", {"graph_db": fake_graph_db}), \
             patch.object(mod, "scope_roots", return_value=graph_data["domains"]), \
             patch.object(mod, "partial_settings", return_value=dict(settings or {})), \
             patch.object(mod, "_build_port_scan_data_from_graph", builder), \
             patch.object(ia, "tls_handshake_cert", handshake), \
             patch.object(ia, "_TLS_RPS", 0.0), \
             patch.object(cb.host_health, "allow", return_value=True):
            os.environ["USER_ID"] = "user1"
            os.environ["PROJECT_ID"] = "proj1"
            mod.run_ip_attribution_partial({"domain": graph_data["domain"], "domain_groups": None})
        return client, builder, handshake

    def test_it_tags_the_graphs_ips_and_writes_them(self):
        client, builder, handshake = self._run(_graph_data(), {"IP_ATTRIBUTION_ENABLED": False})
        self.assertEqual(builder.call_args[0][:3], (["example.com"], "user1", "proj1"))
        recon_data, uid, pid = client.update_graph_from_ip_attribution.call_args[0]
        by_ip = recon_data["ip_attribution"]["by_ip"]
        self.assertEqual(by_ip[OWN]["ownership"], ia.DEDICATED)      # force-enabled despite the setting
        self.assertEqual(by_ip[OTHER]["ownership"], ia.SHARED_EDGE)  # the graph's CDN tag
        self.assertEqual(by_ip[OWN]["current_dns_names"], 1)
        self.assertEqual((uid, pid), ("user1", "proj1"))
        handshake.assert_called_once_with(OWN, None, 443, ia._TLS_TIMEOUT_S)

    def test_stealth_settings_reach_the_step(self):
        client, _builder, handshake = self._run(
            _graph_data(), {"STEALTH_MODE": True, "IP_ATTRIBUTION_TLS_MAX_PROBES": 0})
        handshake.assert_not_called()
        by_ip = client.update_graph_from_ip_attribution.call_args[0][0]["ip_attribution"]["by_ip"]
        self.assertIn("default certificate not checked (stealth mode)", by_ip[OWN]["ownership_reasons"])

    def test_an_ip_mode_placeholder_is_not_a_dns_name(self):
        client, _b, _h = self._run(_ip_mode_data())
        by_ip = client.update_graph_from_ip_attribution.call_args[0][0]["ip_attribution"]["by_ip"]
        self.assertEqual(by_ip[OWN]["current_dns_names"], 0)

    def test_no_ip_in_the_graph_bails_without_a_write(self):
        empty = {"domain": "example.com", "domains": ["example.com"],
                 "port_scan": {"by_ip": {}, "by_host": {}},
                 "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}}, "subdomains": {}},
                 "metadata": {}}
        with self.assertRaises(SystemExit):
            self._run(empty)

    def test_neo4j_down_writes_nothing_and_does_not_raise(self):
        client, _b, _h = self._run(_graph_data(), connected=False)
        client.update_graph_from_ip_attribution.assert_not_called()


class TestDispatch(unittest.TestCase):
    def test_the_tool_id_reaches_the_module(self):
        with patch.object(mod, "run_ip_attribution_partial", return_value=None) as run:
            partial_recon._dispatch("IpAttribution", {"domain": "example.com"})
        run.assert_called_once_with({"domain": "example.com"})


if __name__ == "__main__":
    unittest.main()
