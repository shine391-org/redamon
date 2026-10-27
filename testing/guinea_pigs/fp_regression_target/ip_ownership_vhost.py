"""V-15: vhost/SNI skips its wordlist on the IP that IP attribution tagged shared_edge.

An IP-mode run has no apex domain, so it never uses the default wordlist (see
vhost_wordlist_edge.py). This runs the real IP attribution step, with real TLS
handshakes without SNI, against the lab's .31 (the lab's own *.fplab.test
certificate) and .32 (the Cloudflare-issued one, carrying tlsx's CDN tag) as a
domain-mode run under fplab.test would see them. It then REMOVES tlsx's tag
from the port data, so plan 07's CDN check alone would no longer skip .32, and
runs the real vhost/SNI module: the attribution tag is what decides.

Run inside the recon image, on the host network, with the lab up:

    docker run --rm --network host -v "$PWD/../../..:/repo" -w /repo/recon \\
      -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon:latest \\
      /repo/testing/guinea_pigs/fp_regression_target/ip_ownership_vhost.py

The default wordlist is cut to a few names so the run takes seconds. Exit 0
only when every check holds.
"""
import sys
from unittest.mock import patch

from recon.main_recon_modules import ip_attribution as ia
from recon.main_recon_modules import vhost_sni_enum as vsm

NET = "192.88.94"
APEX = "fplab.test"
PLAIN, EDGE = f"{NET}.31", f"{NET}.32"
WORDS = ["portal", "split", "admin", "dev", "qa"]


def main() -> int:
    combined = {
        "domain": APEX,
        "metadata": {"target": APEX, "root_domain": APEX},
        "port_scan": {
            "by_host": {ip: {"ip": ip, "ports": [{"port": 443, "scheme": "https"}]} for ip in (PLAIN, EDGE)},
            "by_ip": {
                PLAIN: {"ip": PLAIN, "ports": [443], "is_cdn": False, "cdn": None},
                EDGE: {"ip": EDGE, "ports": [443], "is_cdn": True, "cdn": "cloudflare",
                       "cdn_source": "tls_certificate"},
            },
        },
    }
    ia.run_ip_attribution(combined, {"IP_ATTRIBUTION_ENABLED": True, "IP_ATTRIBUTION_TLS_MAX_PROBES": 10})
    tags = combined["ip_attribution"]["by_ip"]
    handshakes = combined["ip_attribution"]["summary"]["tls_handshakes"]

    combined["port_scan"]["by_ip"][EDGE].update({"is_cdn": False, "cdn": None, "cdn_source": None})
    settings = {
        "VHOST_SNI_ENABLED": True, "VHOST_SNI_TEST_L7": True, "VHOST_SNI_TEST_L4": True,
        "VHOST_SNI_TIMEOUT": 3, "VHOST_SNI_CONCURRENCY": 4, "VHOST_SNI_BASELINE_SIZE_TOLERANCE": 50,
        "VHOST_SNI_USE_DEFAULT_WORDLIST": True, "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
        "VHOST_SNI_INJECT_DISCOVERED": False, "VHOST_SNI_CUSTOM_WORDLIST": "",
        "VHOST_SNI_MAX_CANDIDATES_PER_IP": 100,
    }
    with patch.object(vsm, "_load_default_wordlist", return_value=list(WORDS)):
        vsm.run_vhost_sni_enrichment(combined, settings)
    out = combined["vhost_sni"]
    found = sorted(f["hostname"] for f in out["findings"])
    edge, plain = tags.get(EDGE, {}), tags.get(PLAIN, {})

    results = [
        ("V-15a", handshakes == 2 and edge.get("ownership") == "shared_edge"
         and plain.get("ownership") == "dedicated"
         and f"default certificate covers {APEX}" in plain.get("ownership_reasons", []),
         f"real handshakes {handshakes}; .32 {edge.get('ownership')} {edge.get('ownership_reasons')}; "
         f".31 {plain.get('ownership')} {plain.get('ownership_reasons')} (expect 2, shared_edge, dedicated)"),
        ("V-15b", out["scan_metadata"]["wordlist_skipped_edge_ips"] == [EDGE]
         and out["by_ip"].get(EDGE, {}).get("candidates_tested") == 0,
         f"tag only (tlsx's flag removed): skipped={out['scan_metadata']['wordlist_skipped_edge_ips']} "
         f"candidates on .32={out['by_ip'].get(EDGE, {}).get('candidates_tested')} (expect .32 skipped, 0)"),
        ("V-15c", out["by_ip"].get(PLAIN, {}).get("candidates_tested") == len(WORDS)
         and found == [f"portal.{APEX}", f"split.{APEX}"],
         f"dedicated .31: candidates={out['by_ip'].get(PLAIN, {}).get('candidates_tested')} findings={found} "
         f"(expect {len(WORDS)} candidates, portal + split)"),
    ]
    for case, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {case}  {detail}")
    failed = [c for c, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
