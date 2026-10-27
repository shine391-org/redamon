"""V-14: the default vhost wordlist is not brute-forced against a CDN edge.

An IP-mode run has no apex domain, so it never uses the default wordlist and
cannot show the skip. This runs the real vhost/SNI module, with real curl
probes, against the lab's .31 (no CDN) and .32 (the Cloudflare-issued
certificate) as a domain-mode run under fplab.test would see them. .32 carries
the tag tlsx leaves on port_scan.by_ip; T-01 (validate_e2e.py --vhost-origin)
proves a full run puts that tag on the graph.

Run inside the recon image, on the host network, with the lab up:

    docker run --rm --network host -v "$PWD/../../..:/repo" -w /repo/recon \\
      -e PYTHONPATH=/repo/recon:/repo --entrypoint python redamon-recon:latest \\
      /repo/testing/guinea_pigs/fp_regression_target/vhost_wordlist_edge.py

The default wordlist is cut to a few names so the run takes seconds; the code
path is the default wordlist's. Exit 0 only when every check holds.
"""
import sys
from unittest.mock import patch

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import vhost_sni_enum as vsm

NET = "192.88.94"
APEX = "fplab.test"
PLAIN, EDGE = f"{NET}.31", f"{NET}.32"
WORDS = ["portal", "split", "admin", "dev", "qa"]


def main() -> int:
    combined = {
        "domain": APEX,
        "metadata": {"target": APEX},
        "port_scan": {
            "by_host": {ip: {"ip": ip, "ports": [{"port": 443, "scheme": "https"}]} for ip in (PLAIN, EDGE)},
            "by_ip": {
                PLAIN: {"ip": PLAIN, "ports": [443], "is_cdn": False, "cdn": None},
                EDGE: {"ip": EDGE, "ports": [443], "is_cdn": True, "cdn": "cloudflare",
                       "cdn_source": "tls_certificate"},
            },
        },
    }
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
    gaps = [g for g in cb.coverage_report().gaps if g["source"] == "vhost_sni_wordlist"]
    found = sorted(f["hostname"] for f in out["findings"])

    results = [
        ("V-14a", out["scan_metadata"]["wordlist_skipped_edge_ips"] == [EDGE]
         and out["by_ip"].get(EDGE, {}).get("candidates_tested") == 0,
         f"edge .32: skipped={out['scan_metadata']['wordlist_skipped_edge_ips']} "
         f"candidates={out['by_ip'].get(EDGE, {}).get('candidates_tested')} (expect skipped, 0 candidates)"),
        ("V-14b", out["by_ip"].get(PLAIN, {}).get("candidates_tested") == len(WORDS)
         and found == [f"portal.{APEX}", f"split.{APEX}"],
         f"non-edge .31: candidates={out['by_ip'].get(PLAIN, {}).get('candidates_tested')} "
         f"findings={found} (expect {len(WORDS)} candidates, portal + split)"),
        ("V-14c", len(gaps) == 1 and gaps[0]["reason"] == "shared CDN edge" and gaps[0]["skipped"] == 1,
         f"coverage note: {gaps} (expect one vhost_sni_wordlist gap, 1 IP)"),
    ]
    for case, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {case}  {detail}")
    failed = [c for c, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
