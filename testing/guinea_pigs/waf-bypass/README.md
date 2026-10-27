# WAF Bypass via Direct Origin Access — Guinea Pig (taxonomy class 13)

A signature WAF **edge** in front of an **origin** that is *also* reachable directly by
IP. The class-13 finding is the **blocked-vs-allowed differential**: a probe the edge
refuses (403) but the origin serves (200) proves the WAF can be bypassed by addressing
the origin directly.

```
 attacker ─▶  edge (WAF, 172.25.0.91:443)  ─▶  origin (172.25.0.92:443)
                 blocks signature probes         serves everything, no WAF
                 └──────────── origin also reachable directly ───────────┘
```

- **`172.25.0.91`** — the WAF edge. Returns **403** on classic signatures
  (`../`, `etc/passwd`, url-encoded `<script`, `%27`, `union select`); proxies clean
  traffic to the origin.
- **`172.25.0.92`** — the origin, directly reachable, **no WAF**. Serves 200 for every
  request, including the probes.

Both serve HTTPS with a baked self-signed cert (the recon check uses `verify=False`).
Fixed IPs on `redamon-network` so a scan/probe can be pinned to stable addresses.

## Run it

```bash
cd testing/guinea_pigs/waf-bypass
docker compose up -d --build
bash tests/run_tests.sh          # asserts edge-blocks / origin-serves
```

Tear down: `docker compose down`.

## How RedAmon detects it

`recon/helpers/security_checks.py::_waf_payload_differential` sends a canonical
WAF-signature probe as a throwaway query param to the hostname (edge) and to the origin
IP with the real Host header. A bypass needs both halves:

- the edge **blocks** the probe (403, 406, 429, 501, 999 or 202), and
- the origin **serves** it: a **2xx** answer whose body matches the page the edge serves
  for a benign request (one extra request to `https://<host>/`, sent only once a probe is
  a candidate). The bodies are normalised (hostnames, the echoed probe, request ids) and
  must share at least 80% of their tokens.

A 302 to a login page, a 401, a 403, a 404 or a 421 from the origin is the origin
refusing, not serving, and gives no finding; so does a 2xx default page that is not the
site, or an edge that serves no 2xx page itself. The finding is high-severity
`waf_bypass` with `detection_method="payload_differential"` and `control_check:
"passed"`, and its evidence carries the statuses and the similarity. The finding is the
differential, never the payload — this is a WAF-efficacy test.

Verified against this lab: `check_waf_bypass("172.25.0.91", "172.25.0.92")` returns the
finding (`edge_status=403; origin_status=200; edge_baseline_status=200;
body_similarity=1.00`): the edge proxies clean traffic to the origin, so its benign page
and the origin's answer to the probe are the same page.

The fixed addresses assume `redamon-network` is `172.25.0.0/16`. If yours is another
subnet (`docker network inspect redamon-network`), start the lab with a compose override
that sets both `ipv4_address` values inside it, and use those addresses above.
