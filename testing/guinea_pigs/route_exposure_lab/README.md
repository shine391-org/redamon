# Route exposure lab

Four stdlib Python services for the recon **route exposure** scan
(`recon/route_exposure/`) and the agent's route-exposure parts. Everything here
is fake: e-mails are `userN@lab.invalid`, and every secret-shaped value is
generated when a container starts (into `/tmp/lab-secrets.json` inside it),
never committed.

| Service | Address | Host alias (loopback only) | Role |
| --- | --- | --- | --- |
| `route-exposure-main` | `<prefix>.93` | `127.0.0.1:9101` | the application: every lead and finding kind |
| `route-exposure-twin` | `<prefix>.94` | `127.0.0.1:9102` | same title and headers as main: cross-host and RoE exclusion target |
| `route-exposure-hostile` | `<prefix>.95` | `127.0.0.1:9103` | edge cases and safety traps, plus HTTPS on 443 with a build-time self-signed certificate |
| `route-exposure-outsider` | `<prefix>.96` | `127.0.0.1:9104` | a third party the other services name in JS; must receive **0** requests |

`<prefix>` is the first three octets of `redamon-network`'s subnet (`172.25.0`
by default; Docker picks the subnet when the network is created). `./up.sh`
reads it and starts the lab there.

The lab also answers on `redamon_pentest-net` at the same last octets. The capture
proxy (TrafficMind, and `proxy_brain` replay and browser sessions) is on that
network only and cannot reach `redamon-network`, so a project that captures
traffic is pinned at the pentest-net addresses and checked with
`LAB_NETWORK=redamon_pentest-net python3 validate_route_exposure.py ...`. A page
names the outsider on the network the request came in on.

```bash
./up.sh                                   # build and start on both networks
docker exec redamon-route-exposure-main cat /tmp/hits.jsonl   # what a scan sent
docker exec redamon-route-exposure-main touch /tmp/flags/close-export   # S12: close a route
python3 validate_route_exposure.py setup S1           # temp project over MCP
python3 validate_route_exposure.py start <projectId>  # after setting the AuthProfile in the UI
python3 validate_route_exposure.py verify S1 <projectId>
docker compose down
```

## What each service answers

`expected_results.yaml` is the matrix the validator checks: the findings a
v1 run must write, the paths that must have none, the anonymous statuses, and
the hit-log rules (only GET/HEAD in the module's window, 0 hits on `/logout`
and `/account/reset`, HEAD plus a Range read for `/backup.zip`, never a full
download, 0 hits on the outsider during the whole scan).

Authentication on main accepts a bearer token (`lab-token`), an `X-API-Key`
header (`lab-key`) or the cookie `sid=lab-user-1`. Each identity sees its own
data on `/api/users/me` and `/api/me`, and the landing page links the invoice
upload only when logged in.

Every request is appended to `/tmp/hits.jsonl` inside its container: method,
path, which credentials rode on it, the Origin and Range headers, and the
status. There is no HTTP surface for it, since a scan would discover one.

## Rules

- No real target data, no real credential. A format-valid fake committed to
  the repository would trip the secret scanners the gate runs.
- The host aliases are loopback-only: the lab serves open admin, debug and
  backup routes on purpose.
- Reports in `reports/` are committed; `reports/screenshots/` and
  `reports/agent/` are not.
