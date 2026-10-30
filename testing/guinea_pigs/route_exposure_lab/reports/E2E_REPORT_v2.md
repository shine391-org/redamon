# Route exposure: end-to-end report, v2

- **Branch** `feature/route-exposure`. v2 code: `f3696190` (settings cascade, generators, stage
  helpers), `89b1f7ba` (probe-time features), `7fbaa0d0` (lab rows and scenarios). Fixes found by
  this campaign: `9318e726`, `3431f78d`, `68126c0b`, `c2fd1a61`. UI specs: `7e8cabc2`.
- **Date** 2026-10-30. `recon/` is bind-mounted at spawn, so a scan runs the working tree's recon
  code; the webapp image was rebuilt for the v2 and v3 columns (`db push` runs in its entrypoint).
- **Lab** the §14 services on `redamon_pentest-net` (`172.28.0.93` main, `.94` twin, `.95` hostile,
  `.96` outsider). The validator runs with `LAB_NETWORK=redamon_pentest-net`.
- **Verdict** the v2 campaign is **green** under the reduced set agreed with the human on
  2026-10-30 (plan §22.7): v2-A, v2-B and v2-P pass, and every UI check of §22.3 for the v2 fields
  passes. It found three defects (§3), each fixed with a test; the scenarios each fix touches were
  re-run (§5).

## 1. Gate

The gate ran once for v2, v3 and A2, after the last code change: see
[E2E_REPORT_v3.md §1](E2E_REPORT_v3.md#1-gate). The unit tier is green.

## 2. Coverage of the new files

Line coverage from the route exposure and Jev test files, run together in the recon image
(`--cov`), after the last change:

| File | Coverage |
| --- | --- |
| `recon/route_exposure/catalogs.py` (v2) | 100% |
| `recon/route_exposure/gitwalk.py` (v2) | 100% |
| `recon/route_exposure/riders.py` (v2) | 100% |
| `recon/route_exposure/seeds.py` | 100% |
| `recon/route_exposure/harvest.py` | 99% |
| `recon/route_exposure/generators.py` | 98% |
| `recon/route_exposure/verdict.py` | 97% |
| `recon/route_exposure/scanner.py` | 95% (86% before `test_route_exposure_jev_scan.py`) |
| `recon/route_exposure/prober.py` | 93% |
| `recon/route_exposure/` total | 97% |

Every file clears the 90% target.

## 3. Defects found and fixed

| # | Found by | Defect | Fix |
| --- | --- | --- | --- |
| 1 | v2-A, first run | **js_recon never read a bundle on a private target.** Its download took the attacker-influenced URL rule (`is_url_safe_to_probe`, which refuses every RFC-1918 address) for every file, so an internal engagement's own bundles were refused: js_recon reported `no_input` on every host, its routes never reached the harvest, and no API was ever tagged `client_gated`. The v1 lab hid it, because the v1 rows came from jsluice. | `9318e726`: a file on one of the run's own hosts (target list, IP-mode targets, hosts http_probe reached) follows the pipeline's address rule, as route exposure and the OpenAPI discovery already do; any other host and any redirect hop off the run keep the strict rule; metadata stays refused. `test_js_recon_download_guard.py` (10 tests) |
| 2 | v2-A, first run | **The hostile lab dropped random URLs from jsluice's httpx verify.** Its TLS server wrapped the listening socket, so every handshake ran inside `accept()` on the one serving thread; a parallel burst timed some out at random (three replays of the same 17 URLs dropped different ones), and `/xss-snippet` came and went between runs. A lab defect, not recon's. | `3431f78d`: the handshake runs in the worker thread. Five replays afterwards returned all 15 reachable URLs every time |
| 3 | v2-P | **A partial run did not tag client-gated APIs.** Harvest pairs a router route with the APIs the same bundle calls from js_recon's endpoint list, which a partial run (built from the graph) did not have: `/api/admin/stats` came out `admin_function` there and `client_gated` in the full run. | `68126c0b`: the partial builder rebuilds the list from the bundle → endpoint edges js_recon writes (endpoint type and the bundle's URL), in scope only. Two builder tests |
| 4 | the unit gate | `68126c0b`'s bundle query read `JsReconFinding` with no mute filter, so a JS file an operator muted could still pair routes. | `c2fd1a61`: `NOT f:Muted`, as every partial seed reading a finding label must |

Also corrected during the campaign, not code defects:
- v2-A's first run pinned the bearer profile's scope to main only. The crawlers attach a session only
  when **every** target host is in scope (fail closed), so the run crawled logged out and missed
  the logged-in invoice link. S1 left the scope empty (= the project's targets); v2-A now does too
  (set in Postgres, deviation 3).
- The validator maps a finding to its lab role by the network prefix, so it needs
  `LAB_NETWORK=redamon_pentest-net` for this project (the default is `redamon-network`).

## 4. Scans (§22.7)

One temp project, `route-exposure-e2e v2-A (temp)` (`cmvuqf0ye0001ry01ymjnv8jv`), created by
`validate_route_exposure.py setup v2-A` with `scanModules: [port_scan, http_probe, resource_enum,
js_recon]` and the bearer profile set in the UI. v2-B reused it with its settings changed over MCP
(`update_recon_settings`); v2-P ran on it from the UI. Hit logs were emptied before each run.

| Scan | Setup | Observed | Rate | Result |
| --- | --- | --- | --- | --- |
| **v2-A** | every v2 switch on, cross-host off; main + twin + hostile; bearer | 37 harvested, 380 generated, 416 requested, 0 cut; 19 leads, 17 signature findings; 750 requests (main 330, twin 185, hostile 236); every v1 and v2 row present with its fields, `/.git/HEAD` `git_walk_proof=head>ref>commit` on main and absent on hostile (the zlib bomb is bounded, one object request per host), `/api/admin/stats` `client_gated`, `/api/profile` CORS with all four variants and `auth_cacheable`, `/actuator/heapdump` HEAD only, no `debug_console` on the hostile false Ignition, no CORS lead on hostile's `*` route, nothing unexpected, the twin has no `cross_host` row | 5.01 rps (limit 5, slack 10%) | PASS |
| **v2-B** | every v2 switch off, cross-host on | 36 harvested, 307 generated, 342 requested; 15 leads, 14 findings; every v2 row absent and every v1 row as in v2-A; the twin's `/internal/users/export` `anonymous_access` and `sensitive_data` with `generated_by=cross_host` | 4.99 rps | PASS |
| **v2-P** | Route Exposure partial run from the section button, graph targets on, v2-A's settings | 36 route exposure nodes written, the same 19 leads and 17 findings as v2-A with every field checked by the same rows (`client_gated` included after fix 3); the framework seeds ran from the graph's Technology input (`/actuator/*`, `/_ignition/health-check` rows present); main 330, twin 185, hostile 234 requests, GET and HEAD only, 0 outsider | 4.99 rps | PASS |

v2-P was checked by the validator's own `verify` against v2-A's rows, fed with the nodes the run
wrote (`updated_at` at or after the run's start, read over MCP `query_graph`) and the hit logs of
the run's window, since a partial run writes the graph and not the recon JSON.

## 5. Pass history (§22.7 pass rule)

| Scenario | Last passed on | Why later commits do not touch it |
| --- | --- | --- |
| v2-A | recon tree of `4553fe31` (the v3 hooks were in the tree, gated off) | `68126c0b` changes only the partial graph builder; v3's recon code is the hook modules and their call sites, off in this scenario |
| v2-B | same | same |
| v2-P | `c2fd1a61`, re-run as v3-P3 (AI in Pipeline off, so no hook runs) after the mute filter was added to the bundle query | no recon commit after it |
| v1 S1 rows | re-proven by v2-A after fix 1 | v2-A checks every v1 row and every v1 "absent" row on main and hostile; fix 1 only adds js_recon input to the harvest. The S2–S11 variants differ from S1 in route exposure settings only, whose per-switch effect is unit-tested (`test_route_exposure_settings_effect.py`) |

## 6. UI (§22.3, v2 fields)

Driven by Playwright against the rebuilt webapp image (deviation 2):
- `testing/e2e/tests/routeExposureV2Toggles.spec.ts`: the seven v2 switches (`Sibling routes`,
  `Framework paths`, `Follow route catalogs`, `Git walk proof`, `Cross-host`, `Cross-origin (CORS)`,
  `Cacheable logged-in content`) each start at their default, flip, are carried by the PUT, are
  stored, show flipped in the reopened form, flip back and store the default again. No console
  error beyond the graph page's recon and GVM download probes on a never-scanned project (two
  404s the test names exactly). Screenshots in `screenshots/v2/` (gitignored). PASS.
- The partial modal lists the new **Technology** input next to BaseURL and Endpoint (v2-P).
- The v1 section, header, Workflow node, graph, Red Zone and 390 px checks are unchanged since the
  v1 report: v2 adds toggles inside the existing section and no new view.

## 7. Deviations from the plan (agreed with the human, 2026-10-30)

1. **Reduced campaign** (§22.7): v2-A, v2-B and v2-P replace S15–S17 and P1–P7 for v2. P2–P7
   exercise scoping code unchanged since v1, where they passed live, and are unit-tested.
2. **The v2 field sweep ran in Playwright**, not step by step in the DevTools MCP: the same real UI,
   the same per-field protocol (flip, save, PUT body, stored value, reload, flip back, console), and
   it can be re-run. `get_recon_settings` was replaced by `GET /api/projects/<id>`, which reads the
   same row.
3. **Setup outside the UI where needed**: v2-B's settings were changed over MCP on v2-A's project
   instead of a new project; the bearer profile's scope was widened in Postgres to S1's (empty =
   the project's targets) after the first v2-A run.

## 8. Open issues

- js_recon's endpoint probes and source-map fetches still take the strict URL rule, so on a private
  target they record `ssrf_blocked` instead of probing. That keeps a bundle-named URL from reaching
  an internal host, which is the rule's purpose; on the run's own hosts it is more cautious than
  the rest of the pipeline. Left as is; worth a decision.
