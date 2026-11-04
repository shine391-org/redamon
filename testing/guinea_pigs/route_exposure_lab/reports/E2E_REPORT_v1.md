# Route exposure: end-to-end report, v1

- **Branch** `feature/route-exposure`, **commit** `9d37d2f0` (baseline `5c9e40e6`, see `BASELINE.md`).
- **Date** 2026-10-29. Stack built from the branch: `agent` and `webapp` images rebuilt after the last change to their code, `recon-orchestrator` restarted, `recon` and `graph_db` bind-mounted at spawn.
- **Lab** the four §14 services on `redamon-network` (`172.22.0.93` main, `.94` twin, `.95` hostile, `.96` outsider; the plan's `172.25.0.x` with the lab's `LAB_NET_PREFIX`), and since the TrafficMind check also on `redamon_pentest-net` at `172.28.0.93`-`.96` (section 3).
- **Verdict** the v1 campaign is green: every scenario of §22.2, every partial case of §22.4 and every UI check of §22.3 passed in one consecutive pass after the last code change (`9d37d2f0`). One UI check was not run, generating a report (deviation 1), and domain mode is unit-tested only, as §22.2 allows.

The campaign found ten defects. Each was fixed with a test, and every scenario was run again afterwards (section 7).

## 1. Gate

| Gate | Baseline (`5c9e40e6`) | After (`9d37d2f0`) |
| --- | --- | --- |
| section `agent` | 226 files passed | 233 files passed, 0 failed (5210 tests) |
| section `root-agent` | 173 files passed | 174 files passed, 0 failed (3924 tests) |
| section `root-recon` | 12 files passed | 12 files passed, 0 failed (558 tests) |
| section `recon` | 274 files passed | 280 files passed, 0 failed (7029 tests) |
| section `recon_orchestrator` | 46 files passed | 46 files passed, 0 failed (707 tests) |
| section `ai_attack_surface` | 11 files passed | 11 files passed, 0 failed (211 tests) |
| section `capture_proxy` | 7 files passed | 7 files passed, 0 failed (137 tests) |
| section `docker_broker` | 7 files passed | 7 files passed, 0 failed (36 tests) |
| section `plugin_runner` | 19 files passed | 19 files passed, 0 failed (415 tests) |
| shell suites | 39 green | 39 green |
| webapp vitest | 829 files passed, 25 skipped; 14127 tests, 2 expected fail | 839 files passed, 25 skipped; 14221 tests, 2 expected fail |
| `npm run type-check` | clean | clean |
| `npm run lint` | red before the branch | unchanged (see 8) |
| `recon_settings/build.py --check` | up to date | up to date |
| `graph_db/node_filters/build.py --check` | 15 kinds | 16 kinds (the branch adds one) |
| `seed_schema_catalog.py --check` | up to date | up to date |

**xfail:** the branch adds none. The two expected failures in vitest are in the baseline.

## 2. Coverage of the new files

| File | Coverage |
| --- | --- |
| `recon/route_exposure/__init__.py` | 100% |
| `recon/route_exposure/generators.py` | 98% |
| `recon/route_exposure/harvest.py` | 99% |
| `recon/route_exposure/normalizers.py` | 100% |
| `recon/route_exposure/prober.py` | 93% |
| `recon/route_exposure/ranking.py` | 100% |
| `recon/route_exposure/scanner.py` | 95% |
| `recon/route_exposure/seeds.py` | 100% |
| `recon/route_exposure/signals.py` | 98% |
| `recon/route_exposure/signatures.py` | 99% |
| `recon/route_exposure/verdict.py` | 96% |
| recon module total (1626 statements) | 97% |
| `recon/partial_recon_modules/route_exposure_scanning.py` | 95% |
| `graph_db/mixins/recon/route_exposure_mixin.py` | 95% |
| `agentic/prompts/route_exposure_shared.py` | 100% |
| `webapp/src/app/api/analytics/redzone/routeExposure/route.ts` | 100% lines, 82% branches |
| `webapp/src/app/graph/components/RedZoneTables/RouteExposureTable.tsx` | 95% lines, 67% branches |
| `webapp/src/components/projects/ProjectForm/sections/RouteExposureSection.tsx` | 94% lines, 83% branches |

Python: statement coverage from the route exposure test files, run serially with `--cov` in the section's image. TypeScript: `vitest --coverage` on the files' own tests.

## 3. Scans through MCP (§22.2)

Each scenario ran on its own temp project, created over MCP with `scanModules: [port_scan, http_probe, resource_enum, js_recon]` and every other Phase A tool off. The AuthProfile was set in the UI. The hit logs were emptied before each start. `validate_route_exposure.py verify` compares the run with `expected_results.yaml`:
- every expected row is present with its fields, nothing unexpected is written, and the rows of a disabled generator are absent;
- inside the module's window (`summary.started_at` to `finished_at`): only GET and HEAD, `/logout` and `/account/reset` never requested, `/backup.zip` and `/backup.tar.gz` never fully downloaded (HEAD and a ranged GET only), no credential on a request without a profile, no cookie on an anonymous request;
- the outsider has 0 hits for the whole scan;
- the measured rate is at most the limit plus 10%.

| # | Setup | Requests sent (main / hostile) | Rate (limit) | Leads / findings | Result |
| --- | --- | --- | --- | --- | --- |
| S1 | main + hostile, bearer profile, every v1 toggle on | 211 / 196 | 4.95 (5) | 10 / 12 | PASS |
| S2 | as S1, no AuthProfile | 129 / 126 | 4.98 (5) | 7 / 12 | PASS |
| S3 | as S1, cookie profile | 197 / 198 | 5.01 (5) | 8 / 12 | PASS |
| S4 | as S1, header profile (`X-API-Key`) | 197 / 202 | 4.99 (5) | 8 / 12 | PASS |
| S5-seed | seed paths off | 82 / - | 5.00 (5) | 5 / 8 | PASS |
| S5-vcs | VCS and env files off | 169 / - | 5.00 (5) | 6 / 7 | PASS |
| S5-backup | backup variants off | 176 / - | 5.00 (5) | 6 / 9 | PASS |
| S5-version | older API versions off | 194 / - | 5.00 (5) | 5 / 11 | PASS |
| S6-compare | logged-in comparison off | 130 / - | 5.00 (5) | 5 / 11 | PASS |
| S6-pii | personal data detection off | 199 / - | 5.00 (5) | 6 / 11 | PASS |
| S7 | main + twin, twin in `roeExcludedHosts` | 130 / twin 0 | 5.00 (5) | 5 / 11 | PASS |
| S8 | `roeGlobalMaxRps: 2` | 130 / - | 2.00 (2) | 5 / 11 | PASS |
| S10 | stealth mode on | module not run | - | - | PASS |
| S11 | `routeExposureMaxRoutesPerHost: 10`, `routeExposureMaxRoutesTotal: 50` | 10 / 14 | 5.00 (5) | budget cut 212 routes; floor routes requested first | PASS |

Rows compared (`expected_results.yaml` against each project's `recon_<id>.json`):

| Scenario | Rows expected | Observed | Unexpected | Rows required absent, and absent |
| --- | --- | --- | --- | --- |
| S1 | 22 | 22 | 0 | - |
| S2 | 19 | 19 | 0 | - |
| S3 | 20 | 20 | 0 | - |
| S4 | 20 | 20 | 0 | - |
| S5-seed | 13 | 13 | 0 | 4 of 4 |
| S5-vcs | 13 | 13 | 0 | 4 of 4 |
| S5-backup | 15 | 15 | 0 | 2 of 2 |
| S5-version | 16 | 16 | 0 | 1 of 1 |
| S6-compare | 16 | 16 | 0 | - |
| S6-pii | 17 | 17 | 0 | - (and every `pii_types` empty) |
| S7 | 16 | 16 | 0 | 1 of 1 (twin) |
| S8 | 16 | 16 | 0 | - |
| S10 | 0 | 0 | 0 | module did not run |
| S11 | not compared: budget cut | | | |

The S1 rows:

| Host | Path | Kind | Generator | Lead |
| --- | --- | --- | --- | --- |
| hostile | `/backup.tar.gz` | backup_file | backup | |
| hostile | `/xss-snippet` | anonymous_access | found | yes |
| hostile | `/xss-snippet` | sensitive_data | found | yes |
| main | `/.env` | env_file | vcs | |
| main | `/.git/HEAD` | vcs_exposure | vcs | |
| main | `/.git/config` | vcs_exposure | vcs | |
| main | `/actuator/env` | debug_endpoint | seed | |
| main | `/api/admin/export` | anonymous_access | seed | yes |
| main | `/api/admin/help` | anonymous_access | found | yes |
| main | `/api/users/me` | sensitive_data | found | yes |
| main | `/api/v1/orders/42` | anonymous_access | version | yes |
| main | `/api/v2/reports/export` | anonymous_access | found | yes |
| main | `/backup.zip` | backup_file | backup | |
| main | `/config.php.bak` | backup_file | backup | |
| main | `/console` | debug_console | seed | |
| main | `/console-open` | debug_console | found | |
| main | `/debug/error` | debug_page | found | |
| main | `/internal/users/export` | anonymous_access | found | yes |
| main | `/internal/users/export` | sensitive_data | found | yes |
| main | `/phpinfo.php` | debug_page | seed | |
| main | `/uploads/invoice-1001.pdf` | anonymous_access | found | yes |
| main | `/web.config` | config_file | vcs | |

None of the routes that must stay silent has a finding: `/api/v2/orders/42` (locked), `/api/admin/users`, `/roles`, `/audit`, `/api/status`, `/admin` on main; `/spa/admin`, `/api/missing/internal`, `/wall/admin`, `/redirect-internal` on hostile.

### Flows (S9, S12, S13, S14, S21)

| # | What ran | Observed | Result |
| --- | --- | --- | --- |
| S9 | `start_recon` with an RoE time window closed now | refused: "RoE time window: testing not allowed on Thursday. Allowed days: Sunday"; status stayed idle; 0 lab hits | PASS |
| S12 | run 1 (16 route nodes); "Real" on the `/internal/users/export` lead in the Priority Board; `close-export` and `close-admin-export` flags; run 2 | the human-verdict lead kept, with `stale_since`; the `/api/admin/export` lead pruned | PASS |
| S13 | `stop_recon` 2 s after the module's first `.git`/`.env` request, on S2's project | final status idle; 19 route nodes before and after (no prune); the next normal S2 run passed (129 / 125 requests, 4.98 rps) | PASS |
| S14 | the "Bug Bounty - Deep Dive" preset applied in the UI to a project created with the module off | `routeExposureEnabled` true; every route exposure field inside its registry bounds; the 9 Jev flags unchanged | PASS |
| S21 | after S12: `routeExposureEnabled` false, a full recon | 14 route nodes before, 1 after: the human-verdict lead, with `stale_since` | PASS |

### S1b: triage

A triage run on S1 from the Priority Board (review budget 0: rules only, no LLM call), graded by `tooling/scripts/triage_eval.py --guinea-pig route_exposure_lab` against `testing/guinea_pigs/triage_truth.yaml`. 22 findings, all graded (coverage 100%); NDCG@25 1.00, NDCG@10 1.00; 0 flagged false positive. The 12 signature findings rank first (T2: consoles, version control, env and backups, 56-62; T3: `/actuator/env`, `web.config` and the debug pages, 26-33). The 10 leads are T4 (0.23) until the agent confirms them. PASS.

### Report predicate

The report and Insights leave out a lead with no `CONFIRMS` edge (§7.6). On S1's graph after the final run, 12 route nodes are reportable and the 10 pending leads (`anonymous_access`, `sensitive_data`) are left out. See deviation 1 for why no report was generated.

### TrafficMind and the AG project

The capture proxy is on `redamon_pentest-net` only, and the lab was on `redamon-network` only, so the proxy could not reach it. A first run with capture on (AG project at `172.22.0.93`/`.95`) therefore lost both hosts: every proxied request timed out in the proxy. The module recorded the loss as it should, in the Domain's coverage record ("route_exposure: unreachable host(s) skipped", both hosts listed). The lab now also answers on `redamon_pentest-net` at the same last octets (`63705998`, lab only; its `redamon-network` answers are unchanged, and S1 re-run on the rebuilt lab passed with the same counts: 211 / 197 requests, 4.95 rps).

A new project, `route-exposure-e2e AG-pentest (temp)`, pinned at `172.28.0.93`/`.95` with S1's setup, a bearer profile and `captureProxyEnabled: true`:

| Check | Observed | Result |
| --- | --- | --- |
| captured `route_exposure` transactions | 211, all on main: 137 anonymous, 74 logged in; methods GET and HEAD; source `recon` | PASS |
| credential values stored in clear | 0 (every `Authorization` value is `[redacted:…]`) | PASS |
| main rows of S1 | all present | PASS |
| hostile rows of S1 | absent: the proxy answers 502 "Certificate verify failed: self-signed certificate" for every request to hostile's HTTPS (open issue 11) | not a module failure |

This project is the one the agent campaign (A1) runs on: the agent's Kali sandbox reaches both networks, and `proxy_brain` goes through the capture proxy.

**Domain mode:** unit-tested only. The labs run in IP mode, and the stack cannot resolve a lab hostname without editing the host system (§22.2).

## 4. Partial recon through the UI (§22.4)

| # | Case | Observed | Result |
| --- | --- | --- | --- |
| P1 | section button, graph targets on, no URL (2 BaseURLs, 36 Endpoints) | the same 22 route nodes as S1, all rewritten; kind, generator, lead flag and `auth_expected_by` identical to the S1 full run; 209 / 200 requests, GET and HEAD only, 0 outsider, no state-changing path | PASS |
| P2 | graph targets off, `http://172.22.0.93/` attached to "Generic" | one UserInput under the run's root Domain, holding the URL, `PRODUCED` the 9 findings on that base, one of them a lead (`/api/admin/export`); main 139 requests, the other hosts 0 | PASS |
| P3 | the same URL attached to the BaseURL `http://172.22.0.93` | no new UserInput; the 9 rewritten findings hang off that BaseURL | PASS |
| P4 | graph targets off, no URL | Run disabled, red warning "Provide custom targets below or enable graph targets to run the scan." | PASS |
| P5 | a project with no BaseURL in the graph | Run disabled, "No BaseURLs or Endpoints found in graph. Run HTTP Probing (Httpx) and Resource Enumeration first, or provide custom URLs below." | PASS |
| P6 | the outsider URL `http://172.22.0.96/widget.js` | the modal refuses it: "172.22.0.96 is not one of this project's target IPs". Sent past the modal, the orchestrator logs "dropped out-of-scope input": alone it answers 400 "No typed target is in this project's scope", beside a main URL the run goes ahead without it. 0 outsider hits | PASS |
| P7 | the workflow node's Play, then the section button | the same request and the same 22 nodes; the drawer reads "Scanning: Vulnerability Scanning" for the whole run, never another phase | PASS |

## 5. UI (§22.3)

Every cell of [`../ui_checklist.md`](../ui_checklist.md) is ticked, apart from the report (deviation 1). The checks:
- the 12 route exposure fields and the 3 agent switches: flip, save, reload, `get_recon_settings`; min, max, min-1, max+1 and a cleared field; the PUT and its status;
- the section header, tooltip, wiki link, the authentication hint and its link, Advanced, and the "Half a cycle" alert and its link;
- the Workflow node, its gear and Play;
- the graph page (`/xss-snippet` evidence shown as text, no dialog; an Endpoint's `anon_status`) and the Priority Board;
- every Red Zone feature: badge, rows, filters, text filter, mute and unmute, the three exports, empty and loading states;
- 390 px for the section, the partial modal and the Red Zone table.

Screenshots are in `screenshots/v1/` (gitignored).

### 5.1 Addendum: reading the new properties (after v1)

Added on request after the v1 pass (`5d64a727`, `0644cf38`), checked on the live stack with
the AG project's graph after an agent session had confirmed its leads:
- **Node drawer.** A route exposure Vulnerability gets a "Route exposure" block of labelled rows
  (exposure, status, route class, route, both answers, body comparison, why a login is expected,
  leaks, personal data, sensitive fields, signature, generator, catch-all check, confidence,
  evidence). The status reads the lead's CONFIRMS edge from the loaded graph: `/api/users/me`
  showed "Confirmed by the agent". An Endpoint the scan measured shows its anonymous answer.
- **Node Inspector.** The same block leads the expanded row. In the first check it sat after
  Properties and started off-screen, because a 36-column table stretches the row past the
  viewport; it now comes first (`0644cf38`). `/api/v2/reports/export` read "Confirmed by the agent".
- **Mute Rules.** The Route exposure kind offers 14 more fields (host, URL, path, method,
  logged-in status, same page logged in, anonymous body type, login expected because, leak
  signals, personal data types, sensitive fields, signature, catch-all check) after the existing
  ones; a draft rule was discarded, nothing saved.

Screenshots: `screenshots/v1/display_drawer.png`, `screenshots/v1/display_node_inspector.png`.

## 6. Pass history

Sections 3 to 5 ran as one consecutive pass on `9d37d2f0`, after the last code change. The scenario matrix (S1-S11, S9, S12, S13, S14, S21) had also passed in full on `c1fde9ff`. The four fixes after it (`9999a94d`, `a4938e6f`, `c6ca8c6c`, `9d37d2f0`) came from the partial and layout checks, and the whole pass was repeated after the last of them.

## 7. Defects found and fixed

| Commit | Found by | Defect | Fix |
| --- | --- | --- | --- |
| `bcf65bc1` | numeric sweep | emptying any registry number field saved 0 (refused on the 172 fields with a minimum above 0; meant "off" on some) | a cleared field takes its default on blur. Shared component; changelog entry |
| `a9fd0b5e` | section check | the rate field said its RoE cap twice | registry text |
| `1e036186` | alert check | the "Half a cycle" alert named a tab and a skill that do not exist | real names (AI Agent > Agent Skills, Broken Access Control) |
| `fd12caa8` | P5 | the partial modal's no-targets warning fell back to the IP text ("No IPs ... Subdomain Discovery") | a Route Exposure message |
| `9da4d85b` | AG3 check | the alert had no link to the tab it names | a link, as the auth hint has |
| `c1fde9ff` | auth link check | the auth hint named "Authentication"; the section is "Authenticated Session" | the real name |
| `9999a94d` | 390 px | every Red Zone table header clipped its toolbar on a phone: Markdown and Filters unreachable | the toolbar wraps right-aligned below 640 px. Shared; changelog entry |
| `a4938e6f` | P1 | a partial run read back the routes the scan itself had generated, as found routes: `/api/v1/orders/42` lost its `version_locked` lead, `/api/admin/export` turned from seed to found | the partial builder skips an Endpoint the scan created that no other tool lists |
| `c6ca8c6c` | P2 | on an IP-mode project the modal refused every typed URL as out of scope (it checked hosts against the `ip-targets.<id>` placeholder) | the modal applies the orchestrator's IP-mode rule. Shared, every URL tool; changelog entry |
| `9d37d2f0` | P2 | the typed URL's UserInput had no `PRODUCED` edge, so the partial run deleted it as an orphan | `UserInput -[:PRODUCED]-> Vulnerability`, declared in `schema_sections.md` |

Lab and harness fixes (no product code): `406a1489`, `300bb465`.

## 8. Open issues, pre-existing (not fixed on this branch)

1. **`npm run lint`** fails before this branch: Next.js 16 has no `next lint`, so the script reads `lint` as a directory.
2. **JS Recon** endpoint validation requests every URL a bundle names, `/logout` and `/account/reset` included, unpaced (8 requests in 3 ms in the lab), just before Phase A (`recon/main_recon_modules/js_recon.py`, `_endpoint_probe_method`). The module's window starts after it, so it is outside this module's checks.
3. **`PUT /api/projects/<id>`** checks no registry bound: a hand-made PUT stores `routeExposureMaxRps: 51` or `katanaDepth: 11`. The form and MCP refuse both, and this module clamps every value at use, but a field whose consumer does not clamp runs with the stored value.
4. **Partial modal** no-targets text still falls back to the IP message for Web Cache Poisoning, Serialized Scan and GraphQL.
5. **Web Cache Poisoning partial** creates its UserInput with no `PRODUCED` edge, so the orphan cleanup deletes it. This is the defect `9d37d2f0` fixed for route exposure.
6. **`update_user_input_status`** (`graph_db/mixins/recon/user_input_mixin.py`) matches `user_id: $props.user_id` with props that hold no `user_id`, so it never updates a UserInput, for any tool.
7. **`/uploads/invoice-1001.pdf`** is found only when the crawl keeps documents: Katana's default exclude list drops `.pdf`. S1 removes `.pdf` from the list (`needs: keep_docs`).
8. **The MCP token** has no `triage:run`, `triage:write` or `preset:apply` scope, so S12's verdict, S14's preset and S1b's triage run were done in the UI. The token was not widened.
9. **390 px app chrome:** the page header ("Other Scans") and the footer bars clip at 390 px. This is the app's shared layout, not the feature's.
10. **Red Zone empty state** on a stealth project says "Enable Route Exposure ... and run a recon" although the module is enabled; stealth is what stops it. Wording only.
11. **Capture proxy and self-signed HTTPS.** mitmproxy verifies the target's certificate, so with capture on every proxied tool gets the proxy's own 502 from an HTTPS target with a self-signed certificate. The scanners themselves do not verify certificates. Katana found 1 route on hostile and the route exposure module delivered none, and nothing records the loss (a 502 is an answer, not an unreachable host). A fix belongs in the capture proxy (`ssl_insecure`, or a recorded skip) and changes a shared security setting, so it is left to a decision.
12. **Capture proxy reach.** The proxy is on `redamon_pentest-net` only, so a target reachable only on another Docker network is lost to every proxied tool when capture is on. It is reported as unreachable in the coverage record. By design for RedAmon's own network; the lab has been moved onto `redamon_pentest-net` as well.

## 9. Deviations from the plan

1. **Reports page.** Generating a report needs a "Report narratives" model saved for the account, an account-wide setting the campaign does not change. The report's predicate was checked on the graph instead (section 3). The `reportData` exclusion itself is covered by `webapp/src/lib/report/routeExposureCandidateExclusion.test.ts`.
2. **Triage review budget 0** on S1, so S1b grades the rule layers without an LLM, for the same reason.
3. **Setup through the UI** where MCP has no tool or scope: the AuthProfile, the OpenAPI source and the Katana exclude list (S1), S12's verdict, S14's preset and the triage run.
4. **Lab addresses** `172.22.0.9x` (the lab's `LAB_NET_PREFIX` on `redamon-network`) instead of the plan's `172.25.0.9x`.
5. **Rows the lab needs from setup** carry `needs:` in `expected_results.yaml`: `openapi` (`/api/v2/reports/export`, declared only by the OpenAPI document; `OPENAPI_AUTO_DISCOVER` is off by default) and `keep_docs` (open issue 7).

## 10. Temp projects

All named `route-exposure-e2e <scenario> (temp)`, owned by the operator account, holding lab data only. Not deleted: they are listed for the human to decide.

| Project | Id | Used by |
| --- | --- | --- |
| S1 | `cmvsnaokm0001o301491ymuwi` | S1, S1b, P1-P7, the Red Zone and graph-page checks |
| UI | `cmvsnd4kn000go301zy2r2ost` | the per-field UI sweep, P5 |
| S2 ... S11 | `cmvso0ff10037o301rftoi594` (S2, also S13), `cmvso0frt003bo301f2pqmwhn` (S3), `cmvso0g5z003fo301z3ej927d` (S4), `cmvso0gi1003jo30186bx363g`, `cmvso0gwd003no3014c4lt49h`, `cmvso0h7s003ro30197097p84`, `cmvso0hlf003vo301jiuj3skp` (S5), `cmvso0hyo003zo301cg5i7urt`, `cmvso0iat0043o3018w0ie6dn` (S6), `cmvso0iom0047o301y29qkkj3` (S7), `cmvso1qo60053o301gdvnmlxe` (S8), `cmvso1r300057o30178d0w90j` (S10, empty state), `cmvso1rgr005bo3014co6mriw` (S11) | the scenario matrix |
| S9, S12/S21, S14 of the final pass | `cmvsytlvj00adl401fpxk3oeo`, `cmvsytqxm00aol401npbzsdok`, `cmvsyveay00b5l401caklqr9r` | the flows |
| AG-pentest | `cmvszuc0700edl401hdn683x0` | TrafficMind; the agent campaign |
| superseded | `cmvsppa7v00i5o301nwylchwj` (AG on `redamon-network`); S9, S12 and S14 of earlier passes: `cmvspx73k00jvo3016z3z74tt`, `cmvspxftt00k6o301ayrov98w`, `cmvsp04qh00d7o3012ojb1oxw`, `cmvsvlgme007no601yu2ppnbs`, `cmvsvllqj007yo601ch3kqkl0`, `cmvsvn9b4008fo601e5kq6ih6` | none |
