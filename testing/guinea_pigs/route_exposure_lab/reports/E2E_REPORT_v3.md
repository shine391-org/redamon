# Route exposure: end-to-end report, v3

- **Branch** `feature/route-exposure`. v3 code: `4aafe0ce` (agent: `/jev/route-privacy-rank`,
  `/jev/route-exposure-assess`), `4553fe31` (recon hooks, settings cascade, UI), `edf33833` and
  `63116b73` (wiki), `7e8cabc2` (UI specs). Lab and harness: the v3 commit after `634a973b`
  (`test(lab): route exposure v3 rows, the disguised login wall and harness fixes`).
- **Date** 2026-10-30. Agent image built from committed HEAD `634a973b`; webapp image rebuilt for the
  three columns; recon bind-mounted.
- **Jev** the owner's own TypeSafe token, model `jev-1.13.0`, every hook in **shadow**.
- **Verdict** the v3 campaign is **green** under the reduced set agreed with the human on
  2026-10-30 (plan §22.7): v3-A, v3-P1, v3-P2 and v3-P3 pass; S18b–S18d are read from v3-A;
  S18g and the §22.3 v3 UI checks pass in Playwright. S19 is covered by unit tests only
  (deviation 3).

## 1. Gate

Run on the shared working tree after the last code change (`./redamon.sh test all`, then
`test coverage` and `test live`). The tree also held another session's uncommitted CVE-lookup
edits, which the gate ran too; nothing failed in them.

| Section | Unit + integration (`test all`) |
| --- | --- |
| `agent` | 271 files passed; 1 failed: `test_cve_intel_integration.py` (PDCP key template and settings route, an integration fixture) |
| `root-agent` | 184 passed; 1 failed: `test_scan_envelope_integration.py` (scan-slot concurrency on a live host) |
| `root-recon` | 14 passed, 0 failed |
| `recon` | 293 passed; 1 failed: `test_ai_js_sdk_integration.py`, a stale stub (its fake `sourcemap` module lacks `pseudo_file_base`, which js_recon imports since `7a8f242b`, before this work) |
| `recon_orchestrator` | 47 passed; 1 failed: `test_orchestrator_integration.py` (spawning a partial recon container) |
| `ai_attack_surface` / `capture_proxy` / `docker_broker` / `plugin_runner` | 11 / 7 / 7 / 19 passed, 0 failed |
| `shell` | 39 suites green |
| webapp (vitest) | 930 files passed, 25 skipped; 15336 tests passed, 2 expected failures |

**The unit tier is green**: every failure above is an `*_integration` file, the same set the A1
report recorded, none in route exposure code. An earlier unit run on the same day found three
real failures, each fixed before this run: the skill-parts endpoint test still pinned 57 parts
(`30892b13`), the partial builder's bundle query read `JsReconFinding` without a mute filter
(`c2fd1a61`), and the MCP API reference was stale after the three new columns (`63116b73`). Two
more files failed only under the gate's load and passed alone (`route.delete.test.ts`,
`plugins_db_test.sh`).

`test coverage`: every section above its floor (agent 89%, recon 87%, recon_orchestrator 79%).
`test live` (the stack up): agent 8, root-agent 40, recon_orchestrator 1 and capture_proxy 1
files passed; recon 6 passed and 2 failed, both pre-existing: `test_js_recon_sourcemap_smoke.py`
(an octet-stream source map rated low, not high) and `test_ai_surface_recon_smoke.py` (it greps
`project_settings.py` for a literal line that no longer exists). Each fails the same way on an
export of `78aee530`, before any change of this campaign.

**Coverage** of the v3 files, from their tests in the recon image: `route_exposure_assess.py`
96%, `route_privacy_rank.py` 94%, `route_wall_check.py` 94%; the scanner's call sites are
covered by `test_route_exposure_jev_scan.py` (`scanner.py` 95%). On the agent side,
`test_jev_endpoints.py` (185), `test_jev_item_hooks.py` (56) and `test_jev_item_contract.py`
(15) cover both endpoints and hooks.

## 2. Scans (§22.7)

Same temp project as v2 (`cmvuqf0ye0001ry01ymjnv8jv`), its settings changed over MCP between runs.

| Run | Setup | Observed | Result |
| --- | --- | --- | --- |
| **v3-A** (full) | v2-A's settings + AI in Pipeline + the three Jev flags | every v1 and v2 row of v2-A plus the new `/internal/portal` lead, with their fields; 39 harvested, 390 generated, 428 requested, 20 leads, 17 findings; 765 requests at 5.01 rps. `jev_shadow.route_privacy_rank` 400 decisions, `.route_exposure_wall` 5, `.route_exposure_assess` 20, all rollout `shadow`, model `jev-1.13.0`, 0 fallbacks | PASS |
| **S18** node identity | v3-A against the route exposure nodes in the graph before v3 (written by v2-P, = v2-A) | 36 nodes compared property by property (ignoring `updated_at`, `anon_status_at`, `created_at` and the triage/review layer): **one** difference, `/.git/HEAD` `git_tree_prefix`, because the lab regenerates its fake repository (with fresh secrets) on every rebuild and was rebuilt in between. One node only in v3-A: `/internal/portal`, the v3 lab row. The two twin cross-host nodes v2-B wrote are not rewritten, as cross-host is off | PASS |
| **v3-P1** (partial, S18f) | v3-A's settings | the three hooks ran on the partial path: `[RoutePrivacy-Jev] 424 routes, 224 distinct asked`, `[RouteWall-Jev] 4 pages asked`, `[RouteExposure-Jev] 20 leads assessed`, three `jev-shadow … summary` lines (400 / 5 / 20 decisions, 0 fallbacks), each hook's own record; 37 nodes, the same rows as v3-A, 4.99 rps | PASS |
| **v3-P2** (partial, S18e) | v3-A's settings, the owner's Jev token unusable | the first call answered `503 jev_auth`; the `agent_jev` breaker stopped Jev for the rest of the run (`jev_auth - stopped for the rest of this run`), and each hook recorded fallbacks instead of raising (1, 1 and 5 batches; 0 decisions); the run completed with the same 37 nodes as v3-P1 | PASS |
| **v3-P3** (partial, S20, and the v2-P re-run) | Jev flags on, AI in Pipeline **off** | no Jev line at all in the run's output (no hook ran, no record); `preflight_scope_check` reports the three hooks `effective: off`; 37 nodes equal v2-A's rows, `client_gated` included, which re-proves v2-P after `c2fd1a61` | PASS |

Partial runs keep their shadow records in memory and print them; the checks read the partial
container's output (captured with `docker logs -f`) and the graph.

### S18b: is Jev right? (v3-A, against the lab's ground truth)

Per item, never averaged. "Not asked" on hook A means the route was below the 400-route cap.

#### Hook A: route privacy rank

400 decisions (224 distinct items), 50% agree with the prior score's verdict, 0 fallbacks.

| Route | Truth | Jev (noul %) | Prior score's verdict | Result |
| --- | --- | --- | --- | --- |
| `/internal/users/export` | private | private (84) | public | right |
| `/api/v2/reports/export` | private | not asked | - | n/a |
| `/api/v1/orders/42` | private | public (35) | public | **miss** |
| `/api/admin/export` | private | private (84) | private | right |
| `/api/users/me` | private | private (84) | public | right |
| `/uploads/invoice-1001.pdf` | private | private (50) | public | right |
| `/` | public | public (8) | public | right |
| `/api/admin/help` | public | private (72) | private | **miss** |
| `/openapi.json` | public | public (10) | public | right |

6 right, 2 missed. Where Jev and the prior disagree on a true lead, Jev is right three times
(`/internal/users/export`, `/api/users/me`, the invoice) and the prior never is.

#### Hook B: disguised login wall

5 decisions, 80% agree with the deterministic prefilter, 0 fallbacks.

| Page | Truth | Jev (confidence) | Prefilter | Result |
| --- | --- | --- | --- | --- |
| `/internal/portal` | login wall | login_only (90) | app | right |
| `/admin/dashboard` | not a wall | app (74) | app | right |
| `/admin/reports` | not a wall | app (74) | app | right |
| `/api/admin/help` | not a wall | app (94) | app | right |
| `/xss-snippet` | not a wall | app (79) | app | right |

5 right, 0 missed: the one disagreement with the prefilter is the wall the prefilter cannot see.

#### Hook C: lead assessment

20 decisions, 80% agree with the route class, 0 fallbacks.

| Lead | Expected kind | Jev kind (confidence) | Sensitivity | Route class | Result |
| --- | --- | --- | --- | --- | --- |
| `/internal/users/export` (anonymous_access) | data_export | data_export (100) | 94 | data_export | right |
| `/internal/users/export` (sensitive_data) | data_export | data_export (99) | 94 | data_export | right |
| `/api/v2/reports/export` | data_export | data_export (100) | 51 | data_export | right |
| `/api/v1/orders/42` | old_version | internal_api (30) | 62 | old_version | **miss** (kind) |
| `/api/admin/export` | data_export | data_export (95) | 76 | admin_function | right |
| `/api/users/me` (sensitive_data) | internal_api | internal_api (68) | 41 | internal_api | **miss** (sensitivity < 50) |
| `/uploads/invoice-1001.pdf` | uploaded_content | uploaded_content (98) | 59 | uploaded_content | right |

5 right, 2 missed. On `/api/v1/orders/42` Jev reads an internal API (at a low 30) although the
item says `generated_by: version`; it rates `/api/users/me`'s personal data, which only the
logged-in answer holds, just below the sensitivity bar. Both are shadow-mode measurements: nothing acted on them.

### S18c: nothing but the contract crosses to Jev

- The request items are the closed fields of the request models, which refuse any other field
  (`extra="forbid"`): a `route_class`, a signature, a header, a cookie or a body value would be a
  422 and a fallback, and v3-A recorded 0 fallbacks. `key_paths` are masked key names
  (`signals.py`), paths clipped to 200 characters (`test_jev_item_contract.py`).
- The agent logs each call as `jev <hook>: user=… project=… questions=N model=jev-1.13.0
  latency=…ms ok`: counts only. A search of two hours of agent logs for the token's shape
  (`apikey_`) found nothing; the leak scan's fake values never reach a Jev item (key names only).

### S18d: caps and the shared bucket

428 routes requested, 400 asked (the cap) as 224 distinct items in one request; 5 wall pages in
one page-type request (well under 100); 20 leads in batches of 4 (8+8+8+8+4 questions, under
200). No 429 from `/jev/*`, no fallback, the assessment took about 6 s of its 60 s budget.

## 3. UI (§22.3 v3, S18g)

`testing/e2e/tests/routeExposureJev.spec.ts`, against the rebuilt webapp image:
- each of the three fields has a row on the Route Exposure card and a card in the AI in Pipeline
  panel, bound to one field: on from the module row shows on the panel before saving, the PUT
  carries it, it is stored, it shows after reload, off from the panel shows on the module row and
  is stored (PASS);
- with AI in Pipeline off the panel hides its cards (as for every hook), the module rows are
  disabled with the hint, the master switch never moves the stored values, and they return as
  they were when it is turned back on (PASS);
- a preset apply keeps them: `KEPT_WHEN_ABSENT` (`project-preset-utils.test.ts`);
- the "No Jev token" badge is a component test (`RouteExposureSection.test.tsx`, mocked
  `jevStatus`).

## 4. Pass history (§22.7 pass rule)

| Run | Last passed on | Why later commits do not touch it |
| --- | --- | --- |
| v3-A | recon at `c2fd1a61`, agent `634a973b`, the v3 lab | no recon or agent commit after it |
| v3-P1, v3-P2, v3-P3 | same | same |

The lab changed twice during v3 (the `/internal/portal` row and the hostile host's
one-request-per-connection rule), each time before the run that checks it.

## 5. Deviations from the plan (agreed with the human, 2026-10-30)

1. **Reduced campaign** (§22.7): v3-A and three partial runs replace S18–S20.
2. **The disguised wall is `/internal/portal`, not `/portal`.** A route with no auth hint never
   becomes a lead, so a bare `/portal` would never reach hook B; the `internal` path word makes it
   one, and nothing in its path or title says "login".
3. **S19 (owner without a token) is unit-tested, not run live**: `validateJevEngineChange` refuses
   a switch-on for each Jev field (`jevEngine.test.ts`), and the badge is a component test. The
   only live owner holds a token.
4. **S18e made the token unusable in Postgres, not through the UI.** The original key was copied to
   a scratch table to restore after the run; a host reboot interrupted the restore, and the
   webapp's startup `prisma db push --accept-data-loss` dropped the scratch table, so the owner's
   Jev key is now an invalid placeholder and has to be re-entered in Settings → LLM Providers.
   Lesson: never keep a credential backup in a table the schema sync owns.
5. **Partial runs' shadow records were read from the container output**, since a partial run does
   not write the recon JSON.

## 6. Open issues

- Hook A's 50% agreement and hook C's two misses are expected of a shadow rollout; flipping any
  hook to ACT is a separate change (plan §13) and should start with hook B, which was right on
  every item.
- `js_recon` verifies TLS, so a self-signed internal HTTPS target's bundles are never read (the
  hostile host). Correct for real targets; a per-project "skip TLS verification" setting would be
  the way to reach a lab-grade internal host.
