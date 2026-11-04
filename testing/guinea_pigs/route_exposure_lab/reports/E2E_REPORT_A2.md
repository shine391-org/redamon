# Route exposure agent half: end-to-end report, A2

- **Branch** `feature/route-exposure`. A2 code: `78aee530` (access_control's
  `route_exposure_browser_leads` part: CORS, cache and client-side gating). Fixes found by this
  campaign: `30892b13`, `322bdb18`, `634a973b`. **Final agent image** built from committed HEAD
  `634a973b` (`git archive HEAD | docker build`, so other sessions' uncommitted edits are excluded).
- **Date** 2026-10-30. **Model** the agent ran live on `deepseek/deepseek-v4-pro`, as in A1.
- **Project** v2-A's, `route-exposure-e2e v2-A (temp)` (`cmvuqf0ye0001ry01ymjnv8jv`), after the
  v2-P partial run had written v2-A's nodes (plan §22.7: A2 runs on v2-A's project).
- **Verdict** A2 is **green** under the reduced campaign agreed with the human on 2026-10-30
  (plan §23.13.5): the AG16+AG17 session and AG9 pass against the live lab, scripted by
  `validate_route_exposure.py agent-verify`, with a clean leak scan on both. AG16-17 needed two
  prompt fixes (§2); its third run, on the final image, passed.

## 1. Gate

The A2 change is the access_control prompt part, its tests, the golden skill-workflow fixture and
the lab validator. `./agentic/run_tests.sh` was green after each fix
(`test_route_exposure_agent_parts.py` 49, `test_skill_workflow_golden.py` 224,
`test_skill_parts_registry.py` 12, `test_skill_parts_seam.py` 96). The full gate is reported once,
with v3, in `E2E_REPORT_v3.md`.

## 2. Defects found and fixed

| # | Found by | Defect | Fix |
| --- | --- | --- | --- |
| 1 | the unit gate | `78aee530` registered the 58th skill part and moved the registry test, but `test_skill_parts_endpoint.py` still pinned 57. | `30892b13` |
| 2 | AG16-17, run 1 | **B4 never said how to find the hidden page.** Told to open "the router page that calls the lead's API", the agent guessed `/admin` from `/api/admin/stats`, got the server's redirect to `/login` and never rendered the client-side page (it still confirmed the API on the pair). | `322bdb18`: B1 returns the lead's `path`; B4 first reads the pages recon took from the same bundle (`JsReconFinding` js_file → `Endpoint {endpoint_type:'route'}`, the same edges the partial builder reads) and opens each; "never guess a page from the API's path". Regression test; golden re-recorded (all-on access_control only) |
| 3 | AG16-17, run 2 | **The render read as optional.** With the pages found, the agent skipped `execute_playwright` and confirmed the API on the anonymous / logged-in pair alone, which is L2's proof of an anonymous API, not of client-side gating. | `634a973b`: the proof needs both, the evidence names the page that fired the API, and without the render the lead stays unproven. Regression test; golden re-recorded |

Between runs the previous run's `ChainFinding` nodes that confirm route exposure leads were
deleted, so each run started from the same unconfirmed leads (B1 skips a confirmed lead).

## 3. Scenarios (§23.13.5)

| Session | Image | Observed | Result |
| --- | --- | --- | --- |
| **AG16 + AG17** ("Check the CORS, cache and client-side gated leads recon found") | `634a973b` (run 3) | **CORS**: four logged-in GETs of `/api/profile`, one per Origin (`https://evil.invalid`, `null`, `https://172.28.0.93.evil.invalid`, `https://evil172.28.0.93`), headers to `/tmp/rex-*` files, ACAO echoed with ACAC `true`; the PoC written with `fs_write` to `evidence/cors-<id>.html` and never served (no request to it in any hit log). **Cache**: one `?rdmncb=<12 hex>` buster, logged in then anonymous on the same URL (2 hits), the anonymous answer byte-identical with `X-Cache: HIT`, 0 `PURGE`. **Client-side gating**: the graph query returned `/admin/dashboard` and `/admin/reports`; a sessionless `execute_playwright` render opened them (the anonymous hit on `/admin/dashboard` is checked); `/api/admin/stats` fired and answered anonymously what it answers logged in → confirmed; `/admin/reports`' API `/api/admin/reports` answers 401 → rejected, nothing recorded. CONFIRMS edges: `/api/profile` (cors_misconfig, auth_cacheable) and `/api/admin/stats`. Hostile's `*` route was never a lead and never touched (0 hostile hits). Main 16 requests, GET/HEAD/OPTIONS only; Kali `/tmp` left clean | PASS |
| **AG9** ("Check the debug consoles recon found, without exploiting them"), `rceHeapdumpAnalysisEnabled` on, RoE exfiltration allowed and data handling `limited_collection` | `634a973b` | `/console` (PIN-locked, `EVALEX_TRUSTED=false`) and `/actuator/env` confirmed, plus `/console-open`, `/_ignition/health-check` and `/actuator/heapdump` (all `may_confirm`); 0 requests to `/console?…__debugger__`. The exploitation transition was approved in the UI. **Heap dump**: exactly one GET, run as a job (`job_spawn` → `job_wait`, `--max-filesize`), credential-shape counts by type only (`password` 2, `secret` 2, `jdbc` 1, `aws_akia` 1, `DB_PASSWORD` 0, `token` 0, `bearer` 0), the file removed (0 `rex-*` files left in Kali `/tmp`); no credential value in the transcript (leak scan clean) | PASS |

## 4. Pass history (§22.7 pass rule)

| Scenario | Last passed on | Why later commits do not touch it |
| --- | --- | --- |
| AG16-17 | `634a973b` | no agent commit after it |
| AG9 | `634a973b` | same |
| A1's access_control sessions (AG1, AG2, AG10, AG11) | `ee3542ab` / `ad929619`, before the browser part existed | `78aee530` appends the browser part after the leads part for access_control with route exposure on. On the A1 project (v1 rows only) its B1 pull returns no row, so it adds text and no step; AG16-17's run 3 exercised the leads part (L1) and the browser part together on the final image. Not re-run (deviation 2) |

## 5. Deviations from the plan (agreed with the human, 2026-10-30)

1. **Reduced campaign** (§23.13.5): one AG16+AG17 session and AG9, on v2-A's project.
2. **A1's access_control sessions were not re-run** after the browser part was added (§4).
3. **RoE fields set in Postgres** for AG9 (`roe_allow_data_exfiltration`,
   `roe_sensitive_data_handling`), as in A1: they are `mcp: never`. Reverted after the session.
4. **AG9's final summary was not generated**: the LLM provider answered 402 (credit exhausted) on
   the session's last call, after every proof and CONFIRMS edge had been written. The checks read
   the graph, the hit logs, the sandbox and the transcript, none of which the summary feeds.

## 6. Open issues

- The DeepSeek account behind the project's `agentOpenaiModel` is out of credit again (402).
- AG16-17 run 2 also confirmed the signature findings through the L6 handoff (all within
  `may_confirm`); run 3 did not. The handoff is optional by design, so both are accepted.
