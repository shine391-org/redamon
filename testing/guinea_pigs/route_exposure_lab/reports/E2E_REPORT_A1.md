# Route exposure agent half: end-to-end report, A1

- **Branch** `feature/route-exposure`. **Final agent image** built from committed HEAD `ee3542ab`
  (via `git archive HEAD | docker build`, so other sessions' uncommitted agent edits are excluded).
- **Date** 2026-10-30. The `redamon-agent` image is baked, not mounted, so it was rebuilt after each
  agent-code fix; `webapp` unchanged on this half; `recon`/`graph_db` bind-mounted at spawn.
- **Model** the agent ran live on `deepseek/deepseek-v4-pro` (the lab project's `agentOpenaiModel`).
- **Lab** the four §14 services on `redamon_pentest-net` (`172.28.0.93` main, `.94` twin, `.95`
  hostile, `.96` outsider), with the §14.6 agent rows (fake `/console`, `/console-open`,
  `/_ignition/*`, `/actuator/heapdump`, a fake `.git`, the `.env` GitHub token). All secret values
  are generated at container start (`/tmp/lab-secrets.json`), never committed.
- **Verdict** the A1 campaign is **green**. Every AG scenario passed against the live lab, scripted by
  `validate_route_exposure.py agent-verify`, with a clean leak scan on every one. The campaign ran as
  the **reduced set agreed with the human on 2026-10-30** (plan §23.13.5, §22.7 pass rule): the
  scenarios whose code the last fix touched were re-run on the final image `ee3542ab`; the rest are
  carried over from image `ad929619`, whose only difference from `ee3542ab` is the path_traversal
  `exposed_files` text that those scenarios do not load. See §4 for the per-scenario reason.

The campaign found six defects in the agent half. Each was fixed with a test in the same commit, the
golden skill-workflow fixture re-recorded, and the affected scenarios re-run (§3).

## 1. Gate

Run on an export of committed HEAD `ee3542ab` (`GATE_REPO=~/.cache/redamon-gate-a1`, the handoff's
`gate_sections_at.sh`), because the shared working tree carries another session's uncommitted recon
edits. `test all` (unit + integration), then `test live` with the stack up, then `test coverage`.

**Unit tier** (the A1 gate requirement):

| Section | Unit result |
| --- | --- |
| `agent` | 243 files passed, 0 failed |
| `root-agent` | 173 files passed; 1 "fail" = `test_docs_not_stale` only (empty wiki submodule in the export) |
| `root-recon` | 12 files passed, 0 failed |
| `recon` | 279 files passed; 1 "fail" = `test_ai_lab_fixture` only (its lab-compose file is absent from the export) |
| `recon_orchestrator` | 47 files passed, 0 failed |
| `ai_attack_surface` / `capture_proxy` / `docker_broker` / `plugin_runner` | 11 / 7 / 7 / 19 files passed, 0 failed |

The unit tier is green. The two failures — `test_docs_not_stale` (empty wiki submodule) and
`test_ai_lab_fixture` (a missing AI-lab compose file) — are both artifacts of running on a
`git archive` export, which omits the wiki submodule and some fixture files; both pass on the real
working tree, and neither is in route-exposure code.

**Integration tier** (`test all` adds it): the same export/environment failures, none in code this
half touched — the community-skill **wiki-table** tests (`idor_bola`, `insecure_deserialization`,
`insecure_file_uploads`) and `docs_not_stale` fail on the empty wiki submodule, and the `*_integration`
suites that need a live stack/fixtures (`cve_intel`, `ai_js_sdk`, `ai_lab_fixture`, `orchestrator`,
`scan_envelope` concurrency) fail or flake in a hermetic export run. A1 touched none of these areas
(its changes are the rce/path_traversal prompt parts, `body_sweep`, the skill golden and the lab
validator), so they are independent of this half.

| Other gate | Result |
| --- | --- |
| `./agentic/run_tests.sh` (unit, after every fix) | green at each fix |
| webapp vitest / type-check / lint | unchanged from the v1 report (no webapp change on the A1 half) |
| `test live` | not re-run as a separate tier; the live agent campaign (§4) is A1's live gate, and the `*_integration` suites above are the only live-dependent tests, all unrelated to this half |

## 2. Coverage of the new / changed files

Target ≥ 90% line coverage per new agent file, and every new function in the three prompt modules.

| File | Coverage | Note |
| --- | --- | --- |
| `agentic/prompts/route_exposure_shared.py` | **100%** | `RECORD_CONTRACT`, `SAFETY_RULES`, `VALUES_IN_FILES`, `candidate_query`, `escape` |
| `agentic/orchestrator_helpers/body_sweep.py` | **96%** (1 line: an exception branch) | run-end sandbox body sweep, `test_body_sweep.py` |
| `agentic/prompts/access_control_prompts.py` route-exposure parts | static strings, fully rendered | `route_exposure_leads` (+ `route_exposure_browser_leads` is A2) |
| `agentic/prompts/path_traversal_prompts.py` route-exposure parts | static strings, fully rendered | `exposed_files`, `git_reconstruct`, `validate_secrets` |
| `agentic/prompts/rce_prompts.py` route-exposure parts | static strings, fully rendered | `route_exposure_consoles`, `heapdump_analysis` |

Both logic files clear the ≥ 90% target. The prompt parts are static string constants assembled by
`route_exposure_shared`; every one is rendered and asserted word-by-word by
`test_route_exposure_agent_parts.py` (assembly, ordering, gating, the wording each fix added) and
pinned by the golden skill-workflow fixture.

## 3. Defects found and fixed

Each was reproduced in a unit test, fixed, and the scenario re-run on the rebuilt image.

| # | Commit | Scenario | Defect | Fix |
| --- | --- | --- | --- | --- |
| 1 | `75147b13` | AG8b | The console-state detector counted `__debugger__` (present on every Werkzeug page, locked or not) as a PIN prompt, so an unlocked console was reported locked and never evaluated. Also: `body_sweep.py` had failed `test_roe_gate` since the A1 run-end-cleanup commit `139e2055`. | The rce consoles part reads the lock from `EVALEX_TRUSTED` alone; `body_sweep.py` is listed among the executor calls the RoE does not judge (it deletes only the session's own sandbox files). |
| 2 | `ec097593` | AG8b | The evaluation was sent as `cmd=print(1+1)`; the lab answers 400, and the agent retried the request shape two more times. | The part gives the exact query `cmd=1%2B1` with the page's `frm`/`SECRET`, says the expression is never wrapped, and that any answer without `2` (a 400 included) ends the proof. |
| 3 | `ad929619` | AG8b | The one evaluation was sent without `s=<SECRET>`: the script looked for `SECRET` in form inputs, found none, and sent without it (400). | The part says `SECRET` is the page's `SECRET = "..."` script variable (beside `EVALEX`, not a form field), `frm` is `0` on the standalone console, and nothing is sent when `SECRET` is missing. |
| 4 | `ee3542ab` | AG6 | With git reconstruct on and RoE exfiltration allowed, the agent recorded the minimal `.git` proof + secret validation and completed **without** reconstructing: the always-present `exposed_files` block only said what DISABLED means, so the model read the reconstruct step as optional. | The block states that, when git reconstruction is ENABLED, proving an exposed `.git` includes reconstructing it this run: request the exploitation phase after the minimal proof, and do not complete while it is pending. |

Two further harness-only issues were found and fixed in the lab validator (not agent bugs): AG11's
`may_confirm` was too narrow (the leads part legitimately confirms a true lead on the way to the
render — `f14786dc`), and AG12's denied-URL check matched on a URL prefix rather than exact URL
(`47a9603a`).

## 4. Scenarios (reduced campaign, §23.13.5)

Every row: the validator reported every expected observation, nothing unexpected, and a clean leak
scan. Sessions on the final image `ee3542ab` were run in this campaign; the rest carry over from
`ad929619` with the reason given.

| # | Image · session | Result | What it proved |
| --- | --- | --- | --- |
| AG1 | `ee3542ab` · `session_b94b1ad9c98d2a3b9cfa568fe5f5e87c` | PASS | Six true leads confirmed (`/internal/users/export`, `/api/v2/reports/export`, `/api/v1/orders/42`, `/api/admin/export`, `/api/users/me`, `/uploads/invoice-1001.pdf`) at confidence ≥ 80 → T1; the false lead `/api/admin/help` rejected, stays T4; 28 main requests, GET/HEAD/OPTIONS only; 0 on state-changing paths and the outsider; leak clean |
| AG4 | `ee3542ab` · `session_13e3779a60fc98aeace929e6501f777a` | PASS | Later session, AG1's prompt: leads already confirmed → `switch_skill` to rce; consoles confirmed without evaluating; 5 main GET |
| AG2 | `ee3542ab` · `session_f50cc789a2fc1ad029b53e7644f7e02c` | PASS | Module **off**: no route-exposure part; 0 CONFIRMS from the session; behaves as ordinary access control |
| AG6 | `ee3542ab` · `session_b40d10e607daf4827122508a6c39654d` | PASS | git reconstruct + validate on, RoE exfiltration allowed, exploitation approved: after the minimal proofs it requested the phase; reconstruction job 11 `/.git/objects/` hits, betterleaks counts, `rmtree` + listing proof; the `.env` GitHub token validated **invalid** via `api.github.com`; leak clean (proves fix #4 live) |
| AG7 | `ee3542ab` · `session_81e3a5d1bf6aae7d0813f4a9e4f44375` | PASS | Switches on but RoE exfiltration **off**: reconstruct part absent; `.git` exactly 4 requests (HEAD, config, ref, one object); validation still runs; leak clean |
| AG14 | `ee3542ab` · checks only (triage run 2026-10-30T07:32Z) | PASS | After AG1/AG6-7/AG4: the six confirmed leads are T1 **reportable** on the board, "confirmed" in the Red Zone (7 confirmed / 1 pending), and counted by the report predicate (Insights); `/api/admin/help` stays T4 candidate info and uncounted; `triage_eval.py` NDCG@25 0.99 with the confirmed leads at T1 |
| AG3 | `ad929619` · `session_ae967a1a08a4846fb795d7a915713a6b` | PASS (carried) | access_control **off**: routed to rce, no lead confirmed. Routes to rce, which does not load the path_traversal text changed in `ee3542ab`. (The `ee3542ab` clean-pass run hit an LLM 402 billing wall, not a scenario failure; see §6.) |
| AG5 | `ad929619` · `session_f8bbfad268361e14279490b376ca95e7` | PASS (carried) | path_traversal, switches off: all four files + `.git` confirmed, `.git` exactly 4 requests, backup HEAD+Range only. Its switches-off path ran under the new text in AG1's path_traversal handoff on `ee3542ab`, and AG7 re-checks the four-request walk. |
| AG8 | `ad929619` · `session_5c904fba77bf0ccd02b54bba4a42ecc3` | PASS (carried) | rce, heapdump off: consoles confirmed by detection, no evaluation, 0 PIN/POST/heapdump-GET. rce workflow does not load the changed text. |
| AG8b | `ad929619` · `session_8e3f3b06e8693b48e6b2d13faa2bf75b` | PASS (carried) | The unlocked console proved: exactly one `cmd=1%2B1` evaluation → `2`, recorded as `exploit_success` (no ids) + `vulnerability_confirmed`; no PIN request (proves fixes #1-3). rce workflow. |
| AG10 | `ad929619` · `session_a9b99855e4400ebdc4b2edb33faf7ff8` | PASS (carried) | Header profile, replay: the `proxy_brain` replay with `anonymous=True` reached the lab credential-stripped; captures stored with 0 credential values in clear. access_control. |
| AG11 | `ad929619` · `session_73d8a22d1b3f862f24c0817a0d54a45c` | PASS (carried) | Logged-in `redamon.browser` render of `/profile`; the outsider's `/widget.js` loaded with no credential header; the UI-vs-API diff named `password_hash`/`reset_token` as key names. access_control. |
| AG12 | `ad929619` · `session_29b86eb9089c60a4e0856f551b6a0ff3` | PASS (carried) | `REQUIRE_TOOL_CONFIRMATION` on: every gated tool ran only after approval; a denied `execute_curl` pair never ran and was never re-requested. The confirmation gate is independent of the path_traversal text. |
| AG13 ×6 | `ad929619` · `391c1657` / `643726419` / `da8ab9c9` / `ad7f7570` / `87796c1f` / `156dcf95` | PASS (carried) | Routing: on → access_control / path_traversal / rce; off → never that skill. Decided at the first turn, no graph writes. |
| AG15 | `ad929619` · `session_8857a7e083b83ff4cbec2013a9e5adfd` (project `cmvu2ow170422lf01kcvunqzm`) | PASS (carried) | A project that never had the module: ordinary access-control session, no CONFIRMS edge, no route-exposure text in the transcript. |

AG9 (heapdump GET) is deferred to A2 with v2's framework seeds, per the plan.

## 5. Leak scan

`agent-leaks` ran on every scenario's transcript and was **clean** on all of them: no
`userN@lab.invalid`, no `LAB-NOT-A-SECRET-*`, `lab-token`, `lab-key`, `sid=lab-user-1`, the fake
GitHub token, the heap-dump credentials, or the `.git` blob secret. Evidence is key names, counts,
statuses, header names and 8-char hash prefixes only. Values stayed in kali `/tmp` files, deleted in
the script that read them; `0 rex-*` files were left after every session (the run-end sweep,
`body_sweep.py`, is the backstop).

Noted, as the plan says to: betterleaks does **not** flag the lab's planted `SECRET_KEY = '<value>'`
line (its shape matches no betterleaks rule); the lab still counts it in its own fixtures.

## 6. Pass history and the LLM billing wall

Three passes converged: an exploratory pass on `ad929619` surfaced the AG6 reconstruction gap (the
only agent fix needed there); the fix shipped as `ee3542ab`; the clean pass on `ee3542ab` ran AG1,
AG4, AG2, then **AG3 hit an LLM 402 (Payment Required)** — the `deepseek/deepseek-v4-pro` account ran
out of credit mid-pass. After credit was restored, AG6, AG7 and the AG14 check completed on
`ee3542ab`. AG3 and the other carried scenarios had already passed on `ad929619`; the reduced-campaign
pass rule (§22.7) carries them because `ee3542ab`'s only delta is the path_traversal text they do not
load.

## 7. Deviations from the plan (agreed with the human, 2026-10-30)

1. **Reduced campaign (§23.13.5, §22.7).** A1 ran 2 live sessions + the AG14 check on the final image
   instead of a full consecutive AG1→AG15 pass; the rest are carried from `ad929619` with per-scenario
   reasons (§4). This trades a full repeat pass for the unit gate after every fix.
2. **RoE exfiltration set on the project columns directly.** `roeAllowDataExfiltration` and
   `roeSensitiveDataHandling` are `mcp: never` and are normally set by the RoE document-upload UI,
   which needs an LLM parse model that is not configured on the account (same gap as report
   narratives). AG6/AG9 set the two columns directly (the only effect the agent reads), reproducing
   `roe_lab_ag6.md`. The RoE-upload flow has its own tests.
3. **Report generation via the Insights predicate.** Generating a report needs a "Report narratives"
   model on the account, which is not set. AG14 checked the report's inclusion rule through
   `/api/analytics/vulnerabilities` (which runs the report's own `notMuted ∧ reportCountable ∧
   agentCandidateConfirmedOrNA` predicate) instead, as the v1 report did.

## 8. Open issues (pre-existing, not fixed on this branch)

- The Insights findings list (`/api/analytics/vulnerabilities` Q3) returns one row per parent, so a
  lead attached to both an Endpoint and a BaseURL is counted twice in the per-row charts.
  `serialized_scan` has the same shape; it is pre-existing and not introduced by this half. The
  deduplicated counts (`vulnTypes`) and the report predicate itself are unaffected.
