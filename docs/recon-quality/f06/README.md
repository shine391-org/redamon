# F06 — Arjun contract repair (local candidate)

## Provenance / scope

- Private baseline: `104f66cc5943a2eb5265edf190f39c4184b5e1ee`.
- Implementation parent: `ca2b8cce629c0504fc4b58803496d8d6b30ccb3a`, an existing P0 cherry-pick whose tree is identical to accepted `adc34b10d49b37daf8fa56f7043dd9291b809be3` (`git diff adc34b10 ca2b8cce` empty).
- Branch: `fix/recon-quality-f06-arjun-contract`.
- Worktree: `/data/redamon/workspace/worktrees/recon-quality/f06`.
- No sibling implementation imported. No live checkout edits, pushes, PRs, deployment, stack restart, project-setting/DB writes or target scans.

## Repairs

1. Validate both executable input and output authorities with `urlsplit().hostname/.port` and the existing canonical `_normalize_scope_host` helper. Exact allowlist only: IPv6/IPv4/case-normalized hostnames work; userinfo, malformed ports/authority, control characters, backslashes, non-HTTP schemes and foreign/suffix-lookalike hosts do not reach the input file. Empty scope does not authorize all hosts. Actual merger callers also pass an exact scope; its optional argument preserves legacy two-argument consumers.
2. Preserve each method's return code, timeout, parse state and selected-input execution status, including nonzero exits with positive findings. Recover only complete URL/value JSON records after truncation; never close an unfinished parameter string and invent evidence. Carry parsed results/evidence past the existing temp cleanup for the caller to persist; full raw-output retention is deferred to F08. A complete JSON file from a killed process still has partial execution status.
3. Both callers resolve missing keys through `arjun_contract.arjun_settings`, and share the existing API/dynamic priority and cap selection. Save the unexecuted URL remainder, without enabling a new budget/sampler or changing a saved limit. Full artifact and partial graph payload carry `scan_metadata.arjun_execution`; incomplete execution records a canonical resource-enum coverage gap.
4. Trust the invoked mode, not output-supplied method text. JSON/XML are POST body formats, not HTTP methods named JSON/XML. Keep query/body/path buckets, raw URL evidence and per-parameter `arjun_methods/arjun_modes`. New Arjun-only params are linked/counted for their actual method; POST body evidence is not counted on GET. Graph schema declarations and generated catalog describe these additive fields.
5. Recompute endpoint and base/global summaries from actual parameter bucket members, including all late-producer merges, instead of stale counters/map-key counts. Missing legacy summaries are accepted and reconciled.

## Default/fallback finding

`project_settings.DEFAULT_SETTINGS` and `fetch_project_settings` already resolve `ARJUN_MAX_ENDPOINTS=50000` and methods GET+POST; `partial_settings` uses the same already-loaded dictionary. The real loader is exercised offline with a mocked API response, followed by real partial-settings resolution. The literal fallback 50 is **not** demonstrated as a live saved-cap bug. Registry/Prisma/project defaults and existing settings are unchanged.

Only missing-key fallback resolution is centralized: cap **50**, methods **GET**, matching the conservative full caller. The previous partial-only GET+POST fallback is not allowed to increase workload for a sparse dictionary. Explicit saved values always win. Enabled/disabled state, auth/identity/proxy flags and RoE rates remain under existing controls.

## Executed verification

Pinned local recon image (no pull):
`sha256:6990dc80a76d739d02c0a1a79c3cde50bee27ce39f129d48d1f3e58e1ebd5ae1`.

Runner: accepted `docs/recon-quality/p0/run.py`, one file/process/container, source read-only, network none, no Docker socket, scratch TMPDIR. Native lifecycle tests launch a generated local fake Arjun that only writes JSON and self-kills/sleeps; they do not probe HTTP.

| Gate | Tests | Passed | Skipped | Xfail | Failed / errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| Final union, 40 unique files | 1147 | 1101 | 41 | 5 | 0 / 0 |
| Accepted P0 selection within that union, 28 files | 837 | 826 | 6 | 5 | 0 / 0 |
| Existing `test_arjun.py` | 30 | 30 | 0 | 0 | 0 / 0 |
| New F06 contract file | 27 | 27 | 0 | 0 | 0 / 0 |
| Pristine-base new contract control | 27 | 1 | 0 | 0 | 26 / 0 |

Rows overlap; do not add them. Subtests are not counted as separate tests.
The 41 skips and 5 xfails are retained outside the Arjun acceptance files; see JUnit/logs for exact reasons. Eight stale Arjun skips and two stale xfails were removed only after replacing obsolete `subprocess.run` doubles with current Popen doubles and executing the original assertions. No acceptance test was deleted or newly skipped/xfail-marked.

Final union = all 28 accepted P0 files plus the F06 contract, tool-health, partial multi-root, resource graph/OpenAPI, graph scope/labels/org, refactor/Tor and schema-documentation/mixin-split gates. It is a selected-file gate, **not the entire repository unit suite**.

Pristine control is a fresh `git archive 104f66cc...` with only the new contract test copied in. Original base `test_arjun.py` remains 20 pass / 8 skip / 2 xfail; original tool-health file is 70 pass. The new control's 26 failures include **two characterization/API additions** (optional scoped merger argument, new fallback-resolver import); these are not counted as independent reproductions of old defects. Other failures show IPv6/case host loss, unsafe generated input, fabricated truncated parameter/method evidence, missing partial execution status, stale/missing summary counters, wrong GET/POST graph counts and corrupted partial IPv6 graph-link host. IPv4 is the passing control.

The actual caller test compares generated inputs/argv for equal explicit settings, ingests killed-process params through the real merge, serializes/reloads the full artifact, invokes the real ResourceMixin against a recording graph driver, and exercises `main._write_coverage_record` plus the existing finding-prune boundary against a recording graph. Arjun produces Endpoint/Parameter assets, which finding prune does not delete; no new finding-prune policy is introduced.

`seed_schema_catalog.py --check` reports up-to-date, byte-identical schema round-trip; schema documentation gates pass. `git diff --check` passes.

## Evidence and bounded limitations

The attached `f06-evidence.tar.gz` contains the report, patch, source/test hashes, exact final runner commands, JUnit/logs and pristine negative controls. Intermediate failed run logs are retained separately in the task workspace, not passed off as final results.

- No production Neo4j/Cypher execution, real Arjun HTTP scan, identity-on-the-wire, Traffic Mind E2E or performance/coverage-recall benchmark is claimed. Graph verification records the actual writer's queries/parameters; independent G1 review remains mandatory.
- `status=complete` describes a successful process on **selected inputs**, not exhaustive host/path/method coverage. Arjun's output does not attest every individual request. Timeout, malformed output, omitted inputs and nonzero exit remain partial/unknown as appropriate.
- Legacy other-source parameters lack method-specific execution provenance. Their old discovery applicability is retained, not falsely narrowed or upgraded to Arjun-tested POST; `arjun_methods/modes` and artifact evidence are the independent Arjun evidence axis. Existing graph relations are discovery, not proof of execution.
- Raw origin/query/slash variants are not coalesced under unproved equivalence. Detailed raw URL/mode/result evidence and unexecuted inputs stay in the artifact/payload; the graph projects safe method/mode lists and existing canonical coverage gaps, not raw request bodies or credentials.
- The optional legacy two-argument merger performs syntax validation but cannot infer an allowlist. Production full/partial callers always pass one; direct external callers should supply it.
- Existing graph path normalization, older graph readers' request reconstruction and late-source sequencing remain separate F02/F08/F12 integration concerns. This patch does not claim a new typed inventory or durable resume engine.

## Rollback / integration

This is a correctness/safety repair, not planner optimization. Planner off/shadow must not remove it or erase partial/unexecuted evidence. Legacy keys/readers remain usable; new metadata is additive. If a reader cannot understand it, treat coverage as unknown, not clean.

Rollback is an explicit local revert of the F06 implementation commit only, after review; no DB migration/data deletion is required. Do not silently restore the unsafe scope parser or fabricated JSON recovery as an optimization rollback.

Hotspots for G1: `recon/main_recon_modules/resource_enum.py` and `graph_db/mixins/recon/resource_mixin.py`. Integrate the localized settings/metadata/summary and parameter-method hunks with sibling F01/F02/F05/F07 changes; rerun final caller and graph/coverage gates. G1 is the pre-created independent review child, so implementation completion releases it rather than requesting a duplicate same-card review.
