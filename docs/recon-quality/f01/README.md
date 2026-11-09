# F01 — HTTP admission and consumer seed contracts

## Candidate and dependencies

- Worktree: `/data/redamon/workspace/worktrees/recon-quality/f01`
- Branch: `fix/recon-quality-f01-http-admission`
- Pinned private base: `104f66cc5943a2eb5265edf190f39c4184b5e1ee`
- Accepted P0: `adc34b10d49b37daf8fa56f7043dd9291b809be3`
- Integrated P0 parent: `70d93f6c05a02987a110233f4d9364e56fcba502` (already present on retry; `git diff 70d93f6c adc34b10` is empty). No reset or live-tree checkout.
- Only local implementation; G1 is the pre-created independent review gate. No publication, deployment, settings/DB changes, stack restart or target scan.

## Changes / contract

1. Pure `http_url_rejection` rejects non-HTTP(S), absent host, malformed brackets/authority/port, userinfo, backslash ambiguities and raw controls/whitespace before urllib normalization. Accepted strings remain unchanged, including IPv4/IPv6, port, path case and percent-encoding. IDNs and underscore-host compatibility are retained without using the DNS-injection hostname policy as HTTP admission.
2. Shared builders validate resource bases and composed endpoints, httpx/supplied inputs, hostname/IP fallbacks and final union. URI-like or network-path endpoint keys are not interpreted as relative HTTP paths. Rejections have source + reason aggregates; raw producer data is not deleted. No observed-input cap, path-only filter or global status rejection was added. The existing declared-only GET/HEAD policy and 500 cap remain; malformed generated declarations do not consume eligible slots.
3. DAST independently validates `resource_enum.discovered_urls` before testing the parsed query. A fragment containing `?q=1` is not a query. DAST dispositions persist under `vuln_scan.scan_metadata.http_admission.resource_enum_dast`.
4. FFuf inserts `/FUZZ` in the parsed path, retaining app prefix, matrix parameters, escaped path bytes and query context, dropping only client-side fragment. Example: `/api?q=1` becomes `/api/FUZZ?q=1`, not `/api?q=1/FUZZ`. Only identical generated tasks deduplicate; different query contexts remain distinct. No global mutation of crawler/DAST/cache seeds.
5. Named partial crawling, parameter-discovery, vulnerability/security-check and cache adapters represent explicit seeds as `provenance: supplied`, `status_code: null`, unknown content type. Existing measured evidence is not overwritten. Supplied provenance admits an unmeasured seed, not a later measured 503. Canonical partial scope filtering validates raw URI before normalization and retains the original scope decision.
6. Rejection logs in changed partial handlers emit reason codes, not raw credential-bearing URL strings. Existing auth/RoE/SSRF/identity/proxy/circuit-breaker and redirect settings are not changed.

## Executed verification

All selected repository files run in separate processes/containers using pinned local image:

`sha256:6990dc80a76d739d02c0a1a79c3cde50bee27ce39f129d48d1f3e58e1ebd5ae1`

Source read-only, network none, no Docker socket, caps dropped, no-new-privileges, scratch TMPDIR. P0 runner commands, JUnit and logs are in the attached evidence archive.

- Final selected gate: **36 files, 1414 test cases: 1393 passed, 14 skipped, 7 xfailed, 0 failed/errors.** Not a complete repository gate. Subtests are not promoted to additional cases.
- New executable HTTP admission/caller file: **42 passed**, no skip/xfail. Includes actual generated Detection/DAST target-file reads and FFuf subprocess `-u` argv; full resource-enum -> saved JSON; partial Katana/Hakrawler/FFuf and Kiterunner tool boundaries; cache collector query fidelity; >3000 observed endpoints; measured-vs-supplied status; exact partial scope and raw-control rejection.
- Existing P0 caller/merge/artifact/graph-double/coverage/prune roundtrip remains executable and passes. Partial multi-root, org/IP scope, 298-case partial suite and 168-case cache suite pass.
- Fresh `git archive` of pinned base plus **only the final new test file**: selected **24/24 regressions fail**, no collection errors: 18 public-builder URI leaks; malformed actual caller raises `ValueError`; independent DAST leaks tel/javascript/mailto; FFuf generated argv has query-suffix FUZZ; 3 partial callers fabricate 200. The same cases pass candidate. No missing-new-API failures are counted as bug proof.
- Existing skip/xfail set remains 14/7: three absent ad-hoc template tests; three native Nuclei smoke tests; eight Arjun skips; FFuf one xfail; Arjun two xfails; JS four xfails. New FFuf argv coverage is independent of the old xfailed mock test.
- Updated deliberate characterization expectations: P0 FFuf negative contract now asserts its required `/api/FUZZ?q=1`; legacy query interpolation containing raw whitespace is rejected until F02 repairs encoding; supplied-fingerprint test now asserts null status/unknown type while preserving technology inheritance. No assertion deletion, new skip or new xfail to hide failures.
- `git diff --check` passes. Live source stays at pinned base with only the two pre-existing untracked output markers.

## Review and limits

A read-only aid review identified supplied-marker status override and IDN compatibility issues; both were fixed. A fresh bounded review accepted the repairs for status, host compatibility, FFuf path/query and canonical raw-control ingress. This does **not** replace G1 independent integration review.

- Offline unit/caller/writer-double verification only. No native Nuclei or FFuf target requests, live Neo4j, capture proxy or Traffic Mind receiver E2E. No runtime/request-reduction claim.
- Syntax admission is deliberately not full RFC URI canonicalization and never decodes encoded path/query bytes. Existing scope/SSRF/redirect policies remain separate. Userinfo URLs are not supported; use existing scoped auth profiles.
- F02 owns `_endpoint_url` raw sample/decoded parameter encoding. Until combined, F01 rejects malformed whitespace generated by the legacy interpolation but retains the raw observation. The P0 encoding defect characterization remains explicitly unresolved here.
- Historical graph readers synthesizing unknown status and separate route-exposure/serialized/JS/supply-chain adapters are not claimed migrated by this named-consumer patch; typed inventory is F08. Generic admission source reports are log/optional-return aggregates; only DAST disposition is additionally persisted in scan metadata here. Early-exit/selection coverage accounting is F07.
- Existing cache scanner cap (200) and existing Arjun-specific limits are unchanged; these are not new shared Nuclei budgets.

## Integration hotspots and rollback

- `target_helpers.py`: F01 admission vs F02 request encoding; preserve both. P0 query-encoding characterization requires updating to the combined correct output at G1, not dropping the encoding regression.
- `vuln_scan.py`: F01 DAST syntax/report vs F03 policy, F04 AI and F07 coverage.
- `partial_recon_modules/parameter_discovery.py`: F01 URI/supplied handling vs F06 Arjun contract.
- These edits are correctness/safety, not planner optimization. Planner off must not disable URI/scope safety. Any revert requires review; do not restore invalid inputs as an optimization rollback. No production rollback action is necessary because nothing was deployed.
