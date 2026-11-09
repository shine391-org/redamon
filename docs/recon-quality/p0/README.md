# P0 reproducible baseline and coverage contract

Base: `104f66cc5943a2eb5265edf190f39c4184b5e1ee`.
Branch: `test/recon-quality-p0-baseline`; worktree: `/data/redamon/workspace/worktrees/recon-quality/p0`.
Only tests, fixtures and documentation/harness change. No production code/settings,
DB, service restart, target scan, push or PR is included.

## Reproduce

From this worktree, with the immutable image already available:

```sh
python3 docs/recon-quality/p0/run.py --output "$HERMES_KANBAN_WORKSPACE/evidence/recheck"
python3 docs/recon-quality/p0/verify_templates.py /path/to/nuclei-templates.tar.gz
```

Output must be a new directory outside the checkout. The runner never pulls an image,
installs dependencies, mounts a Docker socket in a test container, or gives tests a network.
Each file gets its own disposable container, immutable image ID, read-only root/source,
`PYTHONHASHSEED=0`, and per-file scratch bind at `TMPDIR=/scratch`. Docker daemon access is
used **by the host runner only**, for sandbox creation/removal. Test subprocess tools and
backend drivers are mocked; successful unit tests are not live scanner/graph evidence.

`baseline.json` records HEAD/base/status at capture, runner hash, image IDs/reported repo
digests, runtime versions, fixture seed/hash and frozen template archive/tree hashes.
The template archive is delivered as a task attachment, not committed third-party content.
Its per-file SHA manifest and logs are in the evidence attachment. The archive is for
future benchmark use: these unit tests do **not** load the real Nuclei template pool.
Do not replace it with the current mutable volume or update templates when comparing runs.
No image export is shipped; the named pinned images must remain available locally.

The pristine control was freshly extracted from `git archive <base>`; its archive digest is
recorded. Recovery found the prior extraction differed only in eight GIF assets; even though
code matched, all final controls were rerun against the fresh verified archive. Old/interim
results are not the final delivery evidence.

## Results actually rerun

| Selected run | Files | Passed | Skipped | Xfailed | Failed/errors |
|---|---:|---:|---:|---:|---:|
| Pristine pinned base | 27 | 786 | 14 | 12 | 0 |
| P0 candidate | 28 | 816 | 14 | 7 | 0 |
| Two-pass file, base | 1 | 32 | 3 | 5 | 0 |
| Two-pass file, P0 | 1 | 37 | 3 | 0 | 0 |
| New baseline file | 1 | 25 | 0 | 0 | 0 |

Counts are pytest test cases (parameterized cases count; subtests are not added). Existing
five caller xfails become real passes, and the new file adds 25 passes. This is an explicit,
wider file inventory, not a reproduction of undocumented historical 99/194-test groupings
and not the full repository gate. `test-results.json` lists each file and every exception
with its original reason; the evidence bundle has stdout and JUnit for each file.
The 14 existing skips are three absent ad-hoc AEM-template tests, three native-Nuclei
smoke tests (binary unavailable in the recon image), and eight stale Arjun mock tests.
Seven existing xfails remain: FFuf 1, Arjun 2, JS endpoint validation 4. They are unresolved,
not coverage successes, and no skip/xfail was added to make P0 pass.

## Why the five two-pass xfails were invalid harnesses

A separate pristine run with `--runxfail` produces four call-count failures and one
`TypeError: ... unexpected keyword argument 'runtime_cap'` (negative-control log attached).
The old common settings used `NUCLEI_TAGS=[]`, which deliberately skips Detection; expecting
one Detection call or two total passes from that input is inconsistent with the caller's
explicit no-selection policy. Set the fixture selection to `['cve']`, not production defaults.
Update the `fake_exec` signature for `runtime_cap`/`container_name`, and assert the values.
Capture proxy discovery is a boundary double to keep this unit path deterministic/offline.
The real command builder remains in use and generated Detection/DAST files are inspected
before cleanup. Original pass order, finding merge/dedup and `force_dast_pass` assertions
remain; the decorators alone are removed, no assertions deleted. No engine defect is claimed
repaired by this test-only change.

## Fixtures and characterization versus future correctness

The 27 synthetic cases use `.test` and documentation-only IP literals; auth references are
labels, not tokens/cookies. They cover distinct origins/port/app prefixes, slash/encoding,
query special characters/duplicate keys, POST/body/auth, declared GET/POST/template paths,
401/403/404/405, timeout/challenge unknown, Kiterunner/OpenAPI/JS-only and seven malformed or
non-HTTP URIs. No engagement corpus was committed or contacted. Real corpus replay, if
later authorized, must stay offline and outside tracked fixtures/logs; publish only sanitized
case evidence and bounded aggregate counters.

`native_resource` is a deliberately lossy TEST adapter into the **existing** schema, not a
new production inventory. Characterization tests assert literal current URL projections;
they do not assert POST/auth semantics, validation truth or vulnerability coverage.
`negative-contracts.json` and separately named negative probes identify FFuf query-seed and
query encoding defects plus future DAST/unknown/prune requirements. F01/F02 must replace
legacy defect probes with desired-behavior assertions and show fail-base/pass-repair.
P0 does not add new xfails for those future requirements. Corpus presence for a malformed URI
is not proof that a production caller rejects it. Provenance, validation, admission and
execution are independent axes; candidate/unknown cannot become validated/dead by projection.
See `CALLERS.md` and `caller-map.json` for the full/domain/IP/batch/partial seams and limits.

The new integrated unit test exercises real isolated caller → generated target files/argv →
JSONL parser → finding merge → whitelist/fan-in → saved artifact → graph mixin/coverage stamp
with recording driver → failed-coverage-write prune guard. It does not execute native Nuclei,
Neo4j, Traffic Mind or a whole production mode. Selected-scan path/template pruning and full
batch merge equivalence remain F07 acceptance, not a conclusion from this unit test.

## Mandatory benchmark acceptance, frozen BEFORE optimization

1. Compare fixed source revision, image IDs, exact templates/selection/settings hashes,
   fixture seed, resource allocation and auth-context references. Off/shadow/enforce are
   separate runs; no new live traffic or LLM probes in shadow.
2. Retain every raw seeded observation with source/context; reconcile identity sets to an
   admitted task or an explicit rejected/unsupported/deferred reason. Counts alone cannot
   prove absence of silent omissions. Invalid URI fixtures stay in raw inventory but must
   not become HTTP execution tasks. Unknown validation is not rejection/dead evidence.
3. Seeded **eligible** detection/hidden-parameter/JS/supply-chain findings retain recall;
   POST/body/auth/query ordering/duplicates/slash/encoding variants remain distinct unless
   equivalence is demonstrated. Required benign and negative controls stay negative.
   The P0 corpus seeds request/evidence cases, not a claim of measured vulnerability recall.
4. Keep uncapped observed shared-builder default (`test_no_b_large_inputs`); preserve the
   current declared-only cap separately. No new default sampling, deferred policy,
   root-only conversion or all-path-only/404/archive/unknown-template exclusion.
5. Measure work at its actual stage: JS candidates/attempts/bytes, extracted observations,
   admitted endpoints, FFuf seeds/wordlist-extension combinations, Arjun requests by method,
   Detection and DAST inputs, effective template IDs, actual receiver requests and errors,
   runtime/memory. URL count, tag count and estimated cross-products are **not** actual
   HTTP request counts. Before/after reduction must be demonstrated at the intended stage
   with unchanged eligible seed recall, not inferred from downstream output size.
6. Partial/cancelled/unknown execution must not promote origin/source to complete or prune
   untested findings. Same-host `/a` versus `/b`, human decisions and missing/failed manifests
   are mandatory F07 negatives before enforce. A failed backend read is unknown, never zero.
7. No numeric speedup or whole-batch ETA is promised by P0. Timings in unit logs are test
   harness timings only, not scan performance. The local controlled-receiver benchmark is
   future work for the owning stage cards; no production egress/guard changes are authorized.

## Rollback

Revert only the P0 delivery commit to remove its fixtures/docs/test harness repairs.
Production logic is identical to the pinned base, so rollback changes no scanner behavior.
Independent review is required before accepting this baseline and releasing implementation
work. No rollout or publication has been performed.
