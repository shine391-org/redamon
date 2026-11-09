# Pinned caller map (P0)

All locations refer to base `104f66cc5943a2eb5265edf190f39c4184b5e1ee`.
This is an inventory of source seams, **not** a claim that every mode was exercised end to end.
`caller-map.json` records direct production call sites mechanically (AST); dynamic dispatch and
shared-mode entrypoints are expanded below. P0 changes no production module.

## Mode routing and output boundaries

| Mode | Entry and shared route | Persistence / coverage / prune |
|---|---|---|
| Domain (including discovery-disabled legacy route) | `recon/main.py::main` → `run_domain_group` (3003); resource enumeration → Phase A vulnerability scanner | `save_recon_file` (605); async graph writes (2218/2313), legacy direct writers (3273/3351); group waits for writes then `_write_coverage_record` (3460); successful single group triggers run-level prune (2926) |
| IP | `main` (2883) → `run_ip_recon` (1002); resource/vuln modules are shared, target extraction and `NUCLEI_SCAN_ALL_IPS` decide composition | resource/vuln writers (1466/1521); canonical artifact; `_write_coverage_record` + prune (2896/2897) |
| Domain batch | `main` → `run_domain_batch` (2740) → each `run_domain_group` (2793), same shared consumers, group-local scope | initialize canonical before first group; `helpers/output_paths.py::merge_batch_outputs` (173), invoked after each group (2804); per-group coverage (3460), run-level prune only if no failed groups (2818–2824). Canonical merge is a separate boundary from isolated fan-in. |
| Partial | `recon/partial_recon.py` module dispatch (including FFuf 436 / Arjun 438); graph builders + supplied inputs → selected module | partial modules directly call graph mixins, not the full-run fan-in/prune orchestration. Full mode coverage must not be inferred from partial success. |

## Shared builder and distinct consumers

`recon/helpers/target_helpers.py`: extraction, `build_target_urls_from_httpx` (98),
`_endpoint_url` (133), resource projection (146), combined union (250).
Combined sources are **union**, not mutually exclusive fallbacks: resource bases/endpoints,
HTTP probe URLs, hostname/IP fallbacks. Existing observed union remains uncapped;
`MAX_DECLARED_NUCLEI_URLS=500` applies only to eligible declared GET/HEAD paths.
Do not apply Nuclei policy to the shared discovery/cache builder.

- Full resource enumeration: `main_recon_modules/resource_enum.py:689`.
- Full vulnerability detection: `main_recon_modules/vuln_scan.py:579`.
- Partial crawlers: `partial_recon_modules/web_crawling.py:134,403,705`.
- Partial FFuf: same module `1027` → `run_ffuf_discovery` at `1147`.
- Partial parameter discovery (ParamSpider): `parameter_discovery.py:282`.
- Cache: `cache_scan/scanner.py:144`; partial adapter is
  `partial_recon_modules/cache_scanning.py` (graph endpoints reshape into native resource input).

## FFuf and Arjun

Full `resource_enum.py:1265` → `helpers/resource_enum/ffuf_helpers.py::run_ffuf_discovery`
→ `_build_fuzz_targets` → subprocess argv / output file → parsed results / metadata →
resource endpoint merge and `by_base_url`/`discovered_urls` output. Partial FFuf follows the
same helper, then its own direct `update_graph_from_resource_enum` at `web_crawling.py:1202`.
The query-bearing directory seed defect is characterized separately, not blessed.
Per-origin prefix/extension ownership is F11, not implemented here.

Full `resource_enum.py:1373` → `helpers/resource_enum/arjun_helpers.py::run_arjun_discovery`
→ `_run_arjun_single_method` → subprocess input/output files → parsed parameter results and
execution metadata → resource endpoint merge. Partial `parameter_discovery.py::run_arjun`
(519) calls the same helper (686), writes resource graph (775), but independently loads
settings/inputs. This is why full/partial fallback and scope parity need F06 tests;
calling the same helper does not prove equal effective settings or complete timeout coverage.

## Detection / DAST / takeover

Full/IP/group share `main_recon_modules/vuln_scan.py::run_vuln_scan`:
- detection reads the combined builder; generated `targets_detection.txt` →
  `build_nuclei_command` (797) → `_execute_nuclei_pass` → JSONL parsing;
- DAST **does not** read the combined builder. It selects strings containing `?` and `=`
  from `resource_enum.discovered_urls` (622–638), writes `targets_dast.txt`, uses a separate
  `build_nuclei_command` call (837) with `force_dast_pass`, then merges findings;
- `run_vuln_scan_isolated` (1242) deep-copies input and returns whitelisted top-level keys;
  `main.py::_merge_isolated_result` (952; called at 991) performs fan-in.

Partial `vulnerability_scanning.py::run_nuclei` (33) loads graph/supplied inputs, force-enables
Nuclei before overrides (53), calls the same `run_vuln_scan`, and writes graph at 262.
`partial_recon_modules/graph_builders.py` is the graph → recon schema adapter, including
BaseURL input around 865 and endpoint/query reconstruction around 1238.
Takeover is a separate explicit-template consumer of `build_nuclei_command`
(`main_recon_modules/subdomain_takeover.py:662`); do not assume DAST inclusion policy applies.

## Graph / coverage / pruning

- `graph_db/mixins/recon/vuln_mixin.py`: parsed finding / technology-CVE writers and Nuclei
  coverage stamps; resource and JS writers are distinct mixins. Shared graph driver boundary
  is mocked, not replaced by synthetic production API responses.
- `main.py::_write_coverage_record` (2472), `_prune_recon_findings` (2542);
  `graph_db/mixins/base_mixin.py` implements persistent run/prune operations.
- `graph_db/coverage_stamps.py` is a separate coverage-reader contract.
- Host/source stamps do not establish path/template coverage. F07 owns selective-run safety,
  missing manifest semantics and batch count reconciliation; none is claimed repaired by P0.

## Executed boundary and limits

The new `test_actual_two_pass_parse_merge_artifact_graph_and_prune` uses the real isolated
caller, generated target files and command builder, real JSONL parser, fan-in, artifact writer,
real graph mixin with a strict recording driver, and failed-coverage-write prune guard.
Only external tool execution and graph/backend boundaries are doubles. It proves no real
Nuclei match, HTTP traffic, Traffic Mind route, Neo4j query execution or UI behavior.
The full mode matrix above is source mapped, not simulated as a successful production scan.
Existing per-file tests supply additional FFuf/Arjun/full/partial/graph unit evidence; their
skips and xfails remain explicit. Future defect regressions must fail on the pinned base and
pass the owning repair branch using the same harness.
