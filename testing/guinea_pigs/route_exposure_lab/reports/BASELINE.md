# Route exposure: baseline gate

Recorded on `feature/route-exposure` at `5c9e40e6` (branched from `master`),
before any route-exposure code, on 2026-10-28.

| Gate | Result |
| --- | --- |
| `./redamon.sh test unit`, section `agent` | 226 files passed, 0 failed |
| section `root-agent` | 173 files passed, 0 failed |
| section `root-recon` | 12 files passed, 0 failed |
| section `recon` | 274 files passed, 0 failed |
| section `recon_orchestrator` | 46 files passed, 0 failed |
| section `ai_attack_surface` | 11 files passed, 0 failed |
| section `capture_proxy` | 7 files passed, 0 failed |
| section `docker_broker` | 7 files passed, 0 failed |
| section `plugin_runner` | 19 files passed, 0 failed |
| shell suites | 39 files green |
| webapp vitest (inside the gate) | 829 files passed, 25 skipped; 14127 tests passed, 2 expected fail, 251 skipped |
| `npm run type-check` | clean |
| `npm run lint` | **red before this branch** (see below) |
| `python3 recon_settings/build.py --check` | registry artifacts up to date |
| `python3 graph_db/node_filters/build.py --check` | catalog OK, 15 kinds |

## Pre-existing red

- `cd webapp && npm run lint` exits 1 with
  `Invalid project directory provided, no such directory: .../webapp/lint`.
  The script is `next lint`, and the installed Next.js (16) no longer ships a
  `lint` subcommand, so it reads `lint` as a project directory. Not caused by
  this branch and not fixed on it; reported to the human.
