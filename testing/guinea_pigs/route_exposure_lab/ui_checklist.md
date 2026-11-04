# Route exposure: UI checklist (plan §22.3)

Ticked during the final v1 pass on `9d37d2f0` (webapp image built from
`c6ca8c6c`, the last webapp change). Screenshots are in
`reports/screenshots/v1/` (gitignored). "MCP" is `get_recon_settings` read back
after the save; "net" is the save's `PUT /api/projects/<id>`, captured in the page.

## Per field (v1)

| Field | flip/save/reload | `get_recon_settings` | min/max/out-of-bounds | network 2xx/4xx | console clean | screenshot |
| --- | --- | --- | --- | --- | --- | --- |
| routeExposureEnabled | [x] off hides the body and Run partial recon; reload shows off | [x] | n/a | [x] 200 | [x] | [x] final_390_section.png |
| routeExposureSeedPaths | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| routeExposureVcsFiles | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| routeExposureBackupFiles | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| routeExposureVersionVariants | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| routeExposureCompareLoggedIn | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| routeExposurePiiDetection | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| routeExposureMaxRps (1-50) | n/a | [x] | [x] 1 and 50 saved; 0 and 51 refused by the form and by MCP; cleared field shows and saves 5 | [x] 200 | [x] | [x] final_numeric_below_min.png, final_numeric_cleared_to_default.png |
| routeExposureWorkers (1-16) | n/a | [x] | [x] 1/16 saved; 0/17 refused (form, MCP); cleared -> 4 | [x] 200 | [x] | [x] |
| routeExposureTimeout (2-60) | n/a | [x] | [x] 2/60 saved; 1/61 refused (form, MCP); cleared -> 10 | [x] 200 | [x] | [x] |
| routeExposureMaxRoutesPerHost (10-5000) | n/a | [x] | [x] 10/5000 saved; 9/5001 refused (form, MCP); cleared -> 300 | [x] 200 | [x] | [x] |
| routeExposureMaxRoutesTotal (50-50000) | n/a | [x] | [x] 50/50000 saved; 49/50001 refused (form, MCP); cleared -> 3000 | [x] 200 | [x] | [x] |
| pathTraversalGitReconstructEnabled (A1) | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| pathTraversalValidateSecretsEnabled (A1) | [x] | [x] | n/a | [x] 200 | [x] | [x] |
| rceHeapdumpAnalysisEnabled (A1) | [x] | [x] | n/a | [x] 200 | [x] | [x] |

Out-of-bounds values never reach the save: the form marks the field invalid and
sends no PUT. The PUT route itself checks no registry bound (a hand-made PUT with
`routeExposureMaxRps: 51` or `katanaDepth: 11` returns 200); the module clamps
every value to its bounds at use. Pre-existing for every field, see the report.

Console: no error or React warning from the section. The only console errors on
the page are four 404s from `HEAD /api/{recon,gvm}/<id>/download`, the app's
probe for a scan file on a project never scanned.

## Section and views

- [x] Body only when enabled; Active badge; NodeInfoTooltip (Consumes BaseURL, Endpoint; Produces Vulnerability, Endpoint; Enriches Endpoint; input and output logic); Run partial recon only in edit mode with the module on
- [x] Authentication hint opens Target & Modules, where the Authenticated Session section it names is
- [x] Advanced holds the five numeric fields
- [x] "Half a cycle" alert with Broken Access Control off; its link opens AI Agent > Agent Skills (final_half_a_cycle_alert.png)
- [x] Workflow view: RouteExposure node in group 6 with the Active badge and its edges; the gear opens the section; Play opens the partial modal (final_workflow_node.png)
- [x] Graph page after S1: route_exposure Vulnerability nodes; the /xss-snippet lead's evidence shows `<img src=x onerror=alert(1)>` as text, no dialog, no alert; the /xss-snippet Endpoint shows anon_status 200 (final_xss_snippet_escaped.png)
- [x] Priority Board: leads at T4 (score 0.2, "Track"), findings scored with their class (T2 "Act soon" 61.8 for consoles, VCS, env; T3 for config and debug pages) (final_priority_board.png)
- [ ] Reports: not generated. Generating needs a "Report narratives" model saved for the account, which this campaign does not change; the report predicate was checked on the graph instead (12 reported, 10 pending leads excluded)
- [x] Red Zone > Route Exposure: unseen badge 22 cleared on opening; 22 rows, 10 pending; kind, route class, severity and status filters (7, 5, 6, 10 rows) and the text filter (4 rows for "export"); /xss-snippet row as text; row mute and unmute; CSV, JSON and Markdown downloads; empty state on S10; "Loading..." on Slow 3G (final_redzone_empty.png, final_redzone_loading.png)
- [x] 390 px wide: section, partial modal and Red Zone table usable, no page overflow; the table scrolls inside its own frame, and the toolbar wraps so Markdown and Filters stay reachable (final_390_section.png, final_390_partial_modal.png, final_390_redzone_table.png)
- [x] TrafficMind: see the report (captured route_exposure transactions on the AG project)

## Partial recon (P1-P7)

- [x] P1 graph targets, no URL  - [x] P2 typed URL, Generic  - [x] P3 typed URL attached to the BaseURL
- [x] P4 graph off, no URL: Run disabled  - [x] P5 no BaseURL: no-targets warning
- [x] P6 outsider URL dropped, 0 hits  - [x] P7 workflow node and section button give the same nodes
