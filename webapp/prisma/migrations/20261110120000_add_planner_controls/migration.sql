-- F09: planner controls (additive, default-off).
-- plannerMode off|shadow|enforce + per-consumer enable controls on Project;
-- run-scoped plan manifest pointer/digest/bounded summary on ScanJob.
-- No column dropped, no table renamed, no data destroyed: a rollback app reads
-- both old and new rows safely (defaults apply to older rows).

ALTER TABLE "projects"
  ADD COLUMN "planner_mode" TEXT NOT NULL DEFAULT 'off',
  ADD COLUMN "planner_manifest_enabled" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "planner_consumer_ai_tags" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "planner_consumer_target_selection" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "planner_consumer_two_pass" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "scan_jobs"
  ADD COLUMN "plan_manifest_path" TEXT,
  ADD COLUMN "plan_manifest_sha256" TEXT,
  ADD COLUMN "plan_manifest_summary" JSON;
