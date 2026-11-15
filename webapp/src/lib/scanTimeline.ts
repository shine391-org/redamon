/**
 * Scan Timeline - full-scan version bookkeeping (server-side).
 *
 * A full scan always wipes and rebuilds the live Neo4j graph, and the live graph
 * IS the current version. So there is no pointer to flip and no completion
 * detection needed for correctness: the only decision is what happens to the
 * graph that is about to be destroyed.
 *
 *   mode = 'new'       keep it. Freeze the current version (capture live graph ->
 *                      gzip -> ScanVersion.snapshot), demote it to a past version,
 *                      and mint the next version as the new current. FAIL CLOSED:
 *                      if the freeze fails we throw and the caller must NOT start
 *                      the scan, so the graph is never lost.
 *   mode = 'overwrite' discard it. No snapshot; the current version row is reused.
 *
 * `ScanJob` rows are the run history the timeline/scheduler tables read.
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { readDegradedSourceCount } from '@/lib/scanCoverage'
import {
  captureGraphSnapshot,
  storeSnapshot,
  ensureCurrentVersion,
  defaultVersionLabel,
  type ScanVersionRow,
} from '@/lib/scanSnapshot'
import { CurrentVersionMovedError } from '@/lib/projectGraphLock'

export type ScanMode = 'new' | 'overwrite'
export type ScanTrigger = 'manual' | 'scheduled'

export const SCAN_MODES: ScanMode[] = ['new', 'overwrite']

export function parseScanMode(value: unknown): ScanMode | null {
  return value === 'new' || value === 'overwrite' ? value : null
}

/** Auto-generated labels are refreshed on overwrite; user-renamed ones are kept. */
const AUTO_LABEL = /^Scan \d+ - \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/

export interface PrepareResult {
  /** The version the scan about to start will populate (the new current). */
  currentVersion: ScanVersionRow
  /** The version that was frozen as a past version, if any. */
  frozenVersionId: string | null
  /** Nodes captured into the frozen snapshot (0 when nothing was kept). */
  frozenNodeCount: number
}

export class SnapshotFreezeError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message)
    this.name = 'SnapshotFreezeError'
  }
}

/**
 * Apply the version-side effects of starting a full scan. MUST be called before
 * the scan is actually started, and its rejection MUST abort the start.
 */
export async function prepareVersionsForFullScan(
  projectId: string,
  mode: ScanMode,
  actorId?: string | null
): Promise<PrepareResult> {
  const current = await ensureCurrentVersion(projectId)

  if (mode === 'overwrite') {
    const label = AUTO_LABEL.test(current.label)
      ? defaultVersionLabel(current.seq)
      : current.label
    const updated = await prisma.scanVersion.update({
      where: { id: current.id },
      data: { label },
      select: VERSION_SELECT,
    })
    await writeAudit({
      actorId: actorId ?? null,
      action: 'scan-version.overwrite',
      targetType: 'scanVersion',
      targetId: current.id,
      before: { seq: current.seq, label: current.label, nodeCount: current.nodeCount },
      after: { seq: current.seq, label, discardedSnapshot: true },
    })
    return { currentVersion: updated, frozenVersionId: null, frozenNodeCount: 0 }
  }

  // mode === 'new': freeze the outgoing graph first. Anything that throws here
  // must propagate - the caller aborts the start rather than risk losing it.
  let captured
  try {
    captured = await captureGraphSnapshot(projectId)
  } catch (err) {
    throw new SnapshotFreezeError(
      'Could not snapshot the current graph, so the scan was not started (no data was lost). ' +
      (err instanceof Error ? err.message : String(err)),
      err
    )
  }

  // An empty live graph has nothing worth keeping: reuse the current version
  // rather than filling the timeline with empty snapshots.
  if (captured.nodeCount === 0) {
    return { currentVersion: current, frozenVersionId: null, frozenNodeCount: 0 }
  }

  try {
    await storeSnapshot(current.id, captured)
  } catch (err) {
    throw new SnapshotFreezeError(
      'Could not store the snapshot of the current graph, so the scan was not started ' +
      '(no data was lost). ' + (err instanceof Error ? err.message : String(err)),
      err
    )
  }

  const created = await rotateToNextVersion(projectId, current.id)

  // Retention is deliberately NOT run here. It deletes the oldest unpinned
  // versions, and a start the orchestrator goes on to refuse must not cost the
  // user a saved version. `startFullScan` calls applyRetentionSafe only after
  // the start is accepted (mcp_plan.md P0-2).
  return {
    currentVersion: created,
    frozenVersionId: current.id,
    frozenNodeCount: captured.nodeCount,
  }
}

/**
 * Undo `prepareVersionsForFullScan` after a start the orchestrator refused.
 *
 * Only meaningful for `mode: 'new'` that actually rotated (`frozenVersionId`
 * set). The live graph is never touched by the freeze, so deleting the empty
 * new version and making the frozen one current again returns the timeline to
 * its prior state. Without this, an external agent retrying a 403 in a loop
 * mints a version and stores a duplicate snapshot on every attempt.
 *
 * Never throws: a start has already failed, and failing to tidy up must not
 * replace that error with a less useful one.
 */
export async function rollbackPreparedVersions(
  projectId: string,
  prepared: PrepareResult
): Promise<boolean> {
  const frozenId = prepared.frozenVersionId
  if (!frozenId) return false

  try {
    await prisma.$transaction(async tx => {
      await tx.scanVersion.delete({ where: { id: prepared.currentVersion.id } })
      await tx.scanVersion.update({
        where: { id: frozenId },
        // nodeCount/linkCount are left as the freeze measured them: the live
        // graph was never touched, so those numbers describe it accurately.
        // Only the snapshot bytes (and the demotion) are undone.
        data: { isCurrent: true, snapshot: null },
      })
    })
    return true
  } catch (err) {
    console.error(
      `[scanTimeline] could not roll back the prepared version for project ${projectId} ` +
      '(the timeline keeps an extra empty version):',
      err
    )
    return false
  }
}

/** Prisma's unique-constraint violation. */
function isSeqCollision(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'P2002'
}

const ROTATE_ATTEMPTS = 4

/**
 * Demote `demoteVersionId` and open the next version, atomically.
 *
 * The scan start and "save current as a version" both read the current version,
 * freeze it, then rotate; the project graph lock (projectGraphLock.ts) keeps them
 * from interleaving in this process. Two guards stay for a writer the lock does
 * not see. The demote matches only a version that is still current: a writer
 * that read the same current and lost the race gets CurrentVersionMovedError
 * rather than minting a second current version. And a seq taken under
 * `@@unique([projectId, seq])` is retried with a recomputed seq, rather than
 * failing after the snapshot was already frozen.
 */
export async function rotateToNextVersion(
  projectId: string,
  demoteVersionId: string
): Promise<ScanVersionRow> {
  let lastError: unknown
  for (let attempt = 0; attempt < ROTATE_ATTEMPTS; attempt++) {
    const nextSeq = await nextVersionSeq(projectId)
    try {
      return await prisma.$transaction(async tx => {
        const demoted = await tx.scanVersion.updateMany({
          where: { id: demoteVersionId, isCurrent: true },
          data: { isCurrent: false },
        })
        if (demoted.count === 0) throw new CurrentVersionMovedError(demoteVersionId)
        return tx.scanVersion.create({
          data: {
            projectId,
            seq: nextSeq,
            label: defaultVersionLabel(nextSeq),
            isCurrent: true,
            snapshot: null,
          },
          select: VERSION_SELECT,
        })
      })
    } catch (err) {
      if (!isSeqCollision(err)) throw err
      lastError = err
      console.warn(
        `[scanTimeline] version seq ${nextSeq} was taken by a concurrent writer for project ` +
        `${projectId}; retrying (${attempt + 1}/${ROTATE_ATTEMPTS})`
      )
    }
  }
  throw lastError
}

export async function nextVersionSeq(projectId: string): Promise<number> {
  const top = await prisma.scanVersion.findFirst({
    where: { projectId },
    orderBy: { seq: 'desc' },
    select: { seq: true },
  })
  return (top?.seq ?? 0) + 1
}

export interface CreateScanJobInput {
  projectId: string
  versionId?: string | null
  trigger: ScanTrigger
  mode: ScanMode | null
  status?: string
  initiatedByUserId?: string | null
  scheduleId?: string | null
  ramReason?: string | null
  /** Defaults to full_recon, which is what every ScanJob used to be. */
  kind?: string
  /** Only for kinds that run several times per project at once. */
  runId?: string
  /** The sha256 of the scan-steering settings this run started with. */
  settingsHash?: string | null
  /** Which authorization permitted it, from the project's current record. */
  authorizationId?: string | null
  /** The project roots the run covers, as the orchestrator returned them. */
  targets?: string[]
  /** digestScopeDocument of the RoE text in force when the run started. */
  roeTextSha256?: string | null
}

export async function createScanJob(input: CreateScanJobInput): Promise<{ id: string }> {
  const status = input.status ?? 'running'
  return prisma.scanJob.create({
    data: {
      projectId: input.projectId,
      versionId: input.versionId ?? null,
      kind: input.kind ?? 'full_recon',
      runId: input.runId ?? '',
      trigger: input.trigger,
      mode: input.mode,
      status,
      initiatedByUserId: input.initiatedByUserId ?? null,
      scheduleId: input.scheduleId ?? null,
      ramReason: input.ramReason ?? null,
      settingsHash: input.settingsHash ?? null,
      authorizationId: input.authorizationId ?? null,
      targets: input.targets ?? [],
      roeTextSha256: input.roeTextSha256 ?? null,
      // Deliberately NOT copied from the input: a new ScanJob row must never
      // inherit a plan manifest from an earlier run. The pointer is written
      // only by persistPlanManifest, for the run that actually produced it.
      planManifestPath: null,
      planManifestSha256: null,
      planManifestSummary: undefined,
      startedAt: status === 'running' ? new Date() : null,
    },
    select: { id: true },
  })
}

/**
 * G2-R3: the manifest tree's directory and file name, exactly as the recon
 * helper writes them:
 * `planner_manifests/<tenant>/<project>/<run>/<group>/plan_manifest.json`.
 * The path is the only place the tenant and project appear, so it is what a
 * pointer is validated against before it is persisted.
 */
const MANIFEST_DIR_SEGMENT = 'planner_manifests'
const MANIFEST_FILE_NAME = 'plan_manifest.json'

/**
 * Encode one manifest path component exactly the way recon's `_encode_component`
 * writes it: every safe character `[A-Za-z0-9_.-]` verbatim, every other code
 * point as `%` + its uppercase hex (at least two digits). Encoding the input
 * context and comparing it to the path segment is unambiguous; decoding the
 * segment is not, because a group such as `domain:abc` is written
 * `domain%3Aabc` and a greedy decoder would read `%3Aab` as one code point.
 */
function encodeManifestComponent(value: string): string {
  let out = ''
  for (const ch of value) {
    if (/[A-Za-z0-9_.-]/.test(ch)) {
      out += ch
    } else {
      out += '%' + ch.codePointAt(0)!.toString(16).toUpperCase().padStart(2, '0')
    }
  }
  return out
}

/** Epoch milliseconds for a manifest timestamp, or null when absent/invalid. */
function parseManifestTime(value: string): number | null {
  if (!value) return null
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

/** The tenant/project/run/group a pointer path claims. */
function manifestPointerContext(path: string): {
  tenant: string
  projectId: string
  runId: string
  groupId: string
} | null {
  const segments = path.split('/')
  const base = segments.lastIndexOf(MANIFEST_DIR_SEGMENT)
  if (base < 0) return null
  // Exactly one run-scoped manifest file below the directory: a trailing
  // segment (or a missing one) is not a manifest this writer produced.
  const rest = segments.slice(base + 1)
  if (rest.length !== 5) return null
  const [tenant, projectId, runId, groupId, file] = rest
  if (file !== MANIFEST_FILE_NAME) return null
  if (!tenant || !projectId || !runId || !groupId) return null
  if ([tenant, projectId, runId, groupId].some(
    (part) => part === '.' || part === '..' || part.includes('\\'),
  )) return null
  return { tenant, projectId, runId, groupId }
}

/**
 * A pointer may only be persisted on a row whose project/run/tenant it names.
 * The run must equal the manifest summary's own run id; the project and tenant
 * are read from the path, because the summary carries neither.
 */
function pointerMatchesJobContext(input: {
  path: string
  projectId: string
  runId: string
  groupId: string
  tenant?: string
}): boolean {
  const ctx = manifestPointerContext(input.path)
  if (!ctx) return false
  if (ctx.projectId !== encodeManifestComponent(input.projectId)) return false
  if (ctx.runId !== encodeManifestComponent(input.runId)) return false
  if (ctx.groupId !== encodeManifestComponent(input.groupId)) return false
  if (input.tenant !== undefined && ctx.tenant !== encodeManifestComponent(input.tenant)) {
    return false
  }
  return true
}

export interface PlanManifestPersistResult {
  persisted: boolean
  /**
   * Why nothing was written, when `persisted` is false. Callers that mirror a
   * status poll ignore it; the internal POST reports it so a mismatched
   * pointer is a visible rejection rather than a silent no-op.
   */
  reason?: 'no_run_id' | 'run_mismatch' | 'context_mismatch' | 'no_open_job' | 'pointer_newer' | 'db_error'
}

/**
 * G2-R3: persist a run-scoped plan-manifest pointer on the open ScanJob row.
 *
 * The orchestrator reports every pointer it read from the project's manifest
 * index on each status poll -- across runs and groups -- and the recon
 * container posts its own pointer before the vuln_scan tool launches. A
 * pointer is attributed by its own summary run id: it is written only onto the
 * open row of that run, and only when its path names the same project, run and
 * tenant. A pointer left by a different run is stale and is replaced; a newer
 * same-run pointer is never regressed by a late poll. The full manifest is
 * never stored here -- only pointer + digest + bounded summary. Best-effort: a
 * failure is logged and swallowed, because history bookkeeping must never break
 * a status poll.
 */
export async function persistPlanManifest(input: {
  projectId: string
  kind: string
  runId?: string
  /** The project owner (tenant) the manifest path must be scoped to. */
  tenant?: string
  pointer: {
    plan_manifest_path: string
    plan_manifest_sha256: string
    plan_manifest_summary: Prisma.InputJsonObject
  }
}): Promise<PlanManifestPersistResult> {
  try {
    const summary = (input.pointer.plan_manifest_summary ?? {}) as Record<string, unknown>
    const pointerRunId = typeof summary.run_id === 'string' ? summary.run_id : ''
    const pointerGroupId = typeof summary.group_id === 'string' ? summary.group_id : ''
    // The manifest's own run id is the only honest attribution key. Without it
    // there is no telling which open run row this pointer belongs to, so it is
    // dropped rather than guessed -- a guessed pointer is a fake current plan.
    if (!pointerRunId) return { persisted: false, reason: 'no_run_id' }
    // A caller-supplied run must agree with the manifest's own run id.
    if (input.runId && input.runId !== pointerRunId) {
      return { persisted: false, reason: 'run_mismatch' }
    }
    if (!pointerMatchesJobContext({
      path: input.pointer.plan_manifest_path,
      projectId: input.projectId,
      runId: pointerRunId,
      groupId: pointerGroupId,
      tenant: input.tenant,
    })) {
      return { persisted: false, reason: 'context_mismatch' }
    }

    const data = {
      planManifestPath: input.pointer.plan_manifest_path,
      planManifestSha256: input.pointer.plan_manifest_sha256,
      planManifestSummary: input.pointer.plan_manifest_summary ?? {},
    }

    for (let attempt = 0; attempt < 2; attempt++) {
      const open = await prisma.scanJob.findFirst({
        where: {
          projectId: input.projectId,
          kind: input.kind,
          status: { in: ['running', 'queued'] },
          runId: pointerRunId,
        },
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          planManifestPath: true,
          planManifestSha256: true,
          planManifestSummary: true,
        },
      })
      if (!open) return { persisted: false, reason: 'no_open_job' }

      const existing = (open.planManifestSummary ?? null) as Record<string, unknown> | null
      const existingRunId = typeof existing?.run_id === 'string' ? existing.run_id : ''
      const existingMs = parseManifestTime(
        typeof existing?.created_at === 'string' ? existing.created_at : '',
      )
      const incomingMs = parseManifestTime(
        typeof summary.created_at === 'string' ? summary.created_at : '',
      )
      // A pointer left by another run is stale: this row is the current run's,
      // so the correct pointer replaces it. A pointer from the same run is
      // replaced only by one that is not older, so a late status poll cannot
      // regress the row to an earlier manifest. Recency is compared as parsed
      // epoch milliseconds -- `Z` and `+00:00` are the same instant, and a
      // lexical compare would misorder them. A known existing timestamp is
      // never treated as older than an incoming pointer with no timestamp.
      const stale = !open.planManifestPath || !existingRunId || existingRunId !== pointerRunId
      const notOlder = existingMs === null || (incomingMs !== null && incomingMs >= existingMs)
      if (!stale && !notOlder) return { persisted: false, reason: 'pointer_newer' }

      // Compare-and-set: the row must still be the open run row carrying the
      // exact pointer just read. The path alone is not enough -- a group's
      // path is stable while its digest and summary change, so two polls that
      // both read an older manifest would otherwise let the later writer
      // overwrite the newer one. Pin the digest (and the summary when present)
      // as well; a concurrent change makes count 0, and the loop re-reads and
      // decides on the new state instead of overwriting. When the row has no
      // pointer yet, pin null; the OR-null form is deliberately not used once a
      // pointer exists, because it would match a concurrent clear.
      const where: Prisma.ScanJobWhereInput = {
        id: open.id,
        projectId: input.projectId,
        kind: input.kind,
        runId: pointerRunId,
        status: { in: ['running', 'queued'] },
        planManifestPath: open.planManifestPath,
      }
      if (open.planManifestPath !== null) {
        where.planManifestSha256 = open.planManifestSha256
        if (open.planManifestSummary !== null) {
          where.planManifestSummary = {
            equals: open.planManifestSummary as Prisma.InputJsonValue,
          }
        }
      }
      const updated = await prisma.scanJob.updateMany({ where, data })
      if (updated.count > 0) return { persisted: true }
    }
    return { persisted: false, reason: 'no_open_job' }
  } catch (err) {
    console.error('[scanTimeline] could not persist plan manifest (continuing):', err)
    return { persisted: false, reason: 'db_error' }
  }
}

/**
 * Record a non-full-recon scan that the orchestrator just accepted.
 *
 * Deliberately never throws: history is a side effect of starting a scan, and a
 * failure to write it must not fail the start the operator asked for. Returns
 * the row's id, or null when it could not be written; the queue links its row
 * to it so the same scan is not listed twice.
 */
export async function recordScanStart(input: {
  projectId: string
  kind: string
  runId?: string
  initiatedByUserId?: string | null
  scheduleId?: string | null
  /** Defaults to 'scheduled' with a scheduleId, else 'manual'. */
  trigger?: ScanTrigger
  /** The roots the run covers (partial recon reports them). */
  targets?: string[]
  /** Read before the orchestrator was called, so a replace cannot misattribute the run. */
  roeTextSha256?: string | null
}): Promise<string | null> {
  try {
    const job = await createScanJob({
      projectId: input.projectId,
      versionId: null,
      kind: input.kind,
      runId: input.runId ?? '',
      targets: input.targets ?? [],
      roeTextSha256: input.roeTextSha256 ?? null,
      // These kinds do not version the graph, so there is no mode to record.
      trigger: input.trigger ?? (input.scheduleId ? 'scheduled' : 'manual'),
      mode: null,
      initiatedByUserId: input.initiatedByUserId ?? null,
      scheduleId: input.scheduleId ?? null,
    })
    return job.id
  } catch (err) {
    console.error(`[scanTimeline] could not record ${input.kind} start (continuing):`, err)
    return null
  }
}

/**
 * Close out the project's open ScanJob from an observed orchestrator status.
 *
 * The orchestrator owns scan liveness; we only mirror terminal states onto the
 * history row. Non-terminal states ('starting', 'running', 'paused', 'stopping')
 * are left alone. Best-effort: this runs inside a status poll and must never
 * break it.
 */
export async function reconcileScanJobStatus(
  projectId: string,
  reconStatus: string | undefined | null,
  opts: { kind?: string; runId?: string } = {}
): Promise<void> {
  const kind = opts.kind ?? 'full_recon'
  const mapped =
    reconStatus === 'completed' ? 'completed'
    : reconStatus === 'error' ? 'failed'
    : reconStatus === 'idle' ? 'canceled'
    : null
  if (!mapped) return

  try {
    // C-1: only ever close out a GENUINELY running job. A 'queued' row has no
    // container, so the orchestrator reports 'idle', which this function maps to
    // 'canceled' -- an ordinary browser status poll would then silently cancel a
    // queued scan just by looking at the page. The JobQueue row is the pending
    // record; a ScanJob exists only for an attempt that really started.
    const open = await prisma.scanJob.findFirst({
      // Scoped to the kind (and, where several can run at once, the run): closing
      // "the project's open job" from a GVM poll would otherwise end the full
      // recon's history row instead of GVM's.
      where: {
        projectId,
        kind,
        status: { in: ['running'] },
        ...(opts.runId ? { runId: opts.runId } : {}),
      },
      orderBy: { createdAt: 'desc' },
      select: { id: true, versionId: true },
    })
    if (!open) return

    const nodeCount = open.versionId
      ? (await prisma.scanVersion.findUnique({
          where: { id: open.versionId },
          select: { nodeCount: true },
        }))?.nodeCount ?? null
      : null

    // Stamp how many finding sources this run could not fully re-check, read
    // from the graph coverage record (the only reliable carrier). full_recon
    // only; null on any other kind or when coverage is unknown.
    const degradedSources =
      kind === 'full_recon' && mapped === 'completed'
        ? await readDegradedSourceCount(projectId)
        : null

    await prisma.scanJob.update({
      where: { id: open.id },
      data: { status: mapped, finishedAt: new Date(), nodeCount, degradedSources },
    })
  } catch (err) {
    console.error('[scanTimeline] scan-job reconcile failed (continuing):', err)
  }
}

/**
 * Close out the run-keyed kinds (partial_recon, ai_attack, trufflehog) from the
 * one list poll the UI already makes, instead of a status call per run.
 *
 * Only an explicitly TERMINAL live status closes a row. A run that has simply
 * disappeared from the orchestrator's list is left alone: it also disappears when
 * the orchestrator restarts, and calling that "completed" would invent an outcome.
 * Such a row is closed by the partial_recon / ai_attack stop route
 * (recordRunStopped) or, for every run-keyed kind, by the reaper's run-keyed
 * sweep (api/internal/job-queue/reconcile).
 */
export async function reconcileRunScanJobs(
  projectId: string,
  kind: string,
  runs: unknown
): Promise<void> {
  if (!Array.isArray(runs) || runs.length === 0) return
  try {
    const open = await prisma.scanJob.findMany({
      where: { projectId, kind, status: 'running' },
      select: { id: true, runId: true },
    })
    if (open.length === 0) return

    const liveStatus = new Map<string, string>()
    for (const r of runs) {
      const run = r as { run_id?: unknown; status?: unknown }
      if (typeof run?.run_id === 'string' && typeof run?.status === 'string') {
        liveStatus.set(run.run_id, run.status)
      }
    }

    await Promise.all(open.map(row => {
      const status = row.runId ? liveStatus.get(row.runId) : undefined
      const mapped =
        status === 'completed' ? 'completed'
        : status === 'error' ? 'failed'
        : null
      if (!mapped) return Promise.resolve()
      return prisma.scanJob.update({
        where: { id: row.id },
        data: { status: mapped, finishedAt: new Date() },
      })
    }))
  } catch (err) {
    console.error(`[scanTimeline] ${kind} run reconcile failed (continuing):`, err)
  }
}

/**
 * Close a run-keyed row from the orchestrator's answer to a Stop.
 *
 * The orchestrator drops a stopped run from its listing once the drain ends, so
 * the list reconcile never sees it end: this answer is the last word on it.
 * `stopping`, and `idle` (a run it no longer has), are canceled; a run that had
 * already ended keeps its real outcome. Never throws: the stop itself worked.
 */
export async function recordRunStopped(
  projectId: string,
  kind: string,
  runId: string,
  orchestratorStatus: unknown
): Promise<void> {
  const mapped =
    orchestratorStatus === 'completed' ? 'completed'
    : orchestratorStatus === 'error' ? 'failed'
    : orchestratorStatus === 'stopping' || orchestratorStatus === 'idle' ? 'canceled'
    : null
  if (!mapped || !runId) return
  try {
    await prisma.scanJob.updateMany({
      where: { projectId, kind, runId, status: 'running' },
      data: { status: mapped, finishedAt: new Date() },
    })
  } catch (err) {
    console.error(`[scanTimeline] could not close the stopped ${kind} run (continuing):`, err)
  }
}

export const VERSION_SELECT = {
  id: true,
  seq: true,
  label: true,
  isCurrent: true,
  pinned: true,
  nodeCount: true,
  linkCount: true,
  createdAt: true,
} as const
