/**
 * Scan Timeline - Scan Scheduler run history maintenance.
 *
 * DELETE /api/projects/[id]/schedules/history
 *   body { ids: string[] }  delete exactly those run-history rows (multi-select)
 *   body {} or no body      clear the whole run history for the project
 *
 * Deleting a ScanJob only removes the history ROW. It does not touch the versions,
 * the schedules, or a scan that is actually running (the orchestrator owns scan
 * liveness); a deleted in-flight row simply stops appearing in the table.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { writeAudit } from '@/lib/audit'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string }>
}

export const DELETE = withRouteErrors('Failed to clear run history', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  const body = await request.json().catch(() => ({}))
  const rawIds = (body as { ids?: unknown })?.ids
  const ids = Array.isArray(rawIds)
    ? rawIds.filter((x): x is string => typeof x === 'string')
    : null

  // Scope every delete to this project so a stray id can never remove another
  // project's history.
  const where = ids && ids.length > 0
    ? { projectId: id, id: { in: ids } }
    : { projectId: id }

  try {
    // The history table lists finished queue jobs alongside ScanJobs (they are the
    // only record of a non-full-recon run), so a selected id can be either. Only
    // TERMINAL queue rows are deletable: a queued or running job is live state, and
    // dropping its row would orphan the scan the dispatcher is about to start.
    const [result, queueResult] = await Promise.all([
      prisma.scanJob.deleteMany({ where }),
      prisma.jobQueue.deleteMany({
        where: { ...where, status: { in: ['done', 'failed', 'canceled'] } },
      }),
    ])
    const deleted = result.count + queueResult.count
    await writeAudit({
      actorId: eff.userId,
      action: 'scan-job.history-clear',
      targetType: 'project',
      targetId: id,
      after: { deleted, scope: ids ? 'selected' : 'all' },
    })
    return NextResponse.json({ ok: true, deleted })
  } catch (error) {
    return internalError(error, 'Failed to clear run history', { log: '[scanTimeline] run-history delete failed' })
  }
})
