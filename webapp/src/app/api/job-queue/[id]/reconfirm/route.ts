/**
 * Scan Queue - re-confirm a needs_review job (plan Phase 5, C-4).
 *
 * A job moves to needs_review when its scan settings changed between enqueue and
 * dispatch. Re-confirming accepts the CURRENT configuration: recompute the
 * fingerprint from the live project and requeue. Object-level authz as in cancel:
 * projectId is re-resolved from the row and guardProject-ed (404 on non-ownership).
 *
 * An AI attack-surface launch also carries `roe_confirmed`: the person's
 * statement that its targets are within the Rules of Engagement. Settings that
 * changed since the job was queued (a replaced RoE among them) void that
 * statement, so the flag is cleared and the job stays held until the request
 * confirms the RoE again (`{ roeConfirmed: true }`).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { guardProject } from '@/lib/access'
import { currentFingerprintFor } from '@/lib/jobFingerprint'
import { internalError } from '@/lib/routeErrors'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json().catch(() => null) as { roeConfirmed?: unknown } | null
    const row = await prisma.jobQueue.findUnique({ where: { id } })
    if (!row) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    const denied = await guardProject(row.projectId)
    if (denied) return denied

    if (row.status !== 'needs_review') {
      return NextResponse.json(
        { error: `Only a job awaiting review can be re-confirmed (state '${row.status}').`, status: row.status },
        { status: 409 },
      )
    }

    const project = await prisma.project.findUnique({ where: { id: row.projectId } })
    if (!project) {
      // The project is gone; there is nothing to run. Fail the row.
      await prisma.jobQueue.update({
        where: { id },
        data: { status: 'failed', error: 'project no longer exists', finishedAt: new Date() },
      })
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    // Both contributions, exactly as enqueue and dispatch compute them. Folding
    // in only the TruffleHog half stored a hash the dispatcher could not
    // reproduce for a full_recon or partial_recon job, whose auth profile is a
    // relation the Project-row fingerprint cannot see: the job was re-confirmed,
    // dispatched, failed the comparison and went straight back to needs_review,
    // with no way out for anyone.
    let payload = row.payload
    if (row.kind === 'ai_attack' && row.blockedCode === 'settings_changed') {
      const current = (row.payload && typeof row.payload === 'object' ? row.payload : {}) as Record<string, unknown>
      if (body?.roeConfirmed !== true) {
        await prisma.jobQueue.update({ where: { id }, data: { payload: { ...current, roe_confirmed: false } } })
        return NextResponse.json(
          {
            error:
              'The project settings changed since this AI attack scan was queued. Confirm again that its ' +
              'targets are within the current Rules of Engagement before it runs.',
            code: 'roe_confirmation_required',
          },
          { status: 409 },
        )
      }
      payload = { ...current, roe_confirmed: true }
    }

    const settingsHash = await currentFingerprintFor(row, project as unknown as Record<string, unknown>)
    await prisma.jobQueue.update({
      where: { id },
      data: {
        status: 'queued',
        payload: payload ?? undefined,
        settingsHash, // accept the CURRENT configuration
        blockedCode: '',
        blockedReason: '',
        notBefore: null,
      },
    })
    return NextResponse.json({ ok: true })
  } catch (error) {
    return internalError(error, 'Could not re-confirm the job', { log: '[jobQueue] reconfirm failed' })
  }
}
