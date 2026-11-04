/**
 * Scan Queue - cancel a queued / needs_review job (plan Phase 5, Section 4).
 *
 * Object-level authz is enforced by re-resolving the projectId FROM THE ROW and
 * then guardProject-ing it, so a JobQueue id is never sufficient: guessing an id
 * that belongs to another tenant yields a 404 (anti-enumeration), never a cancel.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { guardProject } from '@/lib/access'
import { internalError } from '@/lib/routeErrors'

export const runtime = 'nodejs'

const CANCELLABLE = new Set(['queued', 'dispatching', 'needs_review'])

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const row = await prisma.jobQueue.findUnique({
      where: { id },
      select: { id: true, projectId: true, status: true },
    })
    // 404 whether the row is missing OR the caller cannot access its project.
    if (!row) return NextResponse.json({ error: 'Not found' }, { status: 404 })
    const denied = await guardProject(row.projectId)
    if (denied) return denied

    if (!CANCELLABLE.has(row.status)) {
      return NextResponse.json(
        { error: `Cannot cancel a job in state '${row.status}'. Stop the running scan instead.`, status: row.status },
        { status: 409 },
      )
    }

    await prisma.jobQueue.updateMany({
      where: { id, status: { in: [...CANCELLABLE] } },
      data: { status: 'canceled', finishedAt: new Date(), blockedCode: '', blockedReason: '' },
    })
    return NextResponse.json({ ok: true })
  } catch (error) {
    return internalError(error, 'Could not cancel the job', { log: '[jobQueue] cancel failed' })
  }
}
