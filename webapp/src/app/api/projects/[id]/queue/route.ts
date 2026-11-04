/**
 * Scan Queue - enqueue a scan for this project (Scan Queue plan Phase 3).
 *
 * The refusal modal calls this when the operator chooses "Add to queue" after a
 * temporary start failure. Project-scoped, so guardProject runs FIRST (Section 4:
 * a JobQueue id must never be sufficient; object-level authz is the guard, not the
 * row). Queueing is always the operator's explicit choice (R3).
 */
import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { getEffectiveUser } from '@/lib/session'
import { enqueueJob } from '@/lib/enqueueJob'
import { internalError } from '@/lib/routeErrors'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: projectId } = await params
    const denied = await guardProject(projectId)
    if (denied) return denied

    const eff = await getEffectiveUser()
    if (!eff?.userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json().catch(() => ({}))
    const kind = typeof body?.kind === 'string' ? body.kind : ''
    const payload = body?.payload && typeof body.payload === 'object' ? body.payload : {}

    const result = await enqueueJob({
      projectId,
      userId: eff.userId,
      kind,
      payload,
      priority: 10, // manual
    })

    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: result.status })
    }
    return NextResponse.json({ ok: true, id: result.id }, { status: 201 })
  } catch (error) {
    return internalError(error, 'Could not add this scan to the queue', { log: '[jobQueue] enqueue failed' })
  }
}
