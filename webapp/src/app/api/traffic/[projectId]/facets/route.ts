import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { requireEffectiveUser, requireProjectAccess, ownerScope } from '@/lib/access'

// GET /api/traffic/[projectId]/facets - distinct values for the filter dropdowns
// (tools, hosts, runs, sessions), scoped to the caller's own rows in this project.
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  try {
    const { projectId } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, projectId)
    if (access instanceof NextResponse) return access

    const where = { projectId, ...ownerScope(eff) }

    const [tools, hosts, runs, sessions] = await Promise.all([
      prisma.capturedHttpTransaction.findMany({
        where: { ...where, tool: { not: null } },
        distinct: ['tool'],
        select: { tool: true },
        orderBy: { tool: 'asc' },
        take: 200,
      }),
      prisma.capturedHttpTransaction.findMany({
        where,
        distinct: ['host'],
        select: { host: true },
        orderBy: { host: 'asc' },
        take: 500,
      }),
      prisma.capturedHttpTransaction.findMany({
        where: { ...where, runId: { not: null } },
        distinct: ['runId'],
        select: { runId: true },
        orderBy: { runId: 'asc' },
        take: 200,
      }),
      prisma.capturedHttpTransaction.findMany({
        where: { ...where, sessionId: { not: null } },
        distinct: ['sessionId'],
        select: { sessionId: true },
        orderBy: { sessionId: 'asc' },
        take: 200,
      }),
    ])

    return NextResponse.json({
      tools: tools.map(t => t.tool).filter(Boolean),
      hosts: hosts.map(h => h.host).filter(Boolean),
      runs: runs.map(r => r.runId).filter(Boolean),
      sessions: sessions.map(s => s.sessionId).filter(Boolean),
    })
  } catch (error) {
    return internalError(error, 'Failed to load facets', { log: 'Failed to load traffic facets' })
  }
}
