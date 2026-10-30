import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { internalError } from '@/lib/routeErrors'

// GET /api/projects/[id]/roe/revisions - The superseded RoE documents, newest first.
// Metadata only: the bytes come from .../revisions/[revId]/download.
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    const revisions = await prisma.roeDocumentRevision.findMany({
      where: { projectId: id },
      orderBy: { supersededAt: 'desc' },
      select: {
        id: true, documentName: true, mimeType: true, bytesSha256: true, textSha256: true,
        appliedAt: true, supersededAt: true, supersededById: true, reason: true,
      },
    })
    return NextResponse.json({ revisions })
  } catch (error) {
    return internalError(error, 'Failed to list RoE revisions', { log: 'RoE revisions error' })
  }
}
