import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { internalError } from '@/lib/routeErrors'
import { writeAudit } from '@/lib/audit'
import { actingAdminId } from '@/lib/roe/actor'
import { attachmentDisposition, downloadContentType } from '@/lib/roe/limits'

// GET /api/projects/[id]/roe/download - Download the original RoE document
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    // The document names the client, their contacts and what may be attacked:
    // it is the owner's, like every other project read.
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    const project = await prisma.project.findUnique({
      where: { id },
      select: {
        roeDocumentData: true,
        roeDocumentName: true,
        roeDocumentMimeType: true,
      },
    })

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    if (!project.roeDocumentData) {
      return NextResponse.json({ error: 'No RoE document uploaded' }, { status: 404 })
    }

    const fileName = project.roeDocumentName || 'roe-document'

    await writeAudit({
      actorId: eff.userId,
      action: 'project.roe.download',
      targetType: 'project',
      targetId: id,
      after: {
        documentName: fileName,
        bytes: project.roeDocumentData.length,
        actingAdminId: await actingAdminId(eff),
      },
    })

    return new NextResponse(project.roeDocumentData, {
      headers: {
        'Content-Type': downloadContentType(project.roeDocumentMimeType),
        'Content-Disposition': attachmentDisposition(fileName),
        'Content-Length': String(project.roeDocumentData.length),
        'X-Content-Type-Options': 'nosniff',
      },
    })
  } catch (error) {
    return internalError(error, 'Failed to download RoE document', { log: 'RoE download error' })
  }
}
