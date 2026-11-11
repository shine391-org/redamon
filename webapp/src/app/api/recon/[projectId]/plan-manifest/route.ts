/** G2-R3: read back a run's plan manifest, validated against the job context.
 *
 * Returns the manifest (status 'known') only when the persisted pointer's
 * path/sha256 and the expected tenant/project/run/group all match the file on
 * disk; otherwise status 'unknown'. Best-effort: never breaks the page.
 */
import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { readPlanManifest } from '@/lib/planManifestReader'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { userId: true },
    })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const job = await prisma.scanJob.findFirst({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
      select: {
        planManifestPath: true,
        planManifestSha256: true,
        planManifestSummary: true,
        runId: true,
      },
    })

  const read = await readPlanManifest(
    projectId,
    {
      planManifestPath: job?.planManifestPath ?? null,
      planManifestSha256: job?.planManifestSha256 ?? null,
      planManifestSummary: job?.planManifestSummary ?? undefined,
      runId: job?.runId ?? undefined,
    },
    project.userId ?? null,
  )

    return NextResponse.json(read)
  } catch (error) {
    return internalError(error, 'Failed to read plan manifest', { log: 'Error reading plan manifest' })
  }
}
