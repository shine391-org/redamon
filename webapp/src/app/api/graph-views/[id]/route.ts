import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectScopedResource } from '@/lib/access'

// A graph view is owned via its parent project.
async function guardView(id: string): Promise<NextResponse | null> {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const guard = await requireProjectScopedResource(eff, async () => {
    const v = await prisma.graphView.findUnique({ where: { id }, select: { projectId: true } })
    return v?.projectId
  })
  return guard instanceof NextResponse ? guard : null
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params
  try {
    const denied = await guardView(id)
    if (denied) return denied

    const body = await request.json()
    const { name, description } = body

    const view = await prisma.graphView.update({
      where: { id },
      data: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
      },
    })

    return NextResponse.json(view)
  } catch (error) {
    return internalError(error, 'Failed to update graph view')
  }
}

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params

  try {
    const denied = await guardView(id)
    if (denied) return denied

    await prisma.graphView.delete({ where: { id } })
    return NextResponse.json({ success: true })
  } catch (error) {
    return internalError(error, 'Failed to delete graph view')
  }
}
