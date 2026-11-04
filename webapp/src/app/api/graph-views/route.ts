import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, projectId)
    if (access instanceof NextResponse) return access

    const views = await prisma.graphView.findMany({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
    })
    return NextResponse.json(views)
  } catch (error) {
    return internalError(error, 'Failed to fetch graph views')
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, name, description, cypherQuery } = body

    if (!projectId || !name?.trim() || !cypherQuery?.trim()) {
      return NextResponse.json(
        { error: 'projectId, name, and cypherQuery are required' },
        { status: 400 }
      )
    }

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, projectId)
    if (access instanceof NextResponse) return access

    const view = await prisma.graphView.create({
      data: {
        projectId,
        name: name.trim(),
        description: description || '',
        cypherQuery,
      },
    })

    return NextResponse.json(view, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create graph view')
  }
}
