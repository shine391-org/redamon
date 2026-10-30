import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

const FAILED = 'Failed to fetch tree'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  const path = request.nextUrl.searchParams.get('path') ?? '.'
  const maxDepth = request.nextUrl.searchParams.get('maxDepth') ?? '3'
  const maxEntries = request.nextUrl.searchParams.get('maxEntries') ?? '500'

  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }

  const call = await callAgent(
    `/workspace/tree?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}&maxDepth=${encodeURIComponent(maxDepth)}&maxEntries=${encodeURIComponent(maxEntries)}`,
    { cache: 'no-store' },
    FAILED,
  )
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
