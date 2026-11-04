import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

const FAILED = 'Failed to fetch properties'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  const path = request.nextUrl.searchParams.get('path')

  if (!projectId || !path) {
    return NextResponse.json({ error: 'projectId, path required' }, { status: 400 })
  }

  const call = await callAgent(
    `/workspace/properties?projectId=${encodeURIComponent(projectId)}&path=${encodeURIComponent(path)}`,
    { cache: 'no-store' },
    FAILED,
  )
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
