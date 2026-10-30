import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

const FAILED = 'Failed to fetch jobs'

export const GET = withRouteErrors(FAILED, async (request: NextRequest) => {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  const active = request.nextUrl.searchParams.get('active')  // 'true' | 'false' | null

  if (!projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }

  let url = `/workspace/jobs?projectId=${encodeURIComponent(projectId)}`
  if (active !== null) url += `&active=${encodeURIComponent(active)}`
  const call = await callAgent(url, { cache: 'no-store' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
