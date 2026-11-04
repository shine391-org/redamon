import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../agentProxy'

const FAILED = 'Failed to reset'

export const POST = withRouteErrors(FAILED, async (request: NextRequest) => {
  let body: { projectId?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 })
  }
  if (!body.projectId) {
    return NextResponse.json({ error: 'projectId required' }, { status: 400 })
  }
  const __denied = await guardProject(body.projectId || '')
  if (__denied) return __denied

  const call = await callAgent('/workspace/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
