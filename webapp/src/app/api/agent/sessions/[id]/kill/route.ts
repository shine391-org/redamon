import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../../../agentProxy'

const FAILED = 'Failed to kill session'

export const POST = withRouteErrors(FAILED, async (
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const { id } = await params
  const call = await callAgent(`/sessions/${encodeURIComponent(id)}/kill`, { method: 'POST' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
