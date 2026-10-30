import { NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../agentProxy'

const FAILED = 'Failed to fetch sessions'

export const GET = withRouteErrors(FAILED, async () => {
  const call = await callAgent('/sessions', { cache: 'no-store' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
