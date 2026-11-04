import { NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { agentErrorResponse, callAgent } from '../agentProxy'

const FAILED = 'Failed to stop agents'

export const POST = withRouteErrors(FAILED, async () => {
  // D7/S8: /emergency-stop-all requires internal auth; agentFetch presents the
  // master INTERNAL_API_KEY the webapp already holds.
  const call = await callAgent('/emergency-stop-all', { method: 'POST' }, FAILED)
  if (!call.ok) return call.response
  if (!call.res.ok) return agentErrorResponse(call.res, FAILED)
  return NextResponse.json(await call.res.json())
})
