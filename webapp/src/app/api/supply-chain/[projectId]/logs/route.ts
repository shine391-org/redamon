import { NextRequest } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const FAILED = 'Failed to connect to Supply-Chain log stream'

interface RouteParams { params: Promise<{ projectId: string }> }

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    let response: Response
    try {
      response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/supply-chain/${projectId}/logs`, {
        headers: { 'Accept': 'text/event-stream' }, signal: request.signal,
      })
    } catch (error) {
      return upstreamFailureResponse('orchestrator', error, FAILED)
    }
    if (!response.ok) {
      return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
    }
    return new Response(response.body, {
      headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', 'Connection': 'keep-alive' },
    })
  } catch (error) {
    return internalError(error, FAILED)
  }
}
