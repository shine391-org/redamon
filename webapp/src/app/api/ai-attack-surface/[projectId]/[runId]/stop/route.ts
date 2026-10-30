import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { internalError, upstreamErrorResponse, upstreamFailureResponse } from '@/lib/routeErrors'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

const FAILED = 'Failed to stop AI Gauntlet scan'

// POST /api/ai-attack-surface/{projectId}/{runId}/stop
export async function POST(_request: NextRequest, { params }: RouteParams) {
  const { projectId, runId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/${runId}/stop`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' } },
    )
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, FAILED)
  }
  if (!response.ok) {
    return upstreamErrorResponse('orchestrator', response, FAILED, { forwardText: true })
  }
  try {
    return NextResponse.json(await response.json())
  } catch (err) {
    return internalError(err, FAILED)
  }
}
