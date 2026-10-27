import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'
import { RECON_TOTAL_PHASES } from '@/lib/recon-types'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Call recon orchestrator to get status
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to get recon status' },
        { status: response.status }
      )
    }

    const data = await response.json()

    // Scan Timeline: mirror a terminal orchestrator status onto the open ScanJob
    // history row. The orchestrator remains the source of truth for liveness;
    // this is best-effort bookkeeping and never affects the response.
    await reconcileScanJobStatus(projectId, data?.status)

    return NextResponse.json(data)

  } catch (error) {
    console.error('Error getting recon status:', error)

    // If orchestrator is not available, return idle status
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return NextResponse.json({
        project_id: (await params).projectId,
        status: 'idle',
        current_phase: null,
        phase_number: null,
        total_phases: RECON_TOTAL_PHASES,
        started_at: null,
        completed_at: null,
        error: null,
      })
    }

    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
