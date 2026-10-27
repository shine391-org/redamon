import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { reconcileScanJobStatus } from '@/lib/scanTimeline'
import { orchestratorFetch } from '@/lib/orchestrator'
import { GITHUB_HUNT_PHASES } from '@/lib/recon-types'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied

    // Call recon orchestrator to get GitHub hunt status
    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/github-hunt/${projectId}/status`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to get GitHub hunt status' },
        { status: response.status }
      )
    }

    const data = await response.json()
    // The orchestrator owns liveness; this only mirrors a TERMINAL state onto the
    // history row, so the run stops reading as running once it ends.
    await reconcileScanJobStatus(projectId, data?.status, { kind: 'github_hunt' })
    return NextResponse.json(data)

  } catch (error) {
    console.error('Error getting GitHub hunt status:', error)

    // If orchestrator is not available, return idle status
    if (error instanceof TypeError && error.message.includes('fetch')) {
      return NextResponse.json({
        project_id: (await params).projectId,
        status: 'idle',
        current_phase: null,
        phase_number: null,
        total_phases: GITHUB_HUNT_PHASES.length,
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
