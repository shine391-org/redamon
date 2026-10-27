import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

const unavailable = () =>
  NextResponse.json({ model: null, error: 'The local judge model is unavailable' }, { status: 503 })

// GET /api/ai-attack-surface/{projectId}/judge-model
// The judge model the orchestrator pulls and checks (LOCAL_LLM_MODEL, from
// /local-llm/status), so the page starts from the backend's model rather than
// a literal of its own. Only the model name is passed on: the status also
// carries the container id, the base URL and the pulled models.
export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  try {
    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/local-llm/status`,
      { headers: { 'Content-Type': 'application/json' }, cache: 'no-store' },
      { timeoutMs: 10_000 },
    )
    if (!response.ok) return unavailable()
    const status = await response.json() as { model?: unknown }
    const model = typeof status?.model === 'string' ? status.model.trim() : ''
    if (!model) return unavailable()
    return NextResponse.json({ model })
  } catch {
    return unavailable()
  }
}
