import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { readUpstreamBody, upstreamFailure } from '@/lib/routeErrors'

const RECON_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://recon-orchestrator:8010'

/** Why a pipeline's state is unknown. A failure must not read as "idle": a running scan would look finished. */
interface UnreachablePipeline {
  reachable: false
  code: string
  upstreamStatus?: number
}

async function fetchStatus(url: string, label: string): Promise<Record<string, unknown> | UnreachablePipeline> {
  let res: Response
  try {
    res = await orchestratorFetch(url, { cache: 'no-store' })
  } catch (err) {
    console.error(`${label} status unavailable:`, err)
    return { reachable: false, code: upstreamFailure('orchestrator', err, '').body.code }
  }
  if (!res.ok) {
    const body = await readUpstreamBody(res)
    console.error(`${label} status unavailable: orchestrator answered HTTP ${res.status}`)
    return { reachable: false, code: body.code ?? 'orchestrator_error', upstreamStatus: res.status }
  }
  try {
    return await res.json()
  } catch (err) {
    console.error(`${label} status unavailable: unreadable body`, err)
    return { reachable: false, code: 'invalid_json', upstreamStatus: res.status }
  }
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const [recon, gvm, githubHunt] = await Promise.all([
    fetchStatus(`${RECON_URL}/recon/${projectId}/status`, 'Recon'),
    fetchStatus(`${RECON_URL}/gvm/${projectId}/status`, 'GVM'),
    fetchStatus(`${RECON_URL}/github-hunt/${projectId}/status`, 'GitHub Hunt'),
  ])

  return NextResponse.json({ recon, gvm, githubHunt })
}
