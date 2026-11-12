import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'
import { acquireActivationLock, releaseActivationLock } from '@/lib/activationLock'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { loadEngagement, currentAuthorization } from '@/lib/engagement'
import { settingsFingerprint } from '@/lib/jobQueue'
import { sanitizeReconDiagnostics, validReconId } from '@/lib/reconDiagnostics'
import { upstreamFailureResponse } from '@/lib/routeErrors'

const base = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const refuse = (error: string, status = 409) => NextResponse.json({ error }, { status })

export async function reconOwner(projectId: string) {
  if (!validReconId(projectId)) return refuse('Invalid project', 400)
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  // Strict even when the legacy bulk access guard is in log-only mode.
  const project = await prisma.project.findUnique({ where: { id: projectId } })
  if (!project || project.userId !== eff.userId) return refuse('Not found', 404)
  return project
}

export async function readReconDiagnostics(projectId: string, runId: string | null) {
  const project = await reconOwner(projectId)
  if (project instanceof NextResponse) return project
  if (runId !== null && !validReconId(runId)) return refuse('Invalid run', 400)
  try {
    const res = await orchestratorFetch(`${base}/recon/${encodeURIComponent(projectId)}/diagnostics${runId ? `?run_id=${encodeURIComponent(runId)}` : ''}`, { cache: 'no-store' })
    if (!res.ok) return refuse('Recon diagnostics unavailable', res.status >= 500 ? 502 : res.status)
    const text = await res.text()
    if (text.length > 256 * 1024) return refuse('Recon diagnostics unavailable', 502)
    return NextResponse.json(sanitizeReconDiagnostics(JSON.parse(text)), { headers: { 'Cache-Control': 'no-store' } })
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, 'Recon diagnostics unavailable')
  }
}

export async function continueRecon(projectId: string, body: unknown) {
  const project = await reconOwner(projectId)
  if (project instanceof NextResponse) return project
  if (!body || typeof body !== 'object' || Array.isArray(body)) return refuse('Explicit confirmation required', 400)
  const input = body as Record<string, unknown>
  if (!validReconId(input.run_id) || input.confirm !== true || Object.keys(input).some(k => !['run_id', 'confirm'].includes(k))) {
    return refuse('Explicit confirmation and same run required', 400)
  }
  const runId = input.run_id
  // This existing CAS lock excludes graph activation and all normal start paths.
  // It is held only through admission; the RUNNING scan then holds the graph.
  const lock = await acquireActivationLock(projectId, `continue:${runId}`)
  if (!lock.acquired) return refuse('Graph activation or continuation busy')
  try {
    if (await describeLiveGraphWriters(projectId)) return refuse('Project has active or unverifiable writers')
    const job = await prisma.scanJob.findFirst({ where: { projectId, kind: 'full_recon' }, orderBy: { createdAt: 'desc' }, include: { version: true } })
    const manifest = job?.planManifestSummary as Record<string, unknown> | null
    if (!job || !job.version?.isCurrent || (job.runId || manifest?.run_id) !== runId) return refuse('Run is not the current graph version')
    if (!job.settingsHash || job.settingsHash !== settingsFingerprint('full_recon', project as unknown as Record<string, unknown>)) return refuse('Run settings changed')
    const engagement = await loadEngagement(projectId)
    if (engagement.blockers.length) return refuse('Engagement authorization is not startable', 403)
    if ((await currentAuthorization(projectId))?.id !== (job.authorizationId ?? undefined)) return refuse('Run authorization changed', 403)
    const response = await orchestratorFetch(`${base}/recon/${encodeURIComponent(projectId)}/continue`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ run_id: runId, confirm: true, user_id: project.userId }),
    })
    if (!response.ok) return refuse('Continuation refused: state incompatible, outside RoE window, or busy', response.status >= 500 ? 502 : response.status)
    const state = await response.json()
    if (state.status !== 'running' || state.run_id !== runId) return refuse('Continuation outcome unverified; check status before retrying', 502)
    // Update the SAME job/version; never freeze, rotate, clear, or create a run.
    await prisma.scanJob.update({ where: { id: job.id }, data: { status: 'running', finishedAt: null } })
    return NextResponse.json({ status: 'running', run_id: runId, scope: 'group6_phase_a' })
  } catch (err) {
    return upstreamFailureResponse('orchestrator', err, 'Continuation outcome unknown; check status before retrying')
  } finally {
    await releaseActivationLock(projectId)
  }
}
