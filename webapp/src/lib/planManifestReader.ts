/** G2-R3: read back a run's plan manifest through the orchestrator reader.
 *
 * The manifest itself lives on the recon output volume; the webapp never reads
 * it directly. Instead it asks the orchestrator to validate the persisted
 * pointer (path + sha256 + expected job context) against the file via the
 * manifest helper's ``read_manifest_in_context``. Missing, incomplete,
 * unsupported, tampered or cross-tenant / cross-run / cross-group reads yield
 * ``{"status": "unknown"}`` -- never a guessed clean plan.
 */
import { orchestratorFetch } from '@/lib/orchestrator'

export interface PlanManifestRead {
  status: 'known' | 'unknown'
  reason?: string
  [key: string]: unknown
}

interface ScanJobLike {
  planManifestPath?: string | null
  planManifestSha256?: string | null
  // Prisma JSON columns may contain any JSON value; validate at the boundary.
  planManifestSummary?: unknown
  runId?: string
}

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export async function readPlanManifest(
  projectId: string,
  job: ScanJobLike,
  projectUserId: string | null = null,
): Promise<PlanManifestRead> {
  const path = job.planManifestPath ?? null
  const sha256 = job.planManifestSha256 ?? null
  if (!path || !sha256) {
    return { status: 'unknown', reason: 'no_manifest_pointer' }
  }
  const rawSummary = job.planManifestSummary
  if (rawSummary != null && (typeof rawSummary !== 'object' || Array.isArray(rawSummary))) {
    return { status: 'unknown', reason: 'invalid_manifest_summary' }
  }
  const summary = (rawSummary ?? {}) as Record<string, unknown>
  const runId = typeof summary.run_id === 'string' ? summary.run_id : (job.runId ?? '')
  const groupId = typeof summary.group_id === 'string' ? summary.group_id : ''
  const query = new URLSearchParams({
    path,
    sha256,
    tenant: projectUserId ?? '',
    run_id: runId,
    group_id: groupId,
  })

  let response: Response
  try {
    response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/recon/${projectId}/plan-manifest?${query}`,
      { method: 'GET', headers: { 'Content-Type': 'application/json' } },
    )
  } catch (err) {
    return { status: 'unknown', reason: 'orchestrator_unreachable' }
  }
  if (!response.ok) {
    return { status: 'unknown', reason: `orchestrator_${response.status}` }
  }
  try {
    return (await response.json()) as PlanManifestRead
  } catch (err) {
    return { status: 'unknown', reason: 'orchestrator_unreadable' }
  }
}
