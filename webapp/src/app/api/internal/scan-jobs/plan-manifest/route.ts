/** G2-R3: persist a plan-manifest pointer on a project's open ScanJob row.
 *
 * The recon container (which holds the scoped SCANNER_API_KEY) posts the
 * pointer it wrote to the run-scoped manifest here, right after the manifest
 * file is durably on disk and before the vuln_scan tool launches. The webapp
 * is the single writer of ScanJob history, so this internal endpoint is the
 * only place the pointer reaches the row.
 *
 * Authorized callers: INTERNAL_API_KEY (orchestrator/scheduler) and
 * SCANNER_API_KEY (the recon container) on this route only.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest, isScannerRequest } from '@/lib/session'
import { persistPlanManifest } from '@/lib/scanTimeline'

export const runtime = 'nodejs'

interface Pointer {
  plan_manifest_path: string
  plan_manifest_sha256: string
  plan_manifest_summary?: Record<string, unknown>
}

interface Body {
  projectId: string
  kind?: string
  runId?: string
  pointer: Pointer
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  if (!isInternalRequest(request) && !isScannerRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const body = (await request.json().catch(() => null)) as Body | null
  if (!body || typeof body.projectId !== 'string' || !body.pointer) {
    return NextResponse.json({ error: 'Bad request' }, { status: 400 })
  }
  const p = body.pointer as Pointer
  if (typeof p.plan_manifest_path !== 'string' ||
      typeof p.plan_manifest_sha256 !== 'string') {
    return NextResponse.json({ error: 'Bad request' }, { status: 400 })
  }

  await persistPlanManifest({
    projectId: body.projectId,
    kind: typeof body.kind === 'string' ? body.kind : 'full_recon',
    runId: typeof body.runId === 'string' ? body.runId : undefined,
    pointer: {
      plan_manifest_path: p.plan_manifest_path,
      plan_manifest_sha256: p.plan_manifest_sha256,
      plan_manifest_summary: p.plan_manifest_summary ?? {},
    },
  })

  return NextResponse.json({ ok: true })
}
