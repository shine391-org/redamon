/**
 * POST /api/internal/scan-jobs/plan-manifest — the recon container's pointer
 * write. The route is the only writer of a ScanJob plan-manifest pointer, so
 * it must resolve the tenant from the project (never the body) and reject a
 * pointer that names another project, run or tenant instead of silently
 * dropping it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  isInternal: vi.fn(),
  isScanner: vi.fn(),
  projectFindUnique: vi.fn(),
  scanJobFindFirst: vi.fn(),
  scanJobUpdateMany: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    scanJob: {
      findFirst: (...a: unknown[]) => h.scanJobFindFirst(...a),
      updateMany: (...a: unknown[]) => h.scanJobUpdateMany(...a),
    },
  },
}))
vi.mock('@/lib/session', () => ({
  isInternalRequest: (...a: unknown[]) => h.isInternal(...a),
  isScannerRequest: (...a: unknown[]) => h.isScanner(...a),
}))

import { POST } from './route'

const PATH = (runId: string, projectId = 'p1', tenant = 't1', group = 'g1') =>
  `/out/planner_manifests/${tenant}/${projectId}/${runId}/${group}/plan_manifest.json`
const pointer = (runId: string, extra: Record<string, unknown> = {}) => ({
  plan_manifest_path: PATH(runId),
  plan_manifest_sha256: 'a'.repeat(64),
  plan_manifest_summary: { run_id: runId, group_id: 'g1', created_at: '2026-01-02T00:00:00Z', ...extra },
})

function post(body: unknown): NextRequest {
  return new NextRequest('http://webapp/api/internal/scan-jobs/plan-manifest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-internal-key': 'k' },
    body: JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.isInternal.mockReturnValue(true)
  h.isScanner.mockReturnValue(false)
  h.projectFindUnique.mockResolvedValue({ userId: 't1' })
  h.scanJobFindFirst.mockResolvedValue({
    id: 'j1', planManifestPath: null, planManifestSummary: null,
  })
  h.scanJobUpdateMany.mockResolvedValue({ count: 1 })
})

describe('POST /api/internal/scan-jobs/plan-manifest', () => {
  test('rejects a caller with neither the internal nor the scanner key', async () => {
    h.isInternal.mockReturnValue(false)
    h.isScanner.mockReturnValue(false)
    const res = await POST(post({ projectId: 'p1', pointer: pointer('run9') }))
    expect(res.status).toBe(401)
    expect(h.projectFindUnique).not.toHaveBeenCalled()
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('rejects a body with no project or pointer', async () => {
    expect((await POST(post({}))).status).toBe(400)
    expect((await POST(post({ projectId: 'p1' }))).status).toBe(400)
    expect((await POST(post({ projectId: 'p1', pointer: { plan_manifest_path: '/x' } }))).status).toBe(400)
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('rejects an unknown project before touching a scan job', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    const res = await POST(post({ projectId: 'p1', pointer: pointer('run9') }))
    expect(res.status).toBe(404)
    expect(h.scanJobFindFirst).not.toHaveBeenCalled()
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('persists the pointer with the tenant resolved from the project', async () => {
    const res = await POST(post({
      projectId: 'p1', kind: 'full_recon', runId: 'run9', pointer: pointer('run9'),
    }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
    expect(h.scanJobUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ runId: 'run9', kind: 'full_recon' }),
      data: expect.objectContaining({
        planManifestPath: PATH('run9'),
        planManifestSha256: 'a'.repeat(64),
      }),
    }))
  })

  test('a run-keyed kind is persisted on that run\'s row', async () => {
    const res = await POST(post({
      projectId: 'p1', kind: 'partial_recon', runId: 'r1', pointer: pointer('r1'),
    }))
    expect(res.status).toBe(200)
    expect(h.scanJobUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ runId: 'r1', kind: 'partial_recon' }),
    }))
  })

  test('rejects a pointer whose path names another project', async () => {
    const res = await POST(post({
      projectId: 'p1', kind: 'full_recon', runId: 'run9',
      pointer: { ...pointer('run9'), plan_manifest_path: PATH('run9', 'p2') },
    }))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ ok: false, reason: 'context_mismatch' })
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('rejects a pointer whose path names another run', async () => {
    const res = await POST(post({
      projectId: 'p1', kind: 'full_recon', runId: 'run9',
      pointer: { ...pointer('run9'), plan_manifest_path: PATH('runPATH') },
    }))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ ok: false, reason: 'context_mismatch' })
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('rejects a pointer whose path names another tenant', async () => {
    const res = await POST(post({
      projectId: 'p1', kind: 'full_recon', runId: 'run9',
      pointer: { ...pointer('run9'), plan_manifest_path: PATH('run9', 'p1', 't2') },
    }))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ ok: false, reason: 'context_mismatch' })
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('rejects a caller run id that disagrees with the manifest', async () => {
    const res = await POST(post({
      projectId: 'p1', kind: 'full_recon', runId: 'runCALLER', pointer: pointer('run9'),
    }))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ ok: false, reason: 'run_mismatch' })
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('rejects (does not silently drop) a pointer with no open run row', async () => {
    h.scanJobFindFirst.mockResolvedValue(null)
    const res = await POST(post({
      projectId: 'p1', kind: 'full_recon', runId: 'run9', pointer: pointer('run9'),
    }))
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ ok: false, reason: 'no_open_job' })
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })
})
