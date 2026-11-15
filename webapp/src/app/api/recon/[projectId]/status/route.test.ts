/**
 * GET /api/recon/[projectId]/status — the status poll that mirrors terminal
 * state and persists plan-manifest pointers. The orchestrator's index
 * aggregates every run's pointers, so the route must attribute each one by its
 * own run id and must never write an old run's pointer onto the new run's row.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  requirePermission: vi.fn(),
  orchestratorFetch: vi.fn(),
  scanJobFindFirst: vi.fn(),
  scanJobUpdateMany: vi.fn(),
  scanJobUpdate: vi.fn(),
  scanVersionFindUnique: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => ({
  requirePermission: (...a: unknown[]) => h.requirePermission(...a),
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    scanJob: {
      findFirst: (...a: unknown[]) => h.scanJobFindFirst(...a),
      updateMany: (...a: unknown[]) => h.scanJobUpdateMany(...a),
      update: (...a: unknown[]) => h.scanJobUpdate(...a),
    },
    scanVersion: { findUnique: (...a: unknown[]) => h.scanVersionFindUnique(...a) },
  },
}))

import { GET } from './route'

const PATH = (runId: string, projectId = 'p1', tenant = 't1', group = 'g1') =>
  `/out/planner_manifests/${tenant}/${projectId}/${runId}/${group}/plan_manifest.json`
const pointer = (runId: string, extra: Record<string, unknown> = {}) => ({
  plan_manifest_path: PATH(runId),
  plan_manifest_sha256: 'a'.repeat(64),
  plan_manifest_summary: { run_id: runId, group_id: 'g1', created_at: '2026-01-02T00:00:00Z', ...extra },
})

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const req = () => new NextRequest('http://webapp/api/recon/p1/status')

beforeEach(() => {
  vi.clearAllMocks()
  h.requirePermission.mockResolvedValue({
    access: { project: { id: 'p1', userId: 't1' } },
  })
  h.orchestratorFetch.mockResolvedValue(
    new Response(JSON.stringify({ status: 'running', run_id: 'runNEW', plan_manifest_pointers: [] }), {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }),
  )
  h.scanJobFindFirst.mockImplementation(async (args: { where?: { runId?: string } }) => {
    if (args?.where?.runId === 'runNEW') {
      return { id: 'job-new', planManifestPath: null, planManifestSummary: null }
    }
    return null
  })
  h.scanJobUpdateMany.mockResolvedValue({ count: 1 })
  h.scanVersionFindUnique.mockResolvedValue(null)
})

describe('GET /api/recon/[projectId]/status — plan-manifest pointers', () => {
  test('persists only the pointer whose run matches an open row', async () => {
    h.orchestratorFetch.mockResolvedValue(
      new Response(JSON.stringify({
        status: 'running', run_id: 'runNEW',
        plan_manifest_pointers: [pointer('runOLD'), pointer('runNEW')],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    const res = await GET(req(), params)
    expect(res.status).toBe(200)
    // Both pointers are looked up by their own run id...
    const lookedUp = h.scanJobFindFirst.mock.calls.map(c => c[0].where.runId)
    expect(lookedUp).toContain('runOLD')
    expect(lookedUp).toContain('runNEW')
    // ...but only the current run's pointer is written.
    expect(h.scanJobUpdateMany).toHaveBeenCalledOnce()
    expect(h.scanJobUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: expect.objectContaining({ runId: 'runNEW' }),
      data: expect.objectContaining({ planManifestPath: PATH('runNEW') }),
    }))
  })

  test('replaces a stale pointer left by another run on the current row', async () => {
    h.scanJobFindFirst.mockImplementation(async (args: { where?: { runId?: string } }) => {
      if (args?.where?.runId === 'runNEW') {
        return {
          id: 'job-new',
          planManifestPath: PATH('runOLD'),
          planManifestSummary: { run_id: 'runOLD', created_at: '2026-01-01T00:00:00Z' },
        }
      }
      return null
    })
    h.orchestratorFetch.mockResolvedValue(
      new Response(JSON.stringify({
        status: 'running', run_id: 'runNEW',
        plan_manifest_pointers: [pointer('runNEW')],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    await GET(req(), params)
    expect(h.scanJobUpdateMany).toHaveBeenCalledOnce()
    expect(h.scanJobUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ planManifestPath: PATH('runNEW') }),
    }))
  })

  test('a pointer for another tenant is not persisted', async () => {
    h.orchestratorFetch.mockResolvedValue(
      new Response(JSON.stringify({
        status: 'running', run_id: 'runNEW',
        plan_manifest_pointers: [{ ...pointer('runNEW'), plan_manifest_path: PATH('runNEW', 'p1', 't2') }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    await GET(req(), params)
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('a pointer path naming another project is not persisted', async () => {
    h.orchestratorFetch.mockResolvedValue(
      new Response(JSON.stringify({
        status: 'running', run_id: 'runNEW',
        plan_manifest_pointers: [{ ...pointer('runNEW'), plan_manifest_path: PATH('runNEW', 'p2') }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    await GET(req(), params)
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('a non-OK orchestrator answer is an error and persists nothing', async () => {
    h.orchestratorFetch.mockResolvedValue(new Response('nope', { status: 503 }))
    const res = await GET(req(), params)
    expect(res.status).toBe(502)
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('no pointers means no DB write', async () => {
    await GET(req(), params)
    expect(h.scanJobUpdateMany).not.toHaveBeenCalled()
  })

  test('persists the pointer before the terminal reconcile closes the row', async () => {
    const state: {
      id: string; status: string; planManifestPath: string | null
      planManifestSha256: string | null; planManifestSummary: unknown
    } = {
      id: 'job-new', status: 'running', planManifestPath: null,
      planManifestSha256: null, planManifestSummary: null,
    }
    h.scanJobFindFirst.mockImplementation(async () => ({ ...state }))
    h.scanJobUpdate.mockImplementation(async () => { state.status = 'failed'; return {} })
    h.scanJobUpdateMany.mockResolvedValue({ count: 1 })
    h.orchestratorFetch.mockResolvedValue(
      new Response(JSON.stringify({
        status: 'error', run_id: 'runNEW',
        plan_manifest_pointers: [pointer('runNEW')],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    )
    const res = await GET(req(), params)
    expect(res.status).toBe(200)
    // The pointer was written while the row was still open...
    expect(h.scanJobUpdateMany).toHaveBeenCalledOnce()
    expect(h.scanJobUpdateMany.mock.calls[0][0].where).toMatchObject({
      id: 'job-new', runId: 'runNEW',
    })
    expect(h.scanJobUpdateMany.mock.calls[0][0].data).toMatchObject({
      planManifestPath: PATH('runNEW'),
    })
    // ...onto the same job identity the reconcile then closed.
    expect(h.scanJobUpdate).toHaveBeenCalledOnce()
    expect(h.scanJobUpdate.mock.calls[0][0].where).toEqual({ id: 'job-new' })
    expect(h.scanJobUpdate.mock.calls[0][0].data.status).toBe('failed')
    expect(h.scanJobUpdateMany.mock.invocationCallOrder[0])
      .toBeLessThan(h.scanJobUpdate.mock.invocationCallOrder[0])
    expect(state.status).toBe('failed')
  })
})
