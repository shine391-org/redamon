/** G2-R3 — plan manifest reader: the webapp never trusts a persisted pointer
 * until the orchestrator has validated it against the manifest file on disk.
 * Missing, incomplete, unsupported, tampered or cross-context reads are
 * ``{"status": "unknown"}`` -- never a guessed clean plan.
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const { fetchMock } = vi.hoisted(() => ({ fetchMock: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: fetchMock }))

import { readPlanManifest } from './planManifestReader'

const job = {
  planManifestPath: '/out/planner_manifests/t1/p1/run9/g1/plan_manifest.json',
  planManifestSha256: 'a'.repeat(64),
  planManifestSummary: { run_id: 'run9', group_id: 'g1', settings_hash_prefix: 'abc' },
}

beforeEach(() => {
  fetchMock.mockClear()
  fetchMock.mockResolvedValue(new Response(JSON.stringify({ status: 'known', run_id: 'run9' }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  }))
})

describe('readPlanManifest', () => {
  test('returns the manifest when the orchestrator validates it known', async () => {
    const out = await readPlanManifest('p1', job, 't1')
    expect(out.status).toBe('known')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const url = fetchMock.mock.calls[0][0]
    expect(url).toContain('/recon/p1/plan-manifest')
    expect(url).toContain('sha256=' + 'a'.repeat(64))
    expect(url).toContain('tenant=t1')
    expect(url).toContain('run_id=run9')
    expect(url).toContain('group_id=g1')
  })

  test('no pointer -> unknown without calling the orchestrator', async () => {
    const out = await readPlanManifest('p1', { planManifestPath: null, planManifestSha256: null, planManifestSummary: null })
    expect(out).toEqual({ status: 'unknown', reason: 'no_manifest_pointer' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test.each([true, 1, 'invalid', []])('non-object persisted summary %j -> unknown', async (summary) => {
    const out = await readPlanManifest('p1', { ...job, planManifestSummary: summary }, 't1')
    expect(out).toEqual({ status: 'unknown', reason: 'invalid_manifest_summary' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('orchestrator unreachable -> unknown', async () => {
    fetchMock.mockRejectedValue(new Error('connection refused'))
    const out = await readPlanManifest('p1', job, 't1')
    expect(out.status).toBe('unknown')
    expect(out.reason).toBe('orchestrator_unreachable')
  })

  test('orchestrator error status -> unknown', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 500 }))
    const out = await readPlanManifest('p1', job, 't1')
    expect(out.status).toBe('unknown')
    expect(out.reason).toBe('orchestrator_500')
  })

  test('unreadable orchestrator body -> unknown', async () => {
    fetchMock.mockResolvedValue(new Response('not json', { status: 200 }))
    const out = await readPlanManifest('p1', job, 't1')
    expect(out.status).toBe('unknown')
    expect(out.reason).toBe('orchestrator_unreadable')
  })

  test('uses the summary run_id when the row has none (full_recon)', async () => {
    await readPlanManifest('p1', {
      planManifestPath: '/x.json', planManifestSha256: 'b'.repeat(64),
      planManifestSummary: { run_id: 'summary-run', group_id: 'g1' },
      runId: '',
    }, 't1')
    const url = fetchMock.mock.calls[0][0]
    expect(url).toContain('run_id=summary-run')
  })
})
