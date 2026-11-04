/**
 * The queue's start path refuses what only a person can fix with a status the
 * queue treats as permanent: a 409 reads as "busy" there and would requeue the
 * job forever. Two such refusals: an old-model graph (§4.11.6) for the writers
 * that attach to Domain nodes, and a third-party engagement that is not startable.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  legacy: vi.fn(),
  orchestratorFetch: vi.fn(),
  engagement: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => h.findUnique(...a) } } }))
vi.mock('@/lib/engagement', () => ({ loadEngagement: (...a: unknown[]) => h.engagement(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/startFullScan', async orig => ({
  ...(await orig<typeof import('@/lib/startFullScan')>()),
  startFullScan: vi.fn(),
}))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
}))

import { dispatchStart } from './startScan'
import { classifyStartFailure } from './scanStartOutcome'

beforeEach(() => {
  vi.clearAllMocks()
  h.findUnique.mockResolvedValue({
    id: 'p1', userId: 'u1', supplyChainInputMode: null, targetDomain: '',
    domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk'],
  })
  h.legacy.mockResolvedValue(['co.uk'])
  h.engagement.mockResolvedValue({ blockers: [] })
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1' }) })
})

describe('dispatchStart on an old-model graph', () => {
  test.each(['partial_recon', 'gvm', 'ai_attack'])('%s is refused, permanently', async kind => {
    const r = await dispatchStart(kind, 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(false)
    expect(r.status).toBe(422)
    expect(r.error).toMatch(/built before the current scope model; run a full recon first/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(classifyStartFailure(r.status, { error: r.error }).temporary).toBe(false)
  })

  test('a scanner that never attaches to Domain nodes is not asked', async () => {
    await dispatchStart('github_hunt', 'p1')
    expect(h.legacy).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })

  test('a current graph starts', async () => {
    h.legacy.mockResolvedValue([])
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(true)
  })
})

describe('dispatchStart on a third-party engagement that is not startable', () => {
  test('is refused permanently, so the queue does not retry it as busy', async () => {
    h.engagement.mockResolvedValue({ blockers: ['No authorization record.'] })
    const r = await dispatchStart('gvm', 'p1')
    expect(r.status).toBe(422)
    expect(classifyStartFailure(r.status, { error: r.error }).temporary).toBe(false)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('dispatchStart tells the queue what the start really did (plan 12.6)', () => {
  test('a full recon forwards startOutcome, snapshotFailed and the body code', async () => {
    const { startFullScan } = await import('@/lib/startFullScan')
    const full = vi.mocked(startFullScan)
    full.mockResolvedValueOnce({
      ok: false, status: 503, startOutcome: 'unknown', error: 'no answer', scanJobId: 'sj1',
    })
    expect(await dispatchStart('full_recon', 'p1')).toMatchObject({
      ok: false, status: 503, startOutcome: 'unknown', scanJobId: 'sj1',
    })
    full.mockResolvedValueOnce({ ok: false, status: 500, error: 'freeze failed', snapshotFailed: true })
    expect(await dispatchStart('full_recon', 'p1')).toMatchObject({ snapshotFailed: true })
    full.mockResolvedValueOnce({ ok: false, status: 500, error: 'no image', code: 'spawn_failed' })
    expect(await dispatchStart('full_recon', 'p1')).toMatchObject({ code: 'spawn_failed' })
  })

  test('the queue starts full recons headless, so a transient refusal records no ScanJob', async () => {
    const { startFullScan } = await import('@/lib/startFullScan')
    const full = vi.mocked(startFullScan)
    full.mockResolvedValueOnce({ ok: false, status: 503, error: 'x' })
    await dispatchStart('full_recon', 'p1')
    expect(full).toHaveBeenLastCalledWith(expect.objectContaining({ quietTransient: true }))
  })

  test('a non-full start whose orchestrator call throws has an unknown outcome', async () => {
    h.legacy.mockResolvedValue([])
    h.orchestratorFetch.mockRejectedValue(new Error('The operation was aborted due to timeout'))
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 503, startOutcome: 'unknown' })
    expect(classifyStartFailure(r.status, { error: r.error, startOutcome: r.startOutcome },
      { orchestratorAnswered: false }).kind).toBe('unknown')
  })

  test('a refused connection certainly started nothing, so the queue may retry it', async () => {
    h.legacy.mockResolvedValue([])
    const refused = Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8010'), { code: 'ECONNREFUSED' }),
    })
    h.orchestratorFetch.mockRejectedValue(refused)
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 503, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(r.startOutcome).toBeUndefined()
    expect(classifyStartFailure(r.status, { error: r.error, code: r.code },
      { orchestratorAnswered: r.startOutcome !== 'unknown' }).kind).toBe('transient')
  })

  test('a timed-out start is 504 orchestrator_timeout with an unknown outcome', async () => {
    h.legacy.mockResolvedValue([])
    h.orchestratorFetch.mockRejectedValue(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 504, code: 'orchestrator_timeout', startOutcome: 'unknown' })
  })

  test('a non-full refusal carries the orchestrator status', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 502, json: async () => { throw new SyntaxError('html') } })
    const r = await dispatchStart('github_hunt', 'p1')
    expect(r).toMatchObject({ ok: false, status: 502, upstreamStatus: 502, error: 'Failed to start GitHub Secret Hunt' })
  })

  test('a non-full refusal forwards the orchestrator body code', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 500,
      json: async () => ({ detail: { detail: 'Failed to start: image missing', code: 'spawn_failed' } }),
    })
    const r = await dispatchStart('github_hunt', 'p1')
    expect(r).toMatchObject({ ok: false, status: 500, code: 'spawn_failed', error: 'Failed to start: image missing' })
  })
})
