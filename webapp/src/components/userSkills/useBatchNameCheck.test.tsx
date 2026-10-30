/**
 * useBatchNameCheck: the upload dialog's debounced name check for every row. An answer for a
 * list of names the person has since changed must never be reported, even when it arrives
 * after the newer one: it would mark a row taken (or free) for a name it no longer holds.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import type { NameCheckResult } from '@/lib/userSkills'
import { useBatchNameCheck, type NameEntry, type BatchNameCheckOutcome } from './useBatchNameCheck'

interface Pending { names: string[]; resolve: (results: NameCheckResult[]) => void }

let pending: Pending[]

beforeEach(() => {
  vi.useFakeTimers()
  pending = []
  // Resolves only when the test says so, and ignores the abort signal: a reply can still
  // arrive after its request was aborted, so only the hook itself may drop it.
  vi.stubGlobal('fetch', vi.fn((_url: string, init: RequestInit) => new Promise((done) => {
    const names = JSON.parse(init.body as string).names as string[]
    pending.push({ names, resolve: (results) => done({ ok: true, status: 200, json: async () => ({ results }) }) })
  })))
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const taken = (name: string): NameCheckResult =>
  ({ available: false, normalized: name, suggestion: `${name} v2`, reason: 'name_taken' })
const free = (name: string): NameCheckResult => ({ available: true, normalized: name, suggestion: null })

describe('useBatchNameCheck', () => {
  test('an answer for names since changed, arriving after the newer answer, is never reported', async () => {
    const onOutcome = vi.fn<(o: BatchNameCheckOutcome) => void>()
    const { rerender } = renderHook(
      ({ entries }: { entries: NameEntry[] }) => useBatchNameCheck('alice', entries, onOutcome),
      { initialProps: { entries: [{ key: 'r1', name: 'Old name' }] } },
    )
    await act(async () => { vi.advanceTimersByTime(400) })
    rerender({ entries: [{ key: 'r1', name: 'New name' }] })
    await act(async () => { vi.advanceTimersByTime(400) })
    expect(pending.map((p) => p.names)).toEqual([['Old name'], ['New name']])

    await act(async () => { pending[1].resolve([free('New name')]) })
    await act(async () => { pending[0].resolve([taken('Old name')]) })

    expect(onOutcome.mock.calls).toEqual([[{ keys: ['r1'], results: [free('New name')] }]])
  })
})

describe('useBatchNameCheck: a failed check carries its cause', () => {
  test('a refused check reports the code and status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Failed to check the names', code: 'P1001' }), { status: 500 })))
    const onOutcome = vi.fn<(o: BatchNameCheckOutcome) => void>()
    renderHook(() => useBatchNameCheck('alice', [{ key: 'r1', name: 'Flow' }], onOutcome))
    await act(async () => { vi.advanceTimersByTime(400) })
    await act(async () => {})
    const outcome = onOutcome.mock.calls[0][0] as Extract<BatchNameCheckOutcome, { failed: true }>
    expect(outcome).toMatchObject({ keys: ['r1'], failed: true })
    expect(outcome.error?.message).toBe('Failed to check the names (P1001 · HTTP 500)')
  })

  test('no answer is network_error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const onOutcome = vi.fn<(o: BatchNameCheckOutcome) => void>()
    renderHook(() => useBatchNameCheck('alice', [{ key: 'r1', name: 'Flow' }], onOutcome))
    await act(async () => { vi.advanceTimersByTime(400) })
    await act(async () => {})
    const outcome = onOutcome.mock.calls[0][0] as Extract<BatchNameCheckOutcome, { failed: true }>
    expect(outcome.error?.code).toBe('network_error')
  })
})
