/**
 * useScanControls: the scan-state bundle behind the project form's scan cluster.
 *
 * The hook itself is thin; what matters is what it does to the ORCHESTRATOR.
 * It mounts four polling hooks, so a surface that mounts it carelessly doubles
 * the status traffic of the graph page for no extra information.
 *
 * Run: npx vitest run src/hooks/useScanControls.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup, act } from '@testing-library/react'
import { useScanControls } from './useScanControls'

const calls = vi.hoisted(() => ({ gvm: [] as unknown[], gh: [] as unknown[], th: [] as unknown[], sc: [] as unknown[] }))
// What each mocked scan hook returns; a test overrides fields to drive a scenario.
const hookReturns = vi.hoisted(() => ({
  gvm: {} as Record<string, unknown>,
  gh: {} as Record<string, unknown>,
  th: {} as Record<string, unknown>,
  sc: {} as Record<string, unknown>,
}))
const ui = vi.hoisted(() => ({ handleStartFailure: vi.fn() }))

vi.mock('./useGvmStatus', () => ({
  useGvmStatus: (o: unknown) => { calls.gvm.push(o); return { state: null, ...hookReturns.gvm } },
}))
vi.mock('./useGithubHuntStatus', () => ({
  useGithubHuntStatus: (o: unknown) => { calls.gh.push(o); return { state: null, ...hookReturns.gh } },
}))
vi.mock('./useTrufflehogRuns', () => ({
  useTrufflehogRuns: (o: unknown) => {
    calls.th.push(o)
    return { isAnyRunning: false, activeRuns: [], profiles: [], bySource: {}, ...hookReturns.th }
  },
}))
vi.mock('./useSupplyChainStatus', () => ({
  useSupplyChainStatus: (o: unknown) => { calls.sc.push(o); return { state: null, ...hookReturns.sc } },
}))
vi.mock('./useScanStartFailure', () => ({
  useScanStartFailure: () => ({ handleStartFailure: ui.handleStartFailure }),
}))

beforeEach(() => {
  for (const k of Object.keys(calls) as (keyof typeof calls)[]) calls[k].length = 0
  for (const k of Object.keys(hookReturns) as (keyof typeof hookReturns)[]) hookReturns[k] = {}
  ui.handleStartFailure.mockReset()
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, json: async () => ({}) }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const last = (a: unknown[]) => a[a.length - 1] as Record<string, unknown>
const fetchCalls = () => (fetch as unknown as { mock: { calls: unknown[][] } }).mock.calls

describe('useScanControls', () => {
  test('a project id enables all four scan hooks', () => {
    renderHook(() => useScanControls({ projectId: 'p1' }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k]).enabled, k).toBe(true)
      expect(last(calls[k]).projectId, k).toBe('p1')
    }
  })

  test('no project id means no polling at all', () => {
    // A create-mode form has nothing to scan; polling would be four requests
    // every interval against an id that does not exist.
    renderHook(() => useScanControls({ projectId: null }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k]).enabled, k).toBe(false)
    }
  })

  test('enabled=false overrides a present project id', () => {
    renderHook(() => useScanControls({ projectId: 'p1', enabled: false }))
    expect(last(calls.gvm).enabled).toBe(false)
  })

  test('regression: a secondary surface can slow its polling', () => {
    // F6. Without this every surface polled at the graph page's rate, so having
    // the settings page open doubled the orchestrator's status traffic.
    renderHook(() => useScanControls({ projectId: 'p1', pollingInterval: 15_000 }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k]).pollingInterval, k).toBe(15_000)
    }
  })

  test('omitting the interval leaves each hook on its own default', () => {
    renderHook(() => useScanControls({ projectId: 'p1' }))
    for (const k of ['gvm', 'gh', 'th', 'sc'] as const) {
      expect(last(calls[k])).not.toHaveProperty('pollingInterval')
    }
  })

  test('the data probes are HEAD requests, not downloads', async () => {
    // A GET here would pull the whole artifact just to grey out a button.
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    for (const call of fetchCalls()) {
      if (!String(call[0]).endsWith('/download')) continue
      expect((call[1] as { method: string }).method).toBe('HEAD')
    }
    expect(result.current.hasReconData).toBe(false)
  })

  test('an uninstalled GVM stack marks the scan unavailable', async () => {
    // Redzone greys the GVM button out on /api/gvm/available; the project form
    // showed it enabled, so the only feedback was a scan that could not start.
    vi.stubGlobal('fetch', vi.fn(async (url: string) => (
      String(url).includes('/api/gvm/available')
        ? { ok: true, json: async () => ({ available: false }) }
        : { ok: false, json: async () => ({}) }
    )))
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.gvm.isAvailable).toBe(false))
  })

  test('an installed GVM stack leaves the scan available', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => (
      String(url).includes('/api/gvm/available')
        ? { ok: true, json: async () => ({ available: true }) }
        : { ok: false, json: async () => ({}) }
    )))
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(fetch).toHaveBeenCalled())
    expect(result.current.gvm.isAvailable).toBe(true)
  })

  test('a disabled surface does not probe availability either', () => {
    renderHook(() => useScanControls({ projectId: 'p1', enabled: false }))
    expect(fetchCalls().some(c => String(c[0]).includes('/api/gvm/available'))).toBe(false)
  })

  test('the Other Scans modal starts closed and toggles', () => {
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    expect(result.current.otherScansOpen).toBe(false)
  })
})

/**
 * S-3: on the project form the GVM button failed silently (startGvm resolves to
 * null and nothing read why). Its start now goes through the shared start-failure
 * handler; pause/resume/stop land in the hook's `error`, which the form toasts.
 */
describe('useScanControls: failures reach the person', () => {
  const availability = (body: unknown) => vi.stubGlobal('fetch', vi.fn(async (url: string) => (
    String(url).includes('/api/gvm/available')
      ? new Response(JSON.stringify(body), { status: 200 })
      : new Response(null, { status: 404 })
  )))

  test('an orchestrator that did not answer is not "GVM is not installed"', async () => {
    availability({ available: false, reason: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.gvm.isAvailable).toBe(false))
    expect(result.current.gvm.unavailableReason).toBe(
      'GVM availability unknown: the recon orchestrator did not report it (orchestrator_unreachable · ECONNREFUSED)')
  })

  test('an absent GVM stack keeps the install hint', async () => {
    availability({ available: false, reason: 'gvm_absent' })
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.gvm.isAvailable).toBe(false))
    expect(result.current.gvm.unavailableReason).toMatch(/^GVM is not installed/)
  })

  test('a 5xx on the data check does not read as "no data"', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => (
      String(url).includes('/api/gvm/available')
        ? new Response(JSON.stringify({ available: true }), { status: 200 })
        : new Response(null, { status: String(url).includes('/gvm/') ? 500 : 404 })
    )))
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await waitFor(() => expect(result.current.gvm.dataError).toBe('Could not check for data (HTTP 500)'))
    expect(result.current.gvm.hasData).toBe(false)
    expect(result.current.reconDataError).toBeNull()
  })

  test('a refused GVM start goes through the shared start-failure handler', async () => {
    const startErr = { message: 'Recon data not found', status: 400 }
    hookReturns.gvm = { startGvm: vi.fn(async () => null), getLastStartError: () => startErr }
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await act(async () => { await result.current.gvm.start() })
    expect(ui.handleStartFailure).toHaveBeenCalledWith('gvm', startErr)
  })

  test('a GVM start that throws is caught and shown, not an unhandled rejection', async () => {
    const startErr = { message: 'Failed to start GVM scan', status: 0, code: 'network_error' }
    hookReturns.gvm = { startGvm: vi.fn(async () => { throw new Error('x') }), getLastStartError: () => startErr }
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await act(async () => { await result.current.gvm.start() })
    expect(ui.handleStartFailure).toHaveBeenCalledWith('gvm', startErr)
  })

  test('a started scan shows nothing', async () => {
    hookReturns.gvm = { startGvm: vi.fn(async () => ({ status: 'starting' })), getLastStartError: () => null }
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    await act(async () => { await result.current.gvm.start() })
    expect(ui.handleStartFailure).not.toHaveBeenCalled()
  })

  test('status read failures are collected for the warning badge', () => {
    hookReturns.gvm = { statusError: 'GVM status unavailable (orchestrator_unreachable · HTTP 503)' }
    hookReturns.th = { statusError: null }
    const { result } = renderHook(() => useScanControls({ projectId: 'p1' }))
    expect(result.current.statusErrors).toEqual([
      'GVM status unavailable (orchestrator_unreachable · HTTP 503)', undefined, null, undefined,
    ])
  })
})
