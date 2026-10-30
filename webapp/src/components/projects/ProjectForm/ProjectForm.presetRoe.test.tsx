/**
 * Load Preset on a project whose settings partly came from a RoE document.
 *
 * It used to confirm BEFORE fetching the preset, so it could not say what it
 * would overwrite, and save with no updatedAt, so a RoE replaced in another tab
 * was silently reverted. Now it fetches first, names the document-set settings
 * it changes, and saves as a compare-and-swap.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
vi.mock('next/dynamic', () => ({ default: () => () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'alice' }) }))
vi.mock('@/hooks/useReconStatus', () => ({ default: () => ({ state: null }) }))
vi.mock('@/hooks/useScanControls', () => ({
  useScanControls: () => ({ otherScansOpen: false, gvm: {}, githubHunt: {}, trufflehog: { runs: [] }, supplyChain: {} }),
}))
vi.mock('@/components/scans/ScanActions', () => ({ ScanActions: () => null }))
vi.mock('@/app/graph/components/OtherScansModal/OtherScansModal', () => ({ OtherScansModal: () => null }))
vi.mock('@/hooks/useMultiPartialReconStatus', () => ({ useMultiPartialReconStatus: () => ({ runs: [], activeRuns: [], refetch: vi.fn() }) }))
vi.mock('@/hooks/useScanStartFailure', () => ({ useScanStartFailure: () => ({ handleStartFailure: vi.fn() }) }))
vi.mock('@/hooks/useDrawerOffsets', () => ({ useDrawerOffsets: () => {} }))
vi.mock('@/hooks/useMultiPartialReconSSE', () => ({ useMultiPartialReconSSE: () => ({ logsMap: {}, phaseMap: {}, clearLogsForRun: vi.fn() }) }))
vi.mock('@/hooks/useDetectedHostIp', () => ({ useDetectedHostIp: () => '' }))
vi.mock('./UserPresetDrawer', () => ({
  UserPresetDrawer: ({ onLoad }: { onLoad: (p: { id: string; name: string }) => void }) => (
    <button type="button" onClick={() => onLoad({ id: 'up1', name: 'Fast' })}>load-user-preset</button>
  ),
}))

import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'
import { STALE_SAVE_MESSAGE } from '@/lib/projectVersion'

const V1 = '2026-10-12T10:00:00.000Z'
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const h = vi.hoisted(() => ({ calls: [] as Array<{ url: string; method: string; body?: unknown }>, putStatus: 200 }))

beforeEach(() => {
  window.history.replaceState({}, '', '/projects/p1/settings?tab=attack')
  h.calls = []
  h.putStatus = 200
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    h.calls.push({ url, method, body: init?.body ? JSON.parse(String(init.body)) : undefined })
    if (url === '/api/presets/up1') return json(200, { settings: { naabuRateLimit: 50, katanaDepth: 3 } })
    if (url === '/api/projects/defaults') return json(200, {})
    if (url === '/api/projects/p1' && method === 'PUT') {
      return h.putStatus === 409
        ? json(409, { error: STALE_SAVE_MESSAGE })
        : json(200, { id: 'p1', updatedAt: '2026-10-13T00:00:00.000Z' })
    }
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
})

function draw() {
  const initialData = {
    ...MINIMAL_DEFAULTS,
    id: 'p1',
    name: 'ACME lab',
    targetDomain: 'acme-lab.test',
    naabuRateLimit: 10,
    roeParsedJson: { version: 2, applied: { naabuRateLimit: 10, roeGlobalMaxRps: 5 } },
    updatedAt: V1,
  } as never
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <AlertProvider>
          <ProjectForm mode="edit" initialData={initialData} onSubmit={vi.fn() as never} onCancel={vi.fn()} projectIdFromRoute="p1" />
        </AlertProvider>
      </ToastProvider>
    </QueryClientProvider>,
  )
}

describe('Load Preset and the RoE document', () => {
  test('fetches the preset first, then names the document-set settings it changes', async () => {
    draw()
    fireEvent.click(screen.getByText('load-user-preset'))
    const warning = await screen.findByText(/It also changes 1 setting the Rules of/)
    expect(warning.parentElement!.textContent).toContain('naabuRateLimit')
    // The preset was read before the question was asked.
    expect(h.calls.some(c => c.url === '/api/presets/up1')).toBe(true)
    expect(h.calls.some(c => c.method === 'PUT')).toBe(false)
  })

  test('the save carries updatedAt, so a change made elsewhere is refused, not reverted', async () => {
    draw()
    fireEvent.click(screen.getByText('load-user-preset'))
    fireEvent.click(await screen.findByRole('button', { name: 'Replace and save' }))
    await waitFor(() => expect(h.calls.some(c => c.method === 'PUT')).toBe(true))
    const put = h.calls.find(c => c.method === 'PUT')!
    expect((put.body as Record<string, unknown>).updatedAt).toBe(V1)
  })

  test('a 409 says the preset was not saved, and why', async () => {
    h.putStatus = 409
    draw()
    fireEvent.click(screen.getByText('load-user-preset'))
    fireEvent.click(await screen.findByRole('button', { name: 'Replace and save' }))
    expect(await screen.findByText(/was loaded but NOT saved: This project changed since you opened it/)).toBeInTheDocument()
  })
})
