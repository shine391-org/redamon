/**
 * The project form says why a call failed instead of carrying on as if it had
 * not been made: defaults that did not load, a provider list that failed (read
 * as "none" before, which showed the no-provider gate), a preset that did not
 * load, an export that failed (a tab of raw JSON before), and the scan hooks'
 * failures, which this page held but never rendered.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, renderHook, screen, fireEvent, cleanup, waitFor, act } from '@testing-library/react'
import type { ReactNode } from 'react'
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

import { ProjectForm, useRunFailureToast, useScanErrorToast } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

type Route = (url: string, init?: RequestInit) => Response | null
let route: Route = () => null

beforeEach(() => {
  route = () => null
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const answer = route(String(url), init)
    if (answer) return answer
    if (url === '/api/projects/defaults') return json(200, {})
    if (url.endsWith('/llm-providers')) return json(200, [{ id: 'pr1', providerType: 'openai' }])
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider><AlertProvider>{children}</AlertProvider></ToastProvider>
    </QueryClientProvider>
  )
}

function draw(mode: 'create' | 'edit') {
  const initialData = mode === 'edit'
    ? { ...MINIMAL_DEFAULTS, id: 'p1', name: 'ACME lab', targetDomain: 'acme-lab.test' } as never
    : undefined
  render(
    <ProjectForm mode={mode} initialData={initialData} onSubmit={vi.fn() as never} onCancel={vi.fn()}
      projectIdFromRoute={mode === 'edit' ? 'p1' : undefined} />,
    { wrapper: providers },
  )
}

describe('create mode', () => {
  test('defaults that did not load are said, with the server reason and status', async () => {
    route = url => (url === '/api/projects/defaults'
      ? json(503, { error: 'Recon defaults unavailable: the orchestrator did not answer', code: 'recon_defaults_unavailable' })
      : null)
    draw('create')
    const banner = await screen.findByTestId('defaults-warning')
    expect(banner.textContent).toContain('built-in fallbacks')
    expect(banner.textContent).toContain(
      'Recon defaults unavailable: the orchestrator did not answer (recon_defaults_unavailable · HTTP 503)')
  })

  test('defaults that loaded show no banner', async () => {
    draw('create')
    await screen.findByText('Create New Project')
    expect(screen.queryByTestId('defaults-warning')).toBeNull()
  })

  test('a provider list that failed to load is not "no provider": no gate, and a warning with the code', async () => {
    route = url => (url.endsWith('/llm-providers')
      ? json(500, { error: 'Failed to load providers', code: 'P2024' })
      : null)
    draw('create')
    expect(await screen.findByText('Failed to load providers (P2024 · HTTP 500)')).toBeTruthy()
    expect(screen.queryByText('Configure an LLM provider first')).toBeNull()
    expect(await screen.findByText('Create New Project')).toBeTruthy()
  })

  test('an empty provider list still shows the gate', async () => {
    route = url => (url.endsWith('/llm-providers') ? json(200, []) : null)
    draw('create')
    expect(await screen.findByText('Configure an LLM provider first')).toBeTruthy()
  })
})

describe('edit mode', () => {
  test('a user preset that did not load says why', async () => {
    route = url => (url === '/api/presets/up1' ? json(404, { error: 'Preset not found' }) : null)
    draw('edit')
    fireEvent.click(screen.getByText('load-user-preset'))
    expect(await screen.findByText('Failed to load preset "Fast": Preset not found (HTTP 404)')).toBeTruthy()
  })

  test('a failed export is an error with its code, not a tab of raw JSON', async () => {
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    route = url => (url === '/api/projects/p1/export'
      ? json(500, { error: 'Export failed', code: 'ENOSPC' })
      : null)
    draw('edit')
    fireEvent.click(screen.getByText('Export'))
    expect(await screen.findByText('Export failed (ENOSPC · HTTP 500)')).toBeTruthy()
    expect(open).not.toHaveBeenCalled()
  })

  test('a preset save written before a later step failed says it was saved, and takes the new version', async () => {
    const reads: string[] = []
    route = (url, init) => {
      if (url === '/api/presets/up1') return json(200, { settings: { naabuRateLimit: 50 } })
      if (url === '/api/projects/p1' && init?.method === 'PUT') {
        return json(500, { error: 'Failed to update project', code: 'P2034', stage: 'after_write' })
      }
      if (url === '/api/projects/p1') {
        reads.push(url)
        return json(200, { id: 'p1', updatedAt: '2026-10-29T10:00:00.000Z' })
      }
      return null
    }
    draw('edit')
    fireEvent.click(screen.getByText('load-user-preset'))
    fireEvent.click(await screen.findByRole('button', { name: 'Replace and save' }))
    expect(await screen.findByText(
      'Preset "Fast" was loaded and saved, but a step after the save failed: Failed to update project (P2034 · HTTP 500)',
    )).toBeTruthy()
    expect(reads).toEqual(['/api/projects/p1'])
  })

  test('a preset save refused before the write still says NOT saved', async () => {
    route = (url, init) => {
      if (url === '/api/presets/up1') return json(200, { settings: { naabuRateLimit: 50 } })
      if (url === '/api/projects/p1' && init?.method === 'PUT') {
        return json(500, { error: 'Failed to update project', code: 'P2024', stage: 'before_write' })
      }
      return null
    }
    draw('edit')
    fireEvent.click(screen.getByText('load-user-preset'))
    fireEvent.click(await screen.findByRole('button', { name: 'Replace and save' }))
    expect(await screen.findByText(/was loaded but NOT saved: Failed to update project \(P2024 · HTTP 500\)/)).toBeTruthy()
  })
})

describe('scan hook failures', () => {
  test('each new error is toasted once, a start failure is left to the start modal', async () => {
    const lastStart = { current: null as { message: string } | null }
    const { rerender } = renderHook(
      ({ error }: { error: string | null }) => {
        useScanErrorToast('GitHub Secret Hunt', error, () => lastStart.current)
      },
      { wrapper: providers, initialProps: { error: null as string | null } },
    )
    rerender({ error: 'Failed to stop GitHub Secret Hunt (orchestrator_unreachable · HTTP 503)' })
    expect(await screen.findByText('Failed to stop GitHub Secret Hunt (orchestrator_unreachable · HTTP 503)')).toBeTruthy()

    lastStart.current = { message: 'RAM limit reached' }
    rerender({ error: 'RAM limit reached (HTTP 409)' })
    await act(async () => {})
    expect(screen.queryByText('RAM limit reached (HTTP 409)')).toBeNull()
  })

  test('a run seen ending in error is toasted with its reason; one already failed is not', async () => {
    type Run = { key: string; status: string; error: string | null }
    const { rerender } = renderHook(
      ({ runs }: { runs: Run[] }) => {
        useRunFailureToast('Supply-Chain scan', runs)
      },
      { wrapper: providers, initialProps: { runs: [{ key: 'old', status: 'error', error: 'stale failure' }] as Run[] } },
    )
    rerender({ runs: [
      { key: 'old', status: 'error', error: 'stale failure' },
      { key: 'new', status: 'running', error: null },
    ] })
    rerender({ runs: [
      { key: 'old', status: 'error', error: 'stale failure' },
      { key: 'new', status: 'error', error: 'Container exited with code 137' },
    ] })
    await waitFor(() => expect(screen.getByText('Supply-Chain scan failed: Container exited with code 137')).toBeTruthy())
    expect(screen.queryByText(/stale failure/)).toBeNull()
  })
})
