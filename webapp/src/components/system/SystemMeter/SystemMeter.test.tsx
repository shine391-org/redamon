/**
 * The footer meter says when the stats are missing, instead of vanishing.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SystemMeter } from './SystemMeter'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderMeter() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(<QueryClientProvider client={client}><SystemMeter /></QueryClientProvider>)
}

describe('SystemMeter', () => {
  test('a failed read shows "unavailable" with the cause on hover', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      error: 'Failed to connect to backend services', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    }), { status: 503 })))
    renderMeter()
    const chip = await screen.findByRole('status')
    expect(chip.textContent).toBe('RAM/CPU unavailable')
    expect(chip.getAttribute('title')).toBe('Failed to connect to backend services (orchestrator_unreachable · HTTP 503)')
  })

  test('stats that load show the meters', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      mem: {
        host_total: 8 * 1024 ** 3, available: 4 * 1024 ** 3, os_headroom: 0, service_baseline: 0, scan_pool: 0,
        committed: 0, active_scans: 0, remaining_for_new: 2 * 1024 ** 3, pressure: 'ok',
      },
      cpu: { percent: 10, cores: 4 },
      governor_enabled: true,
    }), { status: 200 })))
    renderMeter()
    await waitFor(() => expect(screen.getByText('RAM')).toBeInTheDocument())
    expect(screen.queryByRole('status')).toBeNull()
  })
})
