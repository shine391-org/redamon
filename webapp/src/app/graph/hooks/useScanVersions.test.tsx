/**
 * The version list's error carries what the route said and the HTTP status, so
 * the page can show why the switch is empty instead of a bare "Failed to load".
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import { useScanVersions } from './useScanVersions'

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('useScanVersions', () => {
  test('a failed list exposes the route reason, its code and the status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Failed to list versions', code: 'P2024' }), { status: 500 })))
    const { result } = renderHook(() => useScanVersions('p1'), { wrapper })
    await waitFor(() => expect(result.current.error).toBeTruthy())
    expect(result.current.error?.message).toBe('Failed to list versions (P2024 · HTTP 500)')
    expect(result.current.versions).toEqual([])
  })

  test('a list that got no answer is a network error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    const { result } = renderHook(() => useScanVersions('p1'), { wrapper })
    await waitFor(() => expect(result.current.error?.message).toBe('Failed to load scan versions (network_error)'))
  })

  test('a good list is returned as before', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      versions: [{ id: 'v1', seq: 1, label: 'Scan 1', isCurrent: true }], activating: false,
    }), { status: 200 })))
    const { result } = renderHook(() => useScanVersions('p1'), { wrapper })
    await waitFor(() => expect(result.current.versions).toHaveLength(1))
    expect(result.current.currentVersion?.id).toBe('v1')
  })
})
