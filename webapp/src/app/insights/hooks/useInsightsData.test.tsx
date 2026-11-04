/**
 * Insights queries fail with the route's reason, code and status, never with
 * "Failed to fetch <url>".
 *
 * Run: npx vitest run src/app/insights/hooks/useInsightsData.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useGraphOverview, useActiveSessions } from './useInsightsData'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useInsightsData', () => {
  test('a route failure carries its error, code and HTTP status, and no URL', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: 'Query failed', code: 'Neo.TransientError.General.DatabaseUnavailable' }), { status: 500 })))
    const { result } = renderHook(() => useGraphOverview('p1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    const message = (result.current.error as Error).message
    expect(message).toBe('Query failed (Neo.TransientError.General.DatabaseUnavailable · HTTP 500)')
    expect(message).not.toContain('/api/')
  })

  test('a proxy HTML page keeps the status and says it was not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>Bad Gateway</html>', { status: 502 })))
    const { result } = renderHook(() => useActiveSessions(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect((result.current.error as Error).message).toBe('Failed to load agent sessions (non_json_response · HTTP 502)')
  })
})
