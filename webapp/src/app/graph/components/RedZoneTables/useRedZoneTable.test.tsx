import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'

vi.mock('../MuteNode', () => ({ useMuteNodeContext: () => ({ epoch: 0 }) }))

import { useRedZoneTable } from './useRedZoneTable'

afterEach(() => {
  vi.unstubAllGlobals()
})

function load(response: () => Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(response))
  return renderHook(() => useRedZoneTable('secrets' as never, 'p1')).result
}

describe('useRedZoneTable errors', () => {
  test("keeps the route's code and status, never only its fixed sentence", async () => {
    const result = load(async () => new Response(JSON.stringify({
      error: 'Query failed', code: 'Neo.TransientError.General.DatabaseUnavailable',
    }), { status: 500 }))
    await waitFor(() => expect(result.current.error)
      .toBe('Query failed (Neo.TransientError.General.DatabaseUnavailable · HTTP 500)'))
  })

  test("a proxy's error page and no answer at all read differently", async () => {
    const page = load(async () => new Response('<html>Bad Gateway</html>', { status: 502 }))
    await waitFor(() => expect(page.current.error).toBe('Failed to load (non_json_response · HTTP 502)'))
    const none = load(async () => { throw new TypeError('Failed to fetch') })
    await waitFor(() => expect(none.current.error).toBe('Failed to load (network_error)'))
  })
})
