import { describe, test, expect } from 'vitest'
import { readScanStartError, scanStartNetworkError } from './scanStartError'

describe('readScanStartError', () => {
  test('keeps the message, status, code, upstream status and limit', async () => {
    const res = new Response(JSON.stringify({
      error: 'Not enough memory', code: 'ram_limit', upstreamStatus: 409, limit: { limitType: 'ram', current: 9, ceiling: 8 },
    }), { status: 409 })
    expect(await readScanStartError(res, 'Failed to start GVM scan')).toEqual({
      message: 'Not enough memory', status: 409, code: 'ram_limit', upstreamStatus: 409,
      limit: { limitType: 'ram', current: 9, ceiling: 8 },
    })
  })

  test("a proxy's HTML page keeps the fallback and is marked non_json_response", async () => {
    const res = new Response('<html>Bad Gateway</html>', { status: 502 })
    expect(await readScanStartError(res, 'Failed to start recon')).toEqual({
      message: 'Failed to start recon', status: 502, code: 'non_json_response',
    })
  })
})

describe('scanStartNetworkError', () => {
  test('a start that got no answer is status 0, network_error', () => {
    expect(scanStartNetworkError(new TypeError('Failed to fetch'), 'Failed to start')).toEqual({
      message: 'Failed to start', status: 0, code: 'network_error',
    })
  })
})
