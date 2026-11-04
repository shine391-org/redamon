/**
 * The failure text shared by the graph toolbar and the project form's scan
 * buttons. An orchestrator that did not answer must not read as "GVM is not
 * installed", a 5xx on a data check must not read as "no data", and only a run
 * seen live may toast when it ends in error.
 *
 * Run: npx vitest run src/components/scans/scanErrors.test.ts
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import {
  GVM_NOT_INSTALLED, describeGvmAvailability, downloadScanFile, fetchGvmAvailability, probeScanData, scanFailureToast,
} from './scanErrors'

afterEach(() => vi.unstubAllGlobals())

describe('describeGvmAvailability', () => {
  test('available', () => {
    expect(describeGvmAvailability({ available: true })).toEqual({ available: true, reason: '' })
  })

  test('absent, or an old answer with no reason, keeps the install hint', () => {
    expect(describeGvmAvailability({ available: false, reason: 'gvm_absent' }).reason).toBe(GVM_NOT_INSTALLED)
    expect(describeGvmAvailability({ available: false }).reason).toBe(GVM_NOT_INSTALLED)
  })

  test('an unreachable orchestrator names the code and the errno', () => {
    expect(describeGvmAvailability({ available: false, reason: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })).toEqual({
      available: false,
      reason: 'GVM availability unknown: the recon orchestrator did not report it (orchestrator_unreachable · ECONNREFUSED)',
    })
  })

  test('an orchestrator error keeps its upstream status', () => {
    expect(describeGvmAvailability({ available: false, reason: 'orchestrator_error', upstreamStatus: 500 }).reason)
      .toBe('GVM availability unknown: the recon orchestrator did not report it (orchestrator_error · upstream HTTP 500)')
  })
})

describe('fetchGvmAvailability', () => {
  test('the availability route itself failing is "unknown", with its status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>', { status: 502 })))
    expect(await fetchGvmAvailability()).toEqual({ available: false, reason: 'GVM availability unknown (non_json_response · HTTP 502)' })
  })

  test('no answer at all is a network error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    expect(await fetchGvmAvailability()).toEqual({ available: false, reason: 'GVM availability unknown (network_error)' })
  })
})

describe('probeScanData', () => {
  test('200 is data, 404 is none, a 5xx is unknown with its status', async () => {
    const answer = (status: number) => vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status })))
    answer(200)
    expect(await probeScanData('/api/gvm/p1/download')).toEqual({ has: true, error: null })
    answer(404)
    expect(await probeScanData('/api/gvm/p1/download')).toEqual({ has: false, error: null })
    answer(500)
    expect(await probeScanData('/api/gvm/p1/download')).toEqual({ has: false, error: 'Could not check for data (HTTP 500)' })
  })

  test('it is a HEAD request and a thrown fetch is a network error', async () => {
    const fetchMock = vi.fn(async () => { throw new TypeError('Failed to fetch') })
    vi.stubGlobal('fetch', fetchMock)
    expect(await probeScanData('/api/gvm/p1/download')).toEqual({ has: false, error: 'Could not check for data (network_error)' })
    expect(fetchMock).toHaveBeenCalledWith('/api/gvm/p1/download', { method: 'HEAD' })
  })
})

describe('scanFailureToast', () => {
  test('a live run ending in error toasts with its reason', () => {
    expect(scanFailureToast('GVM scan', 'running', 'error', 'Container exited with code 1')).toBe('GVM scan failed: Container exited with code 1')
    expect(scanFailureToast('GVM scan', 'stopping', 'error', null)).toBe('GVM scan failed')
  })

  test('a run first seen in error, or any other change, does not toast', () => {
    expect(scanFailureToast('GVM scan', undefined, 'error', 'old')).toBeNull()
    expect(scanFailureToast('GVM scan', 'idle', 'error', 'old')).toBeNull()
    expect(scanFailureToast('GVM scan', 'error', 'error', 'old')).toBeNull()
    expect(scanFailureToast('GVM scan', 'running', 'completed', null)).toBeNull()
  })
})

describe('downloadScanFile', () => {
  test('a refused download returns the reason with its code and status', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'Recon data not found' }), { status: 404 })))
    expect(await downloadScanFile('/api/recon/p1/download', 'recon_p1.json')).toBe('Recon data not found (HTTP 404)')
  })

  test('a proxy error page is a non-JSON failure, not a blank tab', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>Bad Gateway</html>', { status: 502 })))
    expect(await downloadScanFile('/api/recon/p1/download', 'recon_p1.json')).toBe('Download failed (non_json_response · HTTP 502)')
  })

  test('no answer is a network error', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    expect(await downloadScanFile('/api/recon/p1/download', 'recon_p1.json')).toBe('Download failed (network_error)')
  })

  test('a file is handed to the browser under the server\'s name', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', {
      status: 200, headers: { 'Content-Disposition': 'attachment; filename="recon_p1.json"' },
    })))
    const createObjectURL = vi.fn(() => 'blob:x')
    vi.stubGlobal('URL', Object.assign(Object.create(URL), { createObjectURL, revokeObjectURL: vi.fn() }))
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('recon_p1.json')
    })
    expect(await downloadScanFile('/api/recon/p1/download', 'fallback.json')).toBeNull()
    expect(click).toHaveBeenCalledTimes(1)
    expect(createObjectURL).toHaveBeenCalledTimes(1)
    click.mockRestore()
  })
})
