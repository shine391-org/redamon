import { describe, test, expect, vi, afterEach } from 'vitest'
import {
  ApiError, errorMessage, fetchJson, fetchOk, formatApiError, readApiError, settle, toApiError,
} from './apiError'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('formatApiError', () => {
  test('adds the code, the status and the upstream status', () => {
    expect(formatApiError({ reason: 'Failed to load users', code: 'P2024', status: 500 }))
      .toBe('Failed to load users (P2024 · HTTP 500)')
    expect(formatApiError({ reason: 'Refresh failed', code: 'agent_error', status: 502, upstreamStatus: 500 }))
      .toBe('Refresh failed (agent_error · HTTP 502 · upstream HTTP 500)')
  })

  test('is just the reason when there is nothing to add, and never repeats a status the reason names', () => {
    expect(formatApiError({ reason: 'Failed', status: 0 })).toBe('Failed')
    expect(formatApiError({ reason: 'Save failed (500)', status: 500 })).toBe('Save failed (500)')
    expect(formatApiError({ reason: 'Refresh failed: HTTP 503', status: 503, code: 'agent_unreachable' }))
      .toBe('Refresh failed: HTTP 503 (agent_unreachable)')
  })
})

describe('readApiError', () => {
  test('our routes: error, code, upstreamStatus and details', async () => {
    const e = await readApiError(json(502, {
      error: 'Refresh failed', code: 'agent_error', upstreamStatus: 500, details: ['a', 'b'],
    }), 'fallback')
    expect(e).toBeInstanceOf(ApiError)
    expect(e).toMatchObject({ reason: 'Refresh failed', status: 502, code: 'agent_error', upstreamStatus: 500, details: ['a', 'b'] })
    expect(e.message).toBe('Refresh failed (agent_error · HTTP 502 · upstream HTTP 500)')
    expect(e.body).toMatchObject({ error: 'Refresh failed' })
  })

  test('FastAPI: a string detail, an object detail with its code, a 422 array as details', async () => {
    expect((await readApiError(json(409, { detail: 'Recon already running' }), 'x')).reason).toBe('Recon already running')
    expect(await readApiError(json(500, { detail: { detail: 'spawn failed', code: 'spawn_failed' } }), 'x'))
      .toMatchObject({ reason: 'spawn failed', code: 'spawn_failed' })
    const e422 = await readApiError(json(422, { detail: [{ msg: 'field required' }], errors: [{ message: 'name: required' }] }), 'Invalid')
    expect(e422.reason).toBe('Invalid')
    expect(e422.details).toEqual(['name: required'])
  })

  test('falls back to message, then to the fallback', async () => {
    expect((await readApiError(json(400, { message: 'Bad thing' }), 'x')).reason).toBe('Bad thing')
    expect((await readApiError(json(500, { success: false }), 'Failed to save')).message).toBe('Failed to save (HTTP 500)')
  })

  test("a proxy's HTML page and Next's empty 500 read differently from our refusals", async () => {
    const html = await readApiError(new Response('<html>502 Bad Gateway</html>', { status: 502 }), 'Failed to load')
    expect(html.message).toBe('Failed to load (non_json_response · HTTP 502)')
    const empty = await readApiError(new Response('', { status: 500 }), 'Failed to load')
    expect(empty.message).toBe('Failed to load (empty_response · HTTP 500)')
  })

  test('reads a Response-like object that only has json()', async () => {
    const like = { status: 409, json: async () => ({ error: 'busy', code: 'scan_busy' }) } as unknown as Response
    expect((await readApiError(like, 'f')).message).toBe('busy (scan_busy · HTTP 409)')
    const broken = { status: 500, json: async () => { throw new SyntaxError('x') } } as unknown as Response
    expect((await readApiError(broken, 'f')).message).toBe('f (empty_response · HTTP 500)')
  })

  test('ignores an unsafe code and caps a long reason', async () => {
    const e = await readApiError(json(500, { error: 'x'.repeat(900), code: 'not a code <b>' }), 'f')
    expect(e.code).toBeUndefined()
    expect(e.reason.length).toBe(500)
  })
})

describe('toApiError', () => {
  test('a fetch that got no answer is network_error with status 0', () => {
    const e = toApiError(new TypeError('Failed to fetch'), 'Could not save')
    expect(e).toMatchObject({ status: 0, code: 'network_error' })
    expect(e.message).toBe('Could not save (network_error)')
  })

  test('aborts and timeouts are named', () => {
    expect(toApiError(new DOMException('x', 'AbortError'), 'f').code).toBe('aborted')
    expect(toApiError(new DOMException('x', 'TimeoutError'), 'f').code).toBe('timeout')
  })

  test('another error keeps its class; an ApiError passes through', () => {
    expect(toApiError(new SyntaxError('bad'), 'f').code).toBe('SyntaxError')
    expect(toApiError(new Error('bad'), 'f').code).toBe('client_error')
    expect(toApiError('weird', 'f').code).toBe('network_error')
    const own = new ApiError({ reason: 'r', status: 409 })
    expect(toApiError(own, 'f')).toBe(own)
  })
})

describe('fetchOk and fetchJson', () => {
  test('return the response and the body on success', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(200, { a: 1 })))
    expect(await fetchJson('/x', undefined, 'f')).toEqual({ a: 1 })
    expect((await fetchOk('/x', undefined, 'f')).status).toBe(200)
  })

  test('throw an ApiError for a non-OK answer', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(500, { error: 'Failed to list traffic', code: 'P2024' })))
    await expect(fetchJson('/x', undefined, 'f')).rejects.toMatchObject({
      message: 'Failed to list traffic (P2024 · HTTP 500)', status: 500,
    })
  })

  test('throw network_error when fetch rejects', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    await expect(fetchOk('/x', undefined, 'Could not load')).rejects.toMatchObject({ code: 'network_error', status: 0 })
  })

  test('throw invalid_json for a 2xx body that is not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>', { status: 200 })))
    await expect(fetchJson('/x', undefined, 'Could not load')).rejects.toMatchObject({ code: 'invalid_json', status: 200 })
  })

  test('pass the request on unchanged', async () => {
    const f = vi.fn(async () => json(200, {}))
    vi.stubGlobal('fetch', f)
    const init = { method: 'POST', body: '{}' }
    await fetchJson('/x', init, 'f')
    expect(f).toHaveBeenCalledWith('/x', init)
  })
})

describe('errorMessage and settle', () => {
  test('errorMessage prefers the ApiError text, then an Error message, then the fallback', () => {
    expect(errorMessage(new ApiError({ reason: 'r', status: 500, code: 'P1001' }), 'f')).toBe('r (P1001 · HTTP 500)')
    expect(errorMessage(new Error('plain'), 'f')).toBe('plain')
    expect(errorMessage(undefined, 'f')).toBe('f')
  })

  test('settle answers a value or an ApiError instead of throwing', async () => {
    expect(await settle(async () => 3, 'f')).toEqual({ ok: true, value: 3 })
    const failed = await settle(async () => { throw new TypeError('Failed to fetch') }, 'Could not delete')
    expect(failed.ok).toBe(false)
    if (!failed.ok) expect(failed.error.message).toBe('Could not delete (network_error)')
  })
})
