/**
 * The same-origin check of every state-changing /api/plugins/** route (R-29, R-45, D-52):
 * the session cookie is SameSite=lax, so a cross-site page can still POST; an `Origin`
 * from elsewhere is refused. Behind the single-host nginx `Host $host` drops the port, so
 * the deployment's own origin comes from PLUGINS_ALLOWED_ORIGIN (seeded by deploy.sh).
 *
 * @vitest-environment node
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { sameOrigin, crossOriginReason, crossOriginResponse } from './sameOrigin'

const req = (url: string, origin?: string | null) =>
  new NextRequest(url, { method: 'POST', headers: origin === undefined || origin === null ? {} : { origin } })

afterEach(() => {
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe('without PLUGINS_ALLOWED_ORIGIN', () => {
  test('no Origin header passes (a non-browser client, or a same-origin GET-like navigation)', () => {
    expect(sameOrigin(req('http://localhost:3000/api/plugins/echo/actions/run'))).toBe(true)
  })

  test("an Origin with the request's host passes", () => {
    expect(sameOrigin(req('http://localhost:3000/api/plugins/x', 'http://localhost:3000'))).toBe(true)
  })

  test.each(['http://evil.example', 'http://localhost:3001', 'http://localhost', 'null', 'not a url'])(
    'Origin %s is refused',
    (origin) => {
      expect(sameOrigin(req('http://localhost:3000/api/plugins/x', origin))).toBe(false)
    },
  )

  // The standalone Next.js server builds request.url from its bind address (HOSTNAME=0.0.0.0
  // in the image), not from the host the browser addressed: found on the live stack, where
  // every browser POST was refused. The browser-visible host is the Host header.
  test('the Host header is what the browser addressed, not the server bind address in request.url', () => {
    const withHost = (origin: string, host: string) =>
      new NextRequest('http://0.0.0.0:3000/api/plugins/echo/actions/run', { method: 'POST', headers: { origin, host } })
    expect(sameOrigin(withHost('http://localhost:3000', 'localhost:3000'))).toBe(true)
    expect(sameOrigin(withHost('http://192.0.2.10:3000', '192.0.2.10:3000'))).toBe(true)
    expect(sameOrigin(withHost('http://evil.example', 'localhost:3000'))).toBe(false)
    expect(sameOrigin(withHost('http://localhost:3000', 'localhost:3001'))).toBe(false)
  })
})

describe('with PLUGINS_ALLOWED_ORIGIN (behind nginx)', () => {
  test('a Host without the port, an Origin equal to the configured one: passes', () => {
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'https://redamon.example.com:8443')
    expect(sameOrigin(req('http://redamon.example.com/api/plugins/x', 'https://redamon.example.com:8443'))).toBe(true)
  })

  test.each(['http://redamon.example.com:8443', 'https://redamon.example.com', 'https://redamon.example.com:9443', 'https://evil.example:8443'])(
    'Origin %s is refused (scheme, host and port must all match)',
    (origin) => {
      vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'https://redamon.example.com:8443')
      expect(sameOrigin(req('http://redamon.example.com/api/plugins/x', origin))).toBe(false)
    },
  )

  test('a trailing slash in the setting is the same origin', () => {
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', ' https://redamon.example.com/ ')
    expect(sameOrigin(req('http://webapp:3000/api/plugins/x', 'https://redamon.example.com'))).toBe(true)
  })

  test.each(['redamon.example.com:8443', 'not a url', 'ftp://redamon.example.com'])(
    'an invalid setting (%s) refuses everything with an Origin, and says why in the log',
    (value) => {
      vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', value)
      const err = vi.spyOn(console, 'error').mockImplementation(() => {})
      expect(sameOrigin(req('http://localhost:3000/api/plugins/x', 'http://localhost:3000'))).toBe(false)
      expect(err.mock.calls.flat().join(' ')).toContain('[plugins] PLUGINS_ALLOWED_ORIGIN is not a valid URL')
    },
  )
})

test('the refusal: 403 cross_origin', async () => {
  const res = crossOriginResponse()
  expect(res.status).toBe(403)
  expect(await res.json()).toEqual({ error: 'Cross-origin request refused.', code: 'cross_origin' })
})

describe('the refusal says which comparison failed (the person\'s own addresses, never a secret)', () => {
  test('no Origin, or a matching one: no reason', () => {
    expect(crossOriginReason(req('http://localhost:3000/api/plugins/x'))).toBeNull()
    expect(crossOriginReason(req('http://localhost:3000/api/plugins/x', 'http://localhost:3000'))).toBeNull()
  })

  test('a page on another host, without the setting: both hosts and the setting to use behind a proxy', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const r = new NextRequest('http://0.0.0.0:3000/api/plugins/x', { method: 'POST', headers: { origin: 'https://redamon.example.com:8443', host: 'redamon.example.com' } })
    const res = crossOriginResponse(r)
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: "Cross-origin request refused: the page's host redamon.example.com:8443 is not the host this request was sent to (redamon.example.com); behind a proxy set PLUGINS_ALLOWED_ORIGIN.",
      code: 'cross_origin',
    })
  })

  test('with the setting: the page origin and the configured one', async () => {
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'https://redamon.example.com:8443')
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = crossOriginResponse(req('http://redamon.example.com/api/plugins/x', 'https://redamon.example.com'))
    expect((await res.json()).error).toBe(
      "Cross-origin request refused: the page's origin https://redamon.example.com is not PLUGINS_ALLOWED_ORIGIN (https://redamon.example.com:8443).",
    )
  })

  test('an invalid setting is named as the cause', () => {
    vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', 'redamon.example.com:8443')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(crossOriginReason(req('http://localhost:3000/api/plugins/x', 'http://localhost:3000'))).toBe(
      'PLUGINS_ALLOWED_ORIGIN is not a valid URL, so every browser request is refused',
    )
  })

  test('a long Origin is cut when quoted back, and the refusal is logged', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const why = crossOriginReason(req('http://localhost:3000/api/plugins/x', `http://${'a'.repeat(300)}.example`))!
    expect(why.length).toBeLessThan(300)
    crossOriginResponse(req('http://localhost:3000/api/plugins/x', 'http://evil.example'))
    expect(warn.mock.calls.flat().join(' ')).toContain('[plugins] cross-origin request refused: the page\'s host evil.example')
  })
})
