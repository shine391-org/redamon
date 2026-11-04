import { NextRequest, NextResponse } from 'next/server'

/**
 * The same-origin check of every state-changing /api/plugins/** route (README.PLUGINS.md
 * §7.5, R-29). There are no CSRF tokens and the session cookie is SameSite=lax, so a page
 * on another site can still POST a form here; together with JSON-only bodies
 * (readJsonBody), an `Origin` from elsewhere is refused. Modelled on the MCP route's
 * `originAllowed`:
 * - no `Origin` passes (not a browser, which sends one with every cross-site POST);
 * - PLUGINS_ALLOWED_ORIGIN set: the whole origin (scheme, host, port) must equal it.
 *   nginx forwards `Host $host`, which drops a non-default port, so behind the
 *   single-host proxy the request's own host cannot be trusted; deploy.sh seeds it;
 * - otherwise the origin's host must equal the request's `Host` header: the host the
 *   browser addressed. Not `request.url`, which the standalone Next.js server builds from its
 *   bind address (HOSTNAME=0.0.0.0 in the image).
 */
export function sameOrigin(request: NextRequest): boolean {
  return crossOriginReason(request) === null
}

// The Origin header is whatever the other page sent: kept short when it is quoted back.
const quote = (v: string) => (v.length > 120 ? `${v.slice(0, 120)}…` : v)

/**
 * Why `sameOrigin` refuses this request, null when it does not. It names the comparison that
 * failed with both addresses (the person's own deployment and the page they came from) and
 * the setting to change, never anything secret.
 */
export function crossOriginReason(request: NextRequest): string | null {
  const origin = request.headers.get('origin')
  if (!origin) return null
  let candidate: URL
  try {
    candidate = new URL(origin)
  } catch {
    return `the Origin header "${quote(origin)}" is not an origin`
  }
  const configured = (process.env.PLUGINS_ALLOWED_ORIGIN || '').trim()
  if (configured) {
    let allowed: URL | null = null
    try {
      allowed = new URL(configured)
    } catch {
      allowed = null
    }
    // A host without a scheme ("example.com:8443") parses with a scheme of its own.
    if (!allowed || (allowed.protocol !== 'https:' && allowed.protocol !== 'http:')) {
      console.error(`[plugins] PLUGINS_ALLOWED_ORIGIN is not a valid URL: ${configured}`)
      return 'PLUGINS_ALLOWED_ORIGIN is not a valid URL, so every browser request is refused'
    }
    return candidate.origin === allowed.origin
      ? null
      : `the page's origin ${quote(candidate.origin)} is not PLUGINS_ALLOWED_ORIGIN (${allowed.origin})`
  }
  let host: string
  try {
    host = request.headers.get('host') || new URL(request.url).host
  } catch {
    return 'the request names no host to compare the origin with'
  }
  return candidate.host === host
    ? null
    : `the page's host ${quote(candidate.host)} is not the host this request was sent to (${quote(host)}); behind a proxy set PLUGINS_ALLOWED_ORIGIN`
}

/**
 * The 403 of a refused origin. Given the request, it says which comparison failed, so a
 * deployment behind a proxy that rewrites Host can be told from a request from another site.
 */
export function crossOriginResponse(request?: NextRequest): NextResponse {
  const why = request ? crossOriginReason(request) : null
  if (why) console.warn(`[plugins] cross-origin request refused: ${why}`)
  const error = why ? `Cross-origin request refused: ${why}.` : 'Cross-origin request refused.'
  return NextResponse.json({ error, code: 'cross_origin' }, { status: 403 })
}
