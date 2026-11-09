/**
 * The engagement identity header has its own accepted contract.
 *
 * checkHeader is shared by every http_header registry field, so tightening
 * it would silently change unrelated custom-header fields. The stricter
 * rules (framing headers, X-Redamon-Ctx, name length) live in
 * checkIdentityHeader because that is the one field recon re-validates as
 * an identity line (auth_profile.engagement_identity_header). These tests
 * pin both sides of that line, plus the CR/LF-before-strip rule and the
 * recon/webapp length consistency (name <= 256, RAW whole line <= 4096),
 * the recon C0-control set (all but TAB) and the ';;' tool-join delimiter,
 * both raw-before-trim and identity-only.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import { checkHeader, checkIdentityHeader } from './validators'

describe('CR/LF is refused on the raw input, before any strip', () => {
  test.each(['X-BB: v\r\n', 'X-BB: v\nInjected: 1', '  \nX-BB: v', '\rX-BB: v'])(
    '%j is refused by both validators',
    (raw: string) => {
      expect(checkIdentityHeader(raw)).toMatch(/carriage return or newline/)
      expect(checkHeader(raw)).toMatch(/carriage return or newline/)
    },
  )
})

describe('the Proxy-* family is refused in full, any casing', () => {
  test.each(['Proxy-Connection: x', 'PROXY-AUTHENTICATE: x', 'proxy-anything: x', 'Proxy-Authorization: x'])(
    '%j is refused by both validators',
    (raw: string) => {
      expect(checkIdentityHeader(raw)).not.toBeNull()
      expect(checkHeader(raw)).not.toBeNull()
    },
  )
})

describe('framing headers are refused only for the identity header', () => {
  test.each(['Content-Length: 3', 'content-length: 3', 'Transfer-Encoding: chunked', 'Connection: keep-alive'])(
    'identity: %j is refused; shared custom headers: still accepted (contract preserved)',
    (raw: string) => {
      expect(checkIdentityHeader(raw)).not.toBeNull()
      expect(checkHeader(raw)).toBeNull()
    },
  )

  test('the reserved capture-proxy tag is refused only for the identity header', () => {
    expect(checkIdentityHeader('X-Redamon-Ctx: abc')).not.toBeNull()
    expect(checkIdentityHeader('x-redamon-ctx: abc')).not.toBeNull()
    expect(checkHeader('X-Redamon-Ctx: abc')).toBeNull()
  })

  test('routing/credential headers are refused by both', () => {
    for (const raw of ['Host: victim.test', 'Authorization: Bearer x', 'Cookie: a=b']) {
      expect(checkIdentityHeader(raw)).not.toBeNull()
      expect(checkHeader(raw)).not.toBeNull()
    }
  })
})

describe('recon/webapp length and name consistency (identity only)', () => {
  test('a header name longer than recon MAX_HEADER_NAME_LEN (256) is refused for identity', () => {
    const name256 = 'X' + 'a'.repeat(255)
    const name257 = 'X' + 'a'.repeat(256)
    expect(checkIdentityHeader(`${name256}: v`)).toBeNull()
    expect(checkIdentityHeader(`${name257}: v`)).toMatch(/longer than 256/)
    // The shared contract has no name-length cap: unchanged.
    expect(checkHeader(`${name257}: v`)).toBeNull()
  })

  test('the whole line cap is 4096 on both layers', () => {
    expect(checkIdentityHeader(`X-BB: ${'a'.repeat(4096)}`)).toMatch(/longer than 4096/)
    expect(checkIdentityHeader(`X-BB: ${'a'.repeat(100)}`)).toBeNull()
    expect(checkHeader(`X-BB: ${'a'.repeat(4096)}`)).toMatch(/longer than 4096/)
  })

  test('an ordinary identity header passes', () => {
    expect(checkIdentityHeader('X-Bug-Bounty: researcher-7f3a')).toBeNull()
    expect(checkIdentityHeader('x-bug-bounty: researcher-7f3a')).toBeNull()
  })
})

describe('identity-only: raw C0 controls (except TAB) and the ;; tool-join delimiter', () => {
  test.each([
    'X-BB: a;;X-B: 2',
    'X-BB: a;;',
    'X-BB: a\x0bb',
    'X-BB: a\x0cb',
    'X-BB: a\x1fb',
    'X-BB: a\x7fb',
    'X-BB: a\x01b',
    'X-BB: a\x08b',
    '\x0bX-BB: v',
    'X-BB: v\x7f',
  ])('identity: %j is refused; shared contract: still accepted (unchanged)', (raw: string) => {
    expect(checkIdentityHeader(raw)).not.toBeNull()
    expect(checkHeader(raw)).toBeNull()
  })

  test('the ;; refusal names the delimiter; C0 names control characters', () => {
    expect(checkIdentityHeader('X-BB: a;;b')).toMatch(/;;/)
    expect(checkIdentityHeader('X-BB: a\x0bb')).toMatch(/control characters/)
    expect(checkIdentityHeader('X-BB: a\x7fb')).toMatch(/control characters/)
  })

  test('TAB in the value stays legal on both layers (recon excludes only TAB)', () => {
    expect(checkIdentityHeader('X-BB: a\tb')).toBeNull()
    expect(checkHeader('X-BB: a\tb')).toBeNull()
  })

  test('a lone semicolon is not the tool-join delimiter', () => {
    expect(checkIdentityHeader('X-BB: a;b')).toBeNull()
  })
})

describe('RAW 4096 bound (identity and shared): leading/trailing space counts', () => {
  test('raw length over 4096 is refused even when the stripped line fits', () => {
    // Raw 4097, stripped 4096: refused — the cap is on the line as written.
    const raw = ' ' + 'X-BB: ' + 'a'.repeat(4090)
    expect(raw.length).toBe(4097)
    expect(raw.trim().length).toBe(4096)
    expect(checkIdentityHeader(raw)).toMatch(/longer than 4096/)
    expect(checkHeader(raw)).toMatch(/longer than 4096/)
  })

  test('a raw line of exactly 4096 passes', () => {
    const raw = 'X-BB: ' + 'a'.repeat(4090)
    expect(raw.length).toBe(4096)
    expect(checkIdentityHeader(raw)).toBeNull()
  })
})
