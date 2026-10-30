/**
 * Loading the signed plugin catalog (README.PLUGINS.md §6.2, TD-11): the Ed25519
 * signature over the exact bytes, against the key the signature names; the schema; and
 * the serial high-water mark kept with the accepted bytes, so a replayed (older) catalog
 * never wins and is not an error either (RV-45). A catalog never expires.
 *
 * @vitest-environment node
 */
import { describe, test, expect, afterEach, beforeEach, vi } from 'vitest'
import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { makeKeyPair, type TestKeyPair } from './__testing__/ed25519'
import { buildCatalog, type BuildCatalogInput } from './__testing__/catalogBuilder'
import { closeAllFakeServers, startFakeServer } from './__testing__/fakeHttpServer'
import { setNowForTests } from './clock'
import type { TrustedKey } from './keyring'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown> }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))

import {
  CATALOG_CACHE_MS,
  CATALOG_STATE_KEY,
  CatalogError,
  catalogUrl,
  clearCatalogCache,
  loadCatalog,
  type CatalogFetch,
} from './catalog'

const NOW = new Date('2026-10-10T08:00:00Z')
let db: FakePrisma
let clock: Date
let official: TestKeyPair
let dev: TestKeyPair

const asTrusted = (kp: TestKeyPair): TrustedKey => ({ keyId: kp.keyId, publicKey: kp.publicKeyRawB64 })

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  clock = NOW
  setNowForTests(() => clock)
  official = makeKeyPair('redamon-2026')
  dev = makeKeyPair('dev-1')
  process.env.PLUGINS_EXTRA_TRUSTED_KEYS = JSON.stringify([asTrusted(dev)])
  clearCatalogCache()
})

afterEach(async () => {
  setNowForTests(null)
  delete process.env.PLUGINS_EXTRA_TRUSTED_KEYS
  delete process.env.PLUGINS_CATALOG_URL
  await closeAllFakeServers()
  vi.restoreAllMocks()
})

function catalogOf(serial: number, extra: Partial<BuildCatalogInput> = {}) {
  return buildCatalog({
    releases: [{ pluginId: 'echo', version: '1.0.0', permissions: ['session:read'] }],
    serial,
    key: official,
    ...extra,
  })
}

/** A fake fetch that serves one catalog and its signature at the configured URL. */
function serving(c: { bytes: Buffer; sigBytes: Buffer }): CatalogFetch & { calls: string[] } {
  const calls: string[] = []
  const f = (async (url: string) => {
    calls.push(url)
    if (url === catalogUrl()) return { bytes: c.bytes, finalUrl: url }
    if (url === `${catalogUrl()}.sig`) return { bytes: c.sigBytes, finalUrl: url }
    throw new Error(`unexpected ${url}`)
  }) as unknown as CatalogFetch & { calls: string[] }
  f.calls = calls
  return f
}

const officialKeys = () => [asTrusted(official)]

async function refused(p: Promise<unknown>): Promise<CatalogError> {
  const e = await p.then(
    () => {
      throw new Error('expected a refusal')
    },
    (err) => err,
  )
  expect(e).toBeInstanceOf(CatalogError)
  return e as CatalogError
}

function stored(key = CATALOG_STATE_KEY): { serial: number; keyId: string; bytes: string; sig: string } | undefined {
  return db.rows('pluginPlatformState').find((r) => r.key === key)?.value as never
}

describe('signature', () => {
  test('a catalog signed by an official key is accepted and remembered', async () => {
    const c = catalogOf(7)
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(c), officialKeys: officialKeys() })
    expect(out.official).toBe(true)
    expect(out.keyId).toBe('redamon-2026')
    expect(out.serial).toBe(7)
    expect(out.catalog.plugins[0].id).toBe('echo')
    expect('expiresAt' in out).toBe(false)
    expect(out.warnings).toEqual([])
    expect(stored()).toMatchObject({ serial: 7, keyId: 'redamon-2026' })
    expect(Buffer.from(stored()!.bytes, 'base64').equals(c.bytes)).toBe(true)
  })

  test('the default URL is the official catalog, overridable by PLUGINS_CATALOG_URL', async () => {
    expect(catalogUrl()).toBe('https://raw.githubusercontent.com/samugit83/redamon-plugins/master/catalog.json')
    process.env.PLUGINS_CATALOG_URL = ' https://raw.githubusercontent.com/example/other/main/catalog.json '
    expect(catalogUrl()).toBe('https://raw.githubusercontent.com/example/other/main/catalog.json')
    const f = serving(catalogOf(1))
    await loadCatalog({ source: 'official' }, { fetch: f, officialKeys: officialKeys() })
    expect(f.calls).toEqual([catalogUrl(), `${catalogUrl()}.sig`])
  })

  test('a catalog signed by an extra key is accepted, not official, with a warning', async () => {
    const c = catalogOf(3, { key: dev })
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(c), officialKeys: officialKeys() })
    expect(out.official).toBe(false)
    expect(out.warnings).toContain('extra_key')
  })

  test('one flipped byte breaks the signature', async () => {
    const c = catalogOf(7)
    const bytes = Buffer.from(c.bytes)
    bytes[bytes.length - 3] ^= 0x01
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving({ ...c, bytes }), officialKeys: officialKeys() }))
    expect(e.code).toBe('signature_invalid')
    expect(stored()).toBeUndefined()
  })

  test('re-serialised JSON with the same content fails: the signature covers the exact bytes', async () => {
    const c = catalogOf(7)
    const bytes = Buffer.from(JSON.stringify(JSON.parse(c.bytes.toString())))
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving({ ...c, bytes }), officialKeys: officialKeys() }))
    expect(e.code).toBe('signature_invalid')
  })

  test('a signature by a key nobody trusts is refused as unknown_key', async () => {
    const stranger = makeKeyPair('stranger')
    const e = await refused(
      loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(7, { key: stranger })), officialKeys: officialKeys() }),
    )
    expect(e.code).toBe('unknown_key')
    expect(e.message).toMatch(/stranger/)
  })

  test('a signature that claims the official key id but was made by another key is refused', async () => {
    const c = catalogOf(7, { key: dev, claimKeyId: 'redamon-2026' })
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving(c), officialKeys: officialKeys() }))
    expect(e.code).toBe('signature_invalid')
  })

  test('a rotated-out key (past notAfter) no longer verifies', async () => {
    const keys = [{ ...asTrusted(official), notAfter: '2026-10-01T00:00:00Z' }]
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(7)), officialKeys: keys }))
    expect(e.code).toBe('unknown_key')
  })

  test.each([
    ['not JSON', Buffer.from('nope')],
    ['no sig', Buffer.from(JSON.stringify({ keyId: 'redamon-2026' }))],
    ['sig not base64', Buffer.from(JSON.stringify({ keyId: 'redamon-2026', sig: '***' }))],
    ['sig of the wrong length', Buffer.from(JSON.stringify({ keyId: 'redamon-2026', sig: Buffer.alloc(10).toString('base64') }))],
  ])('a malformed signature file (%s) is refused', async (_name, sigBytes) => {
    const c = catalogOf(7)
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving({ ...c, sigBytes }), officialKeys: officialKeys() }))
    expect(e.code).toBe('signature_invalid')
  })

  test('a validly signed catalog that breaks the schema is refused', async () => {
    const c = catalogOf(7, { catalogVersion: 2 })
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving(c), officialKeys: officialKeys() }))
    expect(e.code).toBe('schema_invalid')
    expect(e.details?.length).toBeGreaterThan(0)
  })
})

describe('no expiry (owner decision of 2026-10-11)', () => {
  test('a catalog signed years ago is still accepted, with no warning', async () => {
    const c = catalogOf(9)
    clock = new Date(NOW.getTime() + 5 * 365 * 86_400_000)
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(c), officialKeys: officialKeys() })
    expect(out.serial).toBe(9)
    expect(out.warnings).toEqual([])
  })

  test('an older catalog that still carries a past expires is accepted; the field is ignored', async () => {
    const c = catalogOf(9, { legacyExpires: new Date(NOW.getTime() - 86_400_000).toISOString() })
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(c), officialKeys: officialKeys() })
    expect(out.serial).toBe(9)
    expect(out.warnings).toEqual([])
    expect('expires' in out.catalog).toBe(false)
    expect(stored()).toMatchObject({ serial: 9 })
  })

  test('the same holds for an uploaded catalog (offline install)', async () => {
    const c = catalogOf(11, { key: dev, legacyExpires: '2026-01-01T00:00:00Z' })
    const out = await loadCatalog({ source: 'upload', bytes: c.bytes, sigBytes: c.sigBytes }, { officialKeys: officialKeys() })
    expect(out.serial).toBe(11)
    expect(out.warnings).toEqual(['extra_key'])
  })
})

describe('serial', () => {
  test('a higher serial replaces the stored one; an equal one is accepted unchanged', async () => {
    await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(5)), officialKeys: officialKeys() })
    clearCatalogCache()
    const ten = catalogOf(10)
    await loadCatalog({ source: 'official' }, { fetch: serving(ten), officialKeys: officialKeys() })
    expect(stored()?.serial).toBe(10)
    clearCatalogCache()
    const same = await loadCatalog({ source: 'official' }, { fetch: serving(ten), officialKeys: officialKeys() })
    expect(same.serial).toBe(10)
    expect(same.warnings).not.toContain('replayed')
  })

  test('a lower serial is a replay: the stored last-good catalog is used and the replay logged', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const newer = catalogOf(10, { releases: [{ pluginId: 'echo', version: '2.0.0' }] })
    await loadCatalog({ source: 'official' }, { fetch: serving(newer), officialKeys: officialKeys() })
    clearCatalogCache()
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(4)), officialKeys: officialKeys() })
    expect(out.serial).toBe(10)
    expect(out.catalog.plugins[0].releases[0].version).toBe('2.0.0')
    expect(out.warnings).toContain('replayed')
    expect(stored()?.serial).toBe(10)
    expect(warn.mock.calls.some((c) => /^\[plugins\] catalog replay/.test(String(c[0])))).toBe(true)
  })

  test('a replay falls back to the stored catalog only while it still verifies', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    // The stored catalog's key is rotated out (notAfter passed) while a newer key still signs.
    const next = makeKeyPair('redamon-2027')
    const keys = [{ ...asTrusted(official), notAfter: new Date(NOW.getTime() + 86_400_000).toISOString() }, asTrusted(next)]
    await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(10)), officialKeys: keys })
    clearCatalogCache()
    clock = new Date(NOW.getTime() + 2 * 86_400_000)
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(4, { key: next })), officialKeys: keys }))
    expect(e.code).toBe('unknown_key')
  })

  test('a custom or development catalog never holds the official one back', async () => {
    // The fixture script uses a Unix time as the serial; the official catalog counts from 1.
    const devCatalog = catalogOf(1_791_620_618, { key: dev })
    await loadCatalog({ source: 'upload', bytes: devCatalog.bytes, sigBytes: devCatalog.sigBytes }, { officialKeys: officialKeys() })
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(3)), officialKeys: officialKeys() })
    expect(out).toMatchObject({ serial: 3, official: true })
    expect(out.warnings).not.toContain('replayed')
    expect(stored()).toMatchObject({ serial: 3, keyId: 'redamon-2026' })
    expect(stored(`${CATALOG_STATE_KEY}:extra:dev-1`)).toMatchObject({ serial: 1_791_620_618, keyId: 'dev-1' })
  })

  test('the official keys share one mark: a rotated-in key cannot be replayed under by the older one', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const next = makeKeyPair('redamon-2027')
    const keys = [asTrusted(official), asTrusted(next)]
    await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(10, { key: next })), officialKeys: keys })
    clearCatalogCache()
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(9)), officialKeys: keys })
    expect(out).toMatchObject({ serial: 10, keyId: 'redamon-2027' })
    expect(out.warnings).toContain('replayed')
  })

  test('each extra key keeps its own mark, so a replay under it is still caught', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const twelve = catalogOf(12, { key: dev })
    const eleven = catalogOf(11, { key: dev })
    await loadCatalog({ source: 'upload', bytes: twelve.bytes, sigBytes: twelve.sigBytes }, { officialKeys: officialKeys() })
    const out = await loadCatalog({ source: 'upload', bytes: eleven.bytes, sigBytes: eleven.sigBytes }, { officialKeys: officialKeys() })
    expect(out).toMatchObject({ serial: 12, keyId: 'dev-1' })
    expect(out.warnings).toContain('replayed')
    expect(stored()).toBeUndefined()
  })

  test('an extra key mark stored under the official name by earlier code is not the official mark', async () => {
    const legacy = catalogOf(1_791_620_618, { key: dev })
    db.seed('pluginPlatformState', [{
      key: CATALOG_STATE_KEY,
      value: { serial: 1_791_620_618, keyId: 'dev-1', bytes: legacy.bytes.toString('base64'), sig: legacy.sigBytes.toString('base64'), acceptedAt: NOW.toISOString() },
    }])
    const out = await loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(3)), officialKeys: officialKeys() })
    expect(out).toMatchObject({ serial: 3, official: true })
    expect(stored()).toMatchObject({ serial: 3, keyId: 'redamon-2026' })
  })

  test('two loads at once never lower the stored serial', async () => {
    await Promise.all([
      loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(7)), officialKeys: officialKeys(), noCache: true }),
      loadCatalog({ source: 'official' }, { fetch: serving(catalogOf(5)), officialKeys: officialKeys(), noCache: true }),
    ]).catch(() => {})
    expect(stored()?.serial).toBe(7)
  })
})

describe('sources and caching', () => {
  test('an uploaded catalog goes through the same checks and updates the serial', async () => {
    const c = catalogOf(12, { key: dev })
    const out = await loadCatalog({ source: 'upload', bytes: c.bytes, sigBytes: c.sigBytes }, { officialKeys: officialKeys() })
    expect(out.serial).toBe(12)
    expect(out.official).toBe(false)
    expect(stored(`${CATALOG_STATE_KEY}:extra:dev-1`)?.serial).toBe(12)
    const bad = Buffer.from(c.bytes)
    bad[10] ^= 1
    expect((await refused(loadCatalog({ source: 'upload', bytes: bad, sigBytes: c.sigBytes }))).code).toBe('signature_invalid')
  })

  test('an expires field left in a cached catalog does not cut the 60 s short', async () => {
    const c = catalogOf(7, { legacyExpires: new Date(NOW.getTime() + 30_000).toISOString() })
    const fetch = serving(c)
    await loadCatalog({ source: 'official' }, { fetch, officialKeys: officialKeys() })
    clock = new Date(NOW.getTime() + 40_000)
    const again = await loadCatalog({ source: 'official' }, { fetch, officialKeys: officialKeys() })
    expect(again.serial).toBe(7)
    expect(fetch.calls).toHaveLength(2)
  })

  test('the official catalog is cached for 60 s, failures too', async () => {
    const f = serving(catalogOf(3))
    await loadCatalog({ source: 'official' }, { fetch: f, officialKeys: officialKeys() })
    await loadCatalog({ source: 'official' }, { fetch: f, officialKeys: officialKeys() })
    expect(f.calls).toHaveLength(2)
    clock = new Date(NOW.getTime() + CATALOG_CACHE_MS + 1)
    await loadCatalog({ source: 'official' }, { fetch: f, officialKeys: officialKeys() })
    expect(f.calls).toHaveLength(4)

    clearCatalogCache()
    const down = vi.fn(async () => {
      throw new Error('ECONNREFUSED')
    })
    expect((await refused(loadCatalog({ source: 'official' }, { fetch: down, officialKeys: officialKeys() }))).code).toBe(
      'catalog_unreachable',
    )
    // The catalog and its signature: two downloads for the first load, none for the cached one.
    expect(down).toHaveBeenCalledTimes(2)
    await refused(loadCatalog({ source: 'official' }, { fetch: down, officialKeys: officialKeys() }))
    expect(down).toHaveBeenCalledTimes(2)
  })

  test('unreachable carries the download refusal code', async () => {
    const { FetchRemoteError } = await import('./fetchRemote')
    const f = async () => {
      throw new FetchRemoteError('http_error', 'The plugin download answered HTTP 404.', 'https://x/catalog.json', 404)
    }
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: f, officialKeys: officialKeys() }))
    expect(e.code).toBe('catalog_unreachable')
    expect(e.fetchCode).toBe('http_error')
    expect(e.message).toMatch(/404/)
  })

  test('unreachable names the file that failed; another error is named by its code, never its message', async () => {
    const { FetchRemoteError } = await import('./fetchRemote')
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const sigMissing = async (url: string) => {
      if (url.endsWith('.sig')) throw new FetchRemoteError('http_error', 'The plugin download answered HTTP 404.', url, 404)
      return { bytes: catalogOf(1).bytes } as never
    }
    const e = await refused(loadCatalog({ source: 'official' }, { fetch: sigMissing, officialKeys: officialKeys(), noCache: true }))
    expect(e.message).toBe('The plugin catalog could not be downloaded (catalog.json.sig): The plugin download answered HTTP 404.')
    const odd = async () => {
      throw Object.assign(new Error('token=abc123 in some library text'), { code: 'ECONNRESET' })
    }
    const e2 = await refused(loadCatalog({ source: 'official' }, { fetch: odd, officialKeys: officialKeys(), noCache: true }))
    expect(e2.message).toBe('The plugin catalog could not be downloaded (catalog.json): ECONNRESET')
  })

  test('the default fetch is the guarded fetchRemote (an http catalog URL is refused)', async () => {
    const server = await startFakeServer({ '/catalog.json': { body: catalogOf(1).bytes } })
    process.env.PLUGINS_CATALOG_URL = `${server.baseUrl}/catalog.json`
    const e = await refused(loadCatalog({ source: 'official' }, { officialKeys: officialKeys() }))
    expect(e.code).toBe('catalog_unreachable')
    expect(e.fetchCode).toBe('not_https')
    expect(server.calls).toHaveLength(0)
  })
})
