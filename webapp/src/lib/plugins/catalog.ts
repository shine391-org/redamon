import { verify } from 'crypto'
import prisma from '@/lib/prisma'
import { safeErrorCode } from '@/lib/routeErrors'
import { compareVersions, parseVersion, satisfies } from '@/lib/semver'
import { now } from './clock'
import { FetchRemoteError, fetchRemote, type FetchResult } from './fetchRemote'
import { OFFICIAL_KEYS, findTrustedKey, type TrustedKey } from './keyring'
import { isPluginPermission } from './permissions'
import { parseCatalog, type CatalogRelease, type PluginCatalog } from './schemas/catalog'

/**
 * The signed plugin catalog (README.PLUGINS.md §6.2, TD-11).
 *
 * - `catalog.json.sig` is `{keyId, sig}`: a base64 Ed25519 signature over the EXACT bytes
 *   of `catalog.json`, checked against the trusted key it names.
 * - The highest accepted `serial` is kept in PluginPlatformState together with the bytes
 *   and signature of that catalog. A lower serial is not an error: the raw CDN can serve
 *   an older copy for minutes after a push (E5), so the stored last-good catalog is used
 *   and the replay logged (RV-45). It is verified again on every use, so a key removed
 *   from the keyring (or past its `notAfter`) still applies to it.
 * - One mark for all the official keys, so a catalog signed by a rotated-out key cannot be
 *   replayed under the newer key's serial; one mark per extra key, so a custom or
 *   development catalog (whose serial may be a Unix time) never holds the official one back.
 * - A catalog never expires (the owner's decision of 2026-10-11): an `expires` field left
 *   by older CI is ignored. A replay of an old catalog is caught by the serial only, so an
 *   installation that never saw a newer one can be shown an older genuine catalog.
 * - Nothing here writes anything but the serial record.
 */
export const DEFAULT_CATALOG_URL = 'https://raw.githubusercontent.com/samugit83/redamon-plugins/master/catalog.json'
export const CATALOG_STATE_KEY = 'catalog.serial'
export const CATALOG_CACHE_MS = 60_000
const SIGNATURE_FILE_MAX_BYTES = 4096

export type CatalogErrorCode = 'catalog_unreachable' | 'signature_invalid' | 'unknown_key' | 'schema_invalid'
export type CatalogWarning = 'extra_key' | 'replayed'

export class CatalogError extends Error {
  constructor(
    readonly code: CatalogErrorCode,
    message: string,
    readonly details?: string[],
    /** For `catalog_unreachable`: the download's refusal code. */
    readonly fetchCode?: string,
  ) {
    super(message)
    this.name = 'CatalogError'
  }
}

export interface LoadedCatalog {
  catalog: PluginCatalog
  keyId: string
  official: boolean
  serial: number
  warnings: CatalogWarning[]
}

export type CatalogSource = { source: 'official' } | { source: 'upload'; bytes: Buffer; sigBytes: Buffer }
export type CatalogFetch = (url: string, opts: { kind: 'catalog' }) => Promise<FetchResult>

type Db = Pick<typeof prisma, 'pluginPlatformState' | '$transaction'>

export interface CatalogDeps {
  fetch?: CatalogFetch
  officialKeys?: readonly TrustedKey[]
  db?: Db
  /** Skip the in-memory cache (tests, and a reload the admin asked for). */
  noCache?: boolean
}

interface StoredCatalog {
  serial: number
  keyId: string
  bytes: string
  sig: string
  acceptedAt: string
}

export function catalogUrl(): string {
  return (process.env.PLUGINS_CATALOG_URL || '').trim() || DEFAULT_CATALOG_URL
}

let cache: { at: number; url: string; result: LoadedCatalog | CatalogError } | null = null

export function clearCatalogCache(): void {
  cache = null
}

interface Verified {
  catalog: PluginCatalog
  keyId: string
  official: boolean
}

function parseSignature(sigBytes: Buffer): { keyId: string; sig: Buffer } {
  const bad = (why: string) => new CatalogError('signature_invalid', `The catalog signature file is invalid: ${why}.`)
  if (sigBytes.length > SIGNATURE_FILE_MAX_BYTES) throw bad('too large')
  let o: unknown
  try {
    o = JSON.parse(sigBytes.toString('utf8'))
  } catch {
    throw bad('not JSON')
  }
  if (!o || typeof o !== 'object' || Array.isArray(o)) throw bad('not an object')
  const { keyId, sig } = o as Record<string, unknown>
  if (typeof keyId !== 'string' || !keyId) throw bad('no keyId')
  if (typeof sig !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(sig)) throw bad('no base64 sig')
  const raw = Buffer.from(sig, 'base64')
  if (raw.length !== 64) throw bad('an Ed25519 signature is 64 bytes')
  return { keyId, sig: raw }
}

/** Signature, then schema; the serial is the caller's business. */
function verifyCatalog(bytes: Buffer, sigBytes: Buffer, officialKeys: readonly TrustedKey[]): Verified {
  const { keyId, sig } = parseSignature(sigBytes)
  const trusted = findTrustedKey(keyId, officialKeys)
  if (!trusted) {
    throw new CatalogError('unknown_key', `The catalog is signed with key "${keyId}", which this RedAmon does not trust.`)
  }
  if (!verify(null, bytes, trusted.key, sig)) {
    throw new CatalogError('signature_invalid', `The catalog signature does not match its contents (key "${keyId}").`)
  }
  let json: unknown
  try {
    json = JSON.parse(bytes.toString('utf8'))
  } catch {
    throw new CatalogError('schema_invalid', 'The signed catalog is not JSON.')
  }
  const parsed = parseCatalog(json)
  if (!parsed.ok) {
    throw new CatalogError('schema_invalid', 'The signed catalog does not match the catalog schema.', parsed.errors)
  }
  return { catalog: parsed.value, keyId, official: trusted.official }
}

function result(v: Verified, replayed: boolean): LoadedCatalog {
  const warnings: CatalogWarning[] = []
  if (!v.official) warnings.push('extra_key')
  if (replayed) warnings.push('replayed')
  return { catalog: v.catalog, keyId: v.keyId, official: v.official, serial: v.catalog.serial, warnings }
}

const markKey = (v: Verified) => (v.official ? CATALOG_STATE_KEY : `${CATALOG_STATE_KEY}:extra:${v.keyId}`)

function readStored(value: unknown, v: Verified, officialKeys: readonly TrustedKey[]): StoredCatalog | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const s = value as Record<string, unknown>
  if (!Number.isSafeInteger(s.serial) || typeof s.bytes !== 'string' || typeof s.sig !== 'string') return null
  // The official mark counts only while the key that set it is official: earlier code kept
  // every key's mark under this name, and a key taken out of the keyring (rotated keys stay
  // listed with notAfter) must not hold the catalog back.
  if (v.official && !officialKeys.some((k) => k.keyId === s.keyId)) return null
  return s as unknown as StoredCatalog
}

/**
 * Keeps the highest serial of the catalog's mark. Under an advisory lock, so two loads at
 * once compare against the same stored value and the serial is never lowered.
 */
async function settleSerial(
  v: Verified,
  bytes: Buffer,
  sigBytes: Buffer,
  officialKeys: readonly TrustedKey[],
  db: Db,
): Promise<LoadedCatalog> {
  const key = markKey(v)
  return db.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${'plugins:' + key}))`
    const row = await tx.pluginPlatformState.findUnique({ where: { key } })
    const stored = readStored(row?.value, v, officialKeys)
    if (stored && v.catalog.serial < stored.serial) {
      console.warn(
        `[plugins] catalog replay: fetched serial ${v.catalog.serial} is older than the accepted ` +
          `${stored.serial} (${key}); using the stored catalog`,
      )
      const again = verifyCatalog(Buffer.from(stored.bytes, 'base64'), Buffer.from(stored.sig, 'base64'), officialKeys)
      return result(again, true)
    }
    if (!stored || v.catalog.serial > stored.serial) {
      const value: StoredCatalog = {
        serial: v.catalog.serial,
        keyId: v.keyId,
        bytes: bytes.toString('base64'),
        sig: sigBytes.toString('base64'),
        acceptedAt: now().toISOString(),
      }
      await tx.pluginPlatformState.upsert({
        where: { key },
        create: { key, value: value as never },
        update: { value: value as never },
      })
    }
    return result(v, false)
  })
}

async function download(fetcher: CatalogFetch, url: string, file: string): Promise<Buffer> {
  try {
    return (await fetcher(url, { kind: 'catalog' })).bytes
  } catch (e) {
    const code = e instanceof FetchRemoteError ? e.code : undefined
    // A FetchRemoteError's message is the platform's own (host, HTTP status, errno); any
    // other error is named by its code only.
    const why = e instanceof FetchRemoteError ? e.message : safeErrorCode(e)
    throw new CatalogError('catalog_unreachable', `The plugin catalog could not be downloaded (${file}): ${why}`, undefined, code)
  }
}

export async function loadCatalog(source: CatalogSource, deps: CatalogDeps = {}): Promise<LoadedCatalog> {
  const officialKeys = deps.officialKeys ?? OFFICIAL_KEYS
  const db = deps.db ?? prisma
  if (source.source === 'upload') {
    const v = verifyCatalog(source.bytes, source.sigBytes, officialKeys)
    return settleSerial(v, source.bytes, source.sigBytes, officialKeys, db)
  }

  const url = catalogUrl()
  const t = now().getTime()
  const cached = !deps.noCache && cache && cache.url === url && t - cache.at < CATALOG_CACHE_MS ? cache.result : null
  if (cached instanceof CatalogError) throw cached
  if (cached) return cached
  let out: LoadedCatalog | CatalogError
  try {
    const fetcher = deps.fetch ?? fetchRemote
    const [bytes, sigBytes] = await Promise.all([download(fetcher, url, 'catalog.json'), download(fetcher, `${url}.sig`, 'catalog.json.sig')])
    out = await settleSerial(verifyCatalog(bytes, sigBytes, officialKeys), bytes, sigBytes, officialKeys, db)
  } catch (e) {
    if (!(e instanceof CatalogError)) throw e
    const details = e.details?.length ? ` [${e.details.slice(0, 5).join('; ')}]` : ''
    console.warn(`[plugins] catalog not loaded: ${e.code}${e.fetchCode ? ` (${e.fetchCode})` : ''}: ${e.message}${details}`)
    out = e
  }
  if (!deps.noCache) cache = { at: t, url, result: out }
  if (out instanceof CatalogError) throw out
  return out
}

export function findCatalogPlugin(catalog: PluginCatalog, pluginId: string): PluginCatalog['plugins'][number] | null {
  return catalog.plugins.find((p) => p.id === pluginId) ?? null
}

/** The revocation reason of a version, or null. */
export function isRevoked(catalog: Pick<PluginCatalog, 'revoked'>, pluginId: string, version: string): string | null {
  return catalog.revoked.find((r) => r.id === pluginId && r.version === version)?.reason ?? null
}

/** The newest release this platform can run; never a revoked one. */
export function chooseRelease(
  entry: { id: string; releases: CatalogRelease[] },
  platformVersion: string,
  revoked: PluginCatalog['revoked'] = [],
): CatalogRelease | null {
  const candidates = entry.releases.filter(
    (r) =>
      satisfies(platformVersion, r.platform) &&
      r.permissions.every(isPluginPermission) &&
      !revoked.some((x) => x.id === entry.id && x.version === r.version),
  )
  if (!candidates.length) return null
  return candidates.reduce((best, r) =>
    compareVersions(parseVersion(r.version), parseVersion(best.version)) > 0 ? r : best,
  )
}
