/**
 * Install (README.PLUGINS.md §9.3): consent equal to the release's permissions, a leased
 * operation, download, the six checks, a rename into versions/, the database write that
 * is the commit, then a runner reload. A refused install leaves only `lastError`; an
 * install whose worker cannot start is installed but `failed`. Nothing is built and the
 * schema never changes (D-07).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import path from 'node:path'
import childProcess from 'node:child_process'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, audit: [] as Record<string, unknown>[] }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async (e: Record<string, unknown>) => void h.audit.push(e)) }))

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ADMIN, NOW, exists, startLifecycleWorld, type LifecycleWorld } from './__testing__/lifecycleHarness'
import { setNowForTests } from './clock'
import { CatalogError } from './catalog'
import { FetchRemoteError } from './fetchRemote'
import { LifecycleError, install } from './lifecycle'
import { stagingPath, versionPath } from './staging'

let db: FakePrisma
let w: LifecycleWorld
const PERMS = ['session:read', 'llm:invoke', 'override:skill.text', 'override:user_skill.text']

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.audit = []
  setNowForTests(() => NOW)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
  db.seed('user', [{ id: ADMIN, email: 'admin@example.com', role: 'admin' }])
  w = await startLifecycleWorld(() => db)
})

afterEach(async () => {
  await w.close()
  setNowForTests(null)
  vi.restoreAllMocks()
})

const row = () => db.rows('pluginInstall').find((r) => r.pluginId === 'echo')
const go = (over: Record<string, unknown> = {}) =>
  install('echo', { version: '1.0.0', acceptedPermissions: PERMS, ...over } as never, ADMIN, w.deps)

async function refusal(p: Promise<unknown>): Promise<LifecycleError> {
  const e = await p.then(
    () => {
      throw new Error('expected a refusal')
    },
    (err) => err,
  )
  expect(e).toBeInstanceOf(LifecycleError)
  return e as LifecycleError
}

describe('the happy path', () => {
  test('row ready and enabled, files in versions/1.0.0, catalog entry pinned, runner reloaded, audited', async () => {
    const out = await go()
    expect(out.plugin).toMatchObject({ pluginId: 'echo', status: 'ready', enabled: true, activeVersion: '1.0.0' })
    const r = row()!
    expect(r).toMatchObject({
      status: 'ready',
      enabled: true,
      activeVersion: '1.0.0',
      previousVersion: null,
      pendingVersion: null,
      dataVersion: 1,
      grantedPermissions: PERMS,
      installedBy: ADMIN,
      lastError: null,
      operationId: null,
      leaseExpiresAt: null,
    })
    expect((r.manifest as { id: string }).id).toBe('echo')
    const a = w.archives.get('1.0.0')!
    expect(r.catalogEntry).toMatchObject({ version: '1.0.0', url: a.release.url, sha256: a.sha256 })
    expect(await exists(path.join(versionPath('echo', '1.0.0'), 'engine', 'main.py'))).toBe(true)
    expect(w.runner.reloads).toBe(1)
    expect(w.downloads).toEqual([a.release.url])
    const actions = h.audit.map((e) => e.action)
    expect(actions).toEqual(expect.arrayContaining(['plugin.install', 'plugin.permissions_granted']))
    const audit = h.audit.find((e) => e.action === 'plugin.install')!
    expect(audit).toMatchObject({ actorId: ADMIN, targetType: 'plugin', targetId: 'echo' })
    expect(audit.after).toMatchObject({ status: 'ready', activeVersion: '1.0.0' })
  })

  test('nothing is built and the schema never changes (D-07)', async () => {
    const spawns = [
      vi.spyOn(childProcess, 'spawn'),
      vi.spyOn(childProcess, 'exec'),
      vi.spyOn(childProcess, 'execFile'),
      vi.spyOn(childProcess, 'spawnSync'),
      vi.spyOn(childProcess, 'execSync'),
    ]
    await go()
    for (const s of spawns) expect(s).not.toHaveBeenCalled()
    expect(db.rawCalls.filter((c) => !/pg_advisory_xact_lock/.test(c.sql))).toEqual([])
  })
})

describe('refusals before anything is written', () => {
  test('accepted permissions that are not the release list → 400, no row', async () => {
    const e = await refusal(go({ acceptedPermissions: ['session:read'] }))
    expect([e.status, e.code]).toEqual([400, 'permissions_mismatch'])
    expect(row()).toBeUndefined()
    expect(w.downloads).toEqual([])
  })

  test('the same permissions in another order are consent', async () => {
    expect((await go({ acceptedPermissions: [...PERMS].reverse() })).plugin.status).toBe('ready')
  })

  test.each([
    ['a version the catalog does not list', { version: '9.9.9' }, 404, 'release_not_found'],
    ['a malformed version', { version: 'latest' }, 400, 'invalid_request'],
    ['permissions that are not a list', { acceptedPermissions: 'all' }, 400, 'invalid_request'],
  ])('%s', async (_n, over, status, code) => {
    const e = await refusal(go(over))
    expect([e.status, e.code]).toEqual([status, code])
    expect(row()).toBeUndefined()
  })

  test('a plugin the catalog does not list → 404', async () => {
    const e = await refusal(install('other', { version: '1.0.0', acceptedPermissions: [] }, ADMIN, w.deps))
    expect([e.status, e.code]).toEqual([404, 'not_in_catalog'])
  })

  test('an invalid plugin id → 400', async () => {
    const e = await refusal(install('../etc', { version: '1.0.0', acceptedPermissions: [] }, ADMIN, w.deps))
    expect([e.status, e.code]).toEqual([400, 'invalid_plugin_id'])
  })

  test('a revoked release → 409, never downloaded', async () => {
    w.catalog.revoked = [{ id: 'echo', version: '1.0.0', reason: 'Leaks data.' }]
    const e = await refusal(go())
    expect([e.status, e.code]).toEqual([409, 'release_revoked'])
    expect(e.message).toMatch(/Leaks data/)
    expect(w.downloads).toEqual([])
  })

  test('a release for another platform → 409', async () => {
    await w.close()
    w = await startLifecycleWorld(() => db, [{ manifest: { platform: '>=2.0.0 <3.0.0' } }])
    const e = await refusal(go())
    expect([e.status, e.code]).toEqual([409, 'platform_incompatible'])
  })

  test('an unreachable catalog → 503, no row', async () => {
    w.catalog.unavailable = new CatalogError('catalog_unreachable', 'The catalog could not be downloaded.')
    const e = await refusal(go())
    expect([e.status, e.code]).toEqual([503, 'catalog_unavailable'])
    expect(e.details).toEqual(['catalog_unreachable'])
    expect(row()).toBeUndefined()
  })

  test('already installed → 409', async () => {
    await go()
    const e = await refusal(go())
    expect([e.status, e.code]).toEqual([409, 'already_installed'])
  })
})

describe('refusals after the operation started leave only lastError', () => {
  test.each([
    ['sha256_mismatch', (a: { release: Record<string, unknown> }) => (a.release.sha256 = 'f'.repeat(64))],
    ['manifest_mismatch', (a: { release: Record<string, unknown> }) => (a.release.dataVersion = 7)],
  ])('%s: status available, lastError set, no folder, no staging, audited', async (code, mutate) => {
    mutate(w.archives.get('1.0.0') as never)
    const e = await refusal(go())
    expect([e.status, e.code]).toEqual([422, code])
    const r = row()!
    expect(r.status).toBe('available')
    expect(String(r.lastError)).toMatch(new RegExp(`^${code}`))
    expect(r.operationId).toBeNull()
    expect(r.activeVersion).toBeNull()
    expect(await exists(path.join(w.root, 'echo'))).toBe(false)
    expect(await exists(path.join(w.root, '.staging'))).toBe(false)
    expect(h.audit.map((x) => x.action)).toContain('plugin.install_failed')
    expect(w.runner.reloads).toBe(0)
  })

  test('an unsafe archive (symlink) is refused the same way', async () => {
    await w.close()
    w = await startLifecycleWorld(() => db, [{ tar: { symlink: { name: 'echo/x', target: '/etc/passwd' } } }])
    const e = await refusal(go())
    expect(e.code).toBe('unsafe_archive')
    expect(row()!.status).toBe('available')
    expect(await exists(path.join(w.root, 'echo'))).toBe(false)
  })

  test('a download failure → 502 download_failed, lastError, no folder', async () => {
    w.deps.fetchArchive = async () => {
      throw new FetchRemoteError('http_error', 'The plugin download answered HTTP 404.', 'https://x', 404)
    }
    const e = await refusal(go())
    expect([e.status, e.code]).toEqual([502, 'download_failed'])
    expect(String(row()!.lastError)).toMatch(/^download_failed/)
    expect(row()!.status).toBe('available')
  })

  test('a failed install can be retried', async () => {
    const a = w.archives.get('1.0.0')!
    const good = a.release.sha256
    a.release.sha256 = '0'.repeat(64)
    await refusal(go())
    a.release.sha256 = good
    expect((await go()).plugin.status).toBe('ready')
    expect(row()!.lastError).toBeNull()
  })
})

describe('the runner', () => {
  test('down: the plugin is installed but failed with runner_unavailable and why', async () => {
    await w.runner.close()
    const out = await go()
    expect(out.plugin).toMatchObject({ status: 'failed', lastError: 'runner_unavailable (unreachable)', activeVersion: '1.0.0' })
    expect(await exists(versionPath('echo', '1.0.0'))).toBe(true)
  })

  test('a worker that cannot start: installed but failed with the reason', async () => {
    w.failing.add('echo@1.0.0')
    const out = await go()
    expect(out.plugin.status).toBe('failed')
    expect(String(out.plugin.lastError)).toMatch(/^worker_failed/)
  })
})

describe('races', () => {
  test('two installs at once: one wins, the other is refused 409', async () => {
    const results = await Promise.allSettled([go(), go()])
    const ok = results.filter((r) => r.status === 'fulfilled')
    const bad = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected')
    expect(ok).toHaveLength(1)
    expect(bad).toHaveLength(1)
    expect((bad[0].reason as LifecycleError).status).toBe(409)
    expect(row()!.status).toBe('ready')
    const fsp = await import('node:fs/promises')
    expect(await fsp.readdir(path.join(w.root, '.staging'))).toEqual([])
  })

  test('the staging folder of the operation is gone after the commit', async () => {
    await go()
    const fsp = await import('node:fs/promises')
    expect(await fsp.readdir(path.join(w.root, '.staging'))).toEqual([])
    expect(stagingPath('0f8b6c1e-2a3d-4e5f-8a9b-0c1d2e3f4a5b')).toContain('.staging')
  })
})
