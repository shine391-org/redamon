/**
 * What a lifecycle operation does when something fails before it commits, and when another
 * operation changed the plugin while this one was being prepared.
 *
 * - A disk error while staging, or any unexpected error before the commit, ends the operation
 *   at once: the plugin goes back to its previous status with the reason, audited. It never
 *   stays leased for reconciliation to find ten minutes later.
 * - An operation starts only if the versions it planned with are still the plugin's: two
 *   admins (or two webapp copies) never run the same update or rollback twice.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  audit: [] as Record<string, unknown>[],
  stageError: null as Error | null,
  commitError: null as Error | null,
  healthError: null as Error | null,
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async (e: Record<string, unknown>) => void h.audit.push(e)) }))
vi.mock('./installChecks', async (orig) => {
  const m = (await orig()) as typeof import('./installChecks')
  return {
    ...m,
    checkAndStage: async (...a: Parameters<typeof m.checkAndStage>) => {
      if (h.stageError) throw h.stageError
      return m.checkAndStage(...a)
    },
  }
})
vi.mock('./runnerClient', async (orig) => {
  const m = (await orig()) as typeof import('./runnerClient')
  return {
    ...m,
    runnerHealth: async (...a: Parameters<typeof m.runnerHealth>) => {
      if (h.healthError) throw h.healthError
      return m.runnerHealth(...a)
    },
  }
})
vi.mock('./staging', async (orig) => {
  const m = (await orig()) as typeof import('./staging')
  return {
    ...m,
    commitVersion: async (...a: Parameters<typeof m.commitVersion>) => {
      if (h.commitError) throw h.commitError
      return m.commitVersion(...a)
    },
  }
})

import { createFakePrisma, type FakePrisma } from './__testing__/fakePrisma'
import { ADMIN, NOW, exists, startLifecycleWorld, type LifecycleWorld } from './__testing__/lifecycleHarness'
import { setNowForTests } from './clock'
import { LifecycleError, install, rollback, update, type LifecycleDeps } from './lifecycle'
import { versionPath } from './staging'

let db: FakePrisma
let w: LifecycleWorld
const PERMS = ['session:read', 'llm:invoke', 'override:skill.text', 'override:user_skill.text']

beforeEach(async () => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.audit = []
  h.stageError = null
  h.commitError = null
  h.healthError = null
  setNowForTests(() => NOW)
  for (const m of ['warn', 'error', 'log'] as const) vi.spyOn(console, m).mockImplementation(() => {})
  db.seed('user', [{ id: ADMIN, email: 'admin@example.com', role: 'admin' }])
  w = await startLifecycleWorld(() => db, [{}, { manifest: { version: '1.0.1' } }, { manifest: { version: '1.1.0', dataVersion: 2 } }])
})

afterEach(async () => {
  await w.close()
  setNowForTests(null)
  vi.restoreAllMocks()
})

const row = () => db.rows('pluginInstall').find((r) => r.pluginId === 'echo')!
const installEcho = (deps: LifecycleDeps = w.deps) => install('echo', { version: '1.0.0', acceptedPermissions: PERMS }, ADMIN, deps)
const updateEcho = (version: string, deps: LifecycleDeps = w.deps) => update('echo', { version, acceptedPermissions: PERMS }, ADMIN, deps)
const diskFull = () => Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' })

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

/** deps whose catalog load first lets "another operation" change the row, once. */
function racing(change: Record<string, unknown>): LifecycleDeps {
  let done = false
  return {
    ...w.deps,
    loadCatalog: async () => {
      if (!done) {
        done = true
        db.tables.pluginInstall.set('echo', { ...row(), ...change })
      }
      return w.deps.loadCatalog!()
    },
  }
}

describe('a failure before the commit ends the operation at once', () => {
  test('a disk error while staging a first install: refused, the row free, audited, a retry works', async () => {
    h.stageError = diskFull()
    const e = await refusal(installEcho())
    expect([e.status, e.code]).toEqual([500, 'staging_failed'])
    expect(row()).toMatchObject({ status: 'available', operationId: null, leaseExpiresAt: null })
    expect(String(row().lastError)).toMatch(/^staging_failed: .*ENOSPC/)
    expect(h.audit.find((a) => a.action === 'plugin.install_failed')).toMatchObject({ after: { code: 'staging_failed' } })
    h.stageError = null
    expect((await installEcho()).plugin).toMatchObject({ status: 'ready', activeVersion: '1.0.0' })
  })

  test('the same during an update: back to ready on the old version, audited as a failed update', async () => {
    await installEcho()
    h.audit = []
    h.stageError = diskFull()
    const e = await refusal(updateEcho('1.0.1'))
    expect([e.status, e.code]).toEqual([500, 'staging_failed'])
    expect(row()).toMatchObject({ status: 'ready', activeVersion: '1.0.0', pendingVersion: null, operationId: null })
    expect(h.audit.find((a) => a.action === 'plugin.update')).toMatchObject({ after: { outcome: 'failed', code: 'staging_failed' } })
  })

  test('an unexpected error before the commit (the folder rename): refused, nothing left on disk', async () => {
    h.commitError = Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' })
    const e = await refusal(installEcho())
    expect([e.status, e.code]).toEqual([500, 'install_failed'])
    expect(row()).toMatchObject({ status: 'available', operationId: null })
    expect(await exists(versionPath('echo', '1.0.0'))).toBe(false)
  })
})

describe("a failure's own text never reaches the answer", () => {
  test('an error before the commit is named by its code, not its message (a path, a query)', async () => {
    h.commitError = Object.assign(new Error('EACCES: permission denied, rename /data/plugins/echo/.staging/op-1'), { code: 'EACCES' })
    const e = await refusal(installEcho())
    expect(e.message).toBe('The install failed before it was committed (EACCES).')
    expect(String(row().lastError)).not.toContain('/data/plugins')
  })
})

describe('a failure after the commit says the operation took effect', () => {
  const poolTimeout = () => Object.assign(new Error('Timed out fetching a connection: SELECT * FROM "PluginInstall"'), { name: 'PrismaClientKnownRequestError', code: 'P2024' })

  test('install: 500 with committed, never reported as a failed install', async () => {
    h.healthError = poolTimeout()
    const e = await refusal(installEcho())
    expect(e).toMatchObject({ status: 500, code: 'P2024', extra: { committed: true } })
    expect(e.message).toBe('The install of echo 1.0.0 took effect, but a step after it failed (P2024); the page shows its state now. The webapp log has the details.')
    expect(row()).toMatchObject({ activeVersion: '1.0.0' })
  })

  test('update: the same', async () => {
    await installEcho()
    h.healthError = poolTimeout()
    const e = await refusal(updateEcho('1.0.1'))
    expect(e).toMatchObject({ status: 500, code: 'P2024', extra: { committed: true } })
    expect(e.message).toMatch(/^The update of echo to 1\.0\.1 took effect/)
    expect(row()).toMatchObject({ activeVersion: '1.0.1' })
  })
})

describe('an operation starts only on the versions it planned with', () => {
  test('another update finished while this one loaded the catalog: 409 plugin_changed, nothing ran', async () => {
    await installEcho()
    const downloads = w.downloads.length
    const e = await refusal(updateEcho('1.1.0', racing({ activeVersion: '1.0.1', previousVersion: '1.0.0' })))
    expect([e.status, e.code]).toEqual([409, 'plugin_changed'])
    expect(row()).toMatchObject({ status: 'ready', activeVersion: '1.0.1', operationId: null })
    expect(w.downloads.length).toBe(downloads)
    expect(w.runner.migrateCalls).toHaveLength(0)
  })

  test('a rollback another one already did: 409 plugin_changed, no second down migration', async () => {
    await installEcho()
    db.seed('pluginData', [{ pluginId: 'echo', ownerType: 'user', ownerId: ADMIN, userId: ADMIN, collection: 'items', key: 'a', value: 1, sizeBytes: 1 }])
    await updateEcho('1.1.0')
    const calls = w.runner.migrateCalls.length
    const e = await refusal(rollback('echo', ADMIN, racing({ activeVersion: '1.0.0', previousVersion: '1.1.0', dataVersion: 1 })))
    expect([e.status, e.code]).toEqual([409, 'plugin_changed'])
    expect(w.runner.migrateCalls.length).toBe(calls)
    expect(row()).toMatchObject({ activeVersion: '1.0.0', dataVersion: 1, operationId: null })
  })
})
