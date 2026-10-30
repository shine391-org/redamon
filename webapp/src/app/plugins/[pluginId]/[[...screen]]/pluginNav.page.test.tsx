/**
 * /plugins/<pluginId>/[...screen]: a plugin's `nav` page (design §6). It draws the nav screen,
 * or another screen the manifest lists, from the active version's files; anything else is a
 * 404: unknown or not-showing plugin (disabled, revoked, uninstalled), no `nav`
 * contribution, a screen the manifest does not list, a malformed path. A screen file that
 * cannot be read shows an error naming the plugin, not a crash. Inputs passed between
 * screens travel through sessionStorage, so a crafted link carries none.
 */
import { describe, test, expect, vi, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, push: null as unknown }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('next/navigation', () => ({
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND')
  },
  useRouter: () => ({ push: h.push }),
}))

import { AlertProvider } from '@/components/ui'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { stashInputs } from '@/components/plugins/host/screenHandoff'
import { screenPathFromSegments, screenUrl } from '@/lib/plugins/navPaths'
import PluginNavPage from './page'
import PluginNavError from './error'

let dir: string
let db: FakePrisma

const manifest = {
  id: 'echo',
  displayName: 'Echo',
  permissions: [],
  actions: [{ id: 'save_item', timeoutSeconds: 30 }],
  contributes: { nav: { label: 'Echo items', icon: 'list', screen: 'ui/home.json' } },
  screens: ['ui/home.json', 'ui/detail.json', 'ui/forms/new-item.json', 'ui/missing.json', 'ui/broken.json'],
}

const screens: Record<string, unknown> = {
  'ui/home.json': { type: 'page', title: 'Echo home', children: [{ type: 'emptyState', title: 'Nothing yet' }] },
  'ui/detail.json': { type: 'page', children: [{ type: 'badge', content: { field: 'id' } }, { type: 'emptyState', title: 'Detail' }] },
  'ui/forms/new-item.json': {
    type: 'form',
    title: 'New item',
    fields: [{ name: 'name', label: 'Name', kind: 'text' }],
    submit: { action: 'save_item' },
  },
  'ui/secret.json': { type: 'emptyState', title: 'Not listed' },
}

function row(over: Record<string, unknown> = {}, m: Record<string, unknown> | null = manifest) {
  return { pluginId: 'echo', enabled: true, status: 'ready', activeVersion: '1.0.0', grantedPermissions: [], manifest: m, ...over }
}

/** A fresh database holding these install rows (none: the plugin is not installed). */
function reseed(...rows: Record<string, unknown>[]) {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  if (rows.length) db.seed('pluginInstall', rows)
}

async function open(pluginId: string, segs?: string[], k?: string) {
  const ui = await PluginNavPage({
    params: Promise.resolve({ pluginId, ...(segs ? { screen: segs } : {}) }),
    searchParams: Promise.resolve(k ? { k } : {}),
  })
  return render(<AlertProvider>{ui}</AlertProvider>)
}

beforeAll(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), 'plugin-nav-'))
  const v = path.join(dir, 'echo', 'versions', '1.0.0')
  for (const [file, body] of Object.entries(screens)) {
    await fs.mkdir(path.dirname(path.join(v, file)), { recursive: true })
    await fs.writeFile(path.join(v, file), JSON.stringify(body))
  }
  await fs.writeFile(path.join(v, 'ui/broken.json'), '{ not json')
  // A path that exists but cannot be read as a file (EISDIR), like EACCES or EIO would.
  await fs.mkdir(path.join(v, 'ui/folder.json'), { recursive: true })
})
afterAll(async () => {
  await fs.rm(dir, { recursive: true, force: true })
})

beforeEach(() => {
  reseed(row())
  h.push = vi.fn()
  vi.stubEnv('PLUGINS_DIR', dir)
})
afterEach(() => {
  cleanup()
  vi.unstubAllEnvs()
  sessionStorage.clear()
})

describe('paths', () => {
  test('segments map to a ui/ screen file and back', () => {
    expect(screenPathFromSegments(['forms', 'new-item'])).toBe('ui/forms/new-item.json')
    expect(screenUrl('echo', 'ui/forms/new-item.json')).toBe('/plugins/echo/forms/new-item')
    for (const bad of [['..', 'x'], ['Detail'], ['a.b'], ['a', ''], ['x%2F']]) {
      expect(screenPathFromSegments(bad), bad.join('/')).toBeNull()
    }
  })
})

describe('what is drawn', () => {
  test('the nav screen at the plugin root, under a header with the plugin badge and nav label', async () => {
    await open('echo')
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Echo items')
    expect(screen.getByTitle('RedAmon plugin').textContent).toContain('Echo')
    expect(screen.getByText('Nothing yet')).toBeInTheDocument()
  })

  test('a listed screen, nested too', async () => {
    await open('echo', ['forms', 'new-item'])
    expect(screen.getByText('New item')).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toBeInTheDocument()
  })

  test('an updating plugin keeps its page', async () => {
    reseed(row({ status: 'updating' }))
    await open('echo')
    expect(screen.getByText('Nothing yet')).toBeInTheDocument()
  })

  test('a listed screen missing on disk, or not JSON, shows an error naming the plugin', async () => {
    await open('echo', ['missing'])
    expect(screen.getByRole('alert').textContent).toMatch(/Echo.*the screen file is missing/)
    cleanup()
    await open('echo', ['broken'])
    expect(screen.getByRole('alert').textContent).toMatch(/Echo.*the screen file is not JSON/)
  })

  test('a screen that exists but cannot be read names its errno instead of calling it missing', async () => {
    reseed(row({}, { ...manifest, screens: [...manifest.screens, 'ui/folder.json'] }))
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    await open('echo', ['folder'])
    expect(screen.getByRole('alert').textContent).toMatch(/the screen file could not be read \(EISDIR\)/)
    expect(screen.getByRole('alert').textContent).not.toMatch(/missing/)
  })

  test('a server failure shows the error reference that matches the webapp log', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const reset = vi.fn()
    render(<PluginNavError error={Object.assign(new Error('An error occurred in the Server Components render.'), { digest: '2817394650' })} reset={reset} />)
    expect(screen.getByRole('alert').textContent).toContain('This plugin page could not be loaded (error reference 2817394650; the webapp log has the details).')
    screen.getByRole('button', { name: 'Try again' }).click()
    expect(reset).toHaveBeenCalled()
  })
})

describe('404', () => {
  test.each([
    ['not installed', null],
    ['disabled', { enabled: false }],
    ['revoked', { revokedReason: 'revoked upstream' }],
    ['uninstalled with data kept', { status: 'available', enabled: false }],
    ['failed', { status: 'failed' }],
  ])('%s', async (_name, over) => {
    if (over) reseed(row(over))
    else reseed()
    await expect(open('echo')).rejects.toThrow('NEXT_NOT_FOUND')
  })

  test('a plugin without a nav contribution', async () => {
    reseed(row({}, { ...manifest, contributes: { 'chat.session.actions': [{ label: 'x', action: 'save_item' }] } }))
    await expect(open('echo')).rejects.toThrow('NEXT_NOT_FOUND')
  })

  test('a screen file that exists but is not listed in the manifest', async () => {
    await expect(open('echo', ['secret'])).rejects.toThrow('NEXT_NOT_FOUND')
  })

  test.each([[['..', '..', 'etc']], [['Detail']], [['detail.json']], [['ui', 'home']]])('a malformed path %j', async (segs) => {
    await expect(open('echo', segs)).rejects.toThrow('NEXT_NOT_FOUND')
  })

  test('an invalid or reserved plugin id', async () => {
    await expect(open('Echo')).rejects.toThrow('NEXT_NOT_FOUND')
    await expect(open('../x')).rejects.toThrow('NEXT_NOT_FOUND')
  })
})

describe('inputs between screens', () => {
  test('inputs stashed by the previous screen reach the bindings', async () => {
    const k = stashInputs({ id: 'row-7' })!
    await open('echo', ['detail'], k)
    expect(screen.getByText('row-7')).toBeInTheDocument()
  })

  test('a crafted link with a key that was never stashed carries no inputs', async () => {
    await open('echo', ['detail'], '00000000-0000-4000-8000-000000000000')
    expect(screen.getByText('Detail')).toBeInTheDocument()
    expect(screen.queryAllByTestId('screen-badge')).toHaveLength(0)
  })
})
