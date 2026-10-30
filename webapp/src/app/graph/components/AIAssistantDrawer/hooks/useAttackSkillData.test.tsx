/**
 * The chat drawer's skill data (plan Phase 4.6): the available skills and this project's
 * toggles, read again on `refetch()` (the drawer calls it after a save) and when a version is
 * saved anywhere in the browser for this project or for no project in particular, but not
 * when another project's toggles changed.
 */
import { test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'
import { useAttackSkillData } from './useAttackSkillData'

const h = vi.hoisted(() => ({
  avail: { builtIn: [{ id: 'xss', name: 'Cross-Site Scripting' }], user: [{ id: 'sk1', name: 'My SQLi flow' }] } as Record<string, unknown>,
  project: { id: 'p1', attackSkillConfig: { builtIn: { xss: true }, user: { sk1: true } } } as Record<string, unknown>,
  calls: [] as string[],
}))

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    h.calls.push(url)
    if (url.endsWith('/attack-skills/available')) return json(200, h.avail)
    if (url.startsWith('/api/projects/')) return json(200, h.project)
    return json(404, {})
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  h.calls = []
  h.avail = { builtIn: [{ id: 'xss', name: 'Cross-Site Scripting' }], user: [{ id: 'sk1', name: 'My SQLi flow' }] }
  h.project = { id: 'p1', attackSkillConfig: { builtIn: { xss: true }, user: { sk1: true } } }
})

const projectReads = () => h.calls.filter((u) => u === '/api/projects/p1').length
const settle = () => new Promise((r) => setTimeout(r, 30))

async function mount() {
  const hook = renderHook(() => useAttackSkillData('alice', 'p1'))
  await waitFor(() => expect(hook.result.current.skillData).not.toBeNull())
  return hook
}

test('reads the available skills and the project toggles', async () => {
  const hook = await mount()
  expect(h.calls.sort()).toEqual(['/api/projects/p1', '/api/users/alice/attack-skills/available'])
  expect(hook.result.current.skillData).toEqual({
    builtIn: [{ id: 'xss', name: 'Cross-Site Scripting' }],
    user: [{ id: 'sk1', name: 'My SQLi flow' }],
    config: { builtIn: { xss: true }, user: { sk1: true } },
  })
})

test('a config without `user` (or none at all) reads as empty maps', async () => {
  h.project = { id: 'p1', attackSkillConfig: { builtIn: { xss: true } } }
  const hook = await mount()
  expect(hook.result.current.skillData!.config).toEqual({ builtIn: { xss: true }, user: {} })
  cleanup()
  h.project = { id: 'p1', attackSkillConfig: null }
  const again = await mount()
  expect(again.result.current.skillData!.config).toEqual({ builtIn: {}, user: {} })
})

test('refetch() reads both again and takes the new toggles', async () => {
  const hook = await mount()
  expect(projectReads()).toBe(1)
  h.project = { id: 'p1', attackSkillConfig: { builtIn: { xss: true }, user: { sk1: false, sk2: true } } }
  h.avail = { ...h.avail, user: [{ id: 'sk1', name: 'My SQLi flow' }, { id: 'sk2', name: 'My SQLi flow v2' }] }
  act(() => hook.result.current.refetch())
  await waitFor(() => expect(hook.result.current.skillData!.config.user).toEqual({ sk1: false, sk2: true }))
  expect(projectReads()).toBe(2)
  expect(hook.result.current.skillData!.user).toHaveLength(2)
})

test('a channel message for this project refetches', async () => {
  const hook = await mount()
  h.project = { id: 'p1', attackSkillConfig: { builtIn: {}, user: { sk2: true } } }
  act(() => postUserSkillsChanged({ projectId: 'p1' }))
  await waitFor(() => expect(hook.result.current.skillData!.config.user).toEqual({ sk2: true }))
  expect(projectReads()).toBeGreaterThan(1)
})

test('a channel message with no project refetches', async () => {
  await mount()
  act(() => postUserSkillsChanged({}))
  await waitFor(() => expect(projectReads()).toBeGreaterThan(1))
})

test('a channel message for another project does not refetch', async () => {
  await mount()
  act(() => postUserSkillsChanged({ projectId: 'other' }))
  await settle()
  expect(projectReads()).toBe(1)
})

test('a failed read keeps the last data', async () => {
  const hook = await mount()
  const before = hook.result.current.skillData
  vi.stubGlobal('fetch', vi.fn(async () => json(500, {})))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  act(() => hook.result.current.refetch())
  await settle()
  expect(hook.result.current.skillData).toBe(before)
  vi.restoreAllMocks()
})

test('a failed read says why in `error`, and a good one clears it', async () => {
  const hook = await mount()
  expect(hook.result.current.error).toBeNull()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => (url.endsWith('/attack-skills/available')
    ? json(500, { error: 'Failed to fetch available attack skills', code: 'P1001' })
    : json(200, h.project))))
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
  act(() => hook.result.current.refetch())
  await waitFor(() => expect(hook.result.current.error?.message).toBe('Failed to fetch available attack skills (P1001 · HTTP 500)'))
  expect(warn).toHaveBeenCalled()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => (url.endsWith('/attack-skills/available') ? json(200, h.avail) : json(200, h.project))))
  act(() => hook.result.current.refetch())
  await waitFor(() => expect(hook.result.current.error).toBeNull())
  vi.restoreAllMocks()
})

test('no user or project: nothing is fetched', async () => {
  renderHook(() => useAttackSkillData('', 'p1'))
  renderHook(() => useAttackSkillData('alice', ''))
  await settle()
  expect(h.calls).toEqual([])
})
