/**
 * The project's user-skill toggles (plan D9, D10, Phase 0.B.4, 0.C.2, 4.6, 5.2): a missing
 * toggle is OFF; "N of 20 enabled" counts only the owner's existing skills; the 21st toggle
 * is disabled with the limit tooltip; a quarantined skill cannot be turned on; versions are
 * badged and two members of one family on at once are called out; the Import shortcut
 * enables new skills only up to the limit and says how many it left off; the import alert
 * names each skip reason; a stored config without `user` does not crash. Upload Skill and
 * Upload Batch in the header never collapse it; in a saved project the batch route switches
 * the new skills on (no form write), in create mode the form state does; the upload buttons
 * wait for this user's list.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within, act } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: h.userId }) }))

import { AttackSkillsSection } from './AttackSkillsSection'

type FormData = React.ComponentProps<typeof AttackSkillsSection>['data']
type Skill = {
  id: string; name: string; description?: string | null; createdAt: string
  version?: number | null; lineageRootId?: string | null; derivedFromName?: string | null; quarantinedAt?: string | null
}

const h = vi.hoisted(() => ({
  userId: 'alice' as string | null,
  skills: [] as unknown[],
  refreshed: null as unknown[] | null,
  importAnswer: null as null | (() => Response),
  listAnswer: null as null | (() => Response | Promise<Response>),
  batchAnswer: null as null | ((body: Record<string, unknown>) => Response),
  gets: 0,
  requests: [] as { url: string; method: string; body: Record<string, unknown> | undefined }[],
}))

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const sk = (id: string, over: Partial<Skill> = {}): Skill => ({ id, name: `Skill ${id}`, description: null, createdAt: '2026-10-10T10:00:00.000Z', ...over })

beforeEach(() => {
  h.gets = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined
    h.requests.push({ url, method, body })
    if (url.includes('/import-community')) return h.importAnswer ? h.importAnswer() : json(200, { imported: 0, skipped: 0, skippedBy: {} })
    if (url.endsWith('/attack-skills/name-check') && method === 'POST') {
      return json(200, { results: (body.names as string[]).map((n) => ({ normalized: n, available: true, suggestion: null })) })
    }
    if (url.endsWith('/attack-skills/batch') && method === 'POST') {
      if (h.batchAnswer) return h.batchAnswer(body)
      const ids = (body.items as unknown[]).map((_, i) => `new${i + 1}`)
      return json(201, {
        created: ids.map((id, i) => ({ id, name: (body.items as { name: string }[])[i].name })),
        enabled: body.enableInProjectId ? ids : [], leftOff: [],
      })
    }
    if (/\/api\/users\/alice\/attack-skills$/.test(url) && method === 'GET') {
      if (h.listAnswer) return h.listAnswer()
      h.gets++
      // The first read is the list; any later read is the refresh after an import.
      return json(200, h.gets > 1 && h.refreshed ? h.refreshed : h.skills)
    }
    return json(200, [])
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  h.userId = 'alice'
  h.skills = []
  h.refreshed = null
  h.importAnswer = null
  h.listAnswer = null
  h.batchAnswer = null
  h.requests = []
})

function draw(skills: Skill[], config: unknown = { builtIn: {}, user: {} }, projectId: string | null = null) {
  h.skills = skills
  const updateField = vi.fn()
  const data = { attackSkillConfig: config, hydraEnabled: false } as unknown as FormData
  const utils = render(
    <ToastProvider>
      <AlertProvider>
        <AttackSkillsSection data={data} updateField={updateField} projectId={projectId} />
      </AlertProvider>
    </ToastProvider>,
  )
  return { updateField, ...utils }
}

const toggleWrap = (id: string) => screen.getByTestId(`user-skill-toggle-${id}`)
const toggleOf = (id: string) => within(toggleWrap(id)).getByRole('switch')
const lastConfig = (updateField: ReturnType<typeof vi.fn>) => {
  const calls = updateField.mock.calls.filter((c) => c[0] === 'attackSkillConfig')
  return calls.at(-1)![1] as { builtIn: Record<string, boolean>; user: Record<string, boolean> }
}
const on = (ids: string[]) => Object.fromEntries(ids.map((id) => [id, true]))
const range = (n: number, prefix = 's') => Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`)

describe('the enabled count', () => {
  test('"N of 20 enabled" counts only skills that exist and are true (a missing key is off)', async () => {
    draw([sk('a'), sk('b'), sk('c'), sk('d')], { builtIn: {}, user: { a: true, b: true, c: false, ghost1: true, ghost2: true } })
    await screen.findByText('Skill a')
    expect(screen.getByTestId('user-skill-enabled-count').textContent).toBe('2 of 20 enabled')
    expect(toggleOf('a')).toHaveAttribute('aria-checked', 'true')
    expect(toggleOf('c')).toHaveAttribute('aria-checked', 'false')
    expect(toggleOf('d')).toHaveAttribute('aria-checked', 'false')
  })

  test('a stored config WITHOUT `user` does not crash: every skill is off, 0 of 20', async () => {
    const { updateField } = draw([sk('a'), sk('b')], { builtIn: { sql_injection: true } })
    await screen.findByText('Skill a')
    expect(screen.getByTestId('user-skill-enabled-count').textContent).toBe('0 of 20 enabled')
    expect(toggleOf('a')).toHaveAttribute('aria-checked', 'false')
    fireEvent.click(toggleOf('a'))
    expect(lastConfig(updateField)).toEqual({ builtIn: { sql_injection: true }, user: { a: true } })
  })

  test('a `user` that is not an object is treated as empty', async () => {
    draw([sk('a')], { builtIn: {}, user: null })
    await screen.findByText('Skill a')
    expect(screen.getByTestId('user-skill-enabled-count').textContent).toBe('0 of 20 enabled')
  })

  test('turning a skill on writes user[id]=true and keeps builtIn as stored', async () => {
    const { updateField } = draw([sk('a'), sk('b')], { builtIn: { xss: false }, user: { b: true } })
    await screen.findByText('Skill a')
    fireEvent.click(toggleOf('a'))
    expect(lastConfig(updateField)).toEqual({ builtIn: { xss: false }, user: { a: true, b: true } })
    fireEvent.click(toggleOf('b'))
    expect(lastConfig(updateField)).toEqual({ builtIn: { xss: false }, user: { b: false } })
  })
})

describe('the 20-enabled limit', () => {
  const twentyOn = () => ({ builtIn: {}, user: on(range(20)) })
  const skills21 = () => range(21).map((id) => sk(id))

  test('the 21st toggle is disabled with the limit tooltip; the 20 on stay switchable off', async () => {
    const { updateField } = draw(skills21(), twentyOn())
    await screen.findByText('Skill s21')
    expect(screen.getByTestId('user-skill-enabled-count').textContent).toBe('20 of 20 enabled')
    expect(toggleOf('s21')).toBeDisabled()
    expect(toggleWrap('s21').getAttribute('title')).toBe('A project can use at most 20 of your skills; turn one off first')
    fireEvent.click(toggleOf('s21'))
    expect(updateField).not.toHaveBeenCalled()
    expect(toggleOf('s1')).toBeEnabled()
    expect(toggleWrap('s1').getAttribute('title')).toBeNull()
    fireEvent.click(toggleOf('s1'))
    expect(lastConfig(updateField).user.s1).toBe(false)
  })

  test('19 on: the 20th can still be turned on', async () => {
    const { updateField } = draw(skills21(), { builtIn: {}, user: on(range(19)) })
    await screen.findByText('Skill s21')
    expect(toggleOf('s20')).toBeEnabled()
    fireEvent.click(toggleOf('s20'))
    expect(lastConfig(updateField).user.s20).toBe(true)
  })

  test('stale ids in the map do not use up the limit', async () => {
    draw([sk('a'), sk('b')], { builtIn: {}, user: { ...on(range(25, 'ghost')), a: true } })
    await screen.findByText('Skill b')
    expect(screen.getByTestId('user-skill-enabled-count').textContent).toBe('1 of 20 enabled')
    expect(toggleOf('b')).toBeEnabled()
  })
})

describe('search and filter', () => {
  test('search matches name and description', async () => {
    draw([sk('a', { name: 'SQLi flow', description: 'login form' }), sk('b', { name: 'Recon', description: 'find SQL endpoints' }), sk('c', { name: 'XSS notes' })])
    await screen.findByText('SQLi flow')
    fireEvent.change(screen.getByLabelText('Search your skills'), { target: { value: 'sql' } })
    expect(screen.getByText('SQLi flow')).toBeInTheDocument()
    expect(screen.getByText('Recon')).toBeInTheDocument()
    expect(screen.queryByText('XSS notes')).toBeNull()
    fireEvent.change(screen.getByLabelText('Search your skills'), { target: { value: 'LOGIN' } })
    expect(screen.queryByText('Recon')).toBeNull()
    fireEvent.change(screen.getByLabelText('Search your skills'), { target: { value: 'zzz' } })
    expect(screen.getByText('No skill matches.')).toBeInTheDocument()
  })

  test('"Enabled only" shows only the skills on in this project', async () => {
    draw([sk('a'), sk('b'), sk('c')], { builtIn: {}, user: { a: true, b: false } })
    await screen.findByText('Skill a')
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enabled only' }))
    expect(screen.getByText('Skill a')).toBeInTheDocument()
    expect(screen.queryByText('Skill b')).toBeNull()
    expect(screen.queryByText('Skill c')).toBeNull()
    // The count is of the project, not of what is shown.
    expect(screen.getByTestId('user-skill-enabled-count').textContent).toBe('1 of 20 enabled')
  })
})

describe('versions and quarantine', () => {
  test('a saved version shows "v3 · from <source>"', async () => {
    draw([sk('v3', { name: 'My SQLi flow v3', version: 3, lineageRootId: 'v1', derivedFromName: 'My SQLi flow v2' })])
    await screen.findByText('My SQLi flow v3')
    expect(screen.getByText(/v3 · from My SQLi flow v2/)).toBeInTheDocument()
  })

  test('a quarantined skill that is off cannot be turned on, and says why', async () => {
    const { updateField } = draw([sk('q', { name: 'Client X notes', quarantinedAt: '2026-10-12T00:00:00.000Z' })])
    await screen.findByText('Client X notes')
    expect(screen.getByText('Quarantined')).toBeInTheDocument()
    expect(toggleOf('q')).toBeDisabled()
    expect(toggleWrap('q').getAttribute('title')).toMatch(/Quarantined: release it in Global Settings/)
    fireEvent.click(toggleOf('q'))
    expect(updateField).not.toHaveBeenCalled()
  })

  test('a quarantined skill still marked on can be turned off', async () => {
    const { updateField } = draw([sk('q', { quarantinedAt: '2026-10-12T00:00:00.000Z' })], { builtIn: {}, user: { q: true } })
    await screen.findByText('Skill q')
    expect(toggleOf('q')).toBeEnabled()
    fireEvent.click(toggleOf('q'))
    expect(lastConfig(updateField).user.q).toBe(false)
  })

  test('two members of one family on: each names the other', async () => {
    draw([
      sk('v1', { name: 'My SQLi flow', version: 1, lineageRootId: 'v1' }),
      sk('v2', { name: 'My SQLi flow v2', version: 2, lineageRootId: 'v1', derivedFromName: 'My SQLi flow' }),
      sk('x', { name: 'Unrelated', lineageRootId: null }),
    ], { builtIn: {}, user: { v1: true, v2: true, x: true } })
    await screen.findByText('Unrelated')
    expect(screen.getByText(/My SQLi flow v2 is also on: the agent sees two versions of the same skill\./)).toBeInTheDocument()
    expect(screen.getByText(/^\s*My SQLi flow is also on: the agent sees two versions of the same skill\./)).toBeInTheDocument()
    expect(screen.getAllByText(/is also on: the agent sees two versions/)).toHaveLength(2)
  })

  test('one member on and one off: no warning', async () => {
    draw([
      sk('v1', { name: 'My SQLi flow', version: 1, lineageRootId: 'v1' }),
      sk('v2', { name: 'My SQLi flow v2', version: 2, lineageRootId: 'v1' }),
    ], { builtIn: {}, user: { v1: false, v2: true } })
    await screen.findByText('My SQLi flow v2')
    expect(screen.queryByText(/is also on/)).toBeNull()
  })
})

describe('the Import shortcut', () => {
  test('enables new skills only up to the limit and says how many it left off', async () => {
    const before = range(18).map((id) => sk(id))
    const fresh = [...before, ...range(4, 'new').map((id) => sk(id))]
    h.refreshed = fresh
    h.importAnswer = () => json(200, { imported: 4, skipped: 0, skippedBy: { duplicate: 0, limit: 0, fetchFailed: 0, tooLarge: 0, invalid: 0 }, importedIds: range(4, 'new') })
    const { updateField } = draw(before, { builtIn: { xss: true }, user: on(range(18)) })
    await screen.findByText('Skill s18')
    fireEvent.click(screen.getByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(updateField).toHaveBeenCalledWith('attackSkillConfig', expect.anything()))
    const cfg = lastConfig(updateField)
    expect(cfg.builtIn).toEqual({ xss: true })
    expect(Object.values(cfg.user).filter((v) => v === true)).toHaveLength(20)
    expect(cfg.user.new1).toBe(true)
    expect(cfg.user.new2).toBe(true)
    expect(cfg.user.new3).toBeUndefined()
    expect(cfg.user.new4).toBeUndefined()
    expect(await screen.findByText(/Imported 4 community skill\(s\)\. 2 new skill\(s\) are enabled for this project\. 2 were left off: a project can use at most 20 of your skills\./)).toBeInTheDocument()
  })

  test('at the limit already: nothing enabled, all left off', async () => {
    const before = range(20).map((id) => sk(id))
    h.refreshed = [...before, sk('new1')]
    h.importAnswer = () => json(200, { imported: 1, skipped: 0, skippedBy: {} })
    const { updateField } = draw(before, { builtIn: {}, user: on(range(20)) })
    await screen.findByText('Skill s20')
    fireEvent.click(screen.getByRole('button', { name: /Import from Community/ }))
    expect(await screen.findByText(/1 were left off: a project can use at most 20 of your skills\./)).toBeInTheDocument()
    expect(screen.queryByText(/are enabled for this project/)).toBeNull()
    const cfg = lastConfig(updateField)
    expect(cfg.user.new1).toBeUndefined()
  })

  test('room: every new skill is enabled and nothing is said to be left off', async () => {
    h.refreshed = [sk('a'), sk('new1'), sk('new2')]
    h.importAnswer = () => json(200, { imported: 2, skipped: 0, skippedBy: {} })
    const { updateField } = draw([sk('a')], { builtIn: {}, user: { a: true } })
    await screen.findByText('Skill a')
    fireEvent.click(screen.getByRole('button', { name: /Import from Community/ }))
    expect(await screen.findByText(/2 new skill\(s\) are enabled for this project\./)).toBeInTheDocument()
    expect(screen.queryByText(/left off/)).toBeNull()
    expect(lastConfig(updateField).user).toEqual({ a: true, new1: true, new2: true })
  })

  test('the alert names each skip reason instead of calling them all duplicates', async () => {
    h.refreshed = [sk('a')]
    h.importAnswer = () => json(200, { imported: 0, skipped: 3, skippedBy: { duplicate: 0, limit: 0, fetchFailed: 2, tooLarge: 1, invalid: 0 } })
    draw([sk('a')])
    await screen.findByText('Skill a')
    fireEvent.click(screen.getByRole('button', { name: /Import from Community/ }))
    const msg = await screen.findByText(/Imported 0 community skill\(s\); skipped/)
    expect(msg.textContent).toContain('1 too large')
    expect(msg.textContent).toContain('2 could not be fetched')
    expect(msg.textContent).not.toMatch(/duplicate/i)
  })

  test('a failed import shows the server error with its code and both statuses', async () => {
    h.importAnswer = () => json(502, {
      error: 'Failed to fetch community skills catalog from agent service', code: 'agent_error', upstreamStatus: 500,
    })
    const { updateField } = draw([sk('a')])
    await screen.findByText('Skill a')
    fireEvent.click(screen.getByRole('button', { name: /Import from Community/ }))
    expect(await screen.findByText(
      'Failed to fetch community skills catalog from agent service (agent_error · HTTP 502 · upstream HTTP 500)',
    )).toBeInTheDocument()
    expect(updateField).not.toHaveBeenCalled()
  })

  test("a proxy's HTML error page is read with its status, not as a broken answer", async () => {
    h.importAnswer = () => new Response('<html>502 Bad Gateway</html>', { status: 502 })
    const { updateField } = draw([sk('a')])
    await screen.findByText('Skill a')
    fireEvent.click(screen.getByRole('button', { name: /Import from Community/ }))
    expect(await screen.findByText('Failed to import community skills (non_json_response · HTTP 502)')).toBeInTheDocument()
    expect(updateField).not.toHaveBeenCalled()
  })
})

describe('other windows', () => {
  test('a message on the user-skills channel refetches the list', async () => {
    draw([sk('a')])
    await screen.findByText('Skill a')
    const before = h.gets
    h.skills = [sk('a'), sk('v2', { name: 'Skill a v2', version: 2 })]
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    expect(await screen.findByText('Skill a v2')).toBeInTheDocument()
    expect(h.gets).toBeGreaterThan(before)
  })
})

const DESCRIPTION = /Your own agent skills\. Upload \.md files here/
const button = (name: string) => screen.getByRole('button', { name })
const mdFiles = (n: number) => Array.from({ length: n }, (_, i) => new File([`# Uploaded ${i + 1}\n\nBody.`], `u${i + 1}.md`, { type: 'text/markdown' }))
const batches = () => h.requests.filter((r) => r.url.endsWith('/attack-skills/batch'))
const toggleWrites = (updateField: ReturnType<typeof vi.fn>) => updateField.mock.calls.filter((c) => c[0] === 'attackSkillConfig')

async function uploadBatch(files: File[], { uncheck = false } = {}) {
  await waitFor(() => expect(button('Upload Batch')).toBeEnabled())
  await act(async () => { fireEvent.change(screen.getByTestId('skill-upload-batch-input'), { target: { files } }) })
  const dialog = await screen.findByRole('dialog')
  if (uncheck) fireEvent.click(within(dialog).getByLabelText(/Turn them on in this project/))
  const upload = within(dialog).getByRole('button', { name: /^Upload \d+ skills?$/ })
  await waitFor(() => expect(upload).toBeEnabled())
  fireEvent.click(upload)
  await waitFor(() => expect(batches()).toHaveLength(1))
  return dialog
}

/** Every post on the user-skills channel while the test runs. */
function channelPosts() {
  const seen: unknown[] = []
  const ch = new BroadcastChannel('redamon:user-skills')
  ch.onmessage = (e) => seen.push(e.data)
  return { seen, close: () => ch.close() }
}

describe('upload from the section', () => {
  test('Upload Skill and Upload Batch render, and clicking them never collapses the section', async () => {
    draw([sk('a')])
    await screen.findByText('Skill a')
    expect(screen.getByText(DESCRIPTION)).toBeInTheDocument()
    fireEvent.click(button('Upload Skill'))
    fireEvent.click(button('Upload Batch'))
    expect(screen.getByText(DESCRIPTION)).toBeInTheDocument()
    expect(screen.getByTestId('skill-upload-batch-input')).toHaveProperty('multiple', true)
    await act(async () => { fireEvent.change(screen.getByTestId('skill-upload-batch-input'), { target: { files: mdFiles(1) } }) })
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByTestId('skill-upload-summary'))
    fireEvent.click(within(dialog).getByLabelText('Name for u1.md'))
    expect(screen.getByText(DESCRIPTION)).toBeInTheDocument()
  })

  test('saved project: the batch carries enableInProjectId, the form is not written, the channel names the project', async () => {
    const posts = channelPosts()
    const { updateField } = draw([sk('a')], { builtIn: {}, user: { a: true } }, 'p1')
    await screen.findByText('Skill a')
    await uploadBatch(mdFiles(2))
    expect(batches()[0].body!.enableInProjectId).toBe('p1')
    expect(await screen.findByText('Uploaded 2 skills; 2 turned on for this project.')).toBeInTheDocument()
    await waitFor(() => expect(posts.seen).toContainEqual({ projectId: 'p1' }))
    expect(toggleWrites(updateField)).toEqual([])
    posts.close()
  })

  test('create mode: with 18 on, 3 uploaded turn 2 on in the form and the warning names 1 left off', async () => {
    const before = range(18).map((id) => sk(id))
    const { updateField } = draw(before, { builtIn: { xss: true }, user: on(range(18)) }, null)
    await screen.findByText('Skill s18')
    await uploadBatch(mdFiles(3))
    expect(batches()[0].body).not.toHaveProperty('enableInProjectId')
    await waitFor(() => expect(toggleWrites(updateField)).toHaveLength(1))
    const cfg = lastConfig(updateField)
    expect(cfg.builtIn).toEqual({ xss: true })
    expect(cfg.user.new1).toBe(true)
    expect(cfg.user.new2).toBe(true)
    expect(cfg.user.new3).toBeUndefined()
    expect(Object.values(cfg.user).filter((v) => v === true)).toHaveLength(20)
    expect(await screen.findByText('1 was left off: a project can use at most 20 of your skills.')).toBeInTheDocument()
    expect(screen.getByText('Uploaded 3 skills; 2 will be turned on when you create the project.')).toBeInTheDocument()
  })

  test('with "Turn them on" unchecked: no enableInProjectId and no form write', async () => {
    const { updateField } = draw([sk('a')], { builtIn: {}, user: {} }, 'p1')
    await screen.findByText('Skill a')
    await uploadBatch(mdFiles(1), { uncheck: true })
    expect(batches()[0].body).not.toHaveProperty('enableInProjectId')
    expect(await screen.findByText('Uploaded 1 skill')).toBeInTheDocument()
    expect(toggleWrites(updateField)).toEqual([])
  })
})

describe('the upload buttons and the list', () => {
  test('disabled while the list request is pending, enabled once it loads', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    h.listAnswer = async () => { await gate; return json(200, [sk('a')]) }
    draw([])
    expect(button('Upload Skill')).toBeDisabled()
    expect(button('Upload Batch')).toHaveAttribute('title', 'Loading your skills…')
    await act(async () => { release() })
    await waitFor(() => expect(button('Upload Skill')).toBeEnabled())
    expect(button('Upload Batch')).toBeEnabled()
  })

  test('a failed list keeps them disabled with the reason and its cause, in place of the empty state', async () => {
    h.listAnswer = () => json(500, { error: 'Failed to fetch attack skills', code: 'P1001' })
    draw([])
    expect(await screen.findByText('Your skills could not be loaded (P1001 · HTTP 500). Reload the page.')).toBeInTheDocument()
    expect(screen.queryByText(/No user skills uploaded yet/)).toBeNull()
    expect(button('Upload Skill')).toBeDisabled()
    expect(button('Upload Batch')).toHaveAttribute('title', 'Your skills could not be loaded (P1001 · HTTP 500). Reload the page to upload.')
  })

  test('before the user is known, and until that user\'s list arrives, they stay disabled', async () => {
    h.userId = null
    const updateField = vi.fn()
    const data = { attackSkillConfig: { builtIn: {}, user: {} }, hydraEnabled: false } as unknown as FormData
    const ui = (
      <ToastProvider>
        <AlertProvider>
          <AttackSkillsSection data={data} updateField={updateField} projectId="p1" />
        </AlertProvider>
      </ToastProvider>
    )
    const { rerender } = render(ui)
    expect(button('Upload Skill')).toBeDisabled()
    expect(screen.queryByText(/No user skills uploaded yet/)).toBeNull()
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    h.listAnswer = async () => { await gate; return json(200, []) }
    h.userId = 'alice'
    rerender(ui)
    await waitFor(() => expect(h.requests.some((r) => r.url === '/api/users/alice/attack-skills')).toBe(true))
    expect(button('Upload Skill')).toBeDisabled()
    expect(button('Upload Skill')).toHaveAttribute('title', 'Loading your skills…')
    await act(async () => { release() })
    await waitFor(() => expect(button('Upload Skill')).toBeEnabled())
  })
})

describe('download', () => {
  test('a download that fails says so, with the status (it used to do nothing)', async () => {
    const fetchStub = globalThis.fetch as unknown as ReturnType<typeof vi.fn>
    const real = fetchStub.getMockImplementation() as (url: string, init?: RequestInit) => Promise<Response>
    fetchStub.mockImplementation(async (url: string, init?: RequestInit) => (
      url === '/api/users/alice/attack-skills/a' ? json(404, { error: 'Skill not found' }) : real(url, init)
    ))
    draw([sk('a')])
    await screen.findByText('Skill a')
    fireEvent.click(screen.getByTitle('Download .md'))
    expect(await screen.findByText('Skill not found (HTTP 404)')).toBeInTheDocument()
  })
})
