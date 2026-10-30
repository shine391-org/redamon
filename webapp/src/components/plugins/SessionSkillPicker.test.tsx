/**
 * The core's skill picker (platform 1.1.0, plan Phase 3.2): it lists the skills the agent used
 * in the session that the plugin may work on, built-in and the person's own, says why a row
 * cannot be picked, pre-selects the suggested one, and starts with only `{kind, ref}` plus the
 * labels the job window needs. Every state of GET /api/plugins/<id>/session-skills.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { SessionSkillPicker, type PickerSkill } from './SessionSkillPicker'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const builtin = (over: Partial<PickerSkill> = {}): PickerSkill => ({
  ref: 'skill.text:sql_injection', kind: 'builtin', name: 'SQL Injection', turns: 9, exists: true, selectable: true, revision: 3, ...over,
})
const user = (over: Partial<PickerSkill> = {}): PickerSkill => ({
  ref: 'user_skill:sk1', kind: 'user', name: 'My SQLi flow v2', turns: 14, exists: true, selectable: true, ...over,
})

type Answer = { status: number; body: unknown } | 'network-error'

/** fetch answers the queued answers in order (the last repeats). */
function stub(...answers: Answer[]) {
  let i = 0
  const fn = vi.fn(async () => {
    const a = answers[Math.min(i, answers.length - 1)]
    i++
    if (a === 'network-error') throw new TypeError('Failed to fetch')
    return json(a.status, a.body)
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

const ok = (body: Record<string, unknown>): Answer => ({ status: 200, body: { running: false, suggested: null, skills: [], ...body } })

function draw(context = { projectId: 'p1', sessionId: 's1' }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const invalidate = vi.spyOn(client, 'invalidateQueries')
  const onCancel = vi.fn()
  const onStart = vi.fn()
  render(
    <QueryClientProvider client={client}>
      <SessionSkillPicker pluginId="skiller" pluginName="Skiller" context={context} onCancel={onCancel} onStart={onStart} />
    </QueryClientProvider>,
  )
  return { onCancel, onStart, invalidate }
}

const start = () => screen.getByRole('button', { name: 'Start' })

describe('the request', () => {
  test('GETs the session-skills route of the plugin with the session and project', async () => {
    const fetchMock = stub(ok({ skills: [builtin()] }))
    draw()
    await screen.findByText('SQL Injection')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const url = String((fetchMock.mock.calls[0] as unknown[])[0])
    expect(url.startsWith('/api/plugins/skiller/session-skills?')).toBe(true)
    const qs = new URLSearchParams(url.split('?')[1])
    expect(qs.get('sessionId')).toBe('s1')
    expect(qs.get('projectId')).toBe('p1')
  })
})

describe('loading and failure', () => {
  test('while loading, Start is disabled and it says it is reading the session', async () => {
    let release!: (r: Response) => void
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((r) => { release = r })))
    draw()
    expect(screen.getByRole('status').textContent).toMatch(/Reading the session/)
    expect(start()).toBeDisabled()
    release(json(200, { running: false, suggested: null, skills: [] }))
    await screen.findByText(/This session used no skill/)
  })

  test('a failure shows the server message and Retry fetches again', async () => {
    const fetchMock = stub({ status: 500, body: { error: 'The database is busy.' } }, ok({ skills: [user()], suggested: 'user_skill:sk1' }))
    draw()
    // The server's sentence, then the status, so a screenshot says which failure it was.
    expect(await screen.findByText('The database is busy. (HTTP 500)', { exact: false })).toBeInTheDocument()
    expect(start()).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(await screen.findByText('My SQLi flow v2')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(start()).toBeEnabled()
  })

  test('a network failure says no answer came, with Retry', async () => {
    stub('network-error')
    draw()
    expect(await screen.findByText('The skills of this session could not be read (network_error)', { exact: false })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
  })

  test('an answer without a skills list is a failure, not an empty list', async () => {
    stub({ status: 200, body: { running: false } })
    draw()
    expect(await screen.findByText('The skills of this session could not be read (invalid_answer · HTTP 200)', { exact: false })).toBeInTheDocument()
    expect(screen.queryByText(/This session used no skill/)).toBeNull()
  })
})

describe('the plugin is not available', () => {
  test.each([
    ['plugin_not_found', { status: 404, body: { code: 'plugin_not_found', error: 'No such plugin.' } }],
    ['plugin_unavailable', { status: 409, body: { code: 'plugin_unavailable', error: 'This plugin is disabled or not ready.' } }],
    ['plugin_updating', { status: 409, body: { code: 'plugin_updating', error: 'This plugin is being updated.' } }],
  ] as const)('%s: "<plugin> is not available right now." and the gear menu list is invalidated', async (_label, answer) => {
    stub(answer)
    const { invalidate } = draw()
    expect(await screen.findByText('Skiller is not available right now.')).toBeInTheDocument()
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['plugins', 'contributions'] })
    expect(start()).toBeDisabled()
    expect(screen.queryByRole('button', { name: /Retry/ })).toBeNull()
  })

  test('a session with no conversation yet (404 not_found) says so, offers Retry, and keeps the gear menu list', async () => {
    stub({ status: 404, body: { code: 'not_found', error: 'Not found' } })
    const { invalidate } = draw()
    expect(await screen.findByText(/This session was not found\. Send the agent a message first/)).toBeInTheDocument()
    expect(screen.queryByText('Skiller is not available right now.')).toBeNull()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(invalidate).not.toHaveBeenCalled()
  })

  test('another failure does not invalidate the gear menu list', async () => {
    stub({ status: 500, body: { error: 'boom', code: 'P2024' } })
    const { invalidate } = draw()
    await screen.findByText('boom (P2024 · HTTP 500)', { exact: false })
    expect(invalidate).not.toHaveBeenCalled()
  })
})

describe('the list', () => {
  test('no skills: "This session used no skill <plugin> can work on." and Start disabled', async () => {
    stub(ok({ skills: [] }))
    draw()
    expect(await screen.findByText('This session used no skill Skiller can work on.')).toBeInTheDocument()
    expect(start()).toBeDisabled()
  })

  test('rows show the badge, the turns and the built-in version', async () => {
    stub(ok({ skills: [builtin(), user(), user({ ref: 'user_skill:sk9', name: 'One turn', turns: 1 })] }))
    draw()
    const b = await screen.findByTestId('pick-skill.text:sql_injection')
    expect(b.textContent).toContain('SQL Injection')
    expect(b.textContent).toContain('Built-in')
    expect(b.textContent).toMatch(/9 turns/)
    expect(b.textContent).toMatch(/v3/)
    const u = screen.getByTestId('pick-user_skill:sk1')
    expect(u.textContent).toContain('Your skill')
    expect(u.textContent).toMatch(/14 turns/)
    // A user skill has no built-in version line.
    expect(u.textContent).not.toMatch(/· v\d/)
    expect(screen.getByTestId('pick-user_skill:sk9').textContent).toMatch(/1 turn(?!s)/)
  })

  test('a built-in at factory (no revision) shows no version', async () => {
    stub(ok({ skills: [builtin({ revision: undefined })] }))
    draw()
    const b = await screen.findByTestId('pick-skill.text:sql_injection')
    expect(b.textContent).not.toMatch(/· v\d/)
  })

  test.each([
    ['deleted', 'deleted'],
    ['credentials', 'holds a key or token'],
    ['quarantined', 'quarantined'],
  ] as const)('a %s skill says why and its radio is disabled', async (reason, text) => {
    stub(ok({ skills: [user({ selectable: false, reason, exists: reason !== 'deleted', name: reason === 'deleted' ? null : 'Client X notes' })] }))
    draw()
    const row = await screen.findByTestId('pick-user_skill:sk1')
    expect(row.textContent).toContain(text)
    expect(within(row).getByRole('radio')).toBeDisabled()
    expect(start()).toBeDisabled()
  })

  test('a deleted skill without a name reads "A deleted skill"', async () => {
    stub(ok({ skills: [user({ name: null, exists: false, selectable: false, reason: 'deleted' })] }))
    draw()
    expect((await screen.findByTestId('pick-user_skill:sk1')).textContent).toContain('A deleted skill')
  })

  test('the suggested skill is pre-selected and Start is enabled', async () => {
    stub(ok({ skills: [builtin(), user()], suggested: 'user_skill:sk1' }))
    draw()
    const u = await screen.findByTestId('pick-user_skill:sk1')
    expect(within(u).getByRole('radio')).toBeChecked()
    expect(within(screen.getByTestId('pick-skill.text:sql_injection')).getByRole('radio')).not.toBeChecked()
    expect(start()).toBeEnabled()
  })

  test('no suggestion: nothing is selected and Start waits for a choice', async () => {
    stub(ok({ skills: [builtin(), user()], suggested: null }))
    draw()
    await screen.findByTestId('pick-user_skill:sk1')
    expect(start()).toBeDisabled()
    fireEvent.click(within(screen.getByTestId('pick-skill.text:sql_injection')).getByRole('radio'))
    expect(start()).toBeEnabled()
  })

  test('a suggestion that is not selectable does not enable Start', async () => {
    stub(ok({ skills: [user({ selectable: false, reason: 'credentials' })], suggested: 'user_skill:sk1' }))
    draw()
    await screen.findByTestId('pick-user_skill:sk1')
    expect(start()).toBeDisabled()
  })
})

describe('the agent is running', () => {
  test('running:true disables Start and says to wait', async () => {
    stub(ok({ running: true, skills: [user()], suggested: 'user_skill:sk1' }))
    draw()
    expect(await screen.findByText(/The agent is still working in this session/)).toBeInTheDocument()
    expect(start()).toBeDisabled()
  })

  test("running:'unverified' disables Start, says the end is not confirmed, and Check again reloads", async () => {
    const fetchMock = stub(
      ok({ running: 'unverified', skills: [user()], suggested: 'user_skill:sk1' }),
      ok({ running: false, skills: [user()], suggested: 'user_skill:sk1' }),
    )
    draw()
    expect(await screen.findByText(/could not confirm that the agent has stopped/)).toBeInTheDocument()
    expect(start()).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: /Check again/ }))
    await waitFor(() => expect(start()).toBeEnabled())
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(screen.queryByText(/could not confirm/)).toBeNull()
  })

  test("'unverified' names why the agent could not say: its errno, or its HTTP status", async () => {
    stub(ok({ running: 'unverified', agentCheck: { code: 'agent_unreachable', cause: 'ECONNREFUSED' }, skills: [user()], suggested: 'user_skill:sk1' }))
    draw()
    expect(await screen.findByText(/could not confirm that the agent has stopped in this session \(agent_unreachable · ECONNREFUSED\)\./)).toBeInTheDocument()
    cleanup()
    stub(ok({ running: 'unverified', agentCheck: { code: 'agent_error', upstreamStatus: 500 }, skills: [user()], suggested: 'user_skill:sk1' }))
    draw()
    expect(await screen.findByText(/could not confirm that the agent has stopped in this session \(agent_error · agent HTTP 500\)\./)).toBeInTheDocument()
  })

  test('running:false shows no notice', async () => {
    stub(ok({ running: false, skills: [user()], suggested: 'user_skill:sk1' }))
    draw()
    await screen.findByTestId('pick-user_skill:sk1')
    expect(screen.queryByText(/The agent is still working/)).toBeNull()
  })
})

describe('Start and Cancel', () => {
  test('Start calls onStart with the kind, ref, name and skill kind', async () => {
    stub(ok({ skills: [builtin(), user()], suggested: 'user_skill:sk1' }))
    const { onStart, onCancel } = draw()
    await screen.findByTestId('pick-user_skill:sk1')
    fireEvent.click(start())
    expect(onStart).toHaveBeenCalledTimes(1)
    expect(onStart).toHaveBeenCalledWith({ kind: 'session.skill', ref: 'user_skill:sk1', name: 'My SQLi flow v2', skillKind: 'user' })
    expect(onCancel).not.toHaveBeenCalled()
  })

  test('choosing another row starts that one', async () => {
    stub(ok({ skills: [builtin(), user()], suggested: 'user_skill:sk1' }))
    const { onStart } = draw()
    fireEvent.click(within(await screen.findByTestId('pick-skill.text:sql_injection')).getByRole('radio'))
    fireEvent.click(start())
    expect(onStart).toHaveBeenCalledWith({ kind: 'session.skill', ref: 'skill.text:sql_injection', name: 'SQL Injection', skillKind: 'builtin' })
  })

  test('Cancel calls onCancel and never onStart', async () => {
    stub(ok({ skills: [user()], suggested: 'user_skill:sk1' }))
    const { onStart, onCancel } = draw()
    await screen.findByTestId('pick-user_skill:sk1')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onCancel).toHaveBeenCalledTimes(1)
    expect(onStart).not.toHaveBeenCalled()
  })
})

describe('plugin-provided text', () => {
  test('an HTML-looking name is shown as text, never interpreted', async () => {
    const evil = '<img src=x onerror="alert(1)"><b>bold</b>'
    stub(ok({ skills: [user({ name: evil })], suggested: 'user_skill:sk1' }))
    draw()
    const row = await screen.findByTestId('pick-user_skill:sk1')
    expect(row.textContent).toContain(evil)
    expect(row.querySelector('img')).toBeNull()
    expect(row.querySelector('b')).toBeNull()
  })

  test('an HTML-looking plugin name in the copy is text too', async () => {
    stub(ok({ skills: [] }))
    const client = new QueryClient()
    render(
      <QueryClientProvider client={client}>
        <SessionSkillPicker pluginId="skiller" pluginName="<i>Evil</i>" context={{ projectId: 'p1', sessionId: 's1' }} onCancel={vi.fn()} onStart={vi.fn()} />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(document.body.textContent).toContain('This session used no skill <i>Evil</i> can work on.'))
    expect(document.querySelector('i')).toBeNull()
  })
})
