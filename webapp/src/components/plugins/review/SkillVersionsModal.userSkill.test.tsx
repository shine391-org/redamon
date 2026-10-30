/**
 * "Skill versions" for the person's own skills (plan D13, Phase 5.3): the selector gains a
 * "Your skills" group; a `user_skill:<id>` value opens the user mode, which reads
 * /api/plugins/overrides/versions?point=user_skill.text&group=<id> and lists the family of
 * saved versions, the proposals (open, delete, what they became) and "Delete older
 * versions", which deletes exactly the ids the server marked deletable. The built-in mode is
 * pinned by SkillVersionsModal.test.tsx.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { SkillVersionsModal } from './SkillVersionsModal'
import type { UserSkillVersionsModel } from '@/lib/plugins/userSkillVersionsModel'
import type { VersionsModel } from '@/lib/plugins/versionsModel'
import { useUserSkillsChanged, type UserSkillsChange } from '@/lib/userSkillsChannel'

const h = vi.hoisted(() => ({
  requests: [] as { url: string; method: string }[],
  own: [] as unknown,
  userModel: null as unknown,
  responders: {} as Record<string, () => Response>,
}))

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  h.requests = []
  h.responders = {}
})

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const OWN = [
  { id: 'sk3', name: 'My SQLi flow v3', createdAt: '2026-10-12T10:00:00.000Z' },
  { id: 'sk2', name: 'My SQLi flow v2', createdAt: '2026-10-11T10:00:00.000Z' },
  { id: 'sk1', name: 'My SQLi flow', createdAt: '2026-10-10T10:00:00.000Z' },
]

function userModel(over: Partial<UserSkillVersionsModel> = {}): UserSkillVersionsModel {
  return {
    kind: 'user_skill',
    skill: { id: 'sk2', name: 'My SQLi flow v2' },
    family: [
      { id: 'sk3', name: 'My SQLi flow v3', version: 3, createdAt: '2026-10-12T10:00:00.000Z', enabledInProject: true, enabledProjects: 1, quarantined: false },
      { id: 'sk2', name: 'My SQLi flow v2', version: 2, createdAt: '2026-10-11T10:00:00.000Z', enabledInProject: false, enabledProjects: 2, quarantined: false },
      { id: 'sk1', name: 'My SQLi flow', version: 1, createdAt: '2026-10-10T10:00:00.000Z', enabledInProject: false, enabledProjects: 0, quarantined: true },
    ],
    proposals: [
      {
        changeSetId: 'cs_wait', status: 'proposed', sourceId: 'sk2', sourceName: 'My SQLi flow v2', pluginId: 'skiller', pluginDisplayName: 'Skiller',
        note: 'Adds a WAF step.', createdAt: '2026-10-12T11:00:00.000Z', decidedAt: null, adopted: null,
      },
      {
        changeSetId: 'cs_done', status: 'adopted', sourceId: 'sk2', sourceName: 'My SQLi flow v2', pluginId: 'skiller', pluginDisplayName: 'Skiller',
        note: null, createdAt: '2026-10-11T11:00:00.000Z', decidedAt: '2026-10-12T09:00:00.000Z', adopted: { skillId: 'sk3', name: 'My SQLi flow v3' },
      },
      {
        changeSetId: 'cs_no', status: 'rejected', sourceId: 'sk1', sourceName: 'My SQLi flow', pluginId: 'skiller', pluginDisplayName: 'Skiller',
        note: null, createdAt: '2026-10-10T11:00:00.000Z', decidedAt: '2026-10-10T12:00:00.000Z', adopted: null,
      },
    ],
    deletable: ['sk2', 'sk1'],
    ...over,
  }
}

const builtinModel: VersionsModel = {
  skillId: 'ssrf', skillDisplayName: 'Server-Side Request Forgery', factoryText: { workflow: 'Factory.' }, registryError: null,
  scopes: [{ scopeType: 'user', scopeOwnerId: 'alice', factoryInUse: true, dormantReason: null, lastRevision: 1, versions: [] }],
} as unknown as VersionsModel

function Listener({ onChange }: { onChange: (c: UserSkillsChange) => void }) {
  useUserSkillsChanged(onChange)
  return null
}

function draw(props: Partial<React.ComponentProps<typeof SkillVersionsModal>> = {}, own: unknown = OWN, um: UserSkillVersionsModel = userModel()) {
  h.own = own
  h.userModel = um
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    h.requests.push({ url, method })
    const key = Object.keys(h.responders).find((k) => url.includes(k))
    if (key) return h.responders[key]()
    if (method === 'DELETE') return json(200, { deleted: true })
    if (url.includes('/overrides/versions')) {
      const qs = new URLSearchParams(url.split('?')[1])
      return json(200, qs.get('point') === 'user_skill.text' ? h.userModel : builtinModel)
    }
    if (/\/api\/users\/[^/]+\/attack-skills$/.test(url)) return json(200, h.own)
    return json(404, {})
  }))
  const onClose = vi.fn()
  const onOpenReview = vi.fn()
  const channel = vi.fn()
  render(
    <ToastProvider>
      <AlertProvider>
        <Listener onChange={channel} />
        <SkillVersionsModal projectId="p1" initialSkill="user_skill:sk2" scopeOwnerId="alice" onClose={onClose} onOpenReview={onOpenReview} {...props} />
      </AlertProvider>
    </ToastProvider>,
  )
  return { onClose, onOpenReview, channel }
}

const select = () => screen.getByRole('combobox') as HTMLSelectElement
const versionsCalls = () => h.requests.filter((r) => r.url.includes('/overrides/versions'))
const deletes = () => h.requests.filter((r) => r.method === 'DELETE').map((r) => r.url)

describe('the selector', () => {
  test('has a "Your skills" group listing the user\'s skills as user_skill:<id>', async () => {
    draw({ initialSkill: 'ssrf' })
    await waitFor(() => expect(select().querySelector('optgroup[label="Your skills"]')).not.toBeNull())
    const group = select().querySelector('optgroup[label="Your skills"]')!
    const options = Array.from(group.querySelectorAll('option')).map((o) => [o.value, o.textContent])
    expect(options).toEqual([
      ['user_skill:sk3', 'My SQLi flow v3'],
      ['user_skill:sk2', 'My SQLi flow v2'],
      ['user_skill:sk1', 'My SQLi flow'],
    ])
    expect(select().querySelector('optgroup[label="Built-in"]')!.querySelectorAll('option')).toHaveLength(14)
    expect(h.requests.some((r) => r.url === '/api/users/alice/attack-skills' && r.method === 'GET')).toBe(true)
  })

  test('no own skills and a built-in initial skill: no "Your skills" group', async () => {
    draw({ initialSkill: 'ssrf' }, [])
    await screen.findByTestId('scope-user')
    expect(select().querySelector('optgroup[label="Your skills"]')).toBeNull()
  })

  test('a user_skill initial value for a skill no longer listed reads "A deleted skill"', async () => {
    draw({ initialSkill: 'user_skill:gone' }, OWN, userModel({ skill: { id: 'gone', name: 'Gone' } }))
    await waitFor(() => expect(select().value).toBe('user_skill:gone'))
    expect(select().querySelector('option[value="user_skill:gone"]')!.textContent).toBe('A deleted skill')
  })

  // A list that failed is not an empty list: the open skill must not read as deleted.
  test('the own-skills list failing says so instead of "A deleted skill"', async () => {
    h.responders['/api/users/alice/attack-skills'] = () => new Response('', { status: 500 })
    draw({ initialSkill: 'user_skill:sk2' })
    expect(await screen.findByTestId('own-skills-error')).toHaveTextContent('Your skills could not be loaded (empty_response · HTTP 500)')
    expect(select().querySelector('option[value="user_skill:sk2"]')!.textContent).toBe('Your skills could not be loaded')
  })

  test('picking a user skill in the selector switches to the user mode', async () => {
    draw({ initialSkill: 'ssrf' })
    await screen.findByTestId('scope-user')
    await waitFor(() => expect(select().querySelector('optgroup[label="Your skills"]')).not.toBeNull())
    fireEvent.change(select(), { target: { value: 'user_skill:sk2' } })
    expect(await screen.findByTestId('user-skill-family')).toBeInTheDocument()
    expect(screen.queryByTestId('scope-user')).toBeNull()
    const last = versionsCalls().at(-1)!
    expect(new URLSearchParams(last.url.split('?')[1]).get('point')).toBe('user_skill.text')
  })
})

describe('the user mode', () => {
  test('initialSkill="user_skill:<id>" reads the user_skill.text versions of that skill, with the project', async () => {
    draw()
    await screen.findByTestId('user-skill-family')
    expect(select().value).toBe('user_skill:sk2')
    const calls = versionsCalls()
    expect(calls).toHaveLength(1)
    const qs = new URLSearchParams(calls[0].url.split('?')[1])
    expect(calls[0].url.startsWith('/api/plugins/overrides/versions?')).toBe(true)
    expect(qs.get('point')).toBe('user_skill.text')
    expect(qs.get('group')).toBe('sk2')
    expect(qs.get('projectId')).toBe('p1')
    // The built-in loader never runs in the user mode.
    expect(calls.some((c) => new URLSearchParams(c.url.split('?')[1]).get('point') === 'skill.text')).toBe(false)
  })

  test('without a project there is no projectId in the query', async () => {
    draw({ projectId: null })
    await screen.findByTestId('user-skill-family')
    expect(new URLSearchParams(versionsCalls()[0].url.split('?')[1]).has('projectId')).toBe(false)
  })

  test('the title names the user skill', async () => {
    draw()
    expect(await screen.findByRole('heading', { name: 'Versions · My SQLi flow v2' })).toBeInTheDocument()
  })

  test('family rows: the v badge, which is this skill, on in this project / in N projects / off everywhere, quarantine', async () => {
    draw()
    const v3 = await screen.findByTestId('family-sk3')
    expect(v3.querySelector('[class*="vnum"]')!.textContent).toBe('v3')
    expect(v3.textContent).toContain('On in this project')
    const v2 = screen.getByTestId('family-sk2')
    expect(v2.querySelector('[class*="vnum"]')!.textContent).toBe('v2')
    expect(v2.textContent).toContain('· this skill')
    expect(v2.textContent).toContain('On in 2 projects')
    const v1 = screen.getByTestId('family-sk1')
    expect(v1.textContent).toContain('Off everywhere')
    expect(v1.textContent).toContain('quarantined')
  })

  test('a member without a version number has no v badge', async () => {
    draw({}, OWN, userModel({ family: [{ id: 'sk2', name: 'My SQLi flow v2', version: null, createdAt: '2026-10-11T10:00:00.000Z', enabledInProject: null, enabledProjects: 1, quarantined: false }], deletable: [] }))
    const row = await screen.findByTestId('family-sk2')
    expect(row.querySelector('[class*="vnum"]')).toBeNull()
    expect(row.textContent).toContain('On in 1 project')
    expect(row.textContent).not.toContain('On in 1 projects')
  })

  test('a proposed proposal: "pending review" and Open review hands its change set', async () => {
    const { onOpenReview } = draw()
    const row = await screen.findByTestId('proposal-cs_wait')
    expect(row.textContent).toContain('pending review')
    expect(row.textContent).toContain('from My SQLi flow v2')
    expect(row.textContent).toContain('Adds a WAF step.')
    fireEvent.click(within(row).getByRole('button', { name: 'Open review' }))
    expect(onOpenReview).toHaveBeenCalledWith('cs_wait')
  })

  test('an adopted proposal says what it became and has no Open review', async () => {
    draw()
    const row = await screen.findByTestId('proposal-cs_done')
    expect(row.textContent).toContain('became "My SQLi flow v3"')
    expect(within(row).queryByRole('button', { name: 'Open review' })).toBeNull()
    expect(within(row).getByRole('button', { name: 'Delete' })).toBeInTheDocument()
  })

  test('a rejected proposal says so', async () => {
    draw()
    expect((await screen.findByTestId('proposal-cs_no')).textContent).toContain('rejected')
  })

  test('no proposals: the empty line', async () => {
    draw({}, OWN, userModel({ proposals: [] }))
    expect(await screen.findByText('No proposal for this skill yet.')).toBeInTheDocument()
  })

  test('Delete on a proposal asks (danger) and DELETEs that change set, then reloads', async () => {
    draw()
    const row = await screen.findByTestId('proposal-cs_wait')
    fireEvent.click(within(row).getByRole('button', { name: 'Delete' }))
    expect(await screen.findByText('Delete this proposal? This cannot be undone.')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete' }).pop()!)
    await waitFor(() => expect(deletes()).toEqual(['/api/plugins/overrides/change-sets/cs_wait']))
    await waitFor(() => expect(versionsCalls()).toHaveLength(2))
  })

  test('cancelling the proposal delete deletes nothing', async () => {
    draw()
    fireEvent.click(within(await screen.findByTestId('proposal-cs_wait')).getByRole('button', { name: 'Delete' }))
    await screen.findByText('Delete this proposal? This cannot be undone.')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByText('Delete this proposal? This cannot be undone.')).toBeNull())
    expect(deletes()).toEqual([])
  })
})

describe('Delete older versions', () => {
  test('after a danger confirm naming them, it deletes exactly the deletable skills and tells other windows', async () => {
    const { channel } = draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete older versions' }))
    expect(await screen.findByText(/Delete 2 older versions \("My SQLi flow v2", "My SQLi flow"\)\?/)).toBeInTheDocument()
    expect(screen.getByText(/Their proposals waiting for review are deleted too\./)).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Delete' }).pop()!)
    await waitFor(() => expect(deletes()).toHaveLength(2))
    expect(deletes().sort()).toEqual(['/api/users/alice/attack-skills/sk1', '/api/users/alice/attack-skills/sk2'])
    expect(deletes().some((u) => u.endsWith('/sk3'))).toBe(false)
    await waitFor(() => expect(channel).toHaveBeenCalled())
    await waitFor(() => expect(versionsCalls()).toHaveLength(2))
  })

  test('cancelling deletes nothing', async () => {
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete older versions' }))
    await screen.findByText(/Delete 2 older versions/)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByText(/Delete 2 older versions/)).toBeNull())
    expect(deletes()).toEqual([])
  })

  test('nothing deletable: no button', async () => {
    draw({}, OWN, userModel({ deletable: [] }))
    await screen.findByTestId('user-skill-family')
    expect(screen.queryByRole('button', { name: 'Delete older versions' })).toBeNull()
  })

  test('without a scope owner: no button (it would not know whose skills to delete)', async () => {
    draw({ scopeOwnerId: null })
    await screen.findByTestId('user-skill-family')
    expect(screen.queryByRole('button', { name: 'Delete older versions' })).toBeNull()
  })

  test('a failed delete shows the error and still reloads', async () => {
    h.responders['/attack-skills/sk2'] = () => json(500, { error: 'The database is busy.' })
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete older versions' }))
    fireEvent.click((await screen.findAllByRole('button', { name: 'Delete' })).pop()!)
    expect(await screen.findByText('The database is busy. (HTTP 500)')).toBeInTheDocument()
    await waitFor(() => expect(versionsCalls()).toHaveLength(2))
  })
})

describe('errors', () => {
  test('a 404 (not the owner\'s skill) shows the error instead of a list', async () => {
    h.responders['/overrides/versions'] = () => json(404, { error: 'Not found' })
    draw()
    expect(await screen.findByRole('alert')).toHaveTextContent('Not found')
    expect(screen.queryByTestId('user-skill-family')).toBeNull()
  })
})

describe('built-in mode is unchanged', () => {
  test('a built-in initial skill reads point=skill.text and shows its scopes', async () => {
    draw({ initialSkill: 'ssrf' })
    expect(await screen.findByTestId('scope-user')).toBeInTheDocument()
    const qs = new URLSearchParams(versionsCalls()[0].url.split('?')[1])
    expect(qs.get('point')).toBe('skill.text')
    expect(qs.get('group')).toBe('ssrf')
    expect(screen.queryByTestId('user-skill-family')).toBeNull()
  })
})
