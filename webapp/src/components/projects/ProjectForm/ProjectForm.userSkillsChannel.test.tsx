/**
 * ProjectForm listens on the user-skills channel (plan Phase 4.6): saving a skill version from
 * a review window can switch this project's user-skill toggles and moves its updatedAt. With
 * no unsaved change to attackSkillConfig the form takes the server's toggles AND its updatedAt
 * (so the next full save neither 409s nor reverts the switch); with one, it warns instead of
 * overwriting either side. The heavy hooks and sections are stubbed: only the subscriber and
 * the save it feeds are under test.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
vi.mock('next/dynamic', () => ({ default: () => () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'alice' }) }))
vi.mock('@/hooks/useReconStatus', () => ({ default: () => ({ state: null }) }))
vi.mock('@/hooks/useScanControls', () => ({
  useScanControls: () => ({ otherScansOpen: false, gvm: {}, githubHunt: {}, trufflehog: { runs: [] }, supplyChain: {} }),
}))
vi.mock('@/components/scans/ScanActions', () => ({ ScanActions: () => null }))
vi.mock('@/app/graph/components/OtherScansModal/OtherScansModal', () => ({ OtherScansModal: () => null }))
vi.mock('@/hooks/useMultiPartialReconStatus', () => ({ useMultiPartialReconStatus: () => ({ runs: [], activeRuns: [], refetch: vi.fn() }) }))
vi.mock('@/hooks/useScanStartFailure', () => ({ useScanStartFailure: () => ({ handleStartFailure: vi.fn() }) }))
vi.mock('@/hooks/useDrawerOffsets', () => ({ useDrawerOffsets: () => {} }))
vi.mock('@/hooks/useMultiPartialReconSSE', () => ({ useMultiPartialReconSSE: () => ({ logsMap: {}, phaseMap: {}, clearLogsForRun: vi.fn() }) }))
vi.mock('@/hooks/useDetectedHostIp', () => ({ useDetectedHostIp: () => '' }))

// The Agent Skills tab, reduced to what this test reads and writes.
vi.mock('./sections/AttackSkillsSection', () => ({
  AttackSkillsSection: ({ data, updateField }: { data: { attackSkillConfig: unknown }; updateField: (k: string, v: unknown) => void }) => (
    <div>
      <pre data-testid="cfg">{JSON.stringify(data.attackSkillConfig)}</pre>
      <button type="button" onClick={() => updateField('attackSkillConfig', { builtIn: { xss: true }, user: { sk1: true, local: true } })}>local-toggle</button>
      <button type="button" onClick={() => updateField('stealthMode' as never, true)}>other-change</button>
    </div>
  ),
}))

import { ProjectForm, onlySkillTogglesChanged } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'

const V1 = '2026-10-12T10:00:00.000Z'
const V2 = '2026-10-13T09:30:00.000Z'
const START_CFG = { builtIn: { xss: true }, user: { sk1: true } }
const SERVER_CFG = { builtIn: { xss: true }, user: { sk1: false, sk2: true } }

const h = vi.hoisted(() => ({ row: null as Record<string, unknown> | null, projectGets: 0 }))

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

beforeEach(() => {
  window.history.replaceState({}, '', '/projects/p1/settings?tab=attack')
  h.projectGets = 0
  h.row = { id: 'p1', updatedAt: V2, attackSkillConfig: SERVER_CFG }
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/projects/p1') {
      h.projectGets++
      return json(200, h.row)
    }
    if (url.includes('/settings')) return json(200, {})
    return json(200, [])
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/')
})

function draw(mode: 'edit' | 'create' = 'edit') {
  const onSubmit = vi.fn(async (data: Record<string, unknown>) => ({ ...data, updatedAt: '2026-10-13T12:00:00.000Z' }))
  const initialData = {
    ...MINIMAL_DEFAULTS,
    id: 'p1',
    name: 'ACME lab',
    targetDomain: 'acme-lab.test',
    attackSkillConfig: START_CFG,
    updatedAt: V1,
  } as never
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider>
        <AlertProvider>
          <ProjectForm mode={mode} initialData={initialData} onSubmit={onSubmit as never} onCancel={vi.fn()} projectIdFromRoute={mode === 'edit' ? 'p1' : undefined} />
        </AlertProvider>
      </ToastProvider>
    </QueryClientProvider>,
  )
  return { onSubmit }
}

const cfg = () => JSON.parse(screen.getByTestId('cfg').textContent!)
const updateButton = () => screen.getByRole('button', { name: /Update Settings/ })
const settle = () => new Promise((r) => setTimeout(r, 40))

describe('no unsaved toggle change', () => {
  test('takes the server\'s attackSkillConfig, stays clean, and the next save carries the server\'s updatedAt', async () => {
    const { onSubmit } = draw()
    expect(cfg()).toEqual(START_CFG)
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    await waitFor(() => expect(cfg()).toEqual(SERVER_CFG))
    // Adopted as saved: nothing to save yet.
    expect(updateButton()).toBeDisabled()
    expect(screen.queryByText(/Your skills changed in another window/)).toBeNull()
    fireEvent.click(screen.getByText('other-change'))
    await waitFor(() => expect(updateButton()).toBeEnabled())
    fireEvent.click(updateButton())
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    const sent = onSubmit.mock.calls[0][0] as Record<string, unknown>
    expect(sent.attackSkillConfig).toEqual(SERVER_CFG)
    expect(sent.updatedAt).toBe(V2)
  })

  test('a message with no project is taken too', async () => {
    draw()
    act(() => postUserSkillsChanged({}))
    await waitFor(() => expect(cfg()).toEqual(SERVER_CFG))
  })

  test('the server already has the form\'s toggles: only the updatedAt is adopted', async () => {
    h.row = { id: 'p1', updatedAt: V2, attackSkillConfig: START_CFG }
    const { onSubmit } = draw()
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    await waitFor(() => expect(h.projectGets).toBeGreaterThan(0))
    await settle()
    expect(cfg()).toEqual(START_CFG)
    fireEvent.click(screen.getByText('other-change'))
    await waitFor(() => expect(updateButton()).toBeEnabled())
    fireEvent.click(updateButton())
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect((onSubmit.mock.calls[0][0] as Record<string, unknown>).updatedAt).toBe(V2)
  })
})

describe('an unsaved toggle change', () => {
  const WARNING = 'Your skill toggles were changed by a save elsewhere; reload before saving'

  test('warns "reload before saving" and keeps the local change (no BroadcastChannel)', async () => {
    vi.stubGlobal('BroadcastChannel', undefined)
    draw()
    fireEvent.click(screen.getByText('local-toggle'))
    const local = { builtIn: { xss: true }, user: { sk1: true, local: true } }
    await waitFor(() => expect(cfg()).toEqual(local))
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    expect(await screen.findAllByText(WARNING)).toHaveLength(1)
    expect(cfg()).toEqual(local)
  })

  test('one save elsewhere shows the warning once, also where BroadcastChannel exists', async () => {
    draw()
    fireEvent.click(screen.getByText('local-toggle'))
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    await screen.findAllByText(WARNING)
    await settle()
    expect(screen.getAllByText(WARNING)).toHaveLength(1)
  })

  test('the warning keeps the old updatedAt, so a full save is refused as stale rather than reverting the switch', async () => {
    const { onSubmit } = draw()
    fireEvent.click(screen.getByText('local-toggle'))
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    await screen.findAllByText(WARNING)
    fireEvent.click(updateButton())
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect((onSubmit.mock.calls[0][0] as Record<string, unknown>).updatedAt).toBe(V1)
  })
})

describe('a message that changed nothing of this project', () => {
  test('an unsaved toggle change here is not warned about when the server\'s toggles did not move', async () => {
    // A version saved without a project, or for another one: this row only got a new updatedAt.
    h.row = { id: 'p1', updatedAt: V2, attackSkillConfig: START_CFG }
    draw()
    fireEvent.click(screen.getByText('local-toggle'))
    act(() => postUserSkillsChanged({}))
    await waitFor(() => expect(h.projectGets).toBeGreaterThan(0))
    await settle()
    expect(screen.queryByText(/reload before saving/)).toBeNull()
    expect(cfg()).toEqual({ builtIn: { xss: true }, user: { sk1: true, local: true } })
  })
})

describe('a full save that changed the toggles', () => {
  test('tells the other windows of the project', async () => {
    const heard: unknown[] = []
    const ch = new BroadcastChannel('redamon:user-skills')
    ch.onmessage = (e) => heard.push(e.data)
    const { onSubmit } = draw()
    fireEvent.click(screen.getByText('local-toggle'))
    await waitFor(() => expect(updateButton()).toBeEnabled())
    fireEvent.click(updateButton())
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(heard).toContainEqual({ projectId: 'p1' }))
    ch.close()
  })
})

describe('another field changed on the server too', () => {
  const OTHER = 'This project was changed in another window; reload it before saving'

  test('keeps its toggles and its updatedAt and warns, so the next save is refused as stale instead of reverting that field', async () => {
    // An MCP agent renamed the project while the form sat open; then a skill version was saved.
    h.row = { id: 'p1', updatedAt: V2, attackSkillConfig: SERVER_CFG, name: 'Renamed by an agent' }
    const { onSubmit } = draw()
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    expect(await screen.findAllByText(OTHER)).toHaveLength(1)
    expect(cfg()).toEqual(START_CFG)
    fireEvent.click(screen.getByText('other-change'))
    await waitFor(() => expect(updateButton()).toBeEnabled())
    fireEvent.click(updateButton())
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    expect((onSubmit.mock.calls[0][0] as Record<string, unknown>).updatedAt).toBe(V1)
  })

  test('a field this form saved itself is not another writer\'s change', async () => {
    const { onSubmit } = draw()
    fireEvent.click(screen.getByText('other-change'))
    await waitFor(() => expect(updateButton()).toBeEnabled())
    fireEvent.click(updateButton())
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    // The server now holds the saved stealthMode and, after a skill save, new toggles.
    h.row = { id: 'p1', updatedAt: V2, attackSkillConfig: SERVER_CFG, stealthMode: true }
    act(() => postUserSkillsChanged({ projectId: 'p1' }))
    await waitFor(() => expect(cfg()).toEqual(SERVER_CFG))
    expect(screen.queryByText(OTHER)).toBeNull()
  })
})

describe('onlySkillTogglesChanged', () => {
  const known = { id: 'p1', name: 'ACME lab', attackSkillConfig: START_CFG, updatedAt: V1, updatedById: 'alice' }

  test('only the toggles, updatedAt and updatedById differ: true', () => {
    expect(onlySkillTogglesChanged(known, { ...known, attackSkillConfig: SERVER_CFG, updatedAt: V2, updatedById: 'bob' })).toBe(true)
  })

  test('any other field differs, or one the form never saw appears: false', () => {
    expect(onlySkillTogglesChanged(known, { ...known, name: 'Renamed' })).toBe(false)
    expect(onlySkillTogglesChanged(known, { ...known, katanaDepth: 5 })).toBe(false)
  })

  test('no known row: false', () => {
    expect(onlySkillTogglesChanged(null, known)).toBe(false)
  })
})

describe('ignored messages', () => {
  test('another project\'s message reads nothing', async () => {
    draw()
    act(() => postUserSkillsChanged({ projectId: 'other' }))
    await settle()
    expect(h.projectGets).toBe(0)
    expect(cfg()).toEqual(START_CFG)
  })

  test('a create form ignores the channel', async () => {
    draw('create')
    act(() => postUserSkillsChanged({}))
    await settle()
    expect(h.projectGets).toBe(0)
  })
})
