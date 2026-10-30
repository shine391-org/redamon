/**
 * The plugin version controls in Agent Skills (design §6, X23): a chip, Versions, Reset and an
 * "N pending" link per built-in skill, but only for a SAVED project; and project.skills.row
 * contributions. Reset is its own API call with a visible error, never part of the project PUT.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'alice' }) }))

import { AttackSkillsSection } from './AttackSkillsSection'

type FormData = React.ComponentProps<typeof AttackSkillsSection>['data']

const h = vi.hoisted(() => ({ summary: null as unknown, contributions: [] as unknown[], posts: [] as { url: string; body: unknown }[], responders: {} as Record<string, () => Response> }))

function summaryWith(ssrf: unknown, pending = 0) {
  const skills = [
    { skillId: 'ssrf', applies: ssrf, pending },
    { skillId: 'sql_injection', applies: null, pending: 0 },
  ]
  return { projectId: 'p1', skills }
}

function stub() {
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (method !== 'GET') {
      h.posts.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined })
      const key = Object.keys(h.responders).find((k) => url.includes(k))
      return key ? h.responders[key]() : new Response(JSON.stringify({ cleared: true }), { status: 200 })
    }
    if (url.includes('/overrides/summary')) return new Response(JSON.stringify(h.summary), { status: h.summary ? 200 : 404 })
    if (url.includes('/plugins/contributions')) return new Response(JSON.stringify(h.contributions), { status: 200 })
    if (url.includes('/overrides/versions')) return new Response(JSON.stringify({ skillId: 'ssrf', skillDisplayName: 'SSRF', factoryText: {}, registryError: null, scopes: [] }), { status: 200 })
    if (url.includes('/attack-skills')) return new Response(JSON.stringify([]), { status: 200 })
    return new Response(JSON.stringify([]), { status: 200 })
  }))
}

function draw(projectId: string | null = 'p1') {
  stub()
  const updateField = vi.fn()
  const data = { attackSkillConfig: { builtIn: { ssrf: true, sql_injection: true }, user: {} }, hydraEnabled: false } as unknown as FormData
  render(
    <ToastProvider>
      <AlertProvider>
        <AttackSkillsSection data={data} updateField={updateField} projectId={projectId} />
      </AlertProvider>
    </ToastProvider>,
  )
  return { updateField }
}

const APPLIED = { pluginId: 'skiller', pluginDisplayName: 'Skiller', scope: 'user', revision: 3, status: 'active', staleReason: null, applied: true, dormantReason: null }

beforeEach(() => {
  h.summary = null
  h.contributions = []
  h.posts = []
  h.responders = {}
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('chips and controls', () => {
  test('a changed skill shows the chip, Versions and Reset; an unchanged one shows none', async () => {
    h.summary = summaryWith(APPLIED)
    draw()
    const row = await screen.findByTestId('plugin-skill-row-ssrf')
    expect(within(row).getByTestId('plugin-skill-chip').textContent).toMatch(/changed by Skiller · v3/)
    expect(within(row).getByRole('button', { name: /versions/i })).toBeInTheDocument()
    expect(within(row).getByRole('button', { name: /reset to factory/i })).toBeInTheDocument()
    expect(screen.queryByTestId('plugin-skill-row-sql_injection')).toBeNull()
  })

  test('a dormant version: not applied with the reason', async () => {
    h.summary = summaryWith({ ...APPLIED, applied: false, dormantReason: 'disabled' })
    draw()
    const row = await screen.findByTestId('plugin-skill-row-ssrf')
    expect(within(row).getByTestId('plugin-skill-chip').textContent).toMatch(/not applied \(.*disabled.*\) · factory in use/i)
  })

  test('a stale version chip; a part-removed chip', async () => {
    h.summary = summaryWith({ ...APPLIED, applied: false, status: 'stale', staleReason: 'factory_changed' })
    draw()
    expect((await screen.findByTestId('plugin-skill-chip')).textContent).toMatch(/stale · factory in use/i)
    cleanup()
    h.summary = summaryWith({ ...APPLIED, applied: false, status: 'stale', staleReason: 'part_removed' })
    draw()
    expect((await screen.findByTestId('plugin-skill-chip')).textContent).toMatch(/part removed · factory in use/i)
  })

  test('a pending link opens the versions modal', async () => {
    h.summary = summaryWith(null, 2)
    draw()
    const row = await screen.findByTestId('plugin-skill-row-ssrf')
    fireEvent.click(within(row).getByRole('button', { name: /2 pending/i }))
    expect(await screen.findByText(/Versions ·/)).toBeInTheDocument()
  })

  test('Reset is its own API call with a visible error on failure (not the project PUT)', async () => {
    h.summary = summaryWith(APPLIED)
    const { updateField } = draw()
    h.responders['/overrides/reset'] = () => new Response(JSON.stringify({ code: 'x', error: 'reset failed' }), { status: 500 })
    const row = await screen.findByTestId('plugin-skill-row-ssrf')
    fireEvent.click(within(row).getByRole('button', { name: /reset to factory/i }))
    fireEvent.click(screen.getAllByRole('button', { name: /reset/i }).pop()!)
    expect(await screen.findByText(/reset failed/i)).toBeInTheDocument()
    expect(h.posts.some((p) => p.url.includes('/overrides/reset'))).toBe(true)
    expect(updateField).not.toHaveBeenCalled() // never a project PUT
  })

  test('Versions opens the core versions modal on this skill', async () => {
    h.summary = summaryWith(APPLIED)
    draw()
    const row = await screen.findByTestId('plugin-skill-row-ssrf')
    fireEvent.click(within(row).getByRole('button', { name: /versions/i }))
    expect(await screen.findByText(/Versions ·/)).toBeInTheDocument()
  })
})

describe('a failed load', () => {
  test('says why the plugin versions are missing and retries on request', async () => {
    let summaryCalls = 0
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url.includes('/overrides/summary')) {
        summaryCalls++
        return new Response(JSON.stringify({ error: 'The plugin operation failed', code: 'P1001' }), { status: 500 })
      }
      return new Response(JSON.stringify([]), { status: 200 })
    }))
    const updateField = vi.fn()
    const data = { attackSkillConfig: { builtIn: { ssrf: true }, user: {} }, hydraEnabled: false } as unknown as FormData
    render(
      <ToastProvider>
        <AlertProvider>
          <AttackSkillsSection data={data} updateField={updateField} projectId="p1" />
        </AlertProvider>
      </ToastProvider>,
    )
    const note = await screen.findByText(/P1001 · HTTP 500/)
    expect(note.closest('[role="alert"]')).not.toBeNull()
    const before = summaryCalls
    fireEvent.click(within(note.closest('[role="alert"]') as HTMLElement).getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(summaryCalls).toBeGreaterThan(before))
  })
})

describe('create mode', () => {
  test('no plugin controls without a projectId (create mode)', async () => {
    h.summary = summaryWith(APPLIED)
    draw(null)
    await screen.findByText('Server-Side Request Forgery')
    await waitFor(() => expect(screen.queryByTestId('plugin-skill-row-ssrf')).toBeNull())
  })
})

describe('project.skills.row contributions', () => {
  test('a contribution renders with the plugin badge and calls its action with the skill id', async () => {
    h.summary = summaryWith(null, 0)
    h.contributions = [{ pluginId: 'echo', displayName: 'Echo', updating: false, chatSessionActions: [], projectSkillsRow: [{ key: 'echo_skill', label: 'Echo skill', action: 'echo_skill' }] }]
    draw()
    const row = await screen.findByTestId('plugin-skill-row-ssrf')
    expect(within(row).getByTitle('RedAmon plugin').textContent).toContain('Echo')
    fireEvent.click(within(row).getByRole('button', { name: 'Echo skill' }))
    await waitFor(() => expect(h.posts.some((p) => p.url.includes('/api/plugins/echo/actions/echo_skill'))).toBe(true))
    const post = h.posts.find((p) => p.url.includes('/actions/echo_skill'))!
    expect(post.body).toMatchObject({ context: { projectId: 'p1' } })
  })
})
