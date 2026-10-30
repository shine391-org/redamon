/**
 * Secret Multiscanner sources: every failed list, add, save or delete is said,
 * with the route's code and the HTTP status, instead of an empty list, an
 * unhandled rejection, or an edit that silently never reached the server.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/TrufflehogSection.errors.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { TrufflehogSection } from './TrufflehogSection'

afterEach(() => cleanup())
afterEach(() => vi.unstubAllGlobals())

const GITLAB = { id: 'prof1', source: 'gitlab', label: 'GitLab', config: {} }

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

type Reply = () => Response | Promise<Response>
let routes: { list: Reply; add: Reply; save: Reply; remove: Reply }

beforeEach(() => {
  routes = {
    list: () => json(200, { profiles: [GITLAB] }),
    add: () => json(201, { profile: { id: 'prof2' } }),
    save: () => json(200, { profile: GITLAB }),
    remove: () => json(200, { ok: true }),
  }
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (!String(url).includes('/profiles')) return json(200, {})
    if (method === 'GET') return routes.list()
    if (method === 'POST') return routes.add()
    if (method === 'PATCH') return routes.save()
    if (method === 'DELETE') return routes.remove()
    return json(200, {})
  }))
})

const renderSection = () => render(
  <TrufflehogSection data={{} as never} updateField={(() => {}) as never} mode="edit" projectId="p1" />,
)

describe('TrufflehogSection failures', () => {
  test('a failed source list is an error with its code, not "no sources configured"', async () => {
    routes.list = () => json(500, { error: 'Failed to list sources', code: 'P1001' })
    renderSection()
    expect((await screen.findByRole('alert')).textContent).toBe('Failed to list sources (P1001 · HTTP 500)')
    expect(screen.queryByText(/No sources configured yet/)).toBeNull()
  })

  test('a list that got no answer says so', async () => {
    routes.list = () => { throw new TypeError('Failed to fetch') }
    renderSection()
    expect((await screen.findByRole('alert')).textContent).toBe('Could not load the sources (network_error)')
  })

  test('an add that got no answer is shown, not an unhandled rejection', async () => {
    routes.list = () => json(200, { profiles: [] })
    routes.add = () => { throw new TypeError('Failed to fetch') }
    renderSection()
    await screen.findByText(/No sources configured yet/)
    fireEvent.change(screen.getByLabelText('Add a source'), { target: { value: 'gitlab' } })
    fireEvent.click(screen.getByText('Add source'))
    expect((await screen.findByRole('alert')).textContent).toBe('Could not add the source (network_error)')
  })

  test('an add refused by the server keeps its text and status', async () => {
    routes.list = () => json(200, { profiles: [] })
    routes.add = () => json(409, { error: 'A GitLab profile already exists for this project' })
    renderSection()
    await screen.findByText(/No sources configured yet/)
    fireEvent.change(screen.getByLabelText('Add a source'), { target: { value: 'gitlab' } })
    fireEvent.click(screen.getByText('Add source'))
    expect((await screen.findByRole('alert')).textContent)
      .toBe('A GitLab profile already exists for this project (HTTP 409)')
  })

  test('a failed save says the change is not saved, with the code', async () => {
    routes.save = () => json(500, { error: 'Failed to save the source', code: 'P2024' })
    renderSection()
    fireEvent.click(await screen.findByText('GitLab', { selector: 'strong' }))
    fireEvent.change(await screen.findByLabelText('Group IDs'), { target: { value: '90210' } })
    expect((await screen.findByRole('alert')).textContent)
      .toBe('Failed to save the source (P2024 · HTTP 500). The last change to GitLab is not saved.')
  })

  test('a failed delete is shown and the source stays listed', async () => {
    routes.remove = () => json(500, { error: 'Failed to delete the source', code: 'P2034' })
    renderSection()
    fireEvent.click(await screen.findByLabelText('Remove the GitLab source'))
    expect((await screen.findByRole('alert')).textContent).toBe('Failed to delete the source (P2034 · HTTP 500)')
    expect(screen.getByText('GitLab', { selector: 'strong' })).toBeTruthy()
  })

  test('a delete that got no answer is shown, not an unhandled rejection', async () => {
    routes.remove = () => { throw new TypeError('Failed to fetch') }
    renderSection()
    fireEvent.click(await screen.findByLabelText('Remove the GitLab source'))
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('Could not remove the source (network_error)'))
  })
})
