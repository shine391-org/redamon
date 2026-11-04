/**
 * What the Files drawer shows when the workspace routes fail (G-30, G-47, G-48).
 *
 * It parsed the body before checking the status, so a proxy's HTML page read
 * "Unexpected token '<' ... not valid JSON"; a bulk delete said "see browser
 * console" with nothing logged; a bulk download showed the raw upstream text.
 *
 * Run: npx vitest run src/app/graph/components/FileSystemDrawer/FileSystemDrawer.errors.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'

vi.mock('@/components/ui/Drawer', () => ({
  Drawer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))
const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui', async (orig) => ({ ...(await orig<typeof import('@/components/ui')>()), useAlertModal: () => alertSpies }))

import { FileSystemDrawer } from './FileSystemDrawer'

const entries = [
  { name: 'a.txt', path: 'a.txt', isDir: false, isSymlink: false, size: 1, mtime: '2026-05-15T10:00:00Z' },
  { name: 'b.txt', path: 'b.txt', isDir: false, isSymlink: false, size: 1, mtime: '2026-05-15T10:00:00Z' },
]
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
let handler: (url: string, init?: RequestInit) => Response | Promise<Response>

beforeEach(() => {
  global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => handler(String(url), init)) as unknown as typeof fetch
})
afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('Files drawer failures', () => {
  test('a proxy error page shows the status, not a JSON parse error', async () => {
    handler = () => new Response('<html>502 Bad Gateway</html>', { status: 502 })
    render(<FileSystemDrawer isOpen onClose={() => {}} projectId="p1" />)
    expect(await screen.findByText(/Failed to list workspace \(non_json_response · HTTP 502\)/)).toBeInTheDocument()
    expect(screen.queryByText(/Unexpected token/)).toBeNull()
  })

  test('an unreachable agent shows the route code, not "fetch failed"', async () => {
    handler = () => json(503, { error: 'Failed to list workspace', code: 'agent_unreachable', cause: 'ECONNREFUSED' })
    render(<FileSystemDrawer isOpen onClose={() => {}} projectId="p1" />)
    expect(await screen.findByText(/Failed to list workspace \(agent_unreachable · HTTP 503\)/)).toBeInTheDocument()
  })

  test('a bulk delete names the entries that failed and why', async () => {
    handler = (url, init) => {
      if (url.includes('/workspace/list')) return json(200, { entries })
      if (init?.method === 'DELETE' && url.includes('a.txt')) return json(400, { error: 'cannot delete protected path: a.txt', code: 'agent_error', upstreamStatus: 400 })
      if (init?.method === 'DELETE') return json(503, { error: 'Failed to delete', code: 'agent_unreachable' })
      return json(200, { ok: true })
    }
    render(<FileSystemDrawer isOpen onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])
    fireEvent.click(screen.getAllByRole('checkbox')[1])
    fireEvent.click(screen.getByTitle(/Delete selected/))
    fireEvent.click(await screen.findByRole('button', { name: 'Delete 2' }))
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledWith(
      '2 entries failed to delete:\n'
      + 'a.txt: cannot delete protected path: a.txt (agent_error · HTTP 400 · upstream HTTP 400)\n'
      + 'b.txt: Failed to delete (agent_unreachable · HTTP 503)',
      'Bulk delete',
    ))
    expect(alertSpies.alertError).not.toHaveBeenCalledWith(expect.stringContaining('browser console'), expect.anything())
  })

  test('a bulk download error is parsed, not shown raw', async () => {
    handler = (url) => {
      if (url.includes('/workspace/list')) return json(200, { entries })
      if (url.includes('/bulk-archive')) return json(400, { error: 'not found: a.txt', code: 'agent_error', upstreamStatus: 400 })
      return json(200, { ok: true })
    }
    render(<FileSystemDrawer isOpen onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByRole('checkbox')[0])
    fireEvent.click(screen.getByTitle('Download selected as one tar.gz'))
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledWith(
      'not found: a.txt (agent_error · HTTP 400 · upstream HTTP 400)', 'Bulk download failed',
    ))
  })

  test('a rename refused by the agent shows its sentence and status', async () => {
    handler = (url) => {
      if (url.includes('/workspace/list')) return json(200, { entries })
      if (url.includes('/rename')) return json(400, { error: 'destination already exists: b.txt', code: 'agent_error', upstreamStatus: 400 })
      return json(200, { ok: true })
    }
    render(<FileSystemDrawer isOpen onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('a.txt')).toBeInTheDocument())
    fireEvent.click(screen.getAllByTitle('Rename')[0])
    const input = screen.getByDisplayValue('a.txt')
    fireEvent.change(input, { target: { value: 'b.txt' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledWith(
      'destination already exists: b.txt (agent_error · HTTP 400 · upstream HTTP 400)', 'Rename failed',
    ))
  })
})
