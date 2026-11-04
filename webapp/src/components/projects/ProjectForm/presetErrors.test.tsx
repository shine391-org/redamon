/**
 * The recon preset drawers and the Save as Preset dialog say why a call failed (U-39, U-47,
 * U-48): a list that cannot be read is not shown as "no presets yet", a refused delete names
 * the server's reason with its status, and a save answered by a proxy page is read as such,
 * not as a JSON parse error.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const ui = vi.hoisted(() => ({
  toast: { success: vi.fn(), error: vi.fn() },
  dangerConfirm: vi.fn(),
}))

vi.mock('@/components/ui', () => ({
  useToast: () => ui.toast,
  useAlertModal: () => ({ dangerConfirm: ui.dangerConfirm }),
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/Modal/Modal', () => ({
  Modal: ({ isOpen, children, footer }: { isOpen: boolean; children: React.ReactNode; footer?: React.ReactNode }) =>
    (isOpen ? <div role="dialog">{children}{footer}</div> : null),
}))

import { UserPresetDrawer } from './UserPresetDrawer'
import { ReconPresetModal } from './ReconPresetModal'
import { SavePresetModal } from './SavePresetModal'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const PRESET = { id: 'up1', name: 'Mine', description: '', createdAt: '2026-09-29T08:00:00.000Z', updatedVia: 'ui', lastWriterTokenPrefix: null }

function stub(route: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => route(url, init))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

beforeEach(() => {
  vi.clearAllMocks()
  ui.dangerConfirm.mockResolvedValue(true)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('My Presets drawer', () => {
  test('a list that cannot be read says why, in place of "No saved presets yet"', async () => {
    stub(() => json(500, { error: 'Failed to fetch presets', code: 'P1001' }))
    render(<UserPresetDrawer isOpen onClose={vi.fn()} onLoad={vi.fn()} userId="u1" />)
    expect(await screen.findByText('Failed to fetch presets (P1001 · HTTP 500)')).toBeInTheDocument()
    expect(screen.queryByText('No saved presets yet.')).toBeNull()
  })

  test('a list that got no answer says network_error', async () => {
    stub(() => { throw new TypeError('Failed to fetch') })
    render(<UserPresetDrawer isOpen onClose={vi.fn()} onLoad={vi.fn()} userId="u1" />)
    expect(await screen.findByText('Failed to load presets (network_error)')).toBeInTheDocument()
  })

  test('a refused delete names the reason and the status, and keeps the preset', async () => {
    stub((url, init) => (init?.method === 'DELETE' ? json(404, { error: 'Preset not found' }) : json(200, [PRESET])))
    render(<UserPresetDrawer isOpen onClose={vi.fn()} onLoad={vi.fn()} userId="u1" />)
    fireEvent.click(await screen.findByLabelText('Delete preset'))
    await waitFor(() => expect(ui.toast.error).toHaveBeenCalledWith('Preset not found (HTTP 404)'))
    expect(screen.getByText('Mine')).toBeInTheDocument()
  })
})

describe('Recon Presets drawer, My Recon Presets', () => {
  const open = () => {
    render(<ReconPresetModal isOpen onClose={vi.fn()} onSelect={vi.fn()} onLoadUserPreset={vi.fn()} userId="u1" />)
    fireEvent.click(screen.getByRole('button', { name: /My Recon Presets/ }))
  }

  test('a list that cannot be read says why, in place of "No presets yet"', async () => {
    stub(() => json(503, { error: 'Failed to fetch presets', code: 'P1001' }))
    open()
    expect(await screen.findByText('Failed to fetch presets (P1001 · HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByText('No presets yet.')).toBeNull()
  })

  test('a refused delete names the reason and the status', async () => {
    stub((url, init) => (init?.method === 'DELETE'
      ? json(500, { error: 'Failed to delete preset', code: 'P2034' })
      : json(200, [PRESET])))
    open()
    fireEvent.click(await screen.findByLabelText('Delete preset'))
    await waitFor(() => expect(ui.toast.error).toHaveBeenCalledWith('Failed to delete preset (P2034 · HTTP 500)'))
  })
})

describe('Save as Preset', () => {
  const save = () => {
    render(<SavePresetModal isOpen onClose={vi.fn()} formData={{}} userId="u1" />)
    fireEvent.change(screen.getByPlaceholderText('e.g. My aggressive scan config'), { target: { value: 'Mine' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Preset' }))
  }

  test("a proxy's error page is read with its status, not as a JSON parse error", async () => {
    stub(() => new Response('<html>502 Bad Gateway</html>', { status: 502 }))
    save()
    await waitFor(() => expect(ui.toast.error).toHaveBeenCalledWith('Failed to save preset (non_json_response · HTTP 502)'))
  })

  test("a server failure shows the route's sentence and its code", async () => {
    stub(() => json(500, { error: 'Failed to create preset', code: 'P2024' }))
    save()
    await waitFor(() => expect(ui.toast.error).toHaveBeenCalledWith('Failed to create preset (P2024 · HTTP 500)'))
  })
})
