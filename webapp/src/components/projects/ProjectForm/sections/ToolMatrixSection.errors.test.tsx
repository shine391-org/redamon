/**
 * Tool Matrix: the missing-key badges and the "add API key" modal say when a
 * call failed.
 *
 * A failed tradecraft read used to count as "0 resources" and flag the tool as
 * missing its resources; a key save that failed left the modal open with no
 * word of why.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))
vi.mock('@/components/ui/WikiInfoButton', () => ({ WikiInfoButton: () => null }))
vi.mock('@/components/ui/Modal/Modal', () => ({
  Modal: ({ isOpen, title, children, footer }: { isOpen: boolean; title?: string; children?: ReactNode; footer?: ReactNode }) =>
    isOpen ? <div role="dialog" aria-label={title}>{children}{footer}</div> : null,
}))

import { ToolMatrixSection } from './ToolMatrixSection'

type Answer = { status: number; body: unknown }
let answers: { settings: Answer; tradecraft: Answer; put: Answer }
const fetchMock = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  answers = {
    settings: { status: 200, body: { tavilyApiKey: '' } },
    tradecraft: { status: 200, body: [{ enabled: true }] },
    put: { status: 200, body: {} },
  }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const pick = url.endsWith('/tradecraft-resources') ? answers.tradecraft
      : url.endsWith('/mcp') ? { status: 200, body: { servers: [] } }
        : init?.method === 'PUT' ? answers.put : answers.settings
    return new Response(JSON.stringify(pick.body), { status: pick.status })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const DATA = { agentToolPhaseMap: { web_search: ['informational'], tradecraft_lookup: ['informational'] } }

function renderMatrix() {
  // Only the phase map is read by the parts under test.
  return render(<ToolMatrixSection data={DATA as never} updateField={vi.fn()} />)
}

describe('ToolMatrixSection failures', () => {
  test('a settings read that failed is said, with its code and status', async () => {
    answers.settings = { status: 500, body: { error: 'Failed to fetch user settings', code: 'P1001' } }
    renderMatrix()
    expect((await screen.findByRole('alert')).textContent).toContain(
      "Couldn't check which API keys are set (P1001 · HTTP 500), so a tool may be shown without its missing-key warning.")
  })

  test('a tradecraft read that failed does not flag the tool as having no resources', async () => {
    answers.tradecraft = { status: 500, body: { error: 'Failed to fetch tradecraft resources', code: 'P2024' } }
    renderMatrix()
    expect((await screen.findByRole('alert')).textContent).toContain(
      "Couldn't check your tradecraft resources (P2024 · HTTP 500)")
    expect(screen.getByText(/No Tavily key - Add/)).toBeInTheDocument()
    expect(screen.queryByText(/No Tradecraft Resources key/)).toBeNull()
  })

  test('a key save that failed says why inside the modal, which stays open', async () => {
    answers.put = { status: 500, body: { error: 'Failed to update user settings', code: 'P2024' } }
    renderMatrix()
    fireEvent.click(await screen.findByText(/No Tavily key - Add/))
    fireEvent.change(screen.getByPlaceholderText('Enter tavily API key'), { target: { value: 'tvly-x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('Failed to update user settings (P2024 · HTTP 500)'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  test('a key save with no answer reads as a network failure', async () => {
    renderMatrix()
    fireEvent.click(await screen.findByText(/No Tavily key - Add/))
    fetchMock.mockImplementationOnce(async () => { throw new TypeError('Failed to fetch') })
    fireEvent.change(screen.getByPlaceholderText('Enter tavily API key'), { target: { value: 'tvly-x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.getByRole('alert').textContent).toBe('The key was not saved (network_error)'))
  })
})
