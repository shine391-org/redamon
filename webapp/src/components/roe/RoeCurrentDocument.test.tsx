/**
 * The RoE history modal tells a failed read from an empty history, and a failed
 * revision download shows inside the modal, where the person is looking.
 *
 * Run: npx vitest run --no-file-parallelism src/components/roe/RoeCurrentDocument.test.tsx
 */
import { test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'

import { RoeCurrentDocument } from './RoeCurrentDocument'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function mount() {
  render(<RoeCurrentDocument projectId="p1" documentName="roe.pdf" appliedAt={null} onRemove={vi.fn()} />)
  fireEvent.click(screen.getByRole('button', { name: /History/ }))
}

test('a failed history read shows its cause, never "No earlier document"', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(500, { error: 'Failed to list RoE revisions', code: 'P1001' })))
  mount()
  expect(await screen.findByText('Failed to list RoE revisions (P1001 · HTTP 500)')).toBeInTheDocument()
  expect(screen.queryByText(/No earlier document/)).toBeNull()
})

test('an empty history still says so', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(200, { revisions: [] })))
  mount()
  expect(await screen.findByText(/No earlier document/)).toBeInTheDocument()
})

test('a failed revision download is shown inside the modal', async () => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => url.endsWith('/roe/revisions')
    ? json(200, { revisions: [{ id: 'r1', documentName: 'old.pdf', appliedAt: null, supersededAt: '2026-10-01T00:00:00.000Z', reason: 'replaced' }] })
    : json(500, { error: 'Failed to download the RoE revision', code: 'P2024' })))
  mount()
  const item = (await screen.findByText('old.pdf')).closest('li') as HTMLElement
  fireEvent.click(within(item).getByRole('button', { name: /Download/ }))
  const dialog = screen.getByRole('dialog')
  await waitFor(() => expect(dialog).toHaveTextContent('Failed to download the RoE revision (P2024 · HTTP 500)'))
})
