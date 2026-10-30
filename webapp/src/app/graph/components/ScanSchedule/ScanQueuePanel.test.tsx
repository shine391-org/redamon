/**
 * Scan queue panel on the Scan Scheduler tab.
 *
 * The two things that made the old bottom-bar view lie, asserted here: a scan
 * started from the toolbar (a ScanJob with no queue row, source 'scan') must be
 * listed as running, and rows belonging to other projects must not leak into this
 * project's table - they are a count only.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

import { ScanQueuePanel as Panel } from './ScanQueuePanel'
import { AlertProvider } from '@/components/ui'

// Re-confirming an AI attack job asks through the alert modal.
const ScanQueuePanel = (props: { projectId: string }) => <AlertProvider><Panel {...props} /></AlertProvider>

type Job = {
  id: string; projectId: string; projectName: string; kind: string; status: string
  blockedReason: string; error: string; enqueuedAt: string; startedAt: string | null
  detail?: string
  source: 'queue' | 'scan' | 'live'
}

const job = (over: Partial<Job>): Job => ({
  id: 'j1', projectId: 'p1', projectName: 'Proj One', kind: 'partial_recon',
  status: 'queued', blockedReason: '', error: '',
  enqueuedAt: '2026-08-09T21:00:00.000Z', startedAt: null, source: 'queue',
  ...over,
})

const payload = (over: {
  running?: Job[]; queued?: Job[]; needsReview?: Job[]
  others?: { queued: number; running: number; needsReview: number }
} = {}) => ({
  mine: {
    running: over.running ?? [], queued: over.queued ?? [],
    needsReview: over.needsReview ?? [], recent: [],
  },
  others: over.others ?? { queued: 0, running: 0, needsReview: 0 },
})

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => payload() })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ScanQueuePanel', () => {
  test('lists a running scan that has no queue row behind it', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({
        running: [job({ id: 's1', kind: 'full_recon', status: 'running', source: 'scan', startedAt: '2026-08-09T21:08:00.000Z' })],
      }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Full recon')).toBeTruthy())
    expect(screen.getByText('running')).toBeTruthy()
    // No queue row, so no queue action to offer.
    expect(screen.queryByText('Cancel')).toBeNull()
  })

  test('a queued job shows why it is waiting and can be canceled', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({
        queued: [job({ blockedReason: 'Full recon is running for project p1. Stop it first.' })],
      }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/Full recon is running/)).toBeTruthy())

    fireEvent.click(screen.getByText('Cancel'))
    await waitFor(() => {
      const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')
      expect(post).toBeTruthy()
      expect(String(post![0])).toBe('/api/job-queue/j1/cancel')
    })
  })

  test('a needs_review job offers re-confirm', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({ needsReview: [job({ status: 'needs_review', blockedReason: 'settings changed' })] }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText('needs review')).toBeTruthy())
    fireEvent.click(screen.getByText('Re-confirm'))
    await waitFor(() => {
      const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')
      expect(String(post![0])).toBe('/api/job-queue/j1/reconfirm')
    })
  })

  test('other projects are a count, never rows in this table', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({
        running: [job({ id: 's9', projectId: 'p2', projectName: 'Proj Two', kind: 'full_recon', status: 'running', source: 'scan' })],
        queued: [job({ id: 'j9', projectId: 'p2', projectName: 'Proj Two' })],
      }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/Your other projects/)).toBeTruthy())
    expect(screen.getByText(/1 running, 1 queued/)).toBeTruthy()
    expect(screen.getByText(/Nothing running or queued for this project/)).toBeTruthy()
    expect(screen.queryByText('Proj Two')).toBeNull()
  })

  test('a live orchestrator scan of any kind is listed, with its tool', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({
        running: [
          job({ id: 'gvm:p1:', kind: 'gvm', status: 'running', source: 'live' }),
          job({ id: 'partial_recon:p1:r1', kind: 'partial_recon', status: 'running', source: 'live', detail: 'katana' }),
        ],
      }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText('GVM')).toBeTruthy())
    expect(screen.getByText('Partial recon')).toBeTruthy()
    expect(screen.getByText('katana')).toBeTruthy()
    // Not a queue row: nothing to cancel or re-confirm from here.
    expect(screen.queryByText('Cancel')).toBeNull()
  })

  test('starting and stopping read as in-flight, not as queued', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({
        running: [job({ id: 'x', projectId: 'p2', kind: 'gvm', status: 'starting', source: 'live' })],
      }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/Your other projects/)).toBeTruthy())
    expect(screen.getByText(/1 running, 0 queued/)).toBeTruthy()
  })

  // Fixed 30 rows/page: a large org batch pages instead of rendering hundreds.
  test('caps the table at 30 rows and shows a pager for the rest', async () => {
    const many = Array.from({ length: 35 }, (_, i) =>
      job({ id: `q${i}`, kind: 'supply_chain_repo', enqueuedAt: `2026-08-09T21:${String(i).padStart(2, '0')}:00.000Z` }))
    fetchMock.mockResolvedValue({ ok: true, json: async () => payload({ queued: many }) })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText(/Page 1 of 2/)).toBeTruthy())
    // Only one table on the panel; its body holds 30 rows.
    const body = document.querySelector('tbody')!
    expect(body.querySelectorAll('tr').length).toBe(30)
    expect(screen.getByText(/35 total/)).toBeTruthy()
  })

  // Newest created on top: the row with the latest enqueuedAt renders first.
  test('orders rows newest-first by creation time', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => payload({
        queued: [
          job({ id: 'old', enqueuedAt: '2026-08-09T21:00:00.000Z', blockedReason: 'OLDEST' }),
          job({ id: 'new', enqueuedAt: '2026-08-09T21:30:00.000Z', blockedReason: 'NEWEST' }),
        ],
      }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText('NEWEST')).toBeTruthy())
    const firstRow = document.querySelector('tbody tr')!
    expect(firstRow.textContent).toContain('NEWEST')
  })

  test('a failing load says so instead of rendering an empty queue silently', async () => {
    fetchMock.mockResolvedValue({
      ok: false, status: 500, json: async () => ({ error: 'Could not load scan activity', code: 'P1001' }),
    })
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Could not load scan activity (P1001 · HTTP 500)')).toBeTruthy())
  })

  test('a load that got no answer says so, with the code', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    render(<ScanQueuePanel projectId="p1" />)
    await waitFor(() => expect(screen.getByText('Could not load scan activity. (network_error)')).toBeTruthy())
  })

  test('a cancel answered by a proxy error page shows its status', async () => {
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => (
      init?.method === 'POST'
        ? { ok: false, status: 502, text: async () => '<html>Bad Gateway</html>' }
        : { ok: true, json: async () => payload({ queued: [job({})] }) }
    ))
    render(<ScanQueuePanel projectId="p1" />)
    fireEvent.click(await screen.findByText('Cancel'))
    await waitFor(() => expect(screen.getByText('Could not cancel the job. (non_json_response · HTTP 502)')).toBeTruthy())
  })
})

describe('re-confirming an AI attack job after settings changed', () => {
  test('the RoE is confirmed again before it is re-queued', async () => {
    const held = job({ id: 'ai1', kind: 'ai_attack', status: 'needs_review', blockedReason: 'scan settings changed' })
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === '/api/job-queue/ai1/reconfirm') {
        const confirmed = init?.body && JSON.parse(String(init.body)).roeConfirmed === true
        return confirmed
          ? { ok: true, json: async () => ({ ok: true }) }
          : { ok: false, json: async () => ({ code: 'roe_confirmation_required', error: 'confirm again' }) }
      }
      return { ok: true, json: async () => payload({ needsReview: [held] }) }
    })
    render(<ScanQueuePanel projectId="p1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'Re-confirm' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm and re-queue' }))
    await waitFor(() => {
      const calls = fetchMock.mock.calls.filter(c => c[0] === '/api/job-queue/ai1/reconfirm')
      expect(calls).toHaveLength(2)
      expect(JSON.parse(String(calls[1][1].body))).toEqual({ roeConfirmed: true })
    })
  })
})
