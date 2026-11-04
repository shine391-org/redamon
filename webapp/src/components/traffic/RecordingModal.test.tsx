/**
 * RecordingModal — closing the modal must END the recording.
 *
 * Row 6 of the test strategy. Without this, closing (Esc / backdrop / X) reset
 * only client state: the session stayed active server-side for its 30-minute
 * TTL, the proxy kept tagging the operator's browsing, and every other project
 * was refused the single global recording slot — with nothing in the UI saying so.
 *
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const alertError = vi.fn()

// Stand-ins for the shared UI kit: this test exercises the modal's lifecycle,
// not the design system. Modal exposes its onClose as a button so the test can
// trigger the same path Esc/backdrop use.
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError }),
  WikiInfoButton: () => null,
  Modal: ({ isOpen, onClose, children }: { isOpen: boolean; onClose: () => void; children: React.ReactNode }) =>
    isOpen ? (
      <div>
        <button onClick={onClose}>close-modal</button>
        {children}
      </div>
    ) : null,
}))

import { RecordingModal } from './RecordingModal'

function mockRecordingApi() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((async (url: string, init?: RequestInit) => {
    const u = String(url)
    if (u.endsWith('/recording/start')) {
      return {
        ok: true,
        json: async () => ({
          session: {
            id: 'rec1', state: 'active', scopeHosts: ['t.test'],
            expiresAt: '2099-01-01T00:00:00.000Z', observedCount: 0, lastError: null,
          },
        }),
      } as Response
    }
    if (u.endsWith('/recording/status')) {
      return { ok: true, json: async () => ({ session: null, summary: null, otherProjectRecording: false }) } as Response
    }
    if (u.endsWith('/recording/stop')) {
      return { ok: true, json: async () => ({ session: null, summary: null }) } as Response
    }
    return { ok: true, json: async () => ({}) } as Response
  }) as typeof fetch)
}

beforeEach(() => { vi.clearAllMocks() })
afterEach(() => { cleanup(); vi.restoreAllMocks() })

test('closing while recording POSTs /recording/stop', async () => {
  const fetchMock = mockRecordingApi()
  const onClose = vi.fn()
  render(<RecordingModal isOpen onClose={onClose} projectId="p1" />)

  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByText(/Recording/)).toBeTruthy())

  fireEvent.click(screen.getByText('close-modal'))

  await waitFor(() => {
    const stopCalls = fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/recording/stop'))
    expect(stopCalls.length).toBe(1)
    expect((stopCalls[0][1] as RequestInit).method).toBe('POST')
  })
  expect(onClose).toHaveBeenCalled()
})

test('closing when idle does NOT call stop', async () => {
  const fetchMock = mockRecordingApi()
  const onClose = vi.fn()
  render(<RecordingModal isOpen onClose={onClose} projectId="p1" />)

  fireEvent.click(screen.getByText('close-modal'))

  expect(fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/recording/stop')).length).toBe(0)
  expect(onClose).toHaveBeenCalled()
})

// ── Failures carry their cause ────────────────────────────────────────────────

const SESSION = {
  id: 'rec1', state: 'active', scopeHosts: ['t.test'],
  expiresAt: '2099-01-01T00:00:00.000Z', observedCount: 0, lastError: null,
}

function mockApi(overrides: Record<string, () => Promise<Response>>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((async (url: string) => {
    const u = String(url)
    for (const [suffix, answer] of Object.entries(overrides)) {
      if (u.endsWith(suffix)) return answer()
    }
    if (u.endsWith('/recording/start')) return new Response(JSON.stringify({ session: SESSION }), { status: 200 })
    if (u.endsWith('/recording/status')) return new Response(JSON.stringify({ session: SESSION, summary: null }), { status: 200 })
    if (u.endsWith('/recording/stop')) {
      return new Response(JSON.stringify({ session: { ...SESSION, state: 'stopped' }, summary: { hasCookie: true, hasBearer: false, extraHeaderNames: [], hosts: [] } }), { status: 200 })
    }
    return new Response('{}', { status: 200 })
  }) as typeof fetch)
}

test('a proxy HTML page on start shows the status, not "Could not reach the server"', async () => {
  mockApi({ '/recording/start': async () => new Response('<html>Bad Gateway</html>', { status: 502 }) })
  render(<RecordingModal isOpen onClose={vi.fn()} projectId="p1" />)
  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByText('Could not start recording (non_json_response · HTTP 502)')).toBeTruthy())
})

test('a refused start shows the server reason with its code', async () => {
  mockApi({ '/recording/start': async () => new Response(JSON.stringify({ error: 'activation check failed; try again', code: 'P1001' }), { status: 409 }) })
  render(<RecordingModal isOpen onClose={vi.fn()} projectId="p1" />)
  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByText('activation check failed; try again (P1001 · HTTP 409)')).toBeTruthy())
})

test('no answer at all says the server could not be reached', async () => {
  mockApi({ '/recording/start': async () => { throw new TypeError('Failed to fetch') } })
  render(<RecordingModal isOpen onClose={vi.fn()} projectId="p1" />)
  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByText('Could not reach the server (network_error)')).toBeTruthy())
})

test('a failed stop keeps the recording on screen and says why', async () => {
  mockApi({ '/recording/stop': async () => new Response(JSON.stringify({ error: 'Failed to stop recording', code: 'P2024' }), { status: 500 }) })
  render(<RecordingModal isOpen onClose={vi.fn()} projectId="p1" />)
  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Stop' })).toBeTruthy())
  fireEvent.click(screen.getByRole('button', { name: 'Stop' }))
  await waitFor(() => expect(alertError).toHaveBeenCalledWith('Failed to stop recording (P2024 · HTTP 500)'))
  expect(screen.getByRole('button', { name: 'Stop' })).toBeTruthy()
  expect(screen.queryByText(/No login detected/)).toBeNull()
})

test('a failed save shows the code and status', async () => {
  mockApi({ '/recording/commit': async () => new Response(JSON.stringify({ error: 'Failed to commit recording', code: 'P2002' }), { status: 500 }) })
  render(<RecordingModal isOpen onClose={vi.fn()} projectId="p1" />)
  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Stop' })).toBeTruthy())
  fireEvent.click(screen.getByRole('button', { name: 'Stop' }))
  await waitFor(() => expect(screen.getByText('Save session')).toBeTruthy())
  fireEvent.click(screen.getByText('Save session'))
  await waitFor(() => expect(alertError).toHaveBeenCalledWith('Failed to commit recording (P2002 · HTTP 500)'))
  expect(screen.getByText('Save session')).toBeTruthy()
})

test('a failing status poll marks the live counter stale', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true })
  try {
    mockApi({ '/recording/status': async () => new Response('', { status: 500 }) })
    render(<RecordingModal isOpen onClose={vi.fn()} projectId="p1" />)
    fireEvent.click(screen.getByText('Start recording'))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Stop' })).toBeTruthy())
    await vi.advanceTimersByTimeAsync(3100)
    await waitFor(() => expect(screen.getByText('Live counter not updating (empty_response · HTTP 500); the count may be behind.')).toBeTruthy())
  } finally {
    vi.useRealTimers()
  }
})
