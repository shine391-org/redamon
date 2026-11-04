/**
 * What Other Scans says when something failed, instead of looking empty or idle:
 * - a source list that failed to load is not "No sources configured";
 * - a project read that failed is not "No input configured";
 * - a status read that failed shows a warning next to the last known badge;
 * - a failed run's badge carries the reason the orchestrator kept;
 * - a 5xx on the data check is not "No data available";
 * - a refused org batch says why, with its code and status.
 *
 * Run: npx vitest run src/app/graph/components/OtherScansModal/OtherScansModal.errors.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const alertError = vi.fn()

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: vi.fn(), info: vi.fn(), error: vi.fn() }),
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) =>
    isOpen ? <div>{children}</div> : null,
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ alertError: (...a: unknown[]) => alertError(...a) }),
}))

import { OtherScansModal } from './OtherScansModal'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const PROFILES = [{ id: 'p-github', source: 'github', label: '', config: {} }]

function stubProject(answer: () => Response | Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => (
    String(url) === '/api/projects/p1' ? answer() : json(200, {})
  )))
}

beforeEach(() => {
  vi.clearAllMocks()
  stubProject(() => json(200, { supplyChainInputMode: 'upload', supplyChainSbomFile: 'package-lock.json' }))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderModal(extra: Record<string, unknown> = {}) {
  return render(
    <OtherScansModal isOpen onClose={() => {}} hasReconData hasGithubToken projectId="p1"
      trufflehogProfiles={PROFILES} {...extra} />,
  )
}

describe('OtherScansModal failures', () => {
  test('a source list that failed to load says so instead of "No sources configured"', () => {
    renderModal({ trufflehogProfiles: [], trufflehogProfilesError: 'Failed to list sources (P1001 · HTTP 500)' })
    expect(screen.getByText('Failed to list sources (P1001 · HTTP 500)')).toBeTruthy()
    expect(screen.queryByText(/No sources configured/)).toBeNull()
  })

  test('an empty source list that loaded still offers to add one', () => {
    renderModal({ trufflehogProfiles: [] })
    expect(screen.getByText(/No sources configured/)).toBeTruthy()
  })

  test('a project read that failed is not "No input configured"', async () => {
    stubProject(() => json(500, { error: 'Failed to load project', code: 'P2024' }))
    renderModal()
    await waitFor(() => expect(screen.getByText('Failed to load project (P2024 · HTTP 500)')).toBeTruthy())
    expect(screen.queryByText(/No input configured/)).toBeNull()
  })

  test('a project read with no answer names the network, not "not configured"', async () => {
    stubProject(() => { throw new TypeError('Failed to fetch') })
    renderModal()
    await waitFor(() => expect(screen.getByText('Could not read the scan input (network_error)')).toBeTruthy())
  })

  test('a status read that failed shows a warning with the reason', () => {
    renderModal({ githubHuntStatus: 'running', githubHuntStatusError: 'GitHub Hunt status unavailable (orchestrator_unreachable · HTTP 503)' })
    const warning = screen.getByText('Status unavailable').closest('[role="status"]') as HTMLElement
    expect(warning.title).toBe('GitHub Hunt status unavailable (orchestrator_unreachable · HTTP 503)')
    // The badge still shows the last known state.
    expect(screen.getByText('running')).toBeTruthy()
  })

  test("a failed run's badge carries the orchestrator's reason", () => {
    renderModal({
      supplyChainStatus: 'error', supplyChainError: 'Container exited with code 137: killed (out of memory)',
    })
    const badge = screen.getAllByText('error').find(el => el.title) as HTMLElement
    expect(badge.title).toBe('Container exited with code 137: killed (out of memory)')
  })

  test('a Secret Multiscanner row in error carries its reason too', () => {
    renderModal({ trufflehogRunsBySource: { github: { status: 'error', error: 'Container exited with code 2' } } })
    expect(screen.getAllByText('error').some(el => el.title === 'Container exited with code 2')).toBe(true)
  })

  test('a 5xx on the data check is not "No data available"', () => {
    renderModal({ hasGithubHuntData: false, githubHuntDataError: 'Could not check for data (HTTP 500)' })
    const downloads = screen.getAllByRole('button').filter(b => b.textContent?.includes('Download'))
    expect(downloads.some(b => b.title === 'Could not check for data (HTTP 500)')).toBe(true)
  })

  test('a refused org batch shows the reason with its code and status', async () => {
    stubProject(() => json(200, { supplyChainInputMode: 'org', supplyChainOrgName: 'acme' }))
    vi.mocked(fetch).mockImplementation(async (url: RequestInfo | URL) => {
      if (String(url) === '/api/projects/p1') return json(200, { supplyChainInputMode: 'org', supplyChainOrgName: 'acme' })
      if (String(url).endsWith('/supply-chain-batch')) return new Response('<html>Bad Gateway</html>', { status: 502 })
      return json(200, {})
    })
    renderModal()
    const button = await screen.findByText('Queue org batch')
    fireEvent.click(button)
    await waitFor(() => expect(alertError).toHaveBeenCalledWith(
      'Could not start the org batch. (non_json_response · HTTP 502)', 'Supply-chain org batch'))
  })
})
