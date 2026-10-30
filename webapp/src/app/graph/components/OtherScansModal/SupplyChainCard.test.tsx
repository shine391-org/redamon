/**
 * The Supply Chain Scanner card in Other Scans, after its input configuration
 * moved to Project Settings (Other Scans -> Supply Chain Scanner).
 *
 * The card now owns the run controls ONLY, so the thing that must not regress is
 * the seam: it reads the saved project to learn what would be scanned, Start
 * stays disabled until that input exists, and the org mode - which queues one
 * scan per repo instead of running this project's single input - swaps Start for
 * the queue action rather than showing a button that can never be enabled.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'

const toastSuccess = vi.fn()
const alertError = vi.fn()

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: (...a: unknown[]) => toastSuccess(...a), info: vi.fn(), error: vi.fn() }),
  // The cards are rendered for real; only the modal chrome is stubbed.
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) =>
    isOpen ? <div>{children}</div> : null,
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ alertError: (...a: unknown[]) => alertError(...a) }),
}))

import { OtherScansModal } from './OtherScansModal'

/** One configured source, so the Start counts below stay about Supply-Chain. */
const TRUFFLEHOG_PROFILES = [
  { id: 'p-docker', source: 'docker', label: '', config: { images: ['nginx:1.25'] } },
]

const UPLOAD_PROJECT = {
  supplyChainInputMode: 'upload',
  supplyChainSbomFile: 'package-lock.json',
  supplyChainRepoUrl: '',
  supplyChainRepoRef: '',
  supplyChainOrgName: '',
}

let fetchMock: ReturnType<typeof vi.fn>

function mockProject(project: Record<string, unknown>) {
  fetchMock = vi.fn().mockImplementation((url: string) => {
    if (String(url).startsWith('/api/projects/p1?') || String(url) === '/api/projects/p1') {
      return Promise.resolve({ ok: true, json: async () => project })
    }
    return Promise.resolve({ ok: true, json: async () => ({}) })
  })
  vi.stubGlobal('fetch', fetchMock)
}

beforeEach(() => {
  vi.clearAllMocks()
  mockProject(UPLOAD_PROJECT)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderModal(extra: Record<string, unknown> = {}) {
  return render(
    <OtherScansModal
      isOpen
      onClose={() => {}}
      hasReconData
      hasGithubToken
      projectId="p1"
      trufflehogProfiles={TRUFFLEHOG_PROFILES}
      {...extra}
    />
  )
}

/** Buttons carry a <span> label; find them by that visible text. */
function buttonsByLabel(label: string): HTMLButtonElement[] {
  return screen.getAllByRole('button').filter(b => b.textContent?.includes(label)) as HTMLButtonElement[]
}

/** The Supply-Chain Start is the one whose title names the input gate. */
function supplyChainStart(): HTMLButtonElement | undefined {
  return buttonsByLabel('Start').find(b => /Supply-Chain scan|scan input in project settings/.test(b.title))
}

describe('Supply Chain card - the configured input', () => {
  test('names the uploaded file and lets the scan start', async () => {
    renderModal()
    await waitFor(() => expect(screen.getByText('package-lock.json')).toBeTruthy())
    expect(screen.getByText('SBOM / lockfile')).toBeTruthy()
    expect(supplyChainStart()?.disabled).toBe(false)
  })

  test('names the repository and its ref', async () => {
    mockProject({
      ...UPLOAD_PROJECT,
      supplyChainInputMode: 'github',
      supplyChainSbomFile: '',
      supplyChainRepoUrl: 'acme/widgets',
      supplyChainRepoRef: 'main',
    })
    renderModal()
    await waitFor(() => expect(screen.getByText('acme/widgets @ main')).toBeTruthy())
    expect(supplyChainStart()?.disabled).toBe(false)
  })

  // The gate the move created: with the input configured elsewhere, the card has
  // to refuse the start itself rather than let the API reject it later.
  test('an unconfigured input disables Start and says where to set it', async () => {
    mockProject({ ...UPLOAD_PROJECT, supplyChainSbomFile: '' })
    renderModal()
    await waitFor(() => expect(screen.getByText(/No input configured/)).toBeTruthy())
    const start = supplyChainStart()
    expect(start?.disabled).toBe(true)
    expect(start?.title).toMatch(/project settings/)
    expect(screen.getByText('Set it in project settings').getAttribute('href'))
      .toBe('/projects/p1/settings#supply-chain-scanner')
  })

  // A configured upload must not make a repo-mode scan startable, or the scan
  // would run against something the card never showed.
  test('the selected source is what gates Start, not any configured value', async () => {
    mockProject({
      ...UPLOAD_PROJECT,
      supplyChainInputMode: 'github',
      supplyChainSbomFile: 'package-lock.json',
      supplyChainRepoUrl: '',
    })
    renderModal()
    await waitFor(() => expect(screen.getByText(/No input configured/)).toBeTruthy())
    expect(supplyChainStart()?.disabled).toBe(true)
  })

  test('the gear links into the section that configures the input', async () => {
    renderModal()
    await waitFor(() => expect(screen.getByLabelText('Configure Supply Chain Scanner in project settings')).toBeTruthy())
    expect(screen.getByLabelText('Configure Supply Chain Scanner in project settings').getAttribute('href'))
      .toBe('/projects/p1/settings#supply-chain-scanner')
  })
})

describe('Supply Chain card - org batch mode', () => {
  const ORG_PROJECT = {
    ...UPLOAD_PROJECT,
    supplyChainInputMode: 'org',
    supplyChainSbomFile: '',
    supplyChainOrgName: 'acme-corp',
  }

  test('replaces Start with the queue action', async () => {
    mockProject(ORG_PROJECT)
    renderModal()
    await waitFor(() => expect(buttonsByLabel('Queue org batch')).toHaveLength(1))
    // GitHub Hunt and the one TruffleHog source keep theirs; only Supply-Chain's
    // Start is replaced.
    expect(buttonsByLabel('Start')).toHaveLength(2)
    expect(screen.getByText('acme-corp')).toBeTruthy()
  })

  test('queues the batch for the configured account and reports the count', async () => {
    mockProject(ORG_PROJECT)
    renderModal()
    await waitFor(() => expect(buttonsByLabel('Queue org batch')).toHaveLength(1))
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve({ ok: true, json: async () => ({ totalItems: 12 }) }))
    fireEvent.click(buttonsByLabel('Queue org batch')[0])

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(c => c[1]?.method === 'POST')
      expect(post).toBeTruthy()
      expect(String(post![0])).toBe('/api/projects/p1/supply-chain-batch')
      expect(JSON.parse(post![1].body as string)).toEqual({ org: 'acme-corp' })
    })
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith(expect.stringContaining('12 repo scans')))
  })

  test('a rejected batch surfaces the server reason instead of a silent no-op', async () => {
    mockProject(ORG_PROJECT)
    renderModal()
    await waitFor(() => expect(buttonsByLabel('Queue org batch')).toHaveLength(1))
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve({ ok: false, status: 403, json: async () => ({ error: 'token lacks org scope' }) }))
    fireEvent.click(buttonsByLabel('Queue org batch')[0])
    // The status rides along so a screenshot tells a scope refusal from an outage.
    await waitFor(() => expect(alertError).toHaveBeenCalledWith('token lacks org scope (HTTP 403)', 'Supply-chain org batch'))
  })

  test('with no account configured the queue button is dead and says why', async () => {
    mockProject({ ...ORG_PROJECT, supplyChainOrgName: '' })
    renderModal()
    await waitFor(() => expect(buttonsByLabel('Queue org batch')).toHaveLength(1))
    const queue = buttonsByLabel('Queue org batch')[0]
    expect(queue.disabled).toBe(true)
    expect(queue.title).toMatch(/project settings/)
  })

  // The batch writes into the LIVE graph like every other scan here.
  test('a past version blocks the queue action too', async () => {
    mockProject(ORG_PROJECT)
    renderModal({ viewingPastVersion: true })
    await waitFor(() => expect(buttonsByLabel('Queue org batch')).toHaveLength(1))
    const queue = buttonsByLabel('Queue org batch')[0]
    expect(queue.disabled).toBe(true)
    expect(queue.title).toMatch(/saved version/)
  })
})
