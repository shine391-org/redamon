/**
 * @vitest-environment jsdom
 *
 * Typed URLs on an IP-mode project. The run's root is the `ip-targets.<id>`
 * placeholder, which no typed host sits under, so the modal must apply the
 * orchestrator's IP-mode rule instead (recon_orchestrator/batch_scope.py
 * filter_partial_user_input): a URL host must be one of the project's own
 * addresses. Before, every typed URL was refused as out of scope.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.ipMode.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn((url: string) => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/graph-inputs/')
      ? { domain: 'ip-targets.p1', domains: ['ip-targets.p1'], existing_subdomains: [],
          existing_subdomains_count: 0, existing_baseurls: ['http://10.0.0.5'], existing_baseurls_count: 1,
          existing_endpoints_count: 4, source: 'graph' }
      : {}),
  } as Response)))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

async function typeUrls(urls: string, ipTargets?: string[]) {
  render(<PartialReconModal isOpen toolId="RouteExposure" onClose={vi.fn()} onConfirm={vi.fn()}
                            projectId="p1" targetDomain="" userId="u1" ipTargets={ipTargets} />)
  await waitFor(() => expect(screen.getByText(/1 BaseURLs, 4 Endpoints/)).toBeTruthy())
  // The modal renders in a portal, outside render()'s container.
  fireEvent.change(document.querySelector('textarea')!, { target: { value: urls } })
  return (screen.getByRole('button', { name: 'Run Partial Recon' }) as HTMLButtonElement)
}

describe('PartialReconModal: typed URLs in IP mode', () => {
  test("a URL on one of the project's addresses is accepted", async () => {
    const run = await typeUrls('http://10.0.0.5/admin', ['10.0.0.5', '10.0.0.6'])
    expect(screen.queryByText(/out of scope|not one of this project's target IPs/)).toBeNull()
    expect(run.disabled).toBe(false)
  })

  test('a URL on any other address is refused, naming the rule', async () => {
    const run = await typeUrls('http://10.0.0.9/', ['10.0.0.5'])
    expect(screen.getByText(/10\.0\.0\.9 is not one of this project's target IPs/)).toBeTruthy()
    expect(run.disabled).toBe(true)
  })

  test('an IPv6 target matches without its brackets, as the server parses it', async () => {
    const run = await typeUrls('http://[FD00::5]:8080/', ['fd00::5'])
    expect(screen.queryByText(/not one of this project's target IPs/)).toBeNull()
    expect(run.disabled).toBe(false)
  })
})
