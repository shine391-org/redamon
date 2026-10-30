/**
 * @vitest-environment jsdom
 *
 * The Route Exposure partial-recon modal on a project with no BaseURL or
 * Endpoint yet: Run is disabled and the warning names what the module reads,
 * not the IP-based fallback ("No IPs found... Subdomain Discovery").
 *
 * Run: npx vitest run src/components/projects/ProjectForm/WorkflowView/PartialReconModal.routeExposure.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
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
      ? { domain: '', existing_subdomains: [], existing_subdomains_count: 0, existing_baseurls: [],
          existing_baseurls_count: 0, existing_endpoints_count: 0, source: 'graph' }
      : {}),
  } as Response)))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('PartialReconModal: Route Exposure with an empty graph', () => {
  test('names the inputs it lacks and disables Run', async () => {
    render(<PartialReconModal isOpen toolId="RouteExposure" onClose={vi.fn()} onConfirm={vi.fn()}
                              projectId="p1" targetDomain="" userId="u1" />)
    await waitFor(() => expect(screen.getByText(/No BaseURLs or Endpoints found in graph\. Run HTTP Probing/)).toBeTruthy())
    expect(screen.queryByText(/No IPs found in graph/)).toBeNull()
    expect((screen.getByRole('button', { name: 'Run Partial Recon' }) as HTMLButtonElement).disabled).toBe(true)
  })
})
