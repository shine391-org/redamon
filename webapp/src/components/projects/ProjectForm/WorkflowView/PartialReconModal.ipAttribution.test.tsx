/**
 * @vitest-environment jsdom
 *
 * The IpAttribution partial-recon modal (plan 11.5): graph targets only, so it
 * offers no custom-target control, describes the step instead of the generic
 * fallback, and refuses to run when the graph holds no IP.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

function mockFetch(ipCount: number) {
  return vi.fn((url: string) => {
    if (url.includes('/graph-inputs/')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({
          domain: 'acme.test', existing_subdomains: [], existing_subdomains_count: 2,
          existing_ips_count: ipCount, source: 'graph',
        }),
      } as Response)
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) } as Response)
  })
}

function renderModal() {
  return render(
    <PartialReconModal
      isOpen
      toolId="IpAttribution"
      onClose={vi.fn()}
      onConfirm={vi.fn()}
      projectId="p1"
      targetDomain="acme.test"
      userId="u1"
    />,
  )
}

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('PartialReconModal — IpAttribution', () => {
  test('describes the step, not the generic fallback', async () => {
    vi.stubGlobal('fetch', mockFetch(3))
    renderModal()
    expect((await screen.findAllByText(/shared edge/i)).length).toBeGreaterThan(0)
    expect(screen.queryAllByText(/Runs this pipeline phase independently/i).length).toBe(0)
  })

  test('offers no custom-target control', async () => {
    vi.stubGlobal('fetch', mockFetch(3))
    renderModal()
    await screen.findByRole('button', { name: /Run Partial Recon/i })
    expect(screen.queryAllByText(/Custom IPs/i).length).toBe(0)
    expect(screen.queryAllByText(/Custom subdomains/i).length).toBe(0)
  })

  test('runs when the graph has IPs', async () => {
    vi.stubGlobal('fetch', mockFetch(3))
    renderModal()
    expect((await screen.findByText(/3 IPs, 2 subdomains/)).textContent).toContain('3 IPs')
    const btn = await screen.findByRole('button', { name: /Run Partial Recon/i })
    expect((btn as HTMLButtonElement).disabled).toBe(false)
  })

  test('refuses to run when the graph has no IP', async () => {
    vi.stubGlobal('fetch', mockFetch(0))
    renderModal()
    await screen.findByText(/0 IPs, 2 subdomains/)
    const btn = await screen.findByRole('button', { name: /Run Partial Recon/i })
    expect((btn as HTMLButtonElement).disabled).toBe(true)
  })
})
