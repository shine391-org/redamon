/**
 * @vitest-environment jsdom
 *
 * When the graph cannot be read, the modal's counts are unknown, not zero. It
 * used to fall back to zero counts silently and then advise "No ports found in
 * graph. Run Naabu first", sending the person to re-run a scan that had already
 * run. A failed JS-file delete was ignored outright.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { PartialReconModal } from './PartialReconModal'

vi.mock('@/providers/ProjectProvider', async orig => ({
  ...(await orig<typeof import('@/providers/ProjectProvider')>()),
  useProject: () => ({ userId: 'u1' }),
  useOptionalProject: () => ({ userId: 'u1' }),
}))

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const settingsFallback = {
  domain: 'alpha.test', domains: ['alpha.test'], existing_subdomains_count: 0,
  existing_ips_count: 0, existing_ports_count: 0, source: 'settings',
}

function stubFetch(graphInputs: () => Response | Promise<Response>, extra?: (url: string, init?: RequestInit) => Response | null) {
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const handled = extra?.(String(url), init)
    if (handled) return handled
    if (String(url).includes('/graph-inputs/')) return graphInputs()
    return json(200, {})
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function renderModal(toolId: string) {
  return render(
    <PartialReconModal isOpen toolId={toolId} onClose={vi.fn()} onConfirm={vi.fn()}
      projectId="p1" targetDomain="alpha.test" userId="u1" />,
  )
}

beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => {}))
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('PartialReconModal when the graph cannot be read', () => {
  test('a degraded answer is said, and the "run Naabu first" advice is withheld', async () => {
    stubFetch(() => json(200, {
      ...settingsFallback, degraded: 'graph_unavailable', code: 'Neo.TransientError.General.DatabaseUnavailable',
    }))
    renderModal('Nmap')
    const banner = await screen.findByTestId('partial-recon-graph-unreadable')
    expect(banner.textContent).toBe(
      'Could not read the graph (Neo.TransientError.General.DatabaseUnavailable). The graph counts below are unknown, not zero.')
    expect(screen.queryByText(/No ports found in graph/)).toBeNull()
  })

  test('a failed graph-inputs call shows the route reason with its code and status', async () => {
    stubFetch(() => json(500, { error: 'Failed to get graph inputs', code: 'P1001' }))
    renderModal('Nmap')
    const banner = await screen.findByTestId('partial-recon-graph-unreadable')
    expect(banner.textContent).toMatch(/^Failed to get graph inputs \(P1001 · HTTP 500\)\./)
    expect(screen.queryByText(/No ports found in graph/)).toBeNull()
  })

  test('a graph that really is empty still gets the advice, and no banner', async () => {
    stubFetch(() => json(200, { ...settingsFallback, source: 'graph' }))
    renderModal('Nmap')
    expect(await screen.findByText(/No ports found in graph/)).toBeTruthy()
    expect(screen.queryByTestId('partial-recon-graph-unreadable')).toBeNull()
  })
})

describe('PartialReconModal JS file delete', () => {
  test('a refused delete is shown inline with its status', async () => {
    stubFetch(() => json(200, { ...settingsFallback, source: 'graph' }), (url, init) => {
      if (!url.startsWith('/api/js-recon/p1/upload')) return null
      if (init?.method === 'DELETE') return json(500, { error: 'Failed to delete the file', code: 'EACCES' })
      return json(200, { files: [{ name: 'app.js', size: 2048, uploaded_at: '2026-10-01T00:00:00Z' }] })
    })
    renderModal('JsRecon')
    fireEvent.click(await screen.findByTitle('Delete app.js'))
    await waitFor(() => expect(screen.getByText('Failed to delete the file (EACCES · HTTP 500)')).toBeTruthy())
  })

  test('an upload over the body limit shows the route reason with its code and status', async () => {
    stubFetch(() => json(200, { ...settingsFallback, source: 'graph' }), (url, init) => {
      if (!url.startsWith('/api/js-recon/p1/upload')) return null
      if (init?.method === 'POST') {
        return json(413, { error: 'The upload is larger than 10 MB', code: 'body_too_large', limitBytes: 10485760 })
      }
      return json(200, { files: [] })
    })
    renderModal('JsRecon')
    await screen.findByText(/Upload JS Files/)
    // The modal renders in a portal, outside the render container.
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['x'], 'big.js', { type: 'text/javascript' })] } })
    await waitFor(() => expect(screen.getByText('The upload is larger than 10 MB (body_too_large · HTTP 413)')).toBeTruthy())
  })

  test('a delete that got no answer says so', async () => {
    stubFetch(() => json(200, { ...settingsFallback, source: 'graph' }), (url, init) => {
      if (!url.startsWith('/api/js-recon/p1/upload')) return null
      if (init?.method === 'DELETE') throw new TypeError('Failed to fetch')
      return json(200, { files: [{ name: 'app.js', size: 2048, uploaded_at: '2026-10-01T00:00:00Z' }] })
    })
    renderModal('JsRecon')
    fireEvent.click(await screen.findByTitle('Delete app.js'))
    await waitFor(() => expect(screen.getByText('Could not delete the file (network_error)')).toBeTruthy())
  })
})
