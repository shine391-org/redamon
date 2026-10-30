/**
 * A failed JS Recon load shows the route's sentence with its code and status.
 * It used to read "Failed to fetch" for every non-404 answer, the same text as
 * the browser's own network error.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/JsReconTable/jsReconError.test.tsx
 */
import { test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createElement, type ReactNode } from 'react'

import { JsReconTable } from './JsReconTable'

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return createElement(QueryClientProvider, { client }, children)
}

function serve(jsRecon: () => Response | Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request) => {
    const u = typeof url === 'string' ? url : url.toString()
    if (u.includes('/api/js-recon/')) return jsRecon()
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
}

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

test('a Neo4j failure shows its code and status', async () => {
  serve(() => new Response(JSON.stringify({ error: 'JS Recon query failed', code: 'Neo.TransientError.General.DatabaseUnavailable' }), { status: 500 }))
  render(<JsReconTable projectId="p1" search="" />, { wrapper })
  expect(await screen.findByText('JS Recon query failed (Neo.TransientError.General.DatabaseUnavailable · HTTP 500)')).toBeInTheDocument()
})

test('no answer at all is a network_error, not a bare "Failed to fetch"', async () => {
  serve(() => { throw new TypeError('Failed to fetch') })
  render(<JsReconTable projectId="p1" search="" />, { wrapper })
  expect(await screen.findByText('Failed to load JS Recon data (network_error)')).toBeInTheDocument()
})

test('a project without data keeps its hint', async () => {
  serve(() => new Response('{}', { status: 404 }))
  render(<JsReconTable projectId="p1" search="" />, { wrapper })
  expect(await screen.findByText('No JS Recon data. Run a recon scan with JS Recon enabled.')).toBeInTheDocument()
})
