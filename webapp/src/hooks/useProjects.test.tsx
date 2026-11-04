/**
 * The project fetchers throw an ApiError whose message names the cause (the
 * route's code and the HTTP status), so every `error.message` display that uses
 * these hooks shows it. They used to throw a fixed "Failed to fetch projects",
 * or the SyntaxError of a non-JSON body.
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/useProjects.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { ApiError } from '@/lib/apiError'
import { useCreateProject, useDeleteProject, useProjectById, useProjects, useUpdateProject } from './useProjects'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('reads', () => {
  test('a failed list carries the Prisma code and the status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(500, { error: 'Failed to fetch projects', code: 'P1001' })))
    const { result } = renderHook(() => useProjects('u1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error).toBeInstanceOf(ApiError)
    expect(result.current.error?.message).toBe('Failed to fetch projects (P1001 · HTTP 500)')
  })

  test('a 404 on one project says so', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(404, { error: 'Not found' })))
    const { result } = renderHook(() => useProjectById('p1'), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Not found (HTTP 404)')
  })

  test('a proxy page instead of JSON names the status, not a SyntaxError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('<html>Bad Gateway</html>', { status: 502 })))
    const { result } = renderHook(() => useProjects(), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch projects (non_json_response · HTTP 502)')
  })
})

describe('writes', () => {
  test('create: an empty-bodied 500 is no longer "Unexpected end of JSON input"', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 500 })))
    const { result } = renderHook(() => useCreateProject(), { wrapper })
    await expect(result.current.mutateAsync({ userId: 'u1', name: 'n', targetDomain: 'example.test' }))
      .rejects.toThrow('Failed to create project (empty_response · HTTP 500)')
  })

  test('create: a guardrail refusal keeps its sentence, so the form still recognises it', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(403, { error: 'Target blocked by guardrail: government domain' })))
    const { result } = renderHook(() => useCreateProject(), { wrapper })
    const err = await result.current.mutateAsync({ userId: 'u1', name: 'n', targetDomain: 'example.test' }).catch(e => e)
    expect(err.message).toBe('Target blocked by guardrail: government domain (HTTP 403)')
    expect(err.message.toLowerCase()).toContain('guardrail')
  })

  test('update: the code and stage of a failed save reach the message and the error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(500, { error: 'Failed to update project', code: 'P2024', stage: 'before_write' })))
    const { result } = renderHook(() => useUpdateProject(), { wrapper })
    const err = await result.current.mutateAsync({ projectId: 'p1', data: {} }).catch(e => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.message).toBe('Failed to update project (P2024 · HTTP 500)')
    expect(err.body.stage).toBe('before_write')
  })

  test('delete: the server\'s own sentence and code are kept', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(500, {
      error: 'Could not archive this project\'s engagement authorization records, so it was not deleted.',
      code: 'authorization_archive_failed',
    })))
    const { result } = renderHook(() => useDeleteProject(), { wrapper })
    await expect(result.current.mutateAsync('p1')).rejects.toThrow(
      'Could not archive this project\'s engagement authorization records, so it was not deleted. (authorization_archive_failed · HTTP 500)',
    )
  })

  test('delete: no answer at all is a network_error', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    const { result } = renderHook(() => useDeleteProject(), { wrapper })
    await expect(result.current.mutateAsync('p1')).rejects.toThrow('Failed to delete project (network_error)')
  })
})
