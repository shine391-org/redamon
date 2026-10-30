/**
 * The user-management hooks throw an error that says why.
 *
 * They used to throw fixed strings ("Failed to fetch users") or call `json()`
 * on whatever came back, so a database outage, a cascade the database refused
 * and a proxy's HTML 502 all read the same, or as a SyntaxError.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useUsers, useCreateUser, useDeleteUser, useChangePassword } from './useUsers'

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const answer = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })

describe('useUsers', () => {
  test('a failed list carries the code and status', async () => {
    fetchMock.mockResolvedValue(answer(500, { error: 'Failed to fetch users', code: 'P1001' }))
    const { result } = renderHook(() => useUsers(), { wrapper })
    await waitFor(() => expect(result.current.error).toBeTruthy())
    expect(result.current.error!.message).toBe('Failed to fetch users (P1001 · HTTP 500)')
  })
})

describe('user mutations', () => {
  test('a create the database refused', async () => {
    fetchMock.mockResolvedValue(answer(500, { error: 'Failed to create user', code: 'P2024' }))
    const { result } = renderHook(() => useCreateUser(), { wrapper })
    await act(async () => {
      await expect(result.current.mutateAsync({ name: 'a', email: 'a@b.c' }))
        .rejects.toThrow('Failed to create user (P2024 · HTTP 500)')
    })
  })

  test('a duplicate email keeps the route\'s own sentence', async () => {
    fetchMock.mockResolvedValue(answer(409, { error: 'A user with this email already exists' }))
    const { result } = renderHook(() => useCreateUser(), { wrapper })
    await act(async () => {
      await expect(result.current.mutateAsync({ name: 'a', email: 'a@b.c' }))
        .rejects.toThrow('A user with this email already exists (HTTP 409)')
    })
  })

  test('a delete answered by a proxy error page names its status, not a SyntaxError', async () => {
    fetchMock.mockResolvedValue(new Response('<html>502 Bad Gateway</html>', { status: 502 }))
    const { result } = renderHook(() => useDeleteUser(), { wrapper })
    await act(async () => {
      await expect(result.current.mutateAsync('u2'))
        .rejects.toThrow('Failed to delete user (non_json_response · HTTP 502)')
    })
  })

  test('a delete the database refused names its code', async () => {
    fetchMock.mockResolvedValue(answer(500, { error: 'Failed to delete user', code: 'P2003' }))
    const { result } = renderHook(() => useDeleteUser(), { wrapper })
    await act(async () => {
      await expect(result.current.mutateAsync('u2')).rejects.toThrow('Failed to delete user (P2003 · HTTP 500)')
    })
  })

  test('a password change with no answer reads as a network failure', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const { result } = renderHook(() => useChangePassword(), { wrapper })
    await act(async () => {
      await expect(result.current.mutateAsync({ userId: 'u1', data: { newPassword: 'abcd' } }))
        .rejects.toThrow('Failed to change password (network_error)')
    })
  })
})
