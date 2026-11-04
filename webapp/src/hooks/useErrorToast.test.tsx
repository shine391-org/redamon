/**
 * useErrorToast shows each error once.
 *
 * The toast context changes identity every time a toast is added, so an effect
 * that depended on it and did not remember what it had shown would toast the
 * same error in a loop.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, cleanup } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'

const error = vi.fn()
// A fresh object per render, as the real context is after every toast.
vi.mock('@/components/ui', () => ({ useToast: () => ({ error }) }))

import { useErrorToast } from './useErrorToast'

afterEach(() => {
  cleanup()
  error.mockReset()
})

describe('useErrorToast', () => {
  test('a new error is toasted once, however often the component re-renders', () => {
    const first = new ApiError({ reason: 'Could not switch user', status: 500, code: 'P1001' })
    const { rerender } = renderHook(({ e }) => useErrorToast(e, 'User not switched'), { initialProps: { e: first as ApiError | null } })
    rerender({ e: first })
    rerender({ e: first })
    expect(error).toHaveBeenCalledTimes(1)
    expect(error).toHaveBeenCalledWith('Could not switch user (P1001 · HTTP 500)', 'User not switched')
  })

  test('a later error is toasted too, and no error toasts nothing', () => {
    const { rerender } = renderHook(({ e }) => useErrorToast(e), { initialProps: { e: null as ApiError | null } })
    expect(error).not.toHaveBeenCalled()
    rerender({ e: new ApiError({ reason: 'A', status: 500 }) })
    rerender({ e: null })
    rerender({ e: new ApiError({ reason: 'B', status: 0, code: 'network_error' }) })
    expect(error.mock.calls.map(c => c[0])).toEqual(['A (HTTP 500)', 'B (network_error)'])
  })
})
