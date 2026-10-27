/**
 * useLocalJudgeModel: the AI attack-surface judge model is the backend's
 * (drift-map #16), and there is no client-side default to fall back on.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import { useLocalJudgeModel } from './useLocalJudgeModel'

const fetchMock = vi.fn()

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('useLocalJudgeModel', () => {
  test('starts loading, then holds the model the route returns', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ model: 'judge-under-test:7b' }) })
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    expect(result.current).toEqual({ status: 'loading' })
    await waitFor(() => expect(result.current).toEqual({ status: 'ready', model: 'judge-under-test:7b' }))
    expect(fetchMock.mock.calls[0][0]).toBe('/api/ai-attack-surface/p1/judge-model')
  })

  test('the orchestrator down is unavailable, never a guessed model', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 503, json: async () => ({ model: null }) })
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    await waitFor(() => expect(result.current).toEqual({ status: 'unavailable' }))
  })

  test('a network failure is unavailable', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed'))
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    await waitFor(() => expect(result.current).toEqual({ status: 'unavailable' }))
  })

  test('no project, no request', () => {
    const { result } = renderHook(() => useLocalJudgeModel(null))
    expect(result.current).toEqual({ status: 'loading' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
