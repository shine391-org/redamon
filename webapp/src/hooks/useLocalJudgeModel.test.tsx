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

  test('the orchestrator down is unavailable with its reason and status, never a guessed model', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      model: null, error: 'The local judge model is unavailable',
      code: 'orchestrator_unreachable', reason: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
    }), { status: 503 }))
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    await waitFor(() => expect(result.current).toEqual({
      status: 'unavailable',
      reason: 'orchestrator_unreachable',
      error: 'The local judge model is unavailable (orchestrator_unreachable · HTTP 503)',
    }))
  })

  test('a failed orchestrator answer keeps its upstream status', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      model: null, error: 'The local judge model is unavailable',
      code: 'orchestrator_error', reason: 'orchestrator_error', upstreamStatus: 500,
    }), { status: 503 }))
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    await waitFor(() => expect(result.current).toMatchObject({
      status: 'unavailable',
      reason: 'orchestrator_error',
      error: 'The local judge model is unavailable (orchestrator_error · HTTP 503 · upstream HTTP 500)',
    }))
  })

  test('an answer without a model is no_model', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({
      model: null, error: 'The local judge model is unavailable', code: 'no_model', reason: 'no_model',
    }), { status: 503 }))
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    await waitFor(() => expect(result.current).toMatchObject({ status: 'unavailable', reason: 'no_model' }))
  })

  test('a network failure is unavailable, reason network_error', async () => {
    fetchMock.mockRejectedValue(new TypeError('fetch failed'))
    const { result } = renderHook(() => useLocalJudgeModel('p1'))
    await waitFor(() => expect(result.current).toEqual({
      status: 'unavailable',
      reason: 'network_error',
      error: 'The local judge model is unavailable (network_error)',
    }))
  })

  test('no project, no request', () => {
    const { result } = renderHook(() => useLocalJudgeModel(null))
    expect(result.current).toEqual({ status: 'loading' })
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
