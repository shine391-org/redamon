'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { GithubHuntState, GithubHuntStatus } from '@/lib/recon-types'
import { readScanStartError, scanStartNetworkError, type ScanStartError } from '@/lib/scanStartError'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'

interface UseGithubHuntStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onStatusChange?: (status: GithubHuntStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

interface UseGithubHuntStatusReturn {
  state: GithubHuntState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startGithubHunt: () => Promise<GithubHuntState | null>
  stopGithubHunt: () => Promise<GithubHuntState | null>
  pauseGithubHunt: () => Promise<GithubHuntState | null>
  resumeGithubHunt: () => Promise<GithubHuntState | null>
  getLastStartError: () => ScanStartError | null
  /** Why the last status poll failed ("<scan> status unavailable (code · HTTP n)"); null once one succeeds. */
  statusError: string | null
  /** Why the last start failed, with its code and status; null once a start begins. */
  startError: string | null
  /**
   * Why the most recent stop/pause/resume failed ("reason (code · HTTP n)"), readable
   * right after the call resolves to null; the `error` state only lands on the next render.
   */
  getLastActionError: () => string | null
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

export function useGithubHuntStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseGithubHuntStatusOptions): UseGithubHuntStatusReturn {
  const [state, setState] = useState<GithubHuntState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [startError, setStartError] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)

  const previousStatusRef = useRef<GithubHuntStatus | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  // A pause/stop request is in flight. Docker's freeze can take several seconds,
  // so hold the optimistic status ('pausing' / 'stopping') and skip polling until
  // the request resolves -- a poll landing mid-freeze would revert the button.
  const transitionRef = useRef(false)
  const lastStartErrorRef = useRef<ScanStartError | null>(null)
  const lastActionErrorRef = useRef<string | null>(null)

  const onStatusChangeRef = useRef(onStatusChange)
  const onCompleteRef = useRef(onComplete)
  const onErrorRef = useRef(onError)

  useEffect(() => {
    onStatusChangeRef.current = onStatusChange
    onCompleteRef.current = onComplete
    onErrorRef.current = onError
  }, [onStatusChange, onComplete, onError])

  const fetchStatus = useCallback(async () => {
    if (!projectId) return
    if (transitionRef.current) return

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/status`)
      if (!response.ok) throw await readApiError(response, 'GitHub Hunt status unavailable')

      const data: GithubHuntState = await response.json()
      setState(data)
      setError(null)
      setStatusError(null)

      if (previousStatusRef.current !== data.status) {
        onStatusChangeRef.current?.(data.status)

        if (data.status === 'completed') {
          onCompleteRef.current?.()
        } else if (data.status === 'error' && data.error) {
          onErrorRef.current?.(data.error)
        }

        previousStatusRef.current = data.status
      }

    } catch (err) {
      // The last known state stays: an orchestrator that did not answer says
      // nothing about whether the scan is still running.
      const message = toApiError(err, 'GitHub Hunt status unavailable').message
      setError(message)
      setStatusError(message)
    }
  }, [projectId])

  const startGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)
    setStartError(null)
    lastStartErrorRef.current = null

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        lastStartErrorRef.current = await readScanStartError(response, 'Failed to start GitHub Secret Hunt')
        throw new Error(lastStartErrorRef.current.message)
      }

      const data: GithubHuntState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      return data

    } catch (err) {
      const startErr = lastStartErrorRef.current ?? scanStartNetworkError(err, 'Failed to start GitHub Secret Hunt')
      lastStartErrorRef.current = startErr
      const failure = new ApiError({
        reason: startErr.message, code: startErr.code, status: startErr.status ?? 0, upstreamStatus: startErr.upstreamStatus,
      })
      setError(failure.message)
      setStartError(failure.message)
      onErrorRef.current?.(failure.message)
      // Re-throw so the caller's catch fires (Scan Queue Phase 0.3): this hook
      // used to swallow the failure and return null, so the user saw nothing.
      throw failure

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const getLastStartError = useCallback(() => lastStartErrorRef.current, [])
  const getLastActionError = useCallback(() => lastActionErrorRef.current, [])

  const stopGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    lastActionErrorRef.current = null
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'stopping' as GithubHuntState['status'] } : prev)

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) throw await readApiError(response, 'Failed to stop GitHub Secret Hunt')

      const data: GithubHuntState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = toApiError(err, 'Failed to stop GitHub Secret Hunt').message
      lastActionErrorRef.current = errorMessage
      setError(errorMessage)
      return null

    } finally {
      transitionRef.current = false
      setIsLoading(false)
    }
  }, [projectId])

  const pauseGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    lastActionErrorRef.current = null
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'pausing' as GithubHuntState['status'] } : prev)

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) throw await readApiError(response, 'Failed to pause GitHub hunt')

      const data: GithubHuntState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = toApiError(err, 'Failed to pause GitHub hunt').message
      lastActionErrorRef.current = errorMessage
      setError(errorMessage)
      return null

    } finally {
      transitionRef.current = false
      setIsLoading(false)
    }
  }, [projectId])

  const resumeGithubHunt = useCallback(async (): Promise<GithubHuntState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    lastActionErrorRef.current = null

    try {
      const response = await fetch(`/api/github-hunt/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) throw await readApiError(response, 'Failed to resume GitHub hunt')

      const data: GithubHuntState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = toApiError(err, 'Failed to resume GitHub hunt').message
      lastActionErrorRef.current = errorMessage
      setError(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  // Initial fetch on mount
  useEffect(() => {
    if (!projectId || !enabled) {
      setState(null)
      return
    }

    fetchStatus()
  }, [projectId, enabled, fetchStatus])

  // Smart polling
  useEffect(() => {
    if (!projectId || !enabled) return

    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    const isRunning = state?.status === 'running' || state?.status === 'starting' || state?.status === 'paused'
    const interval = isRunning ? pollingInterval : IDLE_POLLING_INTERVAL

    pollingRef.current = setInterval(fetchStatus, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [projectId, enabled, pollingInterval, fetchStatus, state?.status])

  return {
    state,
    isLoading,
    error,
    refetch: fetchStatus,
    startGithubHunt,
    stopGithubHunt,
    pauseGithubHunt,
    resumeGithubHunt,
    getLastStartError,
    statusError,
    startError,
    getLastActionError,
  }
}

export default useGithubHuntStatus
