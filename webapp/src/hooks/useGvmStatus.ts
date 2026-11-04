'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { GvmState, GvmStatus } from '@/lib/recon-types'
import { readScanStartError, scanStartNetworkError, type ScanStartError } from '@/lib/scanStartError'
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'

interface UseGvmStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onStatusChange?: (status: GvmStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

interface UseGvmStatusReturn {
  state: GvmState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startGvm: () => Promise<GvmState | null>
  stopGvm: () => Promise<GvmState | null>
  pauseGvm: () => Promise<GvmState | null>
  resumeGvm: () => Promise<GvmState | null>
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

export function useGvmStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
}: UseGvmStatusOptions): UseGvmStatusReturn {
  const [state, setState] = useState<GvmState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [startError, setStartError] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)

  const previousStatusRef = useRef<GvmStatus | null>(null)
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
      const response = await fetch(`/api/gvm/${projectId}/status`)
      if (!response.ok) throw await readApiError(response, 'GVM status unavailable')

      const data: GvmState = await response.json()
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
      const message = toApiError(err, 'GVM status unavailable').message
      setError(message)
      setStatusError(message)
    }
  }, [projectId])

  const startGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)
    setStartError(null)
    lastStartErrorRef.current = null

    try {
      const response = await fetch(`/api/gvm/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        // Capture limit + HTTP status so the caller can read getLastStartError()
        // and show a tailored modal (Scan Queue Phase 0.2). GVM keeps the
        // return-null contract; handleConfirmGvm reads the error branch.
        lastStartErrorRef.current = await readScanStartError(response, 'Failed to start GVM scan')
        throw new Error(lastStartErrorRef.current.message)
      }

      const data: GvmState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      return data

    } catch (err) {
      const startErr = lastStartErrorRef.current ?? scanStartNetworkError(err, 'Failed to start GVM scan')
      lastStartErrorRef.current = startErr
      const errorMessage = formatApiError({
        reason: startErr.message, code: startErr.code, status: startErr.status ?? 0, upstreamStatus: startErr.upstreamStatus,
      })
      setError(errorMessage)
      setStartError(errorMessage)
      onErrorRef.current?.(errorMessage)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const getLastStartError = useCallback(() => lastStartErrorRef.current, [])
  const getLastActionError = useCallback(() => lastActionErrorRef.current, [])

  const stopGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    lastActionErrorRef.current = null
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'stopping' as GvmState['status'] } : prev)

    try {
      const response = await fetch(`/api/gvm/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) throw await readApiError(response, 'Failed to stop GVM scan')

      const data: GvmState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = toApiError(err, 'Failed to stop GVM scan').message
      lastActionErrorRef.current = errorMessage
      setError(errorMessage)
      return null

    } finally {
      transitionRef.current = false
      setIsLoading(false)
    }
  }, [projectId])

  const pauseGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    lastActionErrorRef.current = null
    transitionRef.current = true
    setState(prev => prev ? { ...prev, status: 'pausing' as GvmState['status'] } : prev)

    try {
      const response = await fetch(`/api/gvm/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) throw await readApiError(response, 'Failed to pause GVM scan')

      const data: GvmState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = toApiError(err, 'Failed to pause GVM scan').message
      lastActionErrorRef.current = errorMessage
      setError(errorMessage)
      return null

    } finally {
      transitionRef.current = false
      setIsLoading(false)
    }
  }, [projectId])

  const resumeGvm = useCallback(async (): Promise<GvmState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    lastActionErrorRef.current = null

    try {
      const response = await fetch(`/api/gvm/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) throw await readApiError(response, 'Failed to resume GVM scan')

      const data: GvmState = await response.json()
      setState(data)
      return data

    } catch (err) {
      const errorMessage = toApiError(err, 'Failed to resume GVM scan').message
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
    startGvm,
    stopGvm,
    pauseGvm,
    resumeGvm,
    getLastStartError,
    statusError,
    startError,
    getLastActionError,
  }
}

export default useGvmStatus
