'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { readScanStartError, scanStartNetworkError, type ScanStartError } from '@/lib/scanStartError'
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'
import type { TrufflehogState, TrufflehogStatus } from '@/lib/recon-types'

/**
 * Every TruffleHog run for a project, plus the profiles that define them.
 *
 * Replaces the project-level `useTrufflehogStatus`: runs are keyed by SOURCE and
 * several execute in parallel, so a single status can only ever describe one of
 * them and the rest would render as idle while their containers are up.
 *
 * Mirrors `useMultiPartialReconStatus`, which solved the same shape for
 * partial recon.
 */

export interface TrufflehogProfileSummary {
  id: string
  source: string
  label: string
  config: Record<string, unknown>
  validationErrors?: string[]
  missingCredentials?: { settingsKey: string; label: string }[]
}

interface UseTrufflehogRunsOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number
  onRunComplete?: (source: string) => void
  onRunError?: (source: string, error: string) => void
}

interface UseTrufflehogRunsReturn {
  runs: TrufflehogState[]
  profiles: TrufflehogProfileSummary[]
  /** Run state by source, for rendering one row per profile. */
  bySource: Record<string, TrufflehogState | undefined>
  activeRuns: TrufflehogState[]
  isAnyRunning: boolean
  isLoading: boolean
  error: string | null
  /** Why the last run poll failed ("Secret Multiscanner status unavailable (code · HTTP n)"); null once one succeeds. */
  statusError: string | null
  /** Why the source list could not be read; the list on screen is then the last one that loaded. */
  profilesError: string | null
  startTrufflehog: (source: string) => Promise<TrufflehogState | null>
  stopTrufflehog: (source: string) => Promise<TrufflehogState | null>
  refetch: () => Promise<void>
  refetchProfiles: () => Promise<void>
  getLastStartError: () => ScanStartError | null
  /** Why the most recent stop failed ("reason (code · HTTP n)"), readable right after it resolves to null. */
  getLastActionError: () => string | null
}

const DEFAULT_POLLING_INTERVAL = 5000
const IDLE_POLLING_INTERVAL = 30000

const ACTIVE: TrufflehogStatus[] = ['running', 'starting', 'stopping']

export function useTrufflehogRuns({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onRunComplete,
  onRunError,
}: UseTrufflehogRunsOptions): UseTrufflehogRunsReturn {
  const [runs, setRuns] = useState<TrufflehogState[]>([])
  const [profiles, setProfiles] = useState<TrufflehogProfileSummary[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [profilesError, setProfilesError] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)

  const pollingRef = useRef<NodeJS.Timeout | null>(null)
  const lastStartErrorRef = useRef<ScanStartError | null>(null)
  const lastActionErrorRef = useRef<string | null>(null)
  const previousStatusesRef = useRef<Record<string, TrufflehogStatus>>({})
  const onRunCompleteRef = useRef(onRunComplete)
  const onRunErrorRef = useRef(onRunError)

  useEffect(() => {
    onRunCompleteRef.current = onRunComplete
    onRunErrorRef.current = onRunError
  }, [onRunComplete, onRunError])

  const fetchRuns = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/all`)
      if (!response.ok) throw await readApiError(response, 'Secret Multiscanner status unavailable')
      const data = await response.json()
      const next: TrufflehogState[] = Array.isArray(data?.runs) ? data.runs : []
      setRuns(next)
      setError(null)
      setStatusError(null)

      for (const run of next) {
        const key = run.source || run.run_id || ''
        if (!key) continue
        if (previousStatusesRef.current[key] !== run.status) {
          previousStatusesRef.current[key] = run.status
          if (run.status === 'completed') onRunCompleteRef.current?.(key)
          if (run.status === 'error') onRunErrorRef.current?.(key, run.error || 'Scan failed')
        }
      }
    } catch (err) {
      // The runs on screen stay: an orchestrator that did not answer says nothing
      // about whether they are still running.
      const message = toApiError(err, 'Secret Multiscanner status unavailable').message
      setError(message)
      setStatusError(message)
    }
  }, [projectId])

  const fetchProfiles = useCallback(async () => {
    if (!projectId) return
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/profiles`)
      if (!response.ok) throw await readApiError(response, 'Could not load the Secret Multiscanner sources')
      const data = await response.json()
      setProfiles(Array.isArray(data?.profiles) ? data.profiles : [])
      setProfilesError(null)
    } catch (err) {
      // A failed profile list must not blank the runs already on screen, nor
      // read as "no sources configured".
      setProfilesError(toApiError(err, 'Could not load the Secret Multiscanner sources').message)
    }
  }, [projectId])

  const startTrufflehog = useCallback(async (source: string): Promise<TrufflehogState | null> => {
    if (!projectId) return null
    setIsLoading(true)
    lastStartErrorRef.current = null
    try {
      const response = await fetch(`/api/trufflehog/${projectId}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source }),
      })
      if (!response.ok) {
        // Carries the governor's structured limit payload so the caller can
        // offer the queue instead of just showing an error.
        lastStartErrorRef.current = await readScanStartError(response, 'Failed to start Secret Multiscanner scan')
        throw new Error(lastStartErrorRef.current.message)
      }
      const data = await response.json().catch(() => ({}))
      await fetchRuns()
      return data as TrufflehogState
    } catch (err) {
      const startErr = lastStartErrorRef.current ?? scanStartNetworkError(err, 'Failed to start Secret Multiscanner scan')
      lastStartErrorRef.current = startErr
      setError(formatApiError({
        reason: startErr.message, code: startErr.code, status: startErr.status ?? 0, upstreamStatus: startErr.upstreamStatus,
      }))
      return null
    } finally {
      setIsLoading(false)
    }
  }, [projectId, fetchRuns])

  const stopTrufflehog = useCallback(async (source: string): Promise<TrufflehogState | null> => {
    if (!projectId) return null
    lastActionErrorRef.current = null
    try {
      const response = await fetch(
        `/api/trufflehog/${projectId}/${encodeURIComponent(source)}/stop`, { method: 'POST' },
      )
      if (!response.ok) throw await readApiError(response, 'Failed to stop Secret Multiscanner scan')
      const data = await response.json()
      await fetchRuns()
      return data as TrufflehogState
    } catch (err) {
      const message = toApiError(err, 'Failed to stop Secret Multiscanner scan').message
      lastActionErrorRef.current = message
      setError(message)
      return null
    }
  }, [projectId, fetchRuns])

  const activeRuns = runs.filter(r => ACTIVE.includes(r.status))
  const isAnyRunning = activeRuns.length > 0

  useEffect(() => {
    if (!projectId || !enabled) return
    void fetchRuns()
    void fetchProfiles()
  }, [projectId, enabled, fetchRuns, fetchProfiles])

  useEffect(() => {
    if (!projectId || !enabled) return
    // Poll fast only while something is live; an idle project is checked rarely
    // so a page left open does not hammer the orchestrator.
    const interval = isAnyRunning ? pollingInterval : IDLE_POLLING_INTERVAL
    pollingRef.current = setInterval(() => { void fetchRuns() }, interval)
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
      pollingRef.current = null
    }
  }, [projectId, enabled, isAnyRunning, pollingInterval, fetchRuns])

  const bySource: Record<string, TrufflehogState | undefined> = {}
  for (const run of runs) {
    if (run.source) bySource[run.source] = run
  }

  return {
    runs,
    profiles,
    bySource,
    activeRuns,
    isAnyRunning,
    isLoading,
    error,
    statusError,
    profilesError,
    startTrufflehog,
    stopTrufflehog,
    refetch: fetchRuns,
    refetchProfiles: fetchProfiles,
    getLastStartError: () => lastStartErrorRef.current,
    getLastActionError: () => lastActionErrorRef.current,
  }
}
