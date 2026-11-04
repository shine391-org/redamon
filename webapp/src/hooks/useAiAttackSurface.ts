'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import type { AiAttackRunState, AiFinding, AiTarget } from '@/lib/aiAttackSurface'
import { readScanStartError, scanStartNetworkError, type ScanStartError } from '@/lib/scanStartError'
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'

export interface AiAttackLogLine {
  log: string
  phase?: string | null
  phaseNumber?: number | null
  isPhaseStart?: boolean
  level: string
  timestamp: string
}

export interface LaunchTarget {
  baseurl: string
  path: string
  method?: string
  interface_type?: string   // custom targets carry their own shape
  model?: string
  custom?: boolean
}

export interface LaunchPayload {
  tool: string
  targets: LaunchTarget[]
  bounds: { trials?: number; asr_threshold?: number; judge_model?: string; max_turns?: number; seed?: number; parallelism?: number; timeout?: number }
  roe_confirmed: boolean
  dry_run?: boolean
  probes?: string[]
  strategies?: string[]   // promptfoo: payload-mutation strategies
  objective?: string      // pyrit: optional custom attack objective
  target_model?: string
  // Free-text app description (shared): improves giskard/promptfoo/pyrit relevance.
  target_purpose?: string
  // Target auth (shared): resolved from the UI auth mode.
  api_key?: string
  auth_header?: string
  auth_scheme?: string
}

const STOP_FAILED = 'Failed to stop AI Gauntlet scan'

export function useAiAttackSurface(projectId: string | null) {
  const [targets, setTargets] = useState<AiTarget[]>([])
  const [findings, setFindings] = useState<AiFinding[]>([])
  const [run, setRun] = useState<AiAttackRunState | null>(null)
  const [logs, setLogs] = useState<AiAttackLogLine[]>([])
  const [phase, setPhase] = useState<{ name: string | null; num: number | null }>({ name: null, num: null })
  const [launching, setLaunching] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [loadingTargets, setLoadingTargets] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Each read keeps its own error so a failed load never reads as "none found",
  // and a failed poll keeps the last known run instead of making it look idle.
  const [targetsError, setTargetsError] = useState<string | null>(null)
  const [findingsError, setFindingsError] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [streamError, setStreamError] = useState<string | null>(null)

  const esRef = useRef<EventSource | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const lastStartErrorRef = useRef<ScanStartError | null>(null)

  const stopStream = useCallback(() => {
    esRef.current?.close()
    esRef.current = null
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [])

  const loadTargets = useCallback(async () => {
    if (!projectId) return
    setLoadingTargets(true)
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/targets`)
      if (!r.ok) throw await readApiError(r, 'Failed to load the LLM endpoints')
      const d = await r.json()
      setTargets(d.targets || [])
      setTargetsError(null)
    } catch (e) {
      setTargetsError(toApiError(e, 'Failed to load the LLM endpoints').message)
    } finally {
      setLoadingTargets(false)
    }
  }, [projectId])

  const loadFindings = useCallback(async () => {
    if (!projectId) return
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/findings`)
      if (!r.ok) throw await readApiError(r, 'Failed to load AI Gauntlet findings')
      const d = await r.json()
      setFindings(d.findings || [])
      setFindingsError(null)
    } catch (e) {
      setFindingsError(toApiError(e, 'Failed to load AI Gauntlet findings').message)
    }
  }, [projectId])

  const pollStatus = useCallback(async (runId: string) => {
    if (!projectId) return
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/${runId}/status`)
      if (!r.ok) throw await readApiError(r, 'AI Gauntlet status unavailable')
      const d: AiAttackRunState = await r.json()
      setRun(d)
      setStatusError(null)
      if (d.status === 'completed' || d.status === 'error') {
        stopStream()
        loadFindings()
      }
    } catch (e) {
      setStatusError(toApiError(e, 'AI Gauntlet status unavailable').message)
    }
  }, [projectId, stopStream, loadFindings])

  // Open the SSE log stream + status polling for a run. Reusable by launch AND
  // by reconnect-on-mount (so a page refresh re-attaches to an in-flight scan).
  const attachStream = useCallback((runId: string) => {
    if (!projectId) return
    stopStream()
    const es = new EventSource(`/api/ai-attack-surface/${projectId}/${runId}/logs`)
    esRef.current = es
    setStreamError(null)
    // The server replays the full log history on (re)connect; reset our view on
    // open so a refresh/reconnect restores everything without duplicating lines.
    es.onopen = () => { setLogs([]); setPhase({ name: null, num: null }); setStreamError(null) }
    es.addEventListener('log', (ev: MessageEvent) => {
      try {
        const data = JSON.parse(ev.data) as AiAttackLogLine
        setLogs((prev) => [...prev, data])
        if (data.isPhaseStart && data.phase) {
          setPhase({ name: data.phase, num: data.phaseNumber ?? null })
        }
      } catch {
        /* ignore malformed line */
      }
    })
    // A named `error` event is the orchestrator giving up on the stream. Its text
    // is a raw exception, so it goes to the console, not the screen.
    es.addEventListener('error', (ev: Event) => {
      const data = (ev as MessageEvent).data
      if (typeof data !== 'string' || !data) return
      console.error('AI Gauntlet log stream error:', data)
      setStreamError('Log stream lost: the orchestrator stopped streaming this run\'s logs')
    })
    es.addEventListener('complete', () => es.close())
    // EventSource also lands here when the stream simply ended with the run: poll
    // at once so a finished run reads as finished, and the page shows the loss
    // only while the run is still live.
    es.onerror = () => {
      es.close()
      setStreamError((prev) => prev ?? 'Log stream lost')
      void pollStatus(runId)
    }
    pollRef.current = setInterval(() => pollStatus(runId), 3000)
  }, [projectId, stopStream, pollStatus])

  // On mount / project change, re-attach to any still-running scan so the page
  // is stateful across reloads (status + phase + live logs all restored).
  const reconnect = useCallback(async () => {
    if (!projectId || esRef.current) return
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/all`)
      // An orchestrator that cannot list its runs is not "no run in flight".
      if (!r.ok) throw await readApiError(r, 'AI Gauntlet status unavailable')
      const d = await r.json()
      setStatusError(null)
      const active = (d.runs || []).find(
        (x: AiAttackRunState) => x.status === 'running' || x.status === 'starting')
      // Re-check after the await: a launch during the fetch may have attached a
      // stream already (avoid a double-attach race).
      if (active && !esRef.current) {
        setRun(active)
        attachStream(active.run_id)
      }
    } catch (e) {
      setStatusError(toApiError(e, 'AI Gauntlet status unavailable').message)
    }
  }, [projectId, attachStream])

  const launch = useCallback(async (payload: LaunchPayload): Promise<AiAttackRunState | null> => {
    if (!projectId) return null
    setLaunching(true)
    setStopping(false)
    setError(null)
    setLogs([])
    setFindings([])
    setPhase({ name: null, num: null })
    stopStream()
    lastStartErrorRef.current = null
    try {
      let r: Response
      try {
        r = await fetch(`/api/ai-attack-surface/${projectId}/start`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        })
      } catch (e) {
        lastStartErrorRef.current = scanStartNetworkError(e, 'Failed to launch')
        throw e
      }
      if (!r.ok) {
        lastStartErrorRef.current = await readScanStartError(r, 'Failed to launch')
        throw new Error(lastStartErrorRef.current.message)
      }
      const d = await r.json()
      setRun(d)
      setStatusError(null)
      attachStream(d.run_id)
      return d
    } catch (e) {
      if (!lastStartErrorRef.current) lastStartErrorRef.current = scanStartNetworkError(e, 'Launch failed')
      const failed = lastStartErrorRef.current
      setError(formatApiError({
        reason: failed.message, code: failed.code, status: failed.status ?? 0, upstreamStatus: failed.upstreamStatus,
      }))
      return null
    } finally {
      setLaunching(false)
    }
  }, [projectId, attachStream, stopStream])

  const getLastStartError = useCallback(() => lastStartErrorRef.current, [])

  const stop = useCallback(async () => {
    if (!projectId || !run?.run_id) return
    // React immediately: flag stopping + freeze the log stream so the operator
    // sees instant feedback instead of waiting on the backend kill.
    setStopping(true)
    stopStream()
    setError(null)
    try {
      const r = await fetch(`/api/ai-attack-surface/${projectId}/${run.run_id}/stop`, { method: 'POST' })
      if (!r.ok) throw await readApiError(r, STOP_FAILED)
      const d = await r.json().catch(() => null) as AiAttackRunState | null
      if (d && d.status) setRun(d)            // use the authoritative stopped state
      else setRun((prev) => (prev ? { ...prev, status: 'idle' } : prev))
    } catch (e) {
      // The run is still live as far as anyone knows: keep it, say why the stop
      // failed, and resume the stream + poll the stop froze.
      const failed = toApiError(e, STOP_FAILED)
      setError(failed.reason === STOP_FAILED ? failed.message : `Stop failed: ${failed.message}`)
      attachStream(run.run_id)
    } finally {
      setStopping(false)
    }
    loadFindings()
  }, [projectId, run, stopStream, loadFindings, attachStream])

  useEffect(() => () => stopStream(), [stopStream])

  // Re-attach to an in-flight scan on mount / project change (statefulness).
  useEffect(() => { reconnect() }, [reconnect])

  return {
    targets, findings, run, logs, phase, launching, stopping, loadingTargets, error,
    targetsError, findingsError, statusError, streamError,
    loadTargets, loadFindings, launch, stop, reconnect, getLastStartError,
  }
}
