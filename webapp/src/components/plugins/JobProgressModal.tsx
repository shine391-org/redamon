'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { fetchJson, formatApiError, toApiError } from '@/lib/apiError'
import { featureModelMessage, pluginFeatureId, type FeatureModelCode } from '@/lib/llmFeatures'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'
import { PluginBadge } from './PluginBadge'
import type { PluginJob } from './runPluginAction'
import styles from './JobProgressModal.module.css'

interface JobView {
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'
  progress: { message: string; fields: Record<string, string> } | null
  result: Record<string, unknown> | null
  error: { code: string; message: string } | null
  createdAt: string
}

const ACTIVE = new Set(['queued', 'running'])
const GATE_CODES = new Set<string>(['model_required', 'model_unavailable'])
// A poll that fails is asked again a few times, slower each time: a restart of the webapp or
// a proxy blip must not end the window. A signed-out session, a refusal or a job that is not
// there will not get better by asking again.
const POLL_ATTEMPTS = 4
const FINAL_POLL_STATUSES = new Set([401, 403, 404])
const REPORT_REFUSED = 'report_refused:'

/** "reason (code · HTTP n)" for anything a catch receives; the code of no answer is network_error. */
function failureText(e: unknown, reason: string): string {
  const err = toApiError(e, reason)
  return formatApiError({ reason, code: err.code, status: err.status, upstreamStatus: err.upstreamStatus })
}
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

function elapsed(fromIso: string, nowMs: number): string {
  const secs = Math.max(0, Math.floor((nowMs - Date.parse(fromIso)) / 1000))
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, '0')}`
}

/**
 * Follows an async plugin action to its end. It polls GET /api/plugins/jobs/<id> every
 * `pollMs` until the job is terminal, shows the plugin's progress, and lets the owner cancel.
 * On success it opens the review for a reviewProposal or shows the message; a model-gate
 * failure reopens the gate and, once a model is chosen, retries through the caller.
 */
export function JobProgressModal({
  job,
  onClose,
  onReviewProposal,
  gate,
  onRetry,
  pollMs = 2000,
  now = Date.now,
}: {
  job: PluginJob
  onClose: () => void
  onReviewProposal: (changeSetId: string) => void
  gate?: Pick<FeatureModelGateApi, 'ensureFeatureModel'>
  onRetry?: () => void
  pollMs?: number
  now?: () => number
}) {
  const [view, setView] = useState<JobView | null>(null)
  const [fatal, setFatal] = useState<string | null>(null)
  const [cancelError, setCancelError] = useState<string | null>(null)
  const [nowMs, setNowMs] = useState(now)
  const handed = useRef(false)
  // Once the job is terminal (polled, or set by a cancel), a late in-flight poll must not
  // reopen it: the running answer that was in flight when Cancel landed would otherwise win.
  const done = useRef(false)

  const terminal = view ? !ACTIVE.has(view.status) : false

  // Poll until terminal. A recursive timeout (not an interval) so a slow answer never stacks.
  useEffect(() => {
    let live = true
    let timer: ReturnType<typeof setTimeout> | undefined
    let failures = 0
    const tick = async () => {
      let v: JobView
      try {
        v = await fetchJson<JobView>(`/api/plugins/jobs/${encodeURIComponent(job.jobId)}`, { cache: 'no-store' }, 'Lost contact with the job')
      } catch (e) {
        if (!live || done.current) return
        failures += 1
        if (failures < POLL_ATTEMPTS && !FINAL_POLL_STATUSES.has(toApiError(e, '').status)) {
          timer = setTimeout(tick, pollMs * 2 ** failures)
          return
        }
        setFatal(`${failureText(e, 'Lost contact with the job')}; it may still be running.`)
        return
      }
      failures = 0
      if (!live || done.current) return
      setNowMs(now())
      setView(v)
      if (ACTIVE.has(v.status)) timer = setTimeout(tick, pollMs)
      else done.current = true
    }
    void tick()
    return () => {
      live = false
      if (timer) clearTimeout(timer)
    }
  }, [job.jobId, pollMs, now])

  // Success that carries a change set: hand it to the review and close, once.
  useEffect(() => {
    if (handed.current || !view || view.status !== 'succeeded') return
    const rp = view.result?.reviewProposal
    if (isObj(rp) && typeof rp.changeSetId === 'string') {
      handed.current = true
      onReviewProposal(rp.changeSetId)
      onClose()
    }
  }, [view, onReviewProposal, onClose])

  // A refused or failed cancel is said under the progress, which keeps polling: the job runs on.
  const cancel = useCallback(async () => {
    setCancelError(null)
    try {
      const cancelled = await fetchJson<JobView>(
        `/api/plugins/jobs/${encodeURIComponent(job.jobId)}/cancel`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        'The job could not be cancelled',
      )
      done.current = true
      setView(cancelled)
    } catch (e) {
      setCancelError(`${failureText(e, 'The job could not be cancelled')}; it may still be running.`)
    }
  }, [job.jobId])

  const retry = useCallback(async () => {
    if (!gate || !onRetry || !view?.error) return
    const code = view.error.code as FeatureModelCode
    const model = await gate.ensureFeatureModel(pluginFeatureId(job.pluginId), {
      force: true,
      label: job.displayName,
      message: featureModelMessage(code),
    })
    if (model) {
      onClose()
      onRetry()
    }
  }, [gate, onRetry, view, job.pluginId, job.displayName, onClose])

  const canRetry = view?.status === 'failed' && !!gate && !!onRetry && GATE_CODES.has(view.error?.code ?? '')
  const timedOut = view?.status === 'failed' && view.error?.code === 'timeout'
  const reportRefused = view?.status === 'failed' && !!view.error?.code?.startsWith(REPORT_REFUSED)

  // A plugin may report a "Stage" field like "1 of 3"; show it as step dots. Any other
  // shape just leaves the dots out, so this never depends on a plugin's exact wording.
  const stage = (() => {
    const raw = view?.progress?.fields?.Stage ?? view?.progress?.fields?.stage
    const m = typeof raw === 'string' ? /^\s*(\d+)\s+of\s+(\d+)\s*$/i.exec(raw) : null
    if (!m) return null
    const current = Number(m[1])
    const total = Number(m[2])
    return total >= 1 && total <= 12 && current >= 1 && current <= total ? { current, total } : null
  })()

  const footer =
    terminal || fatal ? (
      <div className={styles.jobButtons}>
        {canRetry && (
          <button type="button" className="primaryButton" onClick={() => void retry()}>
            Choose a model and retry
          </button>
        )}
        <button type="button" className="secondaryButton" onClick={onClose}>
          Close
        </button>
      </div>
    ) : (
      <div className={styles.jobButtons}>
        <button type="button" className="secondaryButton" onClick={() => void cancel()}>
          Cancel
        </button>
      </div>
    )

  return (
    <Modal isOpen onClose={onClose} title={job.label} footer={footer} closeOnOverlayClick={false}>
      <div className={styles.jobBody}>
        <PluginBadge label={job.displayName} />
        {job.skillName !== undefined && (
          <div className={styles.jobSkill} data-testid="job-skill">Skill: {job.skillName ?? 'a deleted skill'}</div>
        )}

        {!terminal && !fatal && (
          <>
            <div className={styles.jobStatus}>
              <Loader2 size={14} className={styles.spin} aria-hidden />
              {view?.progress?.message ?? 'Working…'}
            </div>
            <div className={styles.jobProgressTrack} role="progressbar" aria-label="Working">
              <div className={styles.jobProgressBar} aria-hidden />
            </div>
            {stage && (
              <div className={styles.jobSteps} aria-hidden>
                {Array.from({ length: stage.total }, (_, i) => (
                  <span
                    key={i}
                    className={`${styles.jobStep} ${
                      i + 1 < stage.current ? styles.jobStepOn : i + 1 === stage.current ? styles.jobStepActive : ''
                    }`}
                  />
                ))}
              </div>
            )}
            {view?.progress?.fields && Object.keys(view.progress.fields).length > 0 && (
              <dl className={styles.jobFields}>
                {Object.entries(view.progress.fields).map(([k, v]) => (
                  <div key={k} className={styles.jobField}>
                    <dt>{k}</dt>
                    <dd>{v}</dd>
                  </div>
                ))}
              </dl>
            )}
            {view && (
              <div className={styles.jobElapsed}>
                Elapsed <span>{elapsed(view.createdAt, nowMs)}</span>
              </div>
            )}
            {cancelError && <div className={styles.jobError} role="alert">{cancelError}</div>}
          </>
        )}

        {fatal && <div className={styles.jobError} role="alert">{fatal}</div>}

        {terminal && !fatal && view && (
          <div className={view.status === 'succeeded' ? styles.jobDone : styles.jobError} role={view.status === 'succeeded' ? 'status' : 'alert'}>
            {view.status === 'succeeded' && (typeof view.result?.message === 'string' ? view.result.message : 'Finished.')}
            {view.status === 'cancelled' && 'Cancelled.'}
            {view.status === 'failed' && (
              <>
                {timedOut && <div className={styles.jobLabel}>The action timed out.</div>}
                {reportRefused && <div className={styles.jobLabel}>The plugin&apos;s result was refused.</div>}
                {view.error?.message ?? 'The action failed.'}
                {view.error?.code && <span className={styles.jobCode} data-testid="job-error-code">{view.error.code}</span>}
              </>
            )}
          </div>
        )}
      </div>
    </Modal>
  )
}
