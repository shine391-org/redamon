'use client'

import { useEffect, useRef, useState } from 'react'
import { Modal } from '@/components/ui'
import { readApiError } from '@/lib/apiError'
import styles from './ReconDiagnostics.module.css'

type JsonObject = Record<string, unknown>
function object(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null
}

// Defense in depth: artifacts are redacted by the reader, but never render raw
// credentials/headers even if an older or incompatible reader returns them.
const PRIVATE_KEY = /password|secret|credential|authorization|cookie|headers?|api[_-]?key|access[_-]?token|refresh[_-]?token|raw[_-]?(request|response)|auth[_-]?profile/i
function safeText(value: string): string {
  return value.slice(0, 1200)
    .replace(/\b(Bearer|Basic)\s+\S+/gi, '$1 [redacted]')
    .replace(/\b(authorization|cookie|password|token|api[_-]?key)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .replace(/https?:\/\/[^\s<>"']+/gi, raw => {
      try {
        const url = new URL(raw)
        url.username = ''; url.password = ''; url.search = ''; url.hash = ''
        return url.toString()
      } catch { return '[invalid URL]' }
    })
}

export type SafeValue = string | number | boolean | null | SafeValue[] | { [key: string]: SafeValue }
export function boundedDiagnosticValue(value: unknown): SafeValue {
  let remaining = 800
  function visit(v: unknown, depth: number): SafeValue {
    if (--remaining < 0 || depth > 9) return '[truncated]'
    if (v == null) return null
    if (typeof v === 'string') return safeText(v)
    if (typeof v === 'number') return Number.isFinite(v) ? v : null
    if (typeof v === 'boolean') return v
    if (Array.isArray(v)) {
      const out = v.slice(0, 40).map(item => visit(item, depth + 1))
      if (v.length > 40) out.push(`[${v.length - 40} more entries omitted]`)
      return out
    }
    const row = object(v)
    if (!row) return '[unsupported value]'
    const out: Record<string, SafeValue> = {}
    for (const key of Object.keys(row).slice(0, 40)) {
      // Null-prototype input isn't required: React never interprets these as HTML.
      if (PRIVATE_KEY.test(key)) continue
      out[safeText(key)] = visit(row[key], depth + 1)
    }
    if (Object.keys(row).length > 40) out['…'] = 'Additional fields omitted'
    return out
  }
  return visit(value, 0)
}

function label(key: string): string {
  return key.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2')
}

function Values({ value }: { value: SafeValue }) {
  if (value === null) return <span>Unknown / not recorded</span>
  if (Array.isArray(value)) return value.length
    ? <ul>{value.map((item, index) => <li key={index}><Values value={item} /></li>)}</ul>
    : <span>No entries recorded</span>
  if (typeof value === 'object') {
    const entries = Object.entries(value)
    return entries.length ? <dl className={styles.values}>{entries.map(([key, item]) => (
      <div key={key}><dt>{label(key)}</dt><dd><Values value={item} /></dd></div>
    ))}</dl> : <span>No summary fields recorded; coverage unknown</span>
  }
  return <span>{String(value)}</span>
}

async function read(projectId: string, endpoint: string): Promise<JsonObject> {
  const res = await fetch(`/api/recon/${encodeURIComponent(projectId)}/${endpoint}`, { cache: 'no-store' })
  if (!res.ok) throw await readApiError(res, `Could not load ${endpoint}`)
  const row = object(await res.json())
  if (!row) throw new Error(`Invalid ${endpoint} response; coverage unknown`)
  return row
}

function eligibleRun(data: JsonObject | null, history: boolean): string | null {
  const checkpoint = object(data?.checkpoint)
  const continuation = object(checkpoint?.continuation)
  const run = continuation?.run_id ?? data?.run_id
  return !history && data?.status === 'ready' && checkpoint?.scope === 'group6_phase_a'
    && continuation?.supported === true && continuation?.eligible === true
    && typeof run === 'string' && run.length > 0 ? run : null
}

export function ReconDiagnostics({ projectId, historicalView = false }: { projectId: string; historicalView?: boolean }) {
  const [open, setOpen] = useState(false)
  return <>
    <button type="button" className="button buttonSecondary" onClick={() => setOpen(true)}>Recon diagnostics</button>
    {open && <DiagnosticsPanel key={projectId} projectId={projectId} historicalView={historicalView} onClose={() => setOpen(false)} />}
  </>
}

function DiagnosticsPanel({ projectId, historicalView, onClose }: { projectId: string; historicalView: boolean; onClose: () => void }) {
  const [diagnostics, setDiagnostics] = useState<JsonObject | null>(null)
  const [manifest, setManifest] = useState<JsonObject | null>(null)
  const [errors, setErrors] = useState<{ diagnostics?: string; manifest?: string }>({})
  const [loading, setLoading] = useState(true)
  const [refresh, setRefresh] = useState(0)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const submitting = useRef(false)
  const epoch = useRef(0)

  useEffect(() => {
    const current = ++epoch.current
    setLoading(true); setConfirming(false); setDiagnostics(null); setManifest(null); setErrors({})
    const alive = () => epoch.current === current
    void Promise.all([
      read(projectId, 'diagnostics').then(data => { if (alive()) setDiagnostics(data) })
        .catch(error => { if (alive()) setErrors(prev => ({ ...prev, diagnostics: safeText(error instanceof Error ? error.message : 'Diagnostics unavailable') })) }),
      read(projectId, 'plan-manifest').then(data => { if (alive()) setManifest(data) })
        .catch(error => { if (alive()) setErrors(prev => ({ ...prev, manifest: safeText(error instanceof Error ? error.message : 'Manifest unavailable') })) }),
    ]).finally(() => { if (alive()) setLoading(false) })
    return () => { epoch.current++ }
  }, [projectId, refresh])

  const run = eligibleRun(diagnostics, historicalView)
  const checkpoint = object(diagnostics?.checkpoint)
  const continuation = object(checkpoint?.continuation)
  const manifestRun = object(manifest?.manifest)?.run_id ?? manifest?.run_id
  const diagnosticRun = diagnostics?.run_id
  const sameRun = typeof manifestRun === 'string' && typeof diagnosticRun === 'string' && manifestRun === diagnosticRun

  async function continueWork() {
    if (!run || submitting.current || loading) return
    submitting.current = true
    setBusy(true); setMessage(''); setConfirming(false)
    try {
      // Eligibility can change while the dialog is open. Recheck, then let the
      // backend enforce revision, scope, RoE/window, authorization and mutex.
      const fresh = await read(projectId, 'diagnostics')
      setDiagnostics(fresh)
      if (eligibleRun(fresh, historicalView) !== run || fresh.group_id !== diagnostics?.group_id) {
        setMessage('Continuation refused: eligibility or run/group changed. Review refreshed diagnostics.')
        return
      }
      const res = await fetch(`/api/recon/${encodeURIComponent(projectId)}/continue`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ run_id: run, confirm: true }),
      })
      if (!res.ok) throw await readApiError(res, 'Continuation refused')
      const response = object(await res.json())
      if (response?.status === 'refused' || response?.eligible === false || response?.error) {
        setMessage(`Continuation refused: ${safeText(String(response.reason ?? response.error ?? 'backend refusal'))}`)
      } else {
        setMessage('Continuation request accepted by the backend. Refresh diagnostics to check durable progress; this is not a guarantee of completion.')
      }
      setRefresh(n => n + 1)
    } catch (error) {
      setMessage(safeText(error instanceof Error ? error.message : 'Continuation unavailable'))
      // A failed request may have reached the server. Never retry it automatically.
      setDiagnostics(null)
    } finally { submitting.current = false; setBusy(false) }
  }

  return <Modal isOpen onClose={onClose} title="Recon diagnostics" size="xlarge">
    <div className={styles.panel}>
      <p>Read-only run artifacts. Missing evidence is unknown, not zero or a clean scan. Summaries and lists are bounded; omitted entries do not imply complete coverage.</p>
      <p>{historicalView
        ? 'You are viewing a historical graph. These APIs describe the latest recorded run, not necessarily that graph version. Continuation is disabled here.'
        : 'Latest recorded run artifacts; they may be historical. They are not proof that the displayed graph was fully scanned.'}</p>
      <button type="button" className="button buttonSecondary" disabled={loading || busy} onClick={() => setRefresh(n => n + 1)}>Refresh diagnostics</button>
      {loading && <p role="status">Loading diagnostics…</p>}
      {errors.diagnostics && <p role="alert">{errors.diagnostics}</p>}
      {errors.manifest && <p role="alert">{errors.manifest}</p>}
      <section aria-label="Run context"><h3>Run context</h3>
        <Values value={boundedDiagnosticValue(diagnostics ? {
          status: diagnostics.status, reason: diagnostics.reason, run_id: diagnostics.run_id,
          group_id: diagnostics.group_id, is_history: diagnostics.is_history,
          run_mode: diagnostics.run_mode, run_reason: diagnostics.run_reason,
          coverage_summary: diagnostics.coverage_summary,
        } : null)} />
      </section>
      <section aria-label="Discovery inventory"><h3>Discovery inventory & provenance</h3>
        <p>Declared sources are not observed responses; unknown validation is not dead. Counts reflect only recorded inventory.</p>
        <Values value={boundedDiagnosticValue(diagnostics?.inventory)} />
      </section>
      <section aria-label="Selection coverage"><h3>Selection coverage & reasons</h3>
        <p>Planned, compatibility, deferred, rejected and not-applicable dispositions are distinct. A subset selection does not clear findings outside that subset.</p>
        <Values value={boundedDiagnosticValue(diagnostics?.selection)} />
      </section>
      <section aria-label="Checkpoint and backlog"><h3>Group 6 Phase A checkpoint, budgets & backlog</h3>
        <p>Tool/group chunks only—not HTTP requests or arbitrary pipeline resume. A budget of 0 is unbounded. Missing budget data is unknown.</p>
        <Values value={boundedDiagnosticValue(checkpoint)} />
        <p>Continuation: {run ? 'Backend eligible; manual confirmation required.' : safeText(String(continuation?.reason ?? 'Unavailable, unsupported, historical view, or eligibility unknown.'))}</p>
        <button type="button" className="button buttonSecondary" disabled={!run || loading || busy}
          onClick={() => setConfirming(true)}>Continue deferred Group 6 Phase A work</button>
        {confirming && run && <div role="group" aria-label="Confirm continuation" className={styles.confirm}>
          <p>Continue deferred chunks for run <strong>{safeText(run)}</strong> using the original output and graph? This sends a start request. The backend must revalidate the same run/revision, scope, authorization, RoE window and mutex. No other phase will be resumed.</p>
          <button type="button" className="button buttonPrimary" disabled={busy} onClick={() => void continueWork()}>Confirm continuation</button>
          <button type="button" className="button buttonSecondary" onClick={() => setConfirming(false)}>Cancel continuation</button>
        </div>}
        {busy && <p role="status">Requesting continuation…</p>}
        {message && <p role="status">{message}</p>}
      </section>
      <section aria-label="Plan manifest"><h3>Run-scoped plan manifest</h3>
        <p>The manifest API reads the latest persisted job pointer independently of diagnostics. {sameRun ? 'Run IDs match.' : 'Run correlation unknown or different; do not combine these counts.'}</p>
        <Values value={boundedDiagnosticValue(manifest)} />
      </section>
    </div>
  </Modal>
}
