/**
 * Failure text shared by the two surfaces that carry the scan buttons (the graph
 * toolbar and the project form's scan cluster), so both say the same thing about
 * why a button is off or a scan went wrong.
 */
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'

export const GVM_NOT_INSTALLED = 'GVM is not installed. Run ./redamon.sh install --gvm to enable vulnerability scanning'

export interface GvmAvailability {
  available: boolean
  /** The disabled button's tooltip; empty while available. */
  reason: string
}

interface AvailableBody {
  available?: unknown
  reason?: unknown
  cause?: unknown
  upstreamStatus?: unknown
}

/**
 * The tooltip for /api/gvm/available's answer. An orchestrator that did not
 * answer says nothing about GVM, so it must not read as "not installed".
 */
export function describeGvmAvailability(body: AvailableBody | null | undefined): GvmAvailability {
  if (body?.available === true) return { available: true, reason: '' }
  const reason = typeof body?.reason === 'string' ? body.reason : ''
  if (!reason || reason === 'gvm_absent') return { available: false, reason: GVM_NOT_INSTALLED }
  const cause = typeof body?.cause === 'string' ? body.cause : undefined
  const upstreamStatus = typeof body?.upstreamStatus === 'number' ? body.upstreamStatus : undefined
  return {
    available: false,
    reason: formatApiError({
      reason: 'GVM availability unknown: the recon orchestrator did not report it',
      code: cause ? `${reason} · ${cause}` : reason,
      status: 0,
      upstreamStatus,
    }),
  }
}

export async function fetchGvmAvailability(): Promise<GvmAvailability> {
  const fallback = 'GVM availability unknown'
  try {
    const res = await fetch('/api/gvm/available')
    if (!res.ok) return { available: false, reason: (await readApiError(res, fallback)).message }
    return describeGvmAvailability(await res.json())
  } catch (err) {
    return { available: false, reason: toApiError(err, fallback).message }
  }
}

export interface DataProbe {
  has: boolean
  /** Set when the check itself failed, so a 5xx does not read as "no data". */
  error: string | null
}

/** A HEAD against a download route: 200 = data, 404 = none, anything else = unknown. */
export async function probeScanData(url: string): Promise<DataProbe> {
  const reason = 'Could not check for data'
  try {
    const res = await fetch(url, { method: 'HEAD' })
    if (res.ok) return { has: true, error: null }
    if (typeof res.status === 'number' && res.status >= 500) {
      return { has: false, error: formatApiError({ reason, status: res.status }) }
    }
    return { has: false, error: null }
  } catch (err) {
    return { has: false, error: toApiError(err, reason).message }
  }
}

const ACTIVE = new Set(['starting', 'running', 'paused', 'pausing', 'stopping'])

/**
 * The toast for a scan that just ended in `error`, or null when this status
 * change is not one. Only a run seen live first counts: a project opened on a
 * run that failed yesterday must not toast on every visit.
 */
export function scanFailureToast(
  label: string,
  previous: string | null | undefined,
  status: string | null | undefined,
  error: string | null | undefined,
): string | null {
  if (status !== 'error' || !previous || !ACTIVE.has(previous)) return null
  return error ? `${label} failed: ${error}` : `${label} failed`
}

/**
 * Download a scan's JSON through fetch, so a refusal is shown with its reason
 * and status: opened in a new tab, a 404 or 500 was a raw JSON page (or a
 * blank tab) with nothing on the page that asked for it. Resolves to the error
 * text, or null once the file was handed to the browser.
 */
export async function downloadScanFile(url: string, fallbackName: string): Promise<string | null> {
  try {
    const res = await fetch(url)
    if (!res.ok) return (await readApiError(res, 'Download failed')).message
    const blob = await res.blob()
    const disposition = res.headers.get('content-disposition') || ''
    const named = /filename="([^"]+)"/i.exec(disposition)
    const href = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = href
    a.download = named ? named[1] : fallbackName
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(href), 1000)
    return null
  } catch (err) {
    return toApiError(err, 'Download failed').message
  }
}
