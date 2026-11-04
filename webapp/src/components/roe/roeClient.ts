'use client'

/**
 * The browser side of the RoE routes: confirm a review, re-diff it, download a
 * document. Every function answers with a value rather than throwing, so the
 * review can show each failure where it happened.
 */
import { featureModelMessage, readFeatureModelCode } from '@/lib/llmFeatures'
import { formatApiError } from '@/lib/apiError'

export interface RoeApiError {
  status: number
  code?: string
  error: string
  keys?: string[]
  busy?: string
}

export async function readRoeError(res: Response): Promise<RoeApiError> {
  const body = await res.json().catch(() => ({})) as Record<string, unknown>
  const code = readFeatureModelCode(body)
  const bodyCode = typeof body.code === 'string' ? body.code : code ?? undefined
  const message = code
    ? featureModelMessage(code, typeof body.model === 'string' ? body.model : undefined)
    : typeof body.error === 'string' && body.error
      ? body.error
      : `The request failed (${res.status}).`
  return {
    status: res.status,
    code: bodyCode,
    // A refusal's own sentence names its cause; a server failure's fixed sentence
    // does not, so it carries the code (P2028, ENOSPC) and the status.
    error: !code && res.status >= 500 ? formatApiError({ reason: message, code: bodyCode, status: res.status }) : message,
    keys: Array.isArray(body.keys) ? body.keys.filter((k): k is string => typeof k === 'string') : undefined,
    busy: typeof body.busy === 'string' ? body.busy : undefined,
  }
}

export type RoeResult<T> = { ok: true; value: T } | { ok: false; error: RoeApiError }

async function settle<T>(request: () => Promise<Response>): Promise<RoeResult<T>> {
  try {
    const res = await request()
    if (!res.ok) return { ok: false, error: await readRoeError(res) }
    return { ok: true, value: await res.json() as T }
  } catch {
    return { ok: false, error: { status: 0, error: 'The server could not be reached. Check your connection and retry.' } }
  }
}

export interface ConfirmArgs {
  projectId: string
  review: Record<string, unknown>
  file: File | null
}

/** The confirmed set: every row's key and the value it writes. */
export function confirmedChanges(review: Record<string, unknown>): Record<string, unknown> {
  const rows = Array.isArray(review.changes) ? review.changes as Array<{ key: string; after: unknown }> : []
  return Object.fromEntries(rows.map(r => [r.key, r.after]))
}

/** Apply a replace (multipart, with the file) or a remove (JSON) review. */
export function confirmRoe({ projectId, review, file }: ConfirmArgs): Promise<RoeResult<Record<string, unknown>>> {
  const changes = confirmedChanges(review)
  if (review.mode === 'remove') {
    return settle(() => fetch(`/api/projects/${projectId}/roe`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rowVersion: review.rowVersion, changes }),
    }))
  }
  return settle(() => {
    const form = new FormData()
    if (file) form.append('file', file)
    form.append('changes', JSON.stringify(changes))
    form.append('parsedFields', JSON.stringify(review.parsedFields ?? {}))
    form.append('rowVersion', String(review.rowVersion ?? ''))
    form.append('bytesSha256', String(review.bytesSha256 ?? ''))
    if (typeof review.modelUsed === 'string') form.append('modelUsed', review.modelUsed)
    if (Array.isArray(review.unknownKeys)) form.append('unknownKeys', JSON.stringify(review.unknownKeys))
    return fetch(`/api/projects/${projectId}/roe`, { method: 'POST', body: form })
  })
}

/** Rebuild a review against the project as it is now; no document, no model. */
export function rediffRoe(projectId: string, review: Record<string, unknown>): Promise<RoeResult<Record<string, unknown>>> {
  return settle(() => fetch('/api/roe/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(review.mode === 'remove'
      ? { projectId, remove: true }
      : { projectId, parsedFields: review.parsedFields ?? {}, bytesSha256: review.bytesSha256 }),
  }))
}

/** Start reviewing a Remove: a re-diff of an empty document. */
export function reviewRemove(projectId: string): Promise<RoeResult<Record<string, unknown>>> {
  return rediffRoe(projectId, { mode: 'remove' })
}

/**
 * Download through fetch, so a 404 or a 403 shows as a message on the page
 * instead of a JSON body in a new tab. Returns null on success, or the error.
 */
export async function downloadRoeFile(url: string, fallbackName: string): Promise<string | null> {
  try {
    const res = await fetch(url)
    if (!res.ok) return (await readRoeError(res)).error
    const blob = await res.blob()
    const disposition = res.headers.get('content-disposition') || ''
    const utf8 = /filename\*=UTF-8''([^;]+)/i.exec(disposition)
    const plain = /filename="([^"]+)"/i.exec(disposition)
    const name = utf8 ? decodeURIComponent(utf8[1]) : plain ? plain[1] : fallbackName
    const href = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = href
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(href), 1000)
    return null
  } catch {
    return 'The download failed. Check your connection and retry.'
  }
}

/** Which provider a model id is sent to, for the review's "your document went to" line. */
export function providerOfModel(model: string | null | undefined): string {
  if (!model) return 'the configured provider'
  const slash = model.indexOf('/')
  if (slash > 0) {
    const prefix = model.slice(0, slash)
    return prefix === 'custom' ? 'your custom provider' : prefix
  }
  const m = model.toLowerCase()
  if (m.startsWith('claude')) return 'anthropic'
  if (m.startsWith('gpt') || /^o\d/.test(m)) return 'openai'
  if (m.startsWith('gemini')) return 'google'
  return 'the configured provider'
}
