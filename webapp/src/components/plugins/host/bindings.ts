import { toApiError } from '@/lib/apiError'
import { PluginActionError } from './actionClient'
import type { Params } from './hostContext'

/**
 * Plugin data shown in a screen is text only: strings, numbers and booleans. Objects and
 * arrays render as nothing rather than as JSON, so a screen never dumps a raw structure.
 */
export function valueText(v: unknown): string {
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return ''
}

export function bindText(binding: { text?: string; field?: string }, data: Params): string {
  if (binding.text !== undefined) return binding.text
  return binding.field ? valueText(data[binding.field]) : ''
}

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function cellText(v: unknown, format?: 'text' | 'date' | 'number'): string {
  if (format === 'number') {
    const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN
    if (Number.isFinite(n)) return n.toLocaleString()
  }
  if (format === 'date' && (typeof v === 'string' || typeof v === 'number')) {
    const d = new Date(v)
    if (!Number.isNaN(d.getTime())) return dateFormat.format(d)
  }
  return valueText(v)
}

/** Only the row fields a row action lists in `pass`. */
export function pick(row: Params, fields: readonly string[]): Params {
  const out: Params = {}
  for (const f of fields) if (f in row) out[f] = row[f]
  return out
}

/** A refusal or failure the plugin platform named is shown as is; anything else by its class only. */
export function errorMessage(e: unknown): string {
  if (e instanceof PluginActionError) return e.message
  return toApiError(e, 'Something went wrong while running the plugin action').message
}

export function resultMessage(result: Params, fallback: string): string {
  return typeof result.message === 'string' && result.message ? result.message : fallback
}

/** A stable key for params objects, so a source reloads when they change, not on every render. */
export function paramsKey(params: Params): string {
  return JSON.stringify(params)
}
