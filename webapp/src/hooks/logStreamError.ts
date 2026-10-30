import { formatApiError, readApiError, toApiError } from '@/lib/apiError'

/**
 * Shown for a scan log stream's own `error` event. Its payload is the
 * orchestrator's raw exception text (Docker API errors naming containers and
 * hosts), so it goes to the console and the screen gets this fixed line.
 */
export const LOG_STREAM_EVENT_ERROR = 'The log stream reported an error (details in the browser console and the orchestrator log)'

export const LOG_STREAM_LOST = 'Connection lost. Max reconnection attempts reached.'

/**
 * Why a log stream could not be reopened. EventSource never exposes the HTTP
 * status of a failed connect, so after the last reconnect fails one plain GET
 * asks the route itself: a 503 `orchestrator_unreachable` or a 404 "no scan"
 * then reads differently from a dropped connection. A stream that opens fine
 * now is cancelled at once: the route works, so the stream itself kept dropping.
 */
export async function describeLogStreamLoss(url: string, fallback: string): Promise<string> {
  const ctrl = new AbortController()
  try {
    const res = await fetch(url, { headers: { Accept: 'text/event-stream' }, signal: ctrl.signal })
    if (!res.ok) return (await readApiError(res, fallback)).message
    return formatApiError({ reason: LOG_STREAM_LOST, code: 'stream_interrupted', status: 0 })
  } catch (err) {
    return toApiError(err, fallback).message
  } finally {
    ctrl.abort()
  }
}
