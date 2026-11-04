'use client'

/**
 * Shared handling of a failed scan start across all seven start sites (Scan Queue
 * plan Phase 3). A PERMANENT failure falls back to today's single-button error
 * modal. A TEMPORARY one (RAM/hard limit, activation in progress, or any 409)
 * offers Cancel / Add to queue; on "Add to queue" it POSTs the project-scoped
 * enqueue route, so queueing is always the operator's explicit choice (R3).
 *
 * An ai_attack launch that carries an inline api_key is never queueable (the key
 * must not be stored), so it gets Cancel only with an explanation.
 */
import { useCallback } from 'react'
import { useAlertModal } from '@/components/ui/AlertModal/AlertModal'
import { classifyStartFailure } from '@/lib/scanStartOutcome'
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'
import type { ScanStartError } from '@/lib/scanStartError'

export type StartFailureOutcome = 'queued' | 'cancelled' | 'shown'

function temporaryTitle(code: string): string {
  switch (code) {
    case 'ram': return 'Not enough memory'
    case 'hard': return 'Scan limit reached'
    case 'activating': return 'Graph is activating'
    default: return 'Project is busy'
  }
}

function permanentTitle(err: ScanStartError | null | undefined): string {
  return err?.limit?.limitType === 'hard' ? 'Scan limit reached' : 'Could not start scan'
}

export function useScanStartFailure(projectId: string | null) {
  const { confirm, alertError, alert } = useAlertModal()

  const handleStartFailure = useCallback(
    async (
      kind: string,
      err: ScanStartError | null | undefined,
      payload: Record<string, unknown> = {},
    ): Promise<StartFailureOutcome> => {
      const message = err?.message || 'The scan could not be started.'
      const cls = classifyStartFailure(err?.status, { error: message, limit: err?.limit, code: err?.code })

      // Permanent: no point queueing. The code and status say why, for a bug report.
      if (!cls.temporary) {
        const why = formatApiError({ reason: message, code: err?.code, status: err?.status ?? 0, upstreamStatus: err?.upstreamStatus })
        await alertError(why, permanentTitle(err))
        return 'shown'
      }

      // An inline API key must not be persisted in a queue row -> Cancel only.
      const apiKey = payload?.api_key
      if (kind === 'ai_attack' && typeof apiKey === 'string' && apiKey.trim() !== '') {
        await alertError(
          `${message}\n\nThis AI scan uses an inline API key, so it cannot be queued. Cancel and retry once memory frees.`,
          'Cannot queue this scan',
        )
        return 'shown'
      }

      const wantsQueue = await confirm(
        <span>
          {message}
          <br />
          <br />
          Add it to the queue and it will start automatically when resources free up.
        </span>,
        temporaryTitle(cls.blockedCode),
        { confirmLabel: 'Add to queue', cancelLabel: 'Cancel' },
      )
      if (!wantsQueue) return 'cancelled'

      if (!projectId) {
        await alertError('No project selected.')
        return 'shown'
      }

      try {
        const res = await fetch(`/api/projects/${projectId}/queue`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ kind, payload }),
        })
        if (!res.ok) {
          await alertError((await readApiError(res, 'Could not add this scan to the queue.')).message)
          return 'shown'
        }
        await alert('Added to the scan queue. It will start automatically when resources free up.', 'Queued')
        return 'queued'
      } catch (e) {
        await alertError(toApiError(e, 'Could not add this scan to the queue.').message)
        return 'shown'
      }
    },
    [confirm, alertError, alert, projectId],
  )

  return { handleStartFailure }
}

export default useScanStartFailure
