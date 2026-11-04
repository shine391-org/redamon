'use client'

import { useEffect, useState } from 'react'
import { readApiError, toApiError } from '@/lib/apiError'

export type LocalJudgeModel =
  | { status: 'loading' }
  | { status: 'ready'; model: string }
  /**
   * `reason` is the route's code: `no_model` (the orchestrator answered without
   * one), `orchestrator_error` (it answered non-OK), `orchestrator_unreachable` /
   * `orchestrator_timeout` (no answer), or `network_error` (the webapp did not
   * answer). `error` is the formatted cause, with the code and HTTP statuses.
   */
  | { status: 'unavailable'; reason?: string; error?: string }

const UNAVAILABLE = 'The local judge model is unavailable'

/**
 * The AI attack-surface judge model the backend runs (the orchestrator's
 * LOCAL_LLM_MODEL). There is no client-side fallback: a model the orchestrator
 * does not check would be pulled and used without its status ever matching.
 */
export function useLocalJudgeModel(projectId: string | null): LocalJudgeModel {
  const [state, setState] = useState<LocalJudgeModel>({ status: 'loading' })

  useEffect(() => {
    if (!projectId) return
    let cancelled = false
    fetch(`/api/ai-attack-surface/${projectId}/judge-model`, { cache: 'no-store' })
      .then(async (r) => {
        if (!r.ok) {
          const e = await readApiError(r, UNAVAILABLE)
          if (!cancelled) setState({ status: 'unavailable', reason: e.code, error: e.message })
          return
        }
        const d = await r.json().catch(() => null)
        const model = typeof d?.model === 'string' ? d.model : ''
        if (!cancelled) setState(model ? { status: 'ready', model } : { status: 'unavailable', reason: 'no_model' })
      })
      .catch((err) => {
        const e = toApiError(err, UNAVAILABLE)
        if (!cancelled) setState({ status: 'unavailable', reason: e.code, error: e.message })
      })
    return () => { cancelled = true }
  }, [projectId])

  return state
}
