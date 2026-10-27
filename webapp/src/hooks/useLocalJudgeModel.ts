'use client'

import { useEffect, useState } from 'react'

export type LocalJudgeModel =
  | { status: 'loading' }
  | { status: 'ready'; model: string }
  | { status: 'unavailable' }

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
        const d = r.ok ? await r.json() : null
        const model = typeof d?.model === 'string' ? d.model : ''
        if (!cancelled) setState(model ? { status: 'ready', model } : { status: 'unavailable' })
      })
      .catch(() => {
        if (!cancelled) setState({ status: 'unavailable' })
      })
    return () => { cancelled = true }
  }, [projectId])

  return state
}
