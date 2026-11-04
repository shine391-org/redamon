import { useState, useEffect, useCallback } from 'react'
import { useUserSkillsChanged } from '@/lib/userSkillsChannel'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'

interface SkillData {
  builtIn: { id: string; name: string }[]
  user: { id: string; name: string }[]
  config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
}

/**
 * The skills and this project's toggles for the chat drawer's tooltip. Refetched when a
 * skill version is saved anywhere in the browser, and on demand (`refetch`). A failed read
 * keeps the data it had and sets `error`.
 */
export function useAttackSkillData(userId: string, projectId: string) {
  const [skillData, setSkillData] = useState<SkillData | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [generation, setGeneration] = useState(0)
  const refetch = useCallback(() => setGeneration(g => g + 1), [])

  useEffect(() => {
    if (!userId || !projectId) return
    let cancelled = false
    async function fetchSkills() {
      try {
        const [availRes, projRes] = await Promise.all([
          fetch(`/api/users/${userId}/attack-skills/available`),
          fetch(`/api/projects/${projectId}`),
        ])
        if (cancelled) return
        if (!availRes.ok) throw await readApiError(availRes, 'Failed to load the attack skills')
        if (!projRes.ok) throw await readApiError(projRes, 'Failed to load the project skill toggles')
        const avail = await availRes.json()
        const proj = await projRes.json()
        const cfg = proj.attackSkillConfig || { builtIn: {}, user: {} }
        setSkillData({
          builtIn: avail.builtIn,
          user: avail.user,
          config: {
            builtIn: cfg.builtIn || {},
            user: cfg.user || {},
          },
        })
        setError(null)
      } catch (err) {
        if (cancelled) return
        const failure = toApiError(err, 'Failed to load the attack skills')
        console.warn('Attack skill data for the chat drawer:', failure.message)
        setError(failure)
      }
    }
    fetchSkills()
    return () => { cancelled = true }
  }, [userId, projectId, generation])

  useUserSkillsChanged(change => {
    if (!change.projectId || change.projectId === projectId) refetch()
  })

  return { skillData, refetch, error }
}
