'use client'

import { useCallback, useEffect, useState } from 'react'
import type { RedZoneTableResponse, RedZoneTableSlug } from './types'
import { useMuteNodeContext } from '../MuteNode'
import { readApiError, toApiError } from '@/lib/apiError'

export function useRedZoneTable<T>(slug: RedZoneTableSlug, projectId: string | null) {
  const [data, setData] = useState<RedZoneTableResponse<T> | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    if (!projectId) {
      setData(null)
      return
    }
    setIsLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/analytics/redzone/${slug}?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) throw await readApiError(res, 'Failed to load')
      const json = (await res.json()) as RedZoneTableResponse<T>
      setData(json)
    } catch (e) {
      setError(toApiError(e, 'Failed to load').message)
    } finally {
      setIsLoading(false)
    }
  }, [slug, projectId])

  // Every route filters muted nodes out, so refetching on a mute (from this
  // table, another one or the node drawer) is what drops the muted row.
  const { epoch: muteEpoch } = useMuteNodeContext()
  useEffect(() => {
    fetchData()
  }, [fetchData, muteEpoch])

  return { data, isLoading, error, refetch: fetchData }
}
