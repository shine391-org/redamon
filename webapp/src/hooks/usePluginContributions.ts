'use client'

import { useQuery } from '@tanstack/react-query'
import { fetchOk } from '@/lib/apiError'
import type { PluginContributions } from '@/lib/plugins/contributions'

/**
 * GET /api/plugins/contributions: the UI every enabled plugin contributes, for the gear menu
 * and the Plugins page. An answer that is not a list resolves to an empty list: the menus it
 * feeds are on core pages and must never break them. A failed read is an ApiError whose
 * message ("Plugin items could not be loaded (code · HTTP n)") the menus show as a small
 * hint with Retry, so the items do not just vanish. Cached 60 s; contributions change only
 * on a lifecycle action, which invalidates the ['plugins'] queries.
 */
export function usePluginContributions() {
  return useQuery<PluginContributions[]>({
    queryKey: ['plugins', 'contributions'],
    queryFn: async () => {
      const res = await fetchOk('/api/plugins/contributions', { cache: 'no-store' }, 'Plugin items could not be loaded')
      const body: unknown = await res.json().catch(() => null)
      return Array.isArray(body) ? body : []
    },
    staleTime: 60_000,
  })
}
