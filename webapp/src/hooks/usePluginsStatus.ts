'use client'

import { useQuery } from '@tanstack/react-query'
import { fetchJson } from '@/lib/apiError'

export interface PluginsStatus {
  platformVersion: string
  runner: {
    reachable: boolean
    platformVersion?: string
    state?: string
    workers?: number
    error?: string
    /** Not reached: not_configured, unreachable, timeout or bad_response. */
    reason?: string
    /** The plugin-gateway proxy's code when it answered for the runner. */
    proxyCode?: string
    /** The runner's HTTP status when it answered with an error. */
    upstreamStatus?: number
  }
}

/** GET /api/plugins/status: this webapp's platform version and what the plugin runner reports. */
export function usePluginsStatus() {
  return useQuery<PluginsStatus>({
    queryKey: ['plugins', 'status'],
    queryFn: () => fetchJson<PluginsStatus>('/api/plugins/status', { cache: 'no-store' }, 'Runner status unknown'),
    refetchInterval: 30_000,
  })
}
