'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { fetchJson, readApiError, toApiError } from '@/lib/apiError'
import type { PluginsPage } from '@/lib/plugins/pageModel'

const TRANSIENT = new Set(['installing', 'updating', 'uninstalling'])

/** GET /api/plugins: the Plugins page model; polled while an operation runs. */
export function usePluginsPage() {
  return useQuery<PluginsPage>({
    queryKey: ['plugins', 'page'],
    queryFn: () => fetchJson<PluginsPage>('/api/plugins', { cache: 'no-store' }, 'The Plugins page could not be loaded'),
    refetchInterval: (q) => (q.state.data?.plugins.some((p) => TRANSIENT.has(p.state)) ? 3_000 : false),
  })
}

/**
 * A lifecycle call that failed. The message is "reason (code · HTTP n)"; status 0 means no
 * answer at all; `body` keeps the answer's other fields (`committed`).
 */
export class PluginApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly status: number,
    readonly details?: string[],
    readonly body?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'PluginApiError'
  }
}

async function answer(res: Response): Promise<unknown> {
  if (!res.ok) {
    const err = await readApiError(res, 'The plugin operation failed')
    throw new PluginApiError(err.message, err.code ?? 'error', res.status, err.details, err.body)
  }
  return res.json().catch(() => null)
}

async function send(path: string, init: RequestInit): Promise<unknown> {
  let res: Response
  try {
    res = await fetch(path, init)
  } catch (e) {
    const err = toApiError(e, 'The plugin operation got no answer')
    throw new PluginApiError(err.message, err.code ?? 'network_error', 0)
  }
  return answer(res)
}

export async function pluginPost(path: string, body: unknown): Promise<unknown> {
  return send(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
}

export async function pluginUpload(path: string, form: FormData): Promise<unknown> {
  return send(path, { method: 'POST', body: form })
}

/** A lifecycle call; the page model is reloaded whatever the outcome. */
export function usePluginAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (a: { path: string; body?: unknown; form?: FormData }) =>
      a.form ? pluginUpload(a.path, a.form) : pluginPost(a.path, a.body ?? {}),
    onSettled: () => qc.invalidateQueries({ queryKey: ['plugins'] }),
  })
}
