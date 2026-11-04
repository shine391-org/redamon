'use client'

import { useCallback, useEffect, useState } from 'react'
import { readApiError, toApiError } from '@/lib/apiError'

export type SupplyChainSource = 'upload' | 'github' | 'org'

export interface SupplyChainConfig {
  source: SupplyChainSource
  sbomFile: string
  repoUrl: string
  repoRef: string
  org: string
}

export interface SupplyChainConfigState extends SupplyChainConfig {
  loading: boolean
  /** Why the saved input could not be read; "not configured" would then be a false answer. */
  error: string | null
  /** The SELECTED source has a usable value. A configured repository must not
   *  make Start clickable while the upload source is the one selected. */
  ready: boolean
  /** One line naming what a run would actually read, for the card. */
  target: string
  reload: () => void
}

const EMPTY: SupplyChainConfig = {
  source: 'upload', sbomFile: '', repoUrl: '', repoRef: '', org: '',
}

function readySource(c: SupplyChainConfig): boolean {
  if (c.source === 'github') return c.repoUrl.trim() !== ''
  if (c.source === 'org') return c.org.trim() !== ''
  return c.sbomFile.trim() !== ''
}

function describe(c: SupplyChainConfig): string {
  if (c.source === 'github') {
    return c.repoUrl ? `${c.repoUrl}${c.repoRef ? ` @ ${c.repoRef}` : ''}` : ''
  }
  if (c.source === 'org') return c.org
  return c.sbomFile
}

/**
 * The Supply-Chain scan's configured input, read for the Other Scans card.
 *
 * The card owns the run controls only; WHAT is scanned is configured in project
 * settings (Other Scans -> Supply Chain Scanner), exactly like the Secret
 * Multiscanner's sources. So the card has to read the saved project to know
 * whether Start can be enabled at all.
 *
 * `enabled` is the modal's open state: the settings can be changed in another
 * tab and this must not serve a value cached from a previous opening.
 */
export function useSupplyChainConfig(
  projectId: string | undefined,
  enabled: boolean,
): SupplyChainConfigState {
  const [config, setConfig] = useState<SupplyChainConfig>(EMPTY)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!projectId || !enabled) return
    setLoading(true)
    try {
      const res = await fetch(`/api/projects/${projectId}`)
      if (!res.ok) throw await readApiError(res, 'Could not read the scan input')
      const p = await res.json()
      const raw = String(p.supplyChainInputMode ?? 'upload')
      setConfig({
        source: raw === 'github' || raw === 'org' ? raw : 'upload',
        sbomFile: String(p.supplyChainSbomFile ?? ''),
        repoUrl: String(p.supplyChainRepoUrl ?? ''),
        repoRef: String(p.supplyChainRepoRef ?? ''),
        org: String(p.supplyChainOrgName ?? ''),
      })
      setError(null)
    } catch (err) {
      // A failed read must not break the modal: Start stays disabled (the safe
      // answer), and the card says the read failed rather than "not configured".
      setError(toApiError(err, 'Could not read the scan input').message)
    } finally {
      setLoading(false)
    }
  }, [projectId, enabled])

  useEffect(() => { void load() }, [load])

  return {
    ...config,
    loading,
    error,
    ready: readySource(config),
    target: describe(config),
    reload: () => { void load() },
  }
}
