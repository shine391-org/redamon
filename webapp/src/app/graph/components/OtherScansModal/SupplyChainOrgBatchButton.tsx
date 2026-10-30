'use client'

import { useState } from 'react'
import { Loader2, PackageSearch } from 'lucide-react'
import { useToast } from '@/components/ui'
import { useAlertModal } from '@/components/ui/AlertModal/AlertModal'
import { GITHUB_DOT_COM } from '@/lib/github/ownerTarget'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './OtherScansModal.module.css'

interface Props {
  projectId: string
  /** The account configured in project settings. Empty = nothing to queue. */
  org: string
  disabled?: boolean
  /** Shown as the button title when the caller blocks it (past version, ...). */
  blockedReason?: string
}

/**
 * Queues one supply-chain scan per repository in the configured account.
 *
 * It replaces Start in the card while the org mode is selected: Start runs the
 * project's single input, and there is none in this mode, so a Start button here
 * could never be enabled. The account itself is configured in project settings;
 * this only acts on it.
 *
 * Its own component because it needs the toast and alert providers, and the
 * modal around it must stay usable without them.
 */
export function SupplyChainOrgBatchButton({ projectId, org, disabled, blockedReason }: Props) {
  const [busy, setBusy] = useState(false)
  const toast = useToast()
  const { alertError } = useAlertModal()

  const target = org.trim()

  const launch = async () => {
    if (!target || busy) return
    setBusy(true)
    try {
      const res = await fetch(`/api/projects/${projectId}/supply-chain-batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ org: target }),
      })
      if (!res.ok) {
        await alertError((await readApiError(res, 'Could not start the org batch.')).message, 'Supply-chain org batch')
        return
      }
      const data = await res.json().catch(() => ({}))
      toast.success(
        `Queued ${data.totalItems} repo scan${data.totalItems === 1 ? '' : 's'} for ` +
        `${data.org || target} on ${data.host || GITHUB_DOT_COM}. ` +
        'They run as capacity frees up - follow them in Scans -> Scan queue.'
      )
    } catch (err) {
      await alertError(toApiError(err, 'Could not start the org batch.').message, 'Supply-chain org batch')
    } finally {
      setBusy(false)
    }
  }

  return (
    <button
      className={styles.startButton}
      onClick={() => void launch()}
      disabled={!target || busy || disabled}
      title={blockedReason || (!target
        ? 'Set the organization to enumerate in project settings first'
        : 'Queue one scan per repository')}
    >
      {busy ? <Loader2 size={12} className={styles.spinner} /> : <PackageSearch size={12} />}
      <span>{busy ? 'Queuing...' : 'Queue org batch'}</span>
    </button>
  )
}

export default SupplyChainOrgBatchButton
