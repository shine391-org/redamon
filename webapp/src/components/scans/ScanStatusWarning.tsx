'use client'

import { AlertTriangle } from 'lucide-react'
import styles from '@/app/graph/components/GraphToolbar/GraphToolbar.module.css'

/**
 * Says that a scan's status could not be read, next to buttons that still show
 * the last known state. Without it an unreachable orchestrator looked like every
 * scan had quietly finished.
 */
export function ScanStatusWarning({ errors = [] }: { errors?: Array<string | null | undefined> }) {
  const shown = errors.filter((e): e is string => !!e)
  if (shown.length === 0) return null
  return (
    <span className={styles.statusWarning} role="status" title={shown.join('\n')}>
      <AlertTriangle size={12} />
      <span>Status unavailable</span>
    </span>
  )
}
