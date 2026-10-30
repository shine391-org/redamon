'use client'

import { AlertCircle } from 'lucide-react'
import { errorMessage } from '@/lib/apiError'
import styles from './QueryErrors.module.css'

export interface InsightsQueryState {
  label: string
  isError: boolean
  error: unknown
}

/**
 * Names every Insights query that failed, with its reason, code and status.
 * Without it a Neo4j outage drew the same "No data available" cards and zero KPIs
 * as a project that was never scanned.
 */
export function QueryErrors({ queries }: { queries: InsightsQueryState[] }) {
  const failed = queries.filter(q => q.isError)
  if (failed.length === 0) return null
  return (
    <div className={styles.banner} role="alert">
      <div className={styles.title}>
        <AlertCircle size={14} />
        Some Insights data could not be loaded; the cards that depend on it show no data.
      </div>
      <ul className={styles.list}>
        {failed.map(q => (
          <li key={q.label} className={styles.item}>
            {q.label}: {errorMessage(q.error, 'the request failed')}
          </li>
        ))}
      </ul>
    </div>
  )
}
