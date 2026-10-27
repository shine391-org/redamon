'use client'

import {
  DISPOSITION_LABELS, DISPOSITION_MEANINGS, topBlockers, type DispositionSummary,
} from '@/lib/triage/disposition'
import { ChartCard } from './ChartCard'
import styles from './DispositionBreakdown.module.css'

interface DispositionBreakdownProps {
  /** Null when the counts could not be read; undefined while loading. */
  data: DispositionSummary | null | undefined
  isLoading: boolean
}

const SHOWN = ['reportable', 'candidate', 'info'] as const

/**
 * What can go in a report, beside the severity a scanner claimed. Excluded
 * findings are not repeated here: the judged-findings note below the charts
 * already counts them.
 */
export function DispositionBreakdown({ data, isLoading }: DispositionBreakdownProps) {
  const total = data ? data.reportable + data.candidate + data.info : 0
  const blockers = data ? topBlockers(data.blockers) : null

  return (
    <ChartCard
      title="Disposition"
      subtitle={data ? `${total} findings` : 'Can it go in a report?'}
      isLoading={isLoading}
      isEmpty={data !== null && total === 0}
    >
      {data === null ? (
        <p className={styles.unreadable}>The disposition counts could not be read.</p>
      ) : data && blockers ? (
        <div className={styles.body}>
          <ul className={styles.tiles} aria-label="Findings by disposition">
            {SHOWN.map((d) => (
              <li key={d} className={styles.tile} title={DISPOSITION_MEANINGS[d]}>
                <span className={styles.value}>{data[d]}</span>
                <span className={styles.label}>{DISPOSITION_LABELS[d]}</span>
              </li>
            ))}
          </ul>
          {blockers.top.length > 0 && (
            <>
              <div className={styles.heading}>Candidates by blocker</div>
              <ul className={styles.blockers} aria-label="Candidates by blocker">
                {blockers.top.map((b) => (
                  <li key={b.blocker} className={styles.blocker}>
                    <span className={styles.blockerName}>{b.blocker}</span>
                    <span className={styles.blockerCount}>{b.count}</span>
                  </li>
                ))}
                {blockers.otherBlockers > 0 && (
                  <li className={styles.blocker}>
                    <span className={styles.blockerName}>
                      {`${blockers.otherBlockers} other blocker${blockers.otherBlockers === 1 ? '' : 's'}`}
                    </span>
                    <span className={styles.blockerCount}>{blockers.otherCount}</span>
                  </li>
                )}
              </ul>
            </>
          )}
        </div>
      ) : null}
    </ChartCard>
  )
}
