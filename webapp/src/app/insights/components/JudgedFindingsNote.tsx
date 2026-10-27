'use client'

import type { JudgedFindingCounts } from '@/lib/triage/reportable'
import styles from './JudgedFindingsNote.module.css'

interface JudgedFindingsNoteProps {
  /** Null or absent when the counts could not be read: nothing is shown then. */
  judged?: JudgedFindingCounts | null
}

/**
 * What the Priority Board set aside from the charts above. An AI review alone
 * never removes a finding, so its line says the finding is still counted.
 */
export function JudgedFindingsNote({ judged }: JudgedFindingsNoteProps) {
  if (!judged) return null
  const lines = [
    { n: judged.personFalsePositive, text: 'judged false positive by a person: not counted above' },
    { n: judged.resolved, text: 'resolved (fixed, gone, inactive): not counted above' },
    { n: judged.aiFlagged, text: 'flagged as likely false positive by AI review: still counted above' },
  ].filter((l) => l.n > 0)
  if (lines.length === 0) return null
  return (
    <ul className={styles.note} aria-label="Findings the Priority Board judged">
      {lines.map((l) => (
        <li key={l.text}>{`${l.n} ${l.text}`}</li>
      ))}
    </ul>
  )
}
