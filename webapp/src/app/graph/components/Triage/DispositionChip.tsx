'use client'

/**
 * A finding's disposition, in the words lib/triage/disposition.ts gives every
 * surface: a chip on the board's rows, a line in the detail panel and the node
 * drawer. Neither renders anything for props it could not read, so an
 * unreadable finding never shows up as "Reportable".
 */

import { CircleCheck, CircleHelp, CircleMinus, Info, type LucideIcon } from 'lucide-react'
import {
  DISPOSITION_LABELS, DISPOSITION_MEANINGS, dispositionText,
  type Disposition, type DispositionResult,
} from '@/lib/triage/disposition'
import styles from './DispositionChip.module.css'

const ICONS: Record<Disposition, LucideIcon> = {
  reportable: CircleCheck,
  candidate: CircleHelp,
  info: Info,
  excluded: CircleMinus,
}

function tooltip(r: DispositionResult): string {
  return r.disposition === 'candidate'
    ? dispositionText(r)
    : `${DISPOSITION_LABELS[r.disposition]}: ${DISPOSITION_MEANINGS[r.disposition]}`
}

export function DispositionChip({ result }: { result: DispositionResult | null }) {
  if (!result) return null
  const Icon = ICONS[result.disposition]
  const title = tooltip(result)
  return (
    <span
      className={`${styles.dispositionChip} ${styles[`disposition_${result.disposition}`] ?? ''}`}
      data-disposition={result.disposition}
      title={title}
      aria-label={title}
    >
      <Icon size={12} aria-hidden="true" />
      <span className={styles.dispositionText}>{DISPOSITION_LABELS[result.disposition]}</span>
    </span>
  )
}

export function DispositionLine({ result, className }: { result: DispositionResult | null; className?: string }) {
  if (!result) return null
  return (
    <p className={className} data-testid="disposition-line" data-disposition={result.disposition}>
      Disposition: {dispositionText(result)}
    </p>
  )
}
