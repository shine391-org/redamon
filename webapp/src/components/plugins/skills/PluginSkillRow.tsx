'use client'

import { useState } from 'react'
import { History } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import { PluginBadge } from '@/components/plugins/PluginBadge'
import { dormantCopy } from '@/components/plugins/review/dormantCopy'
import { OverrideApiError, resetSkill } from '@/components/plugins/review/overridesClient'
import { errorMessage } from '@/lib/apiError'
import type { SkillSummary } from '@/lib/plugins/summaryModel'
import { runPluginAction } from '@/components/plugins/runPluginAction'
import { useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import type { ProjectSkillRowAction } from './usePluginSkillOverrides'
import styles from './PluginSkillRow.module.css'

/** The chip wording for one skill's governing version. */
function chip(applies: NonNullable<SkillSummary['applies']>): string {
  if (applies.applied) return `changed by ${applies.pluginDisplayName} · v${applies.revision}`
  if (applies.status === 'stale') {
    return applies.staleReason === 'part_removed' ? 'part removed · factory in use' : 'stale · factory in use'
  }
  const why = applies.dormantReason ? dormantCopy(applies.dormantReason) : 'not applied'
  return `v${applies.revision} · not applied (${why}) · factory in use`
}

/**
 * The plugin controls under one built-in skill in project settings (design §6, X23). Shown
 * only for a saved project. Reset is its own API call with a visible error, never part of the
 * project PUT (the debounced whole-row PUT swallows errors). project.skills.row contributions
 * render after, each with the plugin badge, calling their action with the skill id.
 */
export function PluginSkillRow({
  skillId,
  projectId,
  scopeOwnerId,
  summary,
  rowActions,
  onVersions,
  onPending,
  onReset,
}: {
  skillId: string
  projectId: string
  scopeOwnerId: string | null
  summary: SkillSummary | undefined
  rowActions: ProjectSkillRowAction[]
  onVersions: (skillId: string) => void
  onPending: (skillId: string) => void
  onReset: () => void
}) {
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()
  const gate = useFeatureModelGate()
  const [busy, setBusy] = useState(false)
  const applies = summary?.applies ?? null
  const pending = summary?.pending ?? 0

  // Reset clears whichever scope governs this project: its own version if that is what applies,
  // otherwise the owner's user-scope version.
  const scopeType = applies?.scope ?? 'user'

  const reset = async () => {
    const ok = await dangerConfirm(
      scopeType === 'project'
        ? 'This project will use your default version of this skill, or the factory text if you have none. From the next message or resume; a run in progress keeps the text it started with.'
        : 'The factory text runs again in every project you own, from the next message or resume. A run in progress keeps the text it started with.',
      'Reset to factory?',
      { confirmLabel: 'Reset' },
    )
    if (!ok) return
    setBusy(true)
    try {
      await resetSkill({ group: skillId, scopeType, scopeOwnerId: scopeType === 'user' ? scopeOwnerId : null, projectId: scopeType === 'project' ? projectId : null })
      toast.success('Reset to factory.')
      onReset()
    } catch (e) {
      toast.error(errorMessage(e, 'Could not reset this skill.'))
      // The reset took effect; only what came after it failed. Show the factory state now.
      if (e instanceof OverrideApiError && e.extra.committed === true) onReset()
    } finally {
      setBusy(false)
    }
  }

  const runRow = async (row: ProjectSkillRowAction) => {
    await runPluginAction({
      plugin: { pluginId: row.pluginId, displayName: row.pluginDisplayName },
      item: { key: row.action, label: row.label, action: row.action, llm: false, async: false },
      context: { projectId },
      gate,
      handlers: {
        onReviewProposal: () => onReset(),
        onCoreScreen: () => {},
        onJob: () => toast.info('Started; see the chat for progress.'),
        toast,
      },
    })
  }

  const nothing = !applies && pending === 0 && rowActions.length === 0
  if (nothing) return null

  return (
    <div className={styles.row} data-testid={`plugin-skill-row-${skillId}`}>
      {applies && (
        <span className={`${styles.chip} ${applies.applied ? '' : styles.chipDormant}`} data-testid="plugin-skill-chip">
          {chip(applies)}
        </span>
      )}
      {applies && (
        <>
          <button type="button" className={styles.linkBtn} onClick={() => onVersions(skillId)}>
            <History size={12} aria-hidden /> Versions
          </button>
          <button type="button" className={styles.linkBtn} onClick={() => void reset()} disabled={busy}>
            Reset to factory
          </button>
        </>
      )}
      {pending > 0 && (
        <button type="button" className={styles.pending} onClick={() => onPending(skillId)}>
          {pending} pending
        </button>
      )}
      {rowActions.map((row) => (
        <span key={`${row.pluginId}:${row.action}`} className={styles.rowAction}>
          <PluginBadge label={row.pluginDisplayName} />
          <button type="button" className={styles.linkBtn} disabled={busy} onClick={() => void runRow(row)}>
            {row.label}
          </button>
        </span>
      ))}
    </div>
  )
}
