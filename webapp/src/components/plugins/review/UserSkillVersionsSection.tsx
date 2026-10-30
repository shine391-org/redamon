'use client'

import { useCallback, useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { useAlertModal, useToast } from '@/components/ui'
import { PluginBadge } from '@/components/plugins/PluginBadge'
import type { UserSkillVersionsModel } from '@/lib/plugins/userSkillVersionsModel'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'
import { errorMessage } from '@/lib/apiError'
import { deleteChangeSet, deleteUserSkill, fetchUserSkillVersions } from './overridesClient'
import styles from './SkillVersionsModal.module.css'

const STATUS: Record<string, string> = {
  proposed: 'pending review',
  adopted: 'saved as a new skill',
  rejected: 'rejected',
  withdrawn: 'withdrawn',
}

/**
 * The versions window's view of one of the person's own skills: the proposals made from
 * its family, the versions saved from one another, and Delete older versions (keeps the
 * newest and any version on in a project).
 */
export function UserSkillVersionsSection({
  skillId,
  projectId,
  scopeOwnerId,
  onOpenReview,
}: {
  skillId: string
  projectId: string | null
  scopeOwnerId: string | null
  onOpenReview?: (changeSetId: string) => void
}) {
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()
  const [model, setModel] = useState<UserSkillVersionsModel | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    setModel(null)
    setError(null)
    fetchUserSkillVersions(skillId, projectId).then(setModel, (e) => setError(errorMessage(e, 'Could not load the versions.')))
  }, [skillId, projectId])
  useEffect(() => load(), [load])

  const run = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true)
    try {
      await fn()
      toast.success(ok)
    } catch (e) {
      toast.error(errorMessage(e, 'The action failed.'))
    } finally {
      // Also after a failure part way: what was deleted before it is gone for every window.
      postUserSkillsChanged({})
      setBusy(false)
      load()
    }
  }

  const deleteProposal = async (changeSetId: string) => {
    if (!(await dangerConfirm('Delete this proposal? This cannot be undone.', 'Delete this proposal?', { confirmLabel: 'Delete' }))) return
    await run(() => deleteChangeSet(changeSetId), 'Proposal deleted.')
  }

  const deleteOlder = async () => {
    if (!model || !scopeOwnerId || model.deletable.length === 0) return
    const names = model.family.filter((m) => model.deletable.includes(m.id)).map((m) => `"${m.name}"`).join(', ')
    const ok = await dangerConfirm(
      `Delete ${model.deletable.length} older version${model.deletable.length === 1 ? '' : 's'} (${names})? ` +
        'The newest one, this one, and any version on in a project stay. Their proposals waiting for review are deleted too. This cannot be undone.',
      'Delete older versions?',
      { confirmLabel: 'Delete' },
    )
    if (!ok) return
    await run(async () => {
      for (const id of model.deletable) await deleteUserSkill(scopeOwnerId, id)
    }, 'Older versions deleted.')
  }

  if (error) return <div className={styles.error} role="alert">{error}</div>
  if (!model) {
    return (
      <div className={styles.loading}>
        <Loader2 size={14} className={styles.spin} /> Loading…
      </div>
    )
  }
  return (
    <>
      <section className={styles.scope} data-testid="user-skill-family">
        <h3 className={styles.scopeTitle}>Versions of this skill</h3>
        {model.family.map((m) => (
          <div key={m.id} className={styles.row} data-testid={`family-${m.id}`}>
            <div className={styles.rowMain}>
              {m.version !== null && <span className={styles.vnum}>v{m.version}</span>}
              <div className={styles.rowText}>
                <div className={styles.rowStatus}>
                  {m.name}
                  {m.id === model.skill.id ? ' · this skill' : ''}
                  {m.quarantined ? ' · quarantined' : ''}
                </div>
                <div className={styles.rowDate}>
                  {m.enabledInProject === true ? 'On in this project' : m.enabledProjects ? `On in ${m.enabledProjects} project${m.enabledProjects === 1 ? '' : 's'}` : 'Off everywhere'}
                  {' · '}{new Date(m.createdAt).toLocaleDateString()}
                </div>
              </div>
            </div>
          </div>
        ))}
        {model.deletable.length > 0 && scopeOwnerId && (
          <button type="button" className={`secondaryButton ${styles.danger}`} onClick={() => void deleteOlder()} disabled={busy}>
            Delete older versions
          </button>
        )}
      </section>

      <section className={styles.scope} data-testid="user-skill-proposals">
        <h3 className={styles.scopeTitle}>Proposals</h3>
        {model.proposals.length === 0 && <div className={styles.empty}>No proposal for this skill yet.</div>}
        {model.proposals.map((p) => (
          <div key={p.changeSetId} className={styles.row} data-testid={`proposal-${p.changeSetId}`}>
            <div className={styles.rowMain}>
              <div className={styles.rowText}>
                <div className={styles.rowStatus}>
                  {p.status === 'adopted' && p.adopted ? `became "${p.adopted.name}"` : (STATUS[p.status] ?? p.status)}
                  {' · from '}{p.sourceName}
                  <PluginBadge label={p.pluginDisplayName} />
                </div>
                {p.note && <div className={styles.rowNote}>{p.note}</div>}
                <div className={styles.rowDate}>{new Date(p.decidedAt ?? p.createdAt).toLocaleDateString()}</div>
              </div>
            </div>
            <div className={styles.rowActions}>
              {p.status === 'proposed' && (
                <button type="button" className="secondaryButton" onClick={() => onOpenReview?.(p.changeSetId)}>Open review</button>
              )}
              <button type="button" className={`secondaryButton ${styles.danger}`} onClick={() => void deleteProposal(p.changeSetId)} disabled={busy}>
                Delete
              </button>
            </div>
          </div>
        ))}
      </section>
    </>
  )
}
