'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import { PluginBadge } from '@/components/plugins/PluginBadge'
import { TextDiff } from '@/components/plugins/host/TextDiff'
import { errorMessage, fetchJson } from '@/lib/apiError'
import { BUILTIN_SKILLS } from '@/lib/plugins/builtinSkills'
import type { ScopeVersions, VersionRow, VersionsModel } from '@/lib/plugins/versionsModel'
import { deleteChangeSet, fetchVersions, resetSkill } from './overridesClient'
import { dormantCopy } from './dormantCopy'
import { UserSkillVersionsSection } from './UserSkillVersionsSection'
import { useUserSkillsChanged } from '@/lib/userSkillsChannel'

const USER_PREFIX = 'user_skill:'
import styles from './SkillVersionsModal.module.css'

const FACTORY_REVISION = 1

/** Status words for a version row (the active one's "not applied" reason comes from the scope). */
function statusLabel(v: VersionRow, scope: ScopeVersions): string {
  if (v.status === 'active') {
    return scope.dormantReason ? `active · not applied (${dormantCopy(scope.dormantReason)}) · factory text in use` : 'active'
  }
  if (v.status === 'stale') {
    return v.staleReason === 'part_removed'
      ? 'a RedAmon update removed a part this version changed; factory text is in use'
      : 'stale · RedAmon’s factory text changed; factory text is in use'
  }
  if (v.status === 'proposed') return 'pending review'
  if (v.status === 'cleared') return 'reset to factory'
  return v.status
}

export function SkillVersionsModal({
  projectId,
  initialSkill,
  scopeOwnerId,
  onClose,
  onOpenReview,
  onReviewAgain,
}: {
  projectId: string | null
  initialSkill?: string
  /** The effective user, carried on user-scope reset/delete (X9). */
  scopeOwnerId: string | null
  onClose: () => void
  onOpenReview?: (changeSetId: string) => void
  onReviewAgain?: (changeSetId: string) => void
}) {
  const { confirm, dangerConfirm } = useAlertModal()
  const toast = useToast()
  const first = initialSkill && (BUILTIN_SKILLS.some((s) => s.id === initialSkill) || initialSkill.startsWith(USER_PREFIX))
    ? initialSkill
    : BUILTIN_SKILLS[0]?.id
  const [skill, setSkill] = useState(first)
  const [model, setModel] = useState<VersionsModel | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [viewing, setViewing] = useState<string | null>(null)
  // null until read: a skill opened from the chat is not "deleted" just because the list is late.
  const [ownList, setOwnList] = useState<{ id: string; name: string }[] | null>(null)
  // A list that failed is not an empty one: the open skill is not "deleted" because of it.
  const [ownError, setOwnError] = useState<string | null>(null)
  const ownSkills = ownList ?? []
  const userSkillId = skill?.startsWith(USER_PREFIX) ? skill.slice(USER_PREFIX.length) : null

  // The person's own skills, for the selector's "Your skills" group.
  // Read again when a skill is uploaded, deleted or saved elsewhere, this window's "Delete older
  // versions" included, so the selector never offers a skill that is gone.
  const [ownGeneration, setOwnGeneration] = useState(0)
  useUserSkillsChanged(() => setOwnGeneration((g) => g + 1))
  useEffect(() => {
    if (!scopeOwnerId) {
      setOwnList([])
      return
    }
    let cancelled = false
    fetchJson<{ id: string; name: string }[]>(`/api/users/${encodeURIComponent(scopeOwnerId)}/attack-skills`, undefined, 'Your skills could not be loaded')
      .then((rows) => {
        if (cancelled) return
        setOwnError(null)
        setOwnList(Array.isArray(rows) ? rows : [])
      })
      .catch((e) => {
        if (cancelled) return
        setOwnError(errorMessage(e, 'Your skills could not be loaded'))
        setOwnList([])
      })
    return () => { cancelled = true }
  }, [scopeOwnerId, ownGeneration])

  const load = useCallback(() => {
    if (!skill || skill.startsWith(USER_PREFIX)) return
    setModel(null)
    setError(null)
    fetchVersions(skill, projectId).then(setModel, (e) => setError(errorMessage(e, 'Could not load the versions.')))
  }, [skill, projectId])
  useEffect(() => load(), [load])

  const run = useCallback(
    async (fn: () => Promise<unknown>, ok: string) => {
      setBusy(true)
      try {
        await fn()
        toast.success(ok)
        load()
      } catch (e) {
        toast.error(errorMessage(e, 'The action failed.'))
      } finally {
        setBusy(false)
      }
    },
    [toast, load],
  )

  const resetScope = (scope: ScopeVersions) => async () => {
    const owner = scope.scopeType === 'project' ? 'this project' : 'your account'
    const msg =
      scope.scopeType === 'project'
        ? 'This project will use your default version of this skill, or the factory text if you have none. It applies from the next message or resume; a run in progress keeps the text it started with.'
        : 'The factory text runs again in every project you own, from the next message or resume. A run in progress keeps the text it started with.'
    if (!(await confirm(msg, `Reset ${model?.skillDisplayName} for ${owner}?`, { confirmLabel: 'Reset' }))) return
    await run(
      () => resetSkill({ group: skill!, scopeType: scope.scopeType, scopeOwnerId: scope.scopeType === 'user' ? scopeOwnerId : null, projectId: scope.scopeType === 'project' ? scope.scopeOwnerId : null }),
      'Reset to factory.',
    )
  }

  const deleteOne = (v: VersionRow) => async () => {
    if (!(await dangerConfirm(`Delete v${v.revision ?? ''} of ${model?.skillDisplayName}? This cannot be undone.`, 'Delete this version?', { confirmLabel: 'Delete' }))) return
    await run(() => deleteChangeSet(v.changeSetId), 'Version deleted.')
  }

  const deleteAllOld = (scope: ScopeVersions) => async () => {
    const old = scope.versions.filter((v) => v.revision !== null && v.status !== 'active')
    if (old.length === 0) return
    if (!(await dangerConfirm(`Delete all ${old.length} old versions of ${model?.skillDisplayName}? The active version stays. This cannot be undone.`, 'Delete all old versions?', { confirmLabel: 'Delete' }))) return
    await run(async () => {
      for (const v of old) await deleteChangeSet(v.changeSetId)
    }, 'Old versions deleted.')
  }

  const ownName = userSkillId ? ownSkills.find((s) => s.id === userSkillId)?.name : undefined
  const title = userSkillId ? `Versions · ${ownName ?? 'your skill'}` : model ? `Versions · ${model.skillDisplayName}` : 'Skill versions'

  return (
    <Modal isOpen onClose={onClose} title={title} size="xlarge" closeOnOverlayClick={false}>
      <div className={styles.body}>
        <label className={styles.selector}>
          Skill
          <select className="textInput" value={skill} onChange={(e) => setSkill(e.target.value)} disabled={busy}>
            <optgroup label="Built-in">
              {BUILTIN_SKILLS.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.displayName}
                </option>
              ))}
            </optgroup>
            {(ownSkills.length > 0 || userSkillId) && (
              <optgroup label="Your skills">
                {userSkillId && !ownSkills.some((s) => s.id === userSkillId) && (
                  <option value={skill}>{ownList === null ? 'Loading…' : ownError ? 'Your skills could not be loaded' : 'A deleted skill'}</option>
                )}
                {ownSkills.map((s) => (
                  <option key={s.id} value={`${USER_PREFIX}${s.id}`}>
                    {s.name}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </label>

        {userSkillId && (
          <UserSkillVersionsSection
            key={userSkillId}
            skillId={userSkillId}
            projectId={projectId}
            scopeOwnerId={scopeOwnerId}
            onOpenReview={onOpenReview}
          />
        )}

        {!userSkillId && !model && !error && (
          <div className={styles.loading}>
            <Loader2 size={14} className={styles.spin} /> Loading…
          </div>
        )}
        {!userSkillId && error && <div className={styles.error} role="alert">{error}</div>}
        {ownError && <div className={styles.error} role="alert" data-testid="own-skills-error">{ownError}</div>}
        {!userSkillId && model?.registryError && (
          <div className={styles.note}>
            The agent could not be read{model.registryErrorText ? ` (${model.registryErrorText})` : ''}, so the factory text is not shown here.
          </div>
        )}

        {!userSkillId && model?.scopes.map((scope) => (
          <ScopeSection
            key={`${scope.scopeType}:${scope.scopeOwnerId}`}
            scope={scope}
            model={model}
            busy={busy}
            viewing={viewing}
            setViewing={setViewing}
            onReset={resetScope(scope)}
            onDeleteOne={deleteOne}
            onDeleteAllOld={deleteAllOld(scope)}
            onOpenReview={onOpenReview}
            onReviewAgain={onReviewAgain}
          />
        ))}
      </div>
    </Modal>
  )
}

function ScopeSection({
  scope,
  model,
  busy,
  viewing,
  setViewing,
  onReset,
  onDeleteOne,
  onDeleteAllOld,
  onOpenReview,
  onReviewAgain,
}: {
  scope: ScopeVersions
  model: VersionsModel
  busy: boolean
  viewing: string | null
  setViewing: (id: string | null) => void
  onReset: () => void
  onDeleteOne: (v: VersionRow) => () => void
  onDeleteAllOld: () => void
  onOpenReview?: (id: string) => void
  onReviewAgain?: (id: string) => void
}) {
  const revisions = useMemo(() => scope.versions.filter((v) => v.revision !== null).map((v) => v.revision as number), [scope.versions])
  const maxShown = revisions.length ? Math.max(...revisions) : FACTORY_REVISION
  const numbersSkip = scope.lastRevision > maxShown || revisions.length !== new Set(revisions).size || maxShown - FACTORY_REVISION > revisions.length
  const hasOldApproved = scope.versions.some((v) => v.revision !== null && v.status !== 'active')

  return (
    <section className={styles.scope} data-testid={`scope-${scope.scopeType}`}>
      <h3 className={styles.scopeTitle}>{scope.scopeType === 'user' ? 'Your versions (all your projects)' : 'This project'}</h3>

      <div className={styles.row} data-testid="version-factory">
        <div className={styles.rowMain}>
          <span className={styles.vnum}>v{FACTORY_REVISION}</span>
          <span>Factory text{scope.factoryInUse ? ' · in use' : ''}</span>
        </div>
      </div>

      {scope.versions.map((v) => (
        <div key={v.changeSetId} className={styles.row} data-testid={`version-${v.changeSetId}`}>
          <div className={styles.rowMain}>
            {v.revision !== null && <span className={styles.vnum}>v{v.revision}</span>}
            <div className={styles.rowText}>
              <div className={styles.rowStatus}>
                {statusLabel(v, scope)}
                <PluginBadge label={v.pluginDisplayName} />
              </div>
              {v.note && <div className={styles.rowNote}>{v.note}</div>}
              <div className={styles.rowDate}>{new Date(v.decidedAt ?? v.createdAt).toLocaleDateString()}</div>
            </div>
          </div>
          <div className={styles.rowActions}>
            {v.status === 'proposed' ? (
              <button type="button" className="secondaryButton" onClick={() => onOpenReview?.(v.changeSetId)}>
                Open review
              </button>
            ) : (
              <>
                {model.factoryText && (
                  <button type="button" className="secondaryButton" onClick={() => setViewing(viewing === v.changeSetId ? null : v.changeSetId)}>
                    View
                  </button>
                )}
                {v.status === 'stale' && v.staleReason === 'factory_changed' && (
                  <button type="button" className="secondaryButton" onClick={() => (onReviewAgain ?? onOpenReview)?.(v.changeSetId)}>
                    Review again
                  </button>
                )}
                {v.status === 'active' && (
                  <button type="button" className="secondaryButton" onClick={onReset} disabled={busy}>
                    Reset to factory
                  </button>
                )}
                {v.status !== 'active' && (
                  <button type="button" className={`secondaryButton ${styles.danger}`} onClick={onDeleteOne(v)} disabled={busy}>
                    Delete
                  </button>
                )}
              </>
            )}
          </div>
          {viewing === v.changeSetId && model.factoryText && (
            <div className={styles.view}>
              {v.parts.map((p) => (
                <div key={p.partId}>
                  <div className={styles.partName}>{p.partId}</div>
                  <TextDiff before={model.factoryText![p.partId] ?? ''} after={p.value} beforeLabel="Factory" afterLabel={`v${v.revision ?? ''}`} showPlaceholderLegend />
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {scope.versions.length === 0 && <div className={styles.empty}>No versions yet. Factory text is in use.</div>}

      {hasOldApproved && (
        <button type="button" className={`secondaryButton ${styles.danger}`} onClick={onDeleteAllOld} disabled={busy}>
          Delete all old versions
        </button>
      )}
      {numbersSkip && (
        <p className={styles.note}>Version numbers are never reused, so the list can skip numbers after a deletion or reset.</p>
      )}
    </section>
  )
}
