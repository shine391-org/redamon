'use client'

import { useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import { PluginBadge } from '@/components/plugins/PluginBadge'
import { SafeMarkdown } from '@/components/plugins/host/SafeMarkdown'
import { TextDiff } from '@/components/plugins/host/TextDiff'
import { nameCheckMessage, useSkillNameCheck } from '@/components/settings/useSkillNameCheck'
import { errorMessage } from '@/lib/apiError'
import type { UserSkillReviewModel } from '@/lib/plugins/userSkillReviewModel'
import { DESCRIPTION_MAX_CHARS, NAME_MAX_CHARS } from '@/lib/userSkills'
import { postUserSkillsChanged } from '@/lib/userSkillsChannel'
import { OverrideApiError, rejectChangeSet, saveUserSkillVersion } from './overridesClient'
import { riskCopy } from './riskCopy'
import styles from './OverrideReviewModal.module.css'
import own from './UserSkillReview.module.css'

export type UserSkillDecision = { outcome: 'saved'; skillId: string; name: string; version: number } | { outcome: 'rejected' }

function warnings(m: UserSkillReviewModel): { tone: 'warn' | 'block'; text: string }[] {
  const out: { tone: 'warn' | 'block'; text: string }[] = []
  if (!m.source.exists) {
    out.push({ tone: 'warn', text: `"${m.source.nameAtProposal}" was deleted since this proposal. Saving still creates the new skill.` })
  } else {
    if (m.source.name && m.source.name !== m.source.nameAtProposal) {
      out.push({ tone: 'warn', text: `"${m.source.nameAtProposal}" is now called "${m.source.name}".` })
    }
    if (m.source.changedSinceProposal) {
      out.push({ tone: 'warn', text: `"${m.source.name}" was edited since this proposal. The difference below is against the text the proposal was built on.` })
    }
  }
  if (m.sessionPredatesActive) {
    out.push({ tone: 'warn', text: 'The session that produced this proposal ran an older text of the skill than the one it was built on.' })
  }
  if (m.proposer.message) out.push({ tone: 'block', text: m.proposer.message })
  return out
}

/**
 * The review of a proposal for one of the person's own skills: saving it creates a NEW
 * skill (the source is kept), named `<root> vN` unless they type another free name. In a
 * project it can be switched on in place of its source there. Save stays disabled while a
 * limit is reached, flagged lines are unread, or the plugin that proposed it is no longer
 * serving at the version that did.
 */
export function UserSkillReview({
  model,
  scopeOwnerId,
  onClose,
  onDecided,
}: {
  model: UserSkillReviewModel
  scopeOwnerId: string | null
  onClose: () => void
  onDecided: (decision: UserSkillDecision) => void
}) {
  const { confirm } = useAlertModal()
  const toast = useToast()
  const [name, setName] = useState(model.suggestedName)
  const [description, setDescription] = useState(model.source.description ?? '')
  const [acknowledged, setAcknowledged] = useState(false)
  const project = model.project
  const [enableNew, setEnableNew] = useState(!!project)
  const [disableSource, setDisableSource] = useState(!!project && project.sourceEnabled)
  const [busy, setBusy] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const waiting = model.status === 'proposed'
  const check = useSkillNameCheck(scopeOwnerId, name, { sourceId: model.source.id, enabled: waiting && !!name.trim() })
  const flagged = model.parts.flatMap((p) => p.riskFlags)
  const sourceName = model.source.name ?? model.source.nameAtProposal
  const atSkillLimit = model.skillCount >= model.skillLimit
  const projectedEnabled = project
    ? project.enabledCount + (enableNew ? 1 : 0) - (enableNew && disableSource && project.sourceEnabled ? 1 : 0)
    : 0
  const overEnabledLimit = !!project && enableNew && projectedEnabled > project.enabledLimit
  const nameBlocked = !name.trim() || check.state === 'taken' || check.state === 'invalid'
  const saveBlocked = !waiting || busy || atSkillLimit || nameBlocked || (flagged.length > 0 && !acknowledged) ||
    !model.proposer.available || overEnabledLimit

  const save = async () => {
    if (saveBlocked) return
    setBusy(true)
    setSaveError(null)
    try {
      const saved = await saveUserSkillVersion(model.changeSetId, {
        scopeOwnerId,
        name,
        description: description.trim() || null,
        projectId: project?.id ?? null,
        enableNew: !!project && enableNew,
        disableSource: !!project && enableNew && disableSource && project.sourceEnabled,
        acknowledgedRiskLines: flagged.length,
      })
      toast.success(`Saved "${saved.name}" as a new skill.`)
      postUserSkillsChanged({ projectId: project?.id ?? null })
      onDecided({ outcome: 'saved', ...saved })
    } catch (e) {
      if (e instanceof OverrideApiError) {
        setSaveError(e.message)
        if (e.code === 'name_taken' && typeof e.extra.suggestion === 'string') setName(e.extra.suggestion)
      } else {
        setSaveError(errorMessage(e, 'The new skill could not be saved.'))
      }
    } finally {
      setBusy(false)
    }
  }

  const reject = async () => {
    if (busy) return
    const ok = await confirm(`Reject this proposal for "${sourceName}"? The plugin can propose again later.`, 'Reject this proposal?', { confirmLabel: 'Reject' })
    if (!ok) return
    setBusy(true)
    try {
      await rejectChangeSet(model.changeSetId, scopeOwnerId)
      toast.success('Proposal rejected.')
      onDecided({ outcome: 'rejected' })
    } catch (e) {
      toast.error(errorMessage(e, 'Could not reject the proposal.'))
    } finally {
      setBusy(false)
    }
  }

  const footer = (
    <div className={`${styles.footer} ${own.footer}`}>
      {waiting && (
        <button type="button" className="secondaryButton" onClick={() => void reject()} disabled={busy}>Reject</button>
      )}
      <button type="button" className="secondaryButton" onClick={onClose} disabled={busy}>Close</button>
      {waiting && (
        <button type="button" className="primaryButton" onClick={() => void save()} disabled={saveBlocked} data-testid="save-new-skill">
          {busy ? <Loader2 size={12} className={styles.spin} /> : null} Save as new skill
        </button>
      )}
    </div>
  )

  return (
    <Modal isOpen onClose={onClose} title={`New version of "${sourceName}"`} size="xlarge" closeOnOverlayClick={false} footer={footer} className={own.sheet}>
      <div className={`${styles.body} ${own.body}`}>
        <div className={styles.header}>
          <span className={styles.vLine}>Your skill</span>
          <span>proposed by</span>
          <PluginBadge label={model.plugin.displayName} />
        </div>
        <p className={styles.scope}>Saving creates a new skill; &quot;{sourceName}&quot; is kept.</p>

        {!waiting && (
          <div className={styles.warn} role="status">
            {model.status === 'adopted' && model.adopted
              ? `Saved as "${model.adopted.name}".`
              : `This proposal was ${model.status}.`}
          </div>
        )}

        {warnings(model).map((w, i) => (
          <div key={i} className={w.tone === 'block' ? styles.block : styles.warn} role="alert">
            <AlertTriangle size={14} aria-hidden /> {w.text}
          </div>
        ))}

        {model.note && (
          <section className={styles.note}>
            <SafeMarkdown>{model.note}</SafeMarkdown>
          </section>
        )}

        {flagged.length > 0 && (
          <section className={styles.risks} aria-label="Risk flags">
            <div className={styles.risksTitle}>
              <AlertTriangle size={14} aria-hidden /> Lines to look at before saving
            </div>
            <ul>
              {flagged.map((f, i) => (
                <li key={i}>
                  <code>{f.text}</code>
                  <span className={styles.riskWhy}> — {riskCopy(f.flags)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        <div className={own.diff}>
          <TextDiff
            before={model.parts[0]?.before ?? ''}
            after={model.parts[0]?.after ?? ''}
            beforeLabel={`${model.source.nameAtProposal} (built on)`}
            afterLabel="Proposed"
          />
        </div>

        {waiting && (
          <div className={own.fields}>
            {flagged.length > 0 && (
              <label className={own.check}>
                <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} />
                I have read the {flagged.length} flagged line{flagged.length === 1 ? '' : 's'}
              </label>
            )}
            <div className="formGroup">
              <label className="formLabel" htmlFor="user-skill-version-name">Name</label>
              <input
                id="user-skill-version-name"
                className="textInput"
                type="text"
                value={name}
                maxLength={NAME_MAX_CHARS}
                onChange={(e) => { setSaveError(null); setName(e.target.value) }}
              />
              <span className="formHint" role={nameCheckMessage(check) ? 'alert' : undefined}>
                {nameCheckMessage(check) ?? (check.state === 'available' ? '✓ available' : ' ')}
              </span>
            </div>
            <div className="formGroup">
              <label className="formLabel" htmlFor="user-skill-version-description">Description</label>
              <textarea
                id="user-skill-version-description"
                className="textInput"
                rows={3}
                value={description}
                maxLength={DESCRIPTION_MAX_CHARS}
                onChange={(e) => setDescription(e.target.value)}
              />
              <span className="formHint">
                The agent chooses skills by name and description. If you keep &quot;{sourceName}&quot; on in any project,
                describe what this version does differently.
              </span>
            </div>
            {project && (
              <div className={own.swap}>
                <label className={own.check}>
                  <input type="checkbox" checked={enableNew} onChange={(e) => setEnableNew(e.target.checked)} />
                  Use it in project &quot;{project.name}&quot;
                </label>
                {enableNew && project.sourceEnabled && (
                  <label className={`${own.check} ${own.indent}`}>
                    <input type="checkbox" checked={disableSource} onChange={(e) => setDisableSource(e.target.checked)} />
                    instead of &quot;{sourceName}&quot;
                  </label>
                )}
                {enableNew && disableSource && project.sourceEnabled && (
                  <span className="formHint">
                    Sessions in {project.name} that use &quot;{sourceName}&quot; continue with &quot;{name || 'the new skill'}&quot;
                    from their next message or resume.
                  </span>
                )}
                {overEnabledLimit && (
                  <div className={styles.block} role="alert">
                    This project already uses {project.enabledLimit} of your skills, the maximum.{' '}
                    {project.sourceEnabled
                      ? <>Turn one off, or keep &quot;instead of {sourceName}&quot; checked.</>
                      : <>Turn one off in the project first, or save it without using it there.</>}
                  </div>
                )}
              </div>
            )}
            {atSkillLimit && (
              <div className={styles.block} role="alert">
                You have {model.skillLimit} skills, the maximum. Delete one in Global Settings to save this version.
              </div>
            )}
            {saveError && <div className={styles.block} role="alert">{saveError}</div>}
          </div>
        )}
      </div>
    </Modal>
  )
}
