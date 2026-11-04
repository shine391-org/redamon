'use client'

import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import { PluginBadge } from '@/components/plugins/PluginBadge'
import { SafeMarkdown } from '@/components/plugins/host/SafeMarkdown'
import { TextDiff } from '@/components/plugins/host/TextDiff'
import type { ReviewModel, ReviewPart } from '@/lib/plugins/reviewModel'
import type { UserSkillReviewModel } from '@/lib/plugins/userSkillReviewModel'
import { errorMessage } from '@/lib/apiError'
import { OverrideApiError, approveChangeSet, fetchReviewModel, rejectChangeSet } from './overridesClient'
import { UserSkillReview } from './UserSkillReview'
import { dormantCopy } from './dormantCopy'
import { riskCopy } from './riskCopy'
import styles from './OverrideReviewModal.module.css'

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

/** Warnings above the body, from the model and the plugin's own meta. */
function warnings(m: ReviewModel): { tone: 'warn' | 'block'; text: string }[] {
  const out: { tone: 'warn' | 'block'; text: string }[] = []
  const meta = isObj(m.meta) ? m.meta : {}
  if (meta.sessionPredatesActive === true) {
    const at = typeof meta.sessionActiveRevision === 'number' ? meta.sessionActiveRevision : m.fromRevision
    out.push({ tone: 'warn', text: `This session ran before v${at} became active; the proposal is built on v${at}.` })
  }
  if (m.baseOutdated) {
    out.push({
      tone: 'warn',
      text: `This proposal was built on v${m.fromRevision}, but v${m.activeRevision} is active now: approving it discards the changes made in v${m.activeRevision}.`,
    })
  }
  if (m.replaces) out.push({ tone: 'warn', text: `Approving replaces v${m.replaces.revision} made by ${m.replaces.displayName}.` })
  const changed = m.parts.filter((p) => p.factoryChanged).map((p) => p.partId)
  for (const partId of changed) {
    out.push({ tone: 'block', text: `RedAmon's factory text for ${partId} changed since this proposal. Review it again before approving.` })
  }
  if (m.registryError) {
    // registryErrorText says whether the agent answered at all, and with which status.
    out.push({
      tone: 'block',
      text: m.registryError === 'agent_outdated'
        ? 'The agent is older than the webapp (rebuild the agent); this cannot be approved now.'
        : `${m.registryErrorText ?? 'The agent cannot be reached'}; this cannot be approved now.`,
    })
  }
  if (m.dormantReason) out.push({ tone: 'warn', text: `This version would not be applied now: ${dormantCopy(m.dormantReason)}.` })
  return out
}

/**
 * The core review window of a proposed change set. A built-in skill's version is approved
 * into the scope; a proposal for one of the person's own skills (`user_skill.text`) opens the
 * save-as-new-skill review instead, with `projectId` the project it was opened from (its
 * toggles), or none from Global Settings.
 */
export function OverrideReviewModal({
  changeSetId,
  scopeOwnerId,
  projectId = null,
  onClose,
  onDecided,
}: {
  changeSetId: string
  /** The scope owner id a user-scope decision must carry (the effective user). */
  scopeOwnerId: string | null
  projectId?: string | null
  onClose: () => void
  /** `saved`: a user-skill proposal became a new skill (revision is its version). */
  onDecided: (outcome: 'approved' | 'rejected' | 'saved', revision?: number) => void
}) {
  const { confirm } = useAlertModal()
  const toast = useToast()
  const [loaded, setLoaded] = useState<ReviewModel | UserSkillReviewModel | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [tab, setTab] = useState(0)
  // Every reason an approval was refused (an over-limit text can break several limits).
  const [approveErrors, setApproveErrors] = useState<string[]>([])

  const load = useCallback(() => {
    setLoadError(null)
    fetchReviewModel(changeSetId, projectId).then(setLoaded, (e) => setLoadError(errorMessage(e, 'Could not load the proposal.')))
  }, [changeSetId, projectId])
  useEffect(() => load(), [load])

  if (loaded && 'kind' in loaded && loaded.kind === 'user_skill') {
    return (
      <UserSkillReview
        model={loaded}
        scopeOwnerId={scopeOwnerId}
        onClose={onClose}
        onDecided={(d) => (d.outcome === 'saved' ? onDecided('saved', d.version) : onDecided('rejected'))}
      />
    )
  }
  const model = loaded as ReviewModel | null

  const ownerId = model?.scope.type === 'user' ? scopeOwnerId : null

  const approve = async () => {
    if (!model || busy) return
    const ok = await confirm(
      'The agent will follow this text from the next message or resume in every project you own. A run already in progress keeps the text it started with.',
      `Approve ${model.proposedLabel} of ${model.skill.displayName}?`,
      { confirmLabel: 'Approve', size: 'default' },
    )
    if (!ok) return
    setBusy(true)
    setApproveErrors([])
    try {
      const { revision } = await approveChangeSet(changeSetId, ownerId)
      toast.success(`Approved v${revision} of ${model.skill.displayName}.`)
      onDecided('approved', revision)
    } catch (e) {
      if (e instanceof OverrideApiError) {
        toast.error(e.message)
        if (e.details.length > 1) setApproveErrors(e.details)
        load() // re-read: the reason (stale, already decided) is now in the model.
      } else {
        toast.error(errorMessage(e, 'Could not approve the proposal.'))
      }
    } finally {
      setBusy(false)
    }
  }

  const reject = async () => {
    if (!model || busy) return
    const ok = await confirm(`Reject ${model.proposedLabel}? The plugin can propose again later.`, 'Reject this proposal?', { confirmLabel: 'Reject' })
    if (!ok) return
    setBusy(true)
    try {
      await rejectChangeSet(changeSetId, ownerId)
      toast.success('Proposal rejected.')
      onDecided('rejected')
    } catch (e) {
      toast.error(errorMessage(e, 'Could not reject the proposal.'))
    } finally {
      setBusy(false)
    }
  }

  const title = model ? `Skill: ${model.skill.displayName}` : 'Review a proposed skill version'
  const approveBlocked = !!model && (model.parts.some((p) => p.factoryChanged) || !!model.registryError)

  const footer = model && (
    <div className={styles.footer}>
      <button type="button" className="secondaryButton" onClick={onClose} disabled={busy}>
        Close
      </button>
      <button type="button" className="secondaryButton" onClick={() => void reject()} disabled={busy}>
        Reject
      </button>
      <button type="button" className="primaryButton" onClick={() => void approve()} disabled={busy || approveBlocked}>
        {busy ? <Loader2 size={12} className={styles.spin} /> : null} Approve {model.proposedLabel}
      </button>
    </div>
  )

  return (
    <Modal isOpen onClose={onClose} title={title} size="xlarge" closeOnOverlayClick={false} footer={footer}>
      {!model && !loadError && (
        <div className={styles.loading}>
          <Loader2 size={14} className={styles.spin} /> Loading the proposal…
        </div>
      )}
      {loadError && <div className={styles.block} role="alert">{loadError}</div>}
      {approveErrors.length > 0 && (
        <ul className={styles.block} role="alert" data-testid="approve-errors">
          {approveErrors.map((text, i) => (
            <li key={i}>{text}</li>
          ))}
        </ul>
      )}
      {model && <ReviewBody model={model} tab={tab} setTab={setTab} />}
    </Modal>
  )
}

function ReviewBody({ model, tab, setTab }: { model: ReviewModel; tab: number; setTab: (n: number) => void }) {
  const flagged = model.parts.flatMap((p) => p.riskFlags.map((r) => ({ partId: p.partId, ...r })))
  const part: ReviewPart | undefined = model.parts[tab]
  return (
    <div className={styles.body}>
      <div className={styles.header} data-testid="review-header">
        <span className={styles.vLine}>
          v{model.fromRevision} → {model.proposedLabel}
        </span>
        <span>proposed by</span>
        <PluginBadge label={model.plugin.displayName} />
      </div>
      <p className={styles.scope}>{model.scope.text}</p>

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
            <AlertTriangle size={14} aria-hidden /> Lines to look at before approving
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

      <div className={styles.tabs} role="tablist">
        {model.parts.map((p, i) => (
          <button
            key={p.partId}
            type="button"
            role="tab"
            aria-selected={i === tab}
            className={`${styles.tab} ${i === tab ? styles.tabActive : ''}`}
            onClick={() => setTab(i)}
          >
            {p.partId}
            {p.revertsToFactory && <span className={styles.revert}> · reverts to factory</span>}
            {p.riskFlags.length > 0 && <AlertTriangle size={11} className={styles.tabFlag} aria-label="has risk flags" />}
          </button>
        ))}
      </div>

      {part && (
        <TextDiff
          key={part.partId}
          before={part.before}
          after={part.after}
          beforeLabel={`v${model.activeRevision} (active)`}
          afterLabel={`${model.proposedLabel} (proposed)`}
          showPlaceholderLegend
        />
      )}
    </div>
  )
}
