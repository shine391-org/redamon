import { toApiError } from '@/lib/apiError'
import { pluginFeatureId } from '@/lib/llmFeatures'
import type { FeatureModelGateApi } from '@/components/shared/FeatureModelGate'
import type { ChatSessionActionContribution } from '@/lib/plugins/contributions'
import { PluginActionError, postPluginAction, readActionAnswer, type ActionContext } from './host/actionClient'
import type { SessionPick } from './SessionSkillPicker'

/** A running async plugin action, as the job modal needs it. */
export interface PluginJob {
  jobId: string
  pluginId: string
  displayName: string
  label: string
  /** The skill it works on, when the action asked the person to pick one. */
  skillName?: string | null
}

export interface PluginActionToast {
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

/**
 * What a gear-menu click reaches out to. The review and versions modals are built in later
 * steps; here they are injected handlers (step 6.4 passes placeholders, 6.5/6.6 the real
 * modals), so the click flow is testable on its own.
 */
export interface PluginActionHandlers {
  onReviewProposal: (changeSetId: string) => void
  onCoreScreen: (screen: string, context: ActionContext) => void
  onJob: (job: PluginJob) => void
  /** Opens the core's skill picker; null when the person cancels. */
  pickSessionSkill?: (plugin: { pluginId: string; displayName: string }, context: ActionContext) => Promise<SessionPick | null>
  /** Told what was picked, so a Retry replays the same pick. */
  onPicked?: (pick: SessionPick) => void
  toast: PluginActionToast
}

/**
 * The label a job window shows for a picked skill: the person's own skill says so. The kind
 * comes from the pick, or from its ref (`user_skill:<id>`) for a job that was already running.
 */
export function pickedSkillLabel(pick: { name: string | null; skillKind?: 'builtin' | 'user'; ref?: string }): string {
  if (pick.name === null) return 'a deleted skill'
  const user = pick.skillKind ? pick.skillKind === 'user' : !!pick.ref?.startsWith('user_skill:')
  return user ? `${pick.name} (your skill)` : pick.name
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

/**
 * Runs one chat-session action (design §6.7). A `coreScreen` item opens a core screen. An
 * action item that asks for a pick (`pick: "session.skill"`, platform 1.1.0) opens the core's
 * skill picker first (cancel aborts), unless `pick` replays an earlier one. Then: if it calls
 * a model, ask for one (cancel aborts); POST it with the session context and the pick; an
 * async answer opens the job modal; a sync result with a `reviewProposal` opens the review;
 * any other result shows its message. Without a pick only `{context}` is sent, as in 1.0.0.
 */
export async function runPluginAction(opts: {
  plugin: { pluginId: string; displayName: string }
  item: ChatSessionActionContribution
  context: ActionContext
  gate: Pick<FeatureModelGateApi, 'ensureFeatureModel'>
  handlers: PluginActionHandlers
  pick?: SessionPick | null
}): Promise<void> {
  const { plugin, item, context, gate, handlers } = opts

  if (item.coreScreen) {
    handlers.onCoreScreen(item.coreScreen, context)
    return
  }
  if (!item.action) return

  let pick: SessionPick | null = null
  if (item.pick === 'session.skill') {
    pick = opts.pick ?? (handlers.pickSessionSkill ? await handlers.pickSessionSkill(plugin, context) : null)
    if (!pick) return
    handlers.onPicked?.(pick)
  }

  if (item.llm) {
    const model = await gate.ensureFeatureModel(pluginFeatureId(plugin.pluginId), { label: plugin.displayName })
    if (!model) return
  }

  try {
    const body = pick ? { context, params: { pick: { kind: pick.kind, ref: pick.ref } } } : { context }
    const answer = await readActionAnswer(await postPluginAction(plugin.pluginId, item.action, body))
    if (answer.kind === 'job') {
      // One job per session: a running one wins, and says which skill it works on. One started
      // without a pick (an older client) chose its skill itself: the window names none.
      if (answer.existing && pick && answer.pick?.ref !== pick.ref) {
        handlers.toast.info(answer.pick
          ? `A job is already working on ${pickedSkillLabel(answer.pick)} in this session.`
          : 'A job is already running in this session; it works on the skill it chose itself.')
      }
      const skillName = answer.pick
        ? pickedSkillLabel(answer.pick)
        : pick && !answer.existing ? pickedSkillLabel(pick) : undefined
      handlers.onJob({
        jobId: answer.jobId,
        pluginId: plugin.pluginId,
        displayName: plugin.displayName,
        label: item.label,
        ...(skillName !== undefined ? { skillName } : {}),
      })
      return
    }
    handleResult(answer.result, handlers)
  } catch (e) {
    handlers.toast.error(e instanceof PluginActionError ? e.message : toApiError(e, 'The plugin action could not be run').message)
  }
}

/** A finished result: a change set to review, or a message to show. */
export function handleResult(result: Record<string, unknown>, handlers: Pick<PluginActionHandlers, 'onReviewProposal' | 'toast'>): void {
  const rp = result.reviewProposal
  if (isObj(rp) && typeof rp.changeSetId === 'string') {
    handlers.onReviewProposal(rp.changeSetId)
    return
  }
  if (typeof result.message === 'string' && result.message) handlers.toast.info(result.message)
  else handlers.toast.success('Done')
}
