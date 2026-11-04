import * as ov from './overrides'
import { skillDisplayName } from './overrideOps'
import { dormantReason, findInstall, type DormantReason } from './registry'
import { addedRiskLines, type RiskLine } from './riskFlags'
import { SkillPartsRegistryError, clearSkillPartsCache, registryFailureText, registrySkill, type RegistrySkill } from './skillPartsRegistry'
import { buildUserSkillReviewModel, type UserSkillReviewModel } from './userSkillReviewModel'

/**
 * What the core review modal shows for one change set (design §6 core override routes;
 * README.PLUGINS.md §7.5). Built on the server from the store and the agent's registry read
 * WITHOUT its cache, so what the person sees is what approval will check (phase-04 review).
 *
 * A version is a whole snapshot (TD-19): approving makes exactly the proposed parts run, so a
 * part the active version changes but the proposal does not reverts to factory text, and the
 * review shows that too.
 */
export interface ReviewPart {
  partId: string
  kind: string
  placeholders: string[]
  /** What runs now: the active version's text for this part, else the factory text. */
  before: string
  /** What would run after approval: the proposed text, or the factory text (revertsToFactory). */
  after: string
  revertsToFactory: boolean
  /** RedAmon's factory text for this part changed since the proposal was built on it. */
  factoryChanged: boolean
  riskFlags: RiskLine[]
}

export interface ReviewModel {
  changeSetId: string
  status: ov.OverrideStatus
  staleReason: ov.StaleReason | null
  plugin: { pluginId: string; displayName: string }
  skill: { id: string; displayName: string }
  scope: { type: ov.ScopeType; ownerId: string; text: string }
  /** The scope's active revision when the proposal was made (recorded by the platform). */
  fromRevision: number
  /** The scope's active revision now (1 = factory text). */
  activeRevision: number
  /** fromRevision ≠ activeRevision: approving discards the versions approved since (RV-25). */
  baseOutdated: boolean
  proposedLabel: string
  parts: ReviewPart[]
  note: string | null
  meta: Record<string, unknown>
  /** The active version approval would replace, when there is one. */
  replaces: { pluginId: string; displayName: string; revision: number | null } | null
  /** Why an approved version would not reach the agent now, if it would not (RV-26). */
  dormantReason: DormantReason | null
  /** Change sets still waiting in the proposal's own scope (including this one, if pending). */
  pendingCount: number
  /** The agent registry could not be read: factory texts are unknown, approval will refuse. */
  registryError: 'agent_unreachable' | 'agent_outdated' | null
  /** With a registryError: why, in words (the agent's HTTP status, or the errno of no answer). */
  registryErrorText?: string
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)

async function displayNameOf(pluginId: string): Promise<string> {
  const row = await findInstall(pluginId)
  const m = row?.manifest
  return isObj(m) && typeof m.displayName === 'string' && m.displayName ? m.displayName : pluginId
}

export function scopeText(type: ov.ScopeType): string {
  return type === 'user' ? 'Applies to every project you own' : 'Applies to this project only'
}

/**
 * The review model of a change set, or null when there is no such set. A `user_skill.text`
 * set has its own model (userSkillReviewModel.ts), told apart by `kind`; `projectId` is the
 * project the review was opened from, for its skill toggles.
 */
export async function buildReviewModel(
  changeSetId: string,
  opts: { projectId?: string | null } = {},
): Promise<ReviewModel | UserSkillReviewModel | null> {
  const set = await ov.getChangeSet(changeSetId)
  if (!set) return null
  if (set.point === ov.USER_SKILL_POINT) return buildUserSkillReviewModel(set, opts)
  const point = set.point
  const group = set.targetGroup

  let skill: RegistrySkill | null = null
  let registryError: ReviewModel['registryError'] = null
  let registryErrorText: string | null = null
  try {
    clearSkillPartsCache()
    skill = await registrySkill(group)
  } catch (e) {
    if (e instanceof SkillPartsRegistryError && (e.code === 'agent_unreachable' || e.code === 'agent_outdated')) {
      registryError = e.code
      registryErrorText = registryFailureText(e)
    } else throw e
  }
  const factory = new Map((skill?.parts ?? []).map((p) => [p.partId, p]))

  const [active, last, pending, install] = await Promise.all([
    ov.activeChangeSet(set.scope, point, group),
    ov.lastRevision(set.scope, point, group),
    ov.pendingCount(set.scope, point, group),
    findInstall(set.pluginId),
  ])
  // A set reviewed while it is itself the active version (a stale one being re-approved) is
  // compared with the factory, not with itself.
  const current = active && active.changeSetId !== set.changeSetId ? active : null
  const activeValue = new Map((current?.parts ?? []).map((p) => [p.partId, p.value]))
  const factoryText = (partId: string) => factory.get(partId)?.text ?? ''

  const meta = isObj(set.meta) ? set.meta : {}
  const fromRevision = typeof meta.fromRevision === 'number' ? meta.fromRevision : ov.FACTORY_REVISION
  const activeRevision = current?.revision ?? ov.FACTORY_REVISION

  const parts: ReviewPart[] = []
  const proposed = new Set(set.parts.map((p) => p.partId))
  for (const p of set.parts) {
    const reg = factory.get(p.partId)
    const before = activeValue.get(p.partId) ?? factoryText(p.partId)
    parts.push({
      partId: p.partId,
      kind: reg?.kind ?? 'unknown',
      placeholders: reg?.placeholders ?? [],
      before,
      after: p.value,
      revertsToFactory: false,
      factoryChanged: !!reg && reg.sha256 !== p.baseSha256,
      riskFlags: addedRiskLines(before, p.value),
    })
  }
  for (const [partId, value] of activeValue) {
    if (proposed.has(partId)) continue
    const reg = factory.get(partId)
    parts.push({
      partId,
      kind: reg?.kind ?? 'unknown',
      placeholders: reg?.placeholders ?? [],
      before: value,
      after: factoryText(partId),
      revertsToFactory: true,
      factoryChanged: false,
      riskFlags: [],
    })
  }
  const order = new Map((skill?.parts ?? []).map((p) => [p.partId, p.order]))
  parts.sort((a, b) => (order.get(a.partId) ?? 1e9) - (order.get(b.partId) ?? 1e9) || a.partId.localeCompare(b.partId))

  const replaces = current
    ? { pluginId: current.pluginId, displayName: await displayNameOf(current.pluginId), revision: current.revision }
    : null

  return {
    changeSetId: set.changeSetId,
    status: set.status,
    staleReason: set.staleReason,
    plugin: { pluginId: set.pluginId, displayName: await displayNameOf(set.pluginId) },
    skill: { id: group, displayName: skillDisplayName(group) },
    scope: { type: set.scope.type, ownerId: set.scope.id, text: scopeText(set.scope.type) },
    fromRevision,
    activeRevision,
    baseOutdated: fromRevision !== activeRevision,
    proposedLabel: set.status === 'stale' && set.revision ? `v${set.revision}` : `v${last + 1}`,
    parts,
    note: set.note,
    meta,
    replaces,
    dormantReason: dormantReason(install, { agentSupportsSeam: registryError !== 'agent_outdated' }),
    pendingCount: pending,
    registryError,
    ...(registryErrorText ? { registryErrorText } : {}),
  }
}
