/**
 * The limits and toggle rules of a user's own agent skills (uploaded `.md` workflows),
 * shared by every route that writes them, the project writers and the UI.
 *
 * Client-safe: it imports Prisma only as types, and the one function that reads the
 * database takes the client (or a transaction) from its caller.
 */
import type { Prisma } from '@prisma/client'

export const MAX_SKILLS_PER_USER = 1000
// Each enabled skill enters the classifier prompt, the per-turn skill menu and the agent's
// settings payload, so this bound is what keeps those as large as they were with the old
// cap of 20 skills per user.
export const MAX_ENABLED_USER_SKILLS_PER_PROJECT = 20
// In UTF-16 units. A chosen skill's whole text enters the agent's system prompt on every
// turn, so a file near this limit is ~125k tokens: past the context window of smaller models.
// agentic/skill_metadata.py CONTENT_MAX_CHARS and the plugin SDK's USER_SKILL_MAX_CHARS
// (services/plugin_runner/sdk/redamon_plugin_sdk/testing.py) must equal it.
export const MAX_CONTENT_SIZE = 500 * 1024
// A chat skill's text, in UTF-16 units; /skill sends it whole to the agent.
export const MAX_CHAT_SKILL_CONTENT_SIZE = 500 * 1024
export const NAME_MAX_CHARS = 100
export const DESCRIPTION_MAX_CHARS = 500
// One upload batch is one JSON body and one transaction under the per-user lock.
export const MAX_SKILLS_PER_BATCH = 50
// Binds before MAX_SKILLS_PER_BATCH once files are large (about 16 files near MAX_CONTENT_SIZE).
// Past the proxy's 10 MB Next truncates the body silently, so refuse it first with a clear 413.
export const MAX_SKILL_BATCH_BYTES = 8 * 1024 * 1024
// Skills per Generate-with-AI request: the dialog sends them one request at a time to show progress,
// and the agent's per-request timeout covers 5 skills run 3 at a time.
export const SKILL_METADATA_ITEMS_PER_REQUEST = 5
export const USER_SKILL_LIMIT_TEXT = `You have ${MAX_SKILLS_PER_USER} skills, the maximum. Delete one first.`

/** One item of a refused batch upload: its position in the request, the reason, and a free name when taken. */
export interface BatchItemRefusal { index: number; code: string; error: string; suggestion?: string }

export type NameCheckReason = 'name_invalid' | 'name_too_long' | 'name_taken' | 'name_duplicate'
/** The early answer for one name of a batch (userSkillNames.checkNames). */
export interface NameCheckResult { normalized: string; available: boolean; reason?: NameCheckReason; suggestion: string | null }

export interface AttackSkillConfig {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
}

/** A refusal with the HTTP status and code a route answers with. */
export class UserSkillError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message)
    this.name = 'UserSkillError'
  }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

function booleanMapError(value: unknown, path: string): string | null {
  if (!isPlainObject(value)) return `${path} must be an object`
  for (const [k, v] of Object.entries(value)) {
    if (typeof v !== 'boolean') return `${path}.${k} must be true or false`
  }
  return null
}

/**
 * The shape of `attackSkillConfig`, or what is wrong with it. `builtIn` is required: the
 * agent reads a missing one as "no built-in skill", so inventing it would change what runs.
 * `user` may be absent (it is created empty).
 */
export function attackSkillConfigShapeError(value: unknown): string | null {
  if (!isPlainObject(value)) return 'must be an object with builtIn and user maps'
  for (const key of Object.keys(value)) {
    if (key !== 'builtIn' && key !== 'user') return `has an unknown key '${key}' (only builtIn and user)`
  }
  if (!('builtIn' in value)) return 'must carry builtIn, the map of built-in skill toggles'
  const builtIn = booleanMapError(value.builtIn, 'builtIn')
  if (builtIn) return builtIn
  if (value.user !== undefined) return booleanMapError(value.user, 'user')
  return null
}

type SkillReader = { userAttackSkill: Pick<Prisma.TransactionClient['userAttackSkill'], 'findMany'> }

/**
 * The rules of a project's `user` toggle map, for a project owned by `ownerId`: ids the
 * owner does not have are dropped (they could never be seen or turned off), at most
 * MAX_ENABLED_USER_SKILLS_PER_PROJECT of the owner's skills are on, and none of them is
 * quarantined. Throws a UserSkillError. The map must already be an object of booleans.
 */
export async function normalizeUserToggleMap(
  db: SkillReader,
  ownerId: string | null | undefined,
  requested: Record<string, boolean>,
): Promise<Record<string, boolean>> {
  const ids = Object.keys(requested)
  const owned = ownerId && ids.length
    ? await db.userAttackSkill.findMany({
        where: { userId: ownerId, id: { in: ids } },
        select: { id: true, name: true, quarantinedAt: true },
      })
    : []
  const byId = new Map(owned.map((s) => [s.id, s]))
  const user: Record<string, boolean> = {}
  for (const id of ids) if (byId.has(id)) user[id] = requested[id]

  const enabled = Object.entries(user).filter(([, on]) => on).map(([id]) => byId.get(id)!)
  const quarantined = enabled.find((s) => s.quarantinedAt)
  if (quarantined) {
    throw new UserSkillError(409, 'skill_quarantined',
      `"${quarantined.name}" is quarantined and cannot be turned on until its owner releases it in Global Settings.`,
      { skillId: quarantined.id })
  }
  if (enabled.length > MAX_ENABLED_USER_SKILLS_PER_PROJECT) {
    throw new UserSkillError(409, 'too_many_enabled_skills',
      `A project can use at most ${MAX_ENABLED_USER_SKILLS_PER_PROJECT} of your skills; ` +
      `this turns on ${enabled.length}. Turn some off first.`,
      { limit: MAX_ENABLED_USER_SKILLS_PER_PROJECT, enabled: enabled.length })
  }
  return user
}

/**
 * `config` as it may be stored for a project owned by `ownerId`: the right shape (a missing
 * `builtIn` is refused, never filled in), and the `user` rules of normalizeUserToggleMap.
 * Throws a UserSkillError.
 */
export async function normalizeUserSkillToggles(
  db: SkillReader,
  ownerId: string | null | undefined,
  config: unknown,
): Promise<AttackSkillConfig> {
  const shape = attackSkillConfigShapeError(config)
  if (shape) throw new UserSkillError(400, 'invalid_attack_skill_config', `attackSkillConfig ${shape}`)
  const raw = config as { builtIn: Record<string, boolean>; user?: Record<string, boolean> }
  return { builtIn: { ...raw.builtIn }, user: await normalizeUserToggleMap(db, ownerId, raw.user ?? {}) }
}

/**
 * An imported `attackSkillConfig` (a project bundle or a preset from another account),
 * made storable without refusing the import: user ids the new owner does not have are
 * dropped first, then owned skills beyond the enabled bound (by name, then id) and
 * quarantined ones are turned off. An unusable shape yields `value: undefined`, for the
 * caller to leave the column at its default. Each change is counted for a warning.
 */
export async function trimImportedSkillToggles(
  db: SkillReader,
  ownerId: string,
  config: unknown,
): Promise<{ value: AttackSkillConfig | undefined; dropped: number; turnedOff: number; invalid: boolean }> {
  if (attackSkillConfigShapeError(config)) return { value: undefined, dropped: 0, turnedOff: 0, invalid: true }
  const raw = config as { builtIn: Record<string, boolean>; user?: Record<string, boolean> }
  const requested = raw.user ?? {}
  const ids = Object.keys(requested)
  const owned = ids.length
    ? await db.userAttackSkill.findMany({
        where: { userId: ownerId, id: { in: ids } },
        select: { id: true, name: true, quarantinedAt: true },
      })
    : []
  const byId = new Map(owned.map((s) => [s.id, s]))
  const user: Record<string, boolean> = {}
  for (const id of ids) if (byId.has(id)) user[id] = requested[id]
  const on = Object.keys(user).filter((id) => user[id]).map((id) => byId.get(id)!)
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.id < b.id ? -1 : 1))
  let kept = 0
  let turnedOff = 0
  for (const s of on) {
    if (s.quarantinedAt || kept >= MAX_ENABLED_USER_SKILLS_PER_PROJECT) {
      user[s.id] = false
      turnedOff++
    } else {
      kept++
    }
  }
  // Only the foreign ids that were ON are worth a warning: an OFF one changed nothing.
  const dropped = ids.filter((id) => !byId.has(id) && requested[id] === true).length
  return { value: { builtIn: { ...raw.builtIn }, user }, dropped, turnedOff, invalid: false }
}

/** The import warnings for what trimImportedSkillToggles changed. */
export function skillToggleWarnings(t: { dropped: number; turnedOff: number; invalid: boolean }, what: string): string[] {
  const out: string[] = []
  if (t.invalid) out.push(`The ${what}'s skill toggles were unreadable; the defaults are used.`)
  if (t.dropped) out.push(`The ${what} turned on ${t.dropped} user skill(s) this account does not have; they were left out.`)
  if (t.turnedOff) {
    out.push(`The ${what} had more of your skills on than a project may use (${MAX_ENABLED_USER_SKILLS_PER_PROJECT}), ` +
      `or a quarantined one; ${t.turnedOff} were turned off.`)
  }
  return out
}
