import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { upstreamFailure } from '@/lib/routeErrors'
import { now } from './clock'

/**
 * The agent's registry of overridable built-in skill parts (TD-26, README.PLUGINS.md §7.6)
 * as the webapp reads it: `GET /plugins/skill-parts` (factory text, SHA-256, the
 * validator's limits) and `POST /plugins/skill-parts/validate` (the same rules the seam
 * applies at use). The factory text lives in the agent's image, so the agent is the only
 * source; the list is cached five minutes, a failure never.
 *
 * An agent that cannot answer (`agent_unreachable`) and one too old to have these
 * endpoints or their limits (`agent_outdated`) are told apart, because only a rebuild fixes
 * the second.
 */
const CACHE_MS = 5 * 60_000
const TIMEOUT_MS = 10_000
const SHA256_RE = /^[0-9a-f]{64}$/

export interface RegistryPart {
  partId: string
  constant: string
  kind: string
  placeholders: string[]
  sha256: string
  chars: number
  maxChars: number
  order: number
  gate: string
  text: string
}

export interface RegistrySkill {
  id: string
  /** The whole skill's limit (PLUGIN_SKILL_TEXT_MAX_GROWTH × its factory size). */
  maxChars: number
  parts: RegistryPart[]
}

export interface PartsValidation {
  ok: boolean
  parts: Record<string, { errors: string[]; chars: number; maxChars: number }>
  skill: { errors: string[]; chars: number; maxChars: number }
}

export type RegistryErrorCode = 'agent_unreachable' | 'agent_outdated' | 'unknown_skill'

/**
 * Why `agent_unreachable`: the agent's HTTP status when it answered with an error, else the
 * errno (or `timeout`) of a request that got no answer. Kept beside the message, which the
 * Gateway hands to plugins unchanged.
 */
export interface RegistryFailure {
  upstreamStatus?: number
  reason?: string
}

export class SkillPartsRegistryError extends Error {
  constructor(
    readonly code: RegistryErrorCode,
    message: string,
    readonly failure: RegistryFailure = {},
  ) {
    super(message)
    this.name = 'SkillPartsRegistryError'
  }
}

const unreachable = (failure: RegistryFailure = {}) =>
  new SkillPartsRegistryError('agent_unreachable', "The agent service isn't running", failure)

/** The failure in words for a person: an agent that answered with an error is not "not running". */
export function registryFailureText(e: SkillPartsRegistryError): string {
  if (e.code !== 'agent_unreachable') return e.message
  if (e.failure.upstreamStatus) return `The agent service answered HTTP ${e.failure.upstreamStatus}`
  if (e.failure.reason === 'timeout') return 'The agent service did not answer in time'
  return `The agent service could not be reached${e.failure.reason ? ` (${e.failure.reason})` : ''}`
}
const outdated = () => new SkillPartsRegistryError('agent_outdated', 'The agent is older than the webapp: rebuild it')

let cache: { at: number; skills: Map<string, RegistrySkill> } | null = null

/** Tests, and anything that knows the agent just changed. */
export function clearSkillPartsCache(): void {
  cache = null
}

async function call(path: string, init: RequestInit): Promise<{ status: number; body: unknown }> {
  let res: Response
  try {
    res = await agentFetch(path, init, { timeoutMs: TIMEOUT_MS })
  } catch (e) {
    if (e instanceof AgentUnreachableError) {
      const { body } = upstreamFailure('agent', e.cause_, '')
      const reason = body.code === 'agent_timeout' ? 'timeout' : body.cause
      console.warn(`[plugins] skill parts: the agent could not be reached (${path}${reason ? `, ${reason}` : ''})`)
      throw unreachable(reason ? { reason } : {})
    }
    throw e
  }
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  return { status: res.status, body }
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0

function parsePart(p: unknown): RegistryPart | null {
  if (!isObj(p)) return null
  const ok =
    typeof p.partId === 'string' &&
    typeof p.text === 'string' &&
    typeof p.sha256 === 'string' &&
    SHA256_RE.test(p.sha256) &&
    isCount(p.chars) &&
    isCount(p.maxChars) &&
    isCount(p.order) &&
    typeof p.kind === 'string' &&
    Array.isArray(p.placeholders)
  return ok ? (p as unknown as RegistryPart) : null
}

function parseRegistry(body: unknown): Map<string, RegistrySkill> | null {
  if (!isObj(body) || !Array.isArray(body.skills)) return null
  const skills = new Map<string, RegistrySkill>()
  for (const s of body.skills) {
    if (!isObj(s) || typeof s.id !== 'string' || !isCount(s.maxChars) || !Array.isArray(s.parts)) return null
    const parts = s.parts.map(parsePart)
    if (parts.some((p) => p === null)) return null
    skills.set(s.id, { id: s.id, maxChars: s.maxChars, parts: parts as RegistryPart[] })
  }
  return skills
}

async function registry(): Promise<Map<string, RegistrySkill>> {
  const t = now().getTime()
  if (cache && t - cache.at < CACHE_MS) return cache.skills
  const { status, body } = await call('/plugins/skill-parts', { method: 'GET' })
  if (status === 404) throw outdated()
  if (status < 200 || status >= 300) {
    console.warn(`[plugins] skill parts: the agent answered HTTP ${status}`)
    throw unreachable({ upstreamStatus: status })
  }
  const skills = parseRegistry(body)
  if (!skills) {
    console.error('[plugins] skill parts: the agent answered without the fields this webapp needs (maxChars): rebuild the agent')
    throw outdated()
  }
  cache = { at: t, skills }
  return skills
}

/** One skill's parts in assembly order, or null when the agent has no such skill. */
export async function registrySkill(skillId: string): Promise<RegistrySkill | null> {
  return (await registry()).get(skillId) ?? null
}

/** The agent's verdict on proposed values for parts of one skill, and on the whole skill they make. */
export async function validateSkillParts(skillId: string, parts: Record<string, string>): Promise<PartsValidation> {
  const { status, body } = await call('/plugins/skill-parts/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ skillId, parts }),
  })
  if (status === 404) {
    // The handler's own 404 names the skill; FastAPI's "Not Found" means no such route.
    if (isObj(body) && typeof body.error === 'string') throw new SkillPartsRegistryError('unknown_skill', body.error)
    throw outdated()
  }
  if (status < 200 || status >= 300) {
    console.warn(`[plugins] skill parts validate: the agent answered HTTP ${status}`)
    throw unreachable({ upstreamStatus: status })
  }
  if (!isObj(body) || typeof body.ok !== 'boolean' || !isObj(body.parts) || !isObj(body.skill)) throw outdated()
  return body as unknown as PartsValidation
}

export interface TextValidation {
  ok: boolean
  errors: string[]
}

/**
 * The agent's verdict on a proposed plain text against the text it replaces
 * (`POST /plugins/text/validate`): not empty, no NUL, at most `maxChars`, and no reserved
 * marker, RoE heading or hidden character that `baseText` did not already hold.
 */
export async function validatePlainText(text: string, baseText: string, maxChars: number): Promise<TextValidation> {
  const { status, body } = await call('/plugins/text/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, baseText, maxChars }),
  })
  if (status === 404) throw outdated()
  if (status < 200 || status >= 300) {
    console.warn(`[plugins] text validate: the agent answered HTTP ${status}`)
    throw unreachable({ upstreamStatus: status })
  }
  if (!isObj(body) || typeof body.ok !== 'boolean' || !Array.isArray(body.errors)) throw outdated()
  return { ok: body.ok, errors: body.errors.filter((e): e is string => typeof e === 'string') }
}
