import { readApiError, toApiError } from '@/lib/apiError'
import type { ReviewModel } from '@/lib/plugins/reviewModel'
import type { UserSkillReviewModel } from '@/lib/plugins/userSkillReviewModel'
import type { VersionsModel } from '@/lib/plugins/versionsModel'
import type { UserSkillVersionsModel } from '@/lib/plugins/userSkillVersionsModel'

/**
 * The browser side of the core override routes (design §6). A failure's message is
 * "reason (code · HTTP n)"; status 0 means no answer; `extra` is the answer's body
 * (`suggestion`, `errors`, `committed`), `details` its list of errors (over-limit texts).
 */
export class OverrideApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
    readonly extra: Record<string, unknown> = {},
    readonly details: string[] = [],
  ) {
    super(message)
    this.name = 'OverrideApiError'
  }
}

async function answer(res: Response): Promise<unknown> {
  if (!res.ok) {
    const err = await readApiError(res, 'The request failed')
    throw new OverrideApiError(err.code ?? `http_${res.status}`, err.message, res.status, err.body ?? {}, err.details ?? [])
  }
  return res.json().catch(() => null)
}

/** fetch, with a request that got no answer as an OverrideApiError (`network_error`, status 0). */
async function send(input: string, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(input, init)
  } catch (e) {
    const err = toApiError(e, 'RedAmon did not answer')
    throw new OverrideApiError(err.code ?? 'network_error', err.message, 0)
  }
}

const base = (changeSetId: string) => `/api/plugins/overrides/change-sets/${encodeURIComponent(changeSetId)}`

export async function fetchReviewModel(changeSetId: string, projectId?: string | null): Promise<ReviewModel | UserSkillReviewModel> {
  const qs = projectId ? `?${new URLSearchParams({ projectId })}` : ''
  return answer(await send(`${base(changeSetId)}${qs}`, { cache: 'no-store' })) as Promise<ReviewModel | UserSkillReviewModel>
}

export interface SaveUserSkillInput {
  scopeOwnerId: string | null
  name: string
  description: string | null
  projectId: string | null
  enableNew: boolean
  disableSource: boolean
  acknowledgedRiskLines: number
}

/** Save a user-skill proposal as a new skill (the approve route's user-skill branch). */
export async function saveUserSkillVersion(
  changeSetId: string,
  input: SaveUserSkillInput,
): Promise<{ skillId: string; name: string; version: number }> {
  const res = await send(`${base(changeSetId)}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  })
  return answer(res) as Promise<{ skillId: string; name: string; version: number }>
}

const post = (path: string, scopeOwnerId: string | null) =>
  send(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(scopeOwnerId ? { scopeOwnerId } : {}),
  })

export async function approveChangeSet(changeSetId: string, scopeOwnerId: string | null): Promise<{ revision: number }> {
  return answer(await post(`${base(changeSetId)}/approve`, scopeOwnerId)) as Promise<{ revision: number }>
}

export async function rejectChangeSet(changeSetId: string, scopeOwnerId: string | null): Promise<void> {
  await answer(await post(`${base(changeSetId)}/reject`, scopeOwnerId))
}

export async function deleteChangeSet(changeSetId: string): Promise<void> {
  await answer(await send(base(changeSetId), { method: 'DELETE' }))
}

export async function fetchVersions(group: string, projectId: string | null): Promise<VersionsModel> {
  const qs = new URLSearchParams({ point: 'skill.text', group })
  if (projectId) qs.set('projectId', projectId)
  return answer(await send(`/api/plugins/overrides/versions?${qs.toString()}`, { cache: 'no-store' })) as Promise<VersionsModel>
}

export async function fetchUserSkillVersions(skillId: string, projectId: string | null): Promise<UserSkillVersionsModel> {
  const qs = new URLSearchParams({ point: 'user_skill.text', group: skillId })
  if (projectId) qs.set('projectId', projectId)
  return answer(await send(`/api/plugins/overrides/versions?${qs.toString()}`, { cache: 'no-store' })) as Promise<UserSkillVersionsModel>
}

/** Deletes one of the user's own skills (with its waiting proposals and its toggles). */
export async function deleteUserSkill(userId: string, skillId: string): Promise<void> {
  await answer(await send(`/api/users/${encodeURIComponent(userId)}/attack-skills/${encodeURIComponent(skillId)}`, { method: 'DELETE' }))
}

export interface ResetInput {
  group: string
  scopeType: 'user' | 'project'
  scopeOwnerId?: string | null
  projectId?: string | null
}

export async function resetSkill(input: ResetInput): Promise<{ cleared: boolean }> {
  const res = await send('/api/plugins/overrides/reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      point: 'skill.text',
      group: input.group,
      scopeType: input.scopeType,
      ...(input.scopeOwnerId ? { scopeOwnerId: input.scopeOwnerId } : {}),
      ...(input.projectId ? { projectId: input.projectId } : {}),
    }),
  })
  return answer(res) as Promise<{ cleared: boolean }>
}
