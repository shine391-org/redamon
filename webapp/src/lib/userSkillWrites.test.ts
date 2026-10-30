/**
 * Every write of a user's own agent skills (plan 0.C, 0.D, 4.10, 4.11): one transaction
 * under the per-user advisory lock, the name/cap/content rules, audits that hold names and
 * content hashes but never the text, and a delete that leaves no toggle or pending proposal
 * pointing at a skill that is gone.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { createHash } from 'crypto'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { MAX_CONTENT_SIZE, UserSkillError } from './userSkills'
import {
  USER_SKILL_SELECT,
  auditActorFor,
  contentSha16,
  contentSha256,
  createUserSkill,
  deleteUserSkill,
  pendingProposalCount,
  releaseUserSkill,
  updateUserSkill,
  userSkillErrorResponse,
} from './userSkillWrites'

let db: FakePrisma
const ALICE = auditActorFor('alice', 'alice')
const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

/** Records what each transaction does to `project`, optionally failing a write. */
function instrumentProjects(fail?: () => boolean) {
  const writes: string[] = []
  const tx = db.$transaction.bind(db)
  ;(db as unknown as Record<string, unknown>).$transaction = (fn: (t: FakePrisma) => Promise<unknown>) =>
    tx(async (t) => {
      const p = t.project as unknown as Record<string, (a: unknown) => Promise<unknown>>
      const update = p.update
      const updateMany = p.updateMany
      p.update = async (a) => {
        writes.push('update')
        if (fail?.()) throw new Error('disk full')
        return update(a)
      }
      p.updateMany = async (a) => {
        writes.push('updateMany')
        return updateMany(a)
      }
      return fn(t)
    })
  return writes
}

function seedSkill(row: Record<string, unknown>) {
  db.seed('userAttackSkill', [{ userId: 'alice', content: 'Original text', ...row }])
}

function proposal(row: Record<string, unknown>) {
  return {
    pluginId: 'skiller',
    extensionPoint: 'user_skill.text',
    scopeType: 'user',
    scopeId: 'alice',
    userId: 'alice',
    value: 'Proposed text',
    baseSha256: 'a'.repeat(64),
    status: 'proposed',
    createdBy: 'alice',
    ...row,
    targetKey: `${row.targetGroup}/body`,
  }
}

async function refusal(p: Promise<unknown>): Promise<UserSkillError> {
  const e = await p.then(() => null, (err) => err)
  expect(e).toBeInstanceOf(UserSkillError)
  return e as UserSkillError
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.audits = []
})

describe('auditActorFor', () => {
  test('the owner acting: no onBehalfOf', () => {
    expect(auditActorFor('alice', 'alice')).toEqual({ actorId: 'alice', source: 'ui' })
  })

  test('an admin writing for another user records the owner', () => {
    expect(auditActorFor('admin1', 'alice', 'api')).toEqual({ actorId: 'admin1', onBehalfOf: 'alice', source: 'api' })
  })

  test('no session user (an internal caller) is the system', () => {
    expect(auditActorFor(null, 'alice')).toEqual({ actorId: null, source: 'system' })
    expect(auditActorFor(undefined, 'alice', 'api')).toEqual({ actorId: null, source: 'system' })
  })
})

describe('contentSha16', () => {
  test("matches the value the agent's test pins for the same text (D6)", () => {
    // agentic/tests/test_skill_parts_seam.py USER_SHA16: a mismatch would mark every
    // session as having run an older text.
    expect(contentSha16('Probe the login form — then report the finding ✓')).toBe('173fa6f54eba794c')
    expect(contentSha256('abc')).toBe(sha('abc'))
  })
})

describe('createUserSkill', () => {
  test('stores the normalized name and answers without the text', async () => {
    const out = await createUserSkill({ userId: 'alice', name: '  My\t\tSQLi   flow ', description: '  Probes a form. ', content: 'Step 1' }, ALICE)
    expect(Object.keys(out).sort()).toEqual(Object.keys(USER_SKILL_SELECT).sort())
    expect(out).not.toHaveProperty('content')
    expect(out.name).toBe('My SQLi flow')
    const [row] = db.rows('userAttackSkill')
    expect(row).toMatchObject({ userId: 'alice', name: 'My SQLi flow', description: 'Probes a form.', content: 'Step 1', version: null, lineageRootId: null })
  })

  test('holds the per-user advisory lock', async () => {
    await createUserSkill({ userId: 'alice', name: 'A', content: 'x' }, ALICE)
    expect(db.rawCalls.some((c) => /pg_advisory_xact_lock\(hashtext\(\?\)\)/.test(c.sql) && c.values[0] === 'user_attack_skills:alice')).toBe(true)
  })

  test('a taken name (by case and spacing) is 409 name_taken with the next version as suggestion', async () => {
    seedSkill({ id: 'existing', name: 'My SQLi flow' })
    const e = await refusal(createUserSkill({ userId: 'alice', name: 'my  sqli FLOW', content: 'x' }, ALICE))
    expect(e.status).toBe(409)
    expect(e.code).toBe('name_taken')
    expect(e.extra).toEqual({ suggestion: 'my sqli FLOW v2' })
    expect(db.rows('userAttackSkill')).toHaveLength(1)
    expect(h.audits).toEqual([])
  })

  test("another user's name is free", async () => {
    seedSkill({ id: 'b1', userId: 'bob', name: 'Shared name' })
    await createUserSkill({ userId: 'alice', name: 'Shared name', content: 'x' }, ALICE)
    expect(db.rows('userAttackSkill')).toHaveLength(2)
  })

  test('the 1000th skill is accepted, the 1001st is 409 skill_limit', async () => {
    db.seed('userAttackSkill', Array.from({ length: 999 }, (_, i) => ({ userId: 'alice', name: `S${i}`, content: 'x' })))
    await createUserSkill({ userId: 'alice', name: 'Number 1000', content: 'x' }, ALICE)
    const e = await refusal(createUserSkill({ userId: 'alice', name: 'Number 1001', content: 'x' }, ALICE))
    expect(e.status).toBe(409)
    expect(e.code).toBe('skill_limit')
    expect(e.extra).toEqual({ limit: 1000 })
    expect(db.rows('userAttackSkill')).toHaveLength(1000)
  })

  test("another user's skills do not count toward the cap", async () => {
    db.seed('userAttackSkill', Array.from({ length: 1000 }, (_, i) => ({ userId: 'bob', name: `S${i}`, content: 'x' })))
    await createUserSkill({ userId: 'alice', name: 'Mine', content: 'x' }, ALICE)
  })

  test.each([
    ['empty', ''],
    ['whitespace only', ' \n\t '],
    ['not a string', 42],
    ['missing', undefined],
  ])('content %s is 400 content_required', async (_label, content) => {
    const e = await refusal(createUserSkill({ userId: 'alice', name: 'A', content }, ALICE))
    expect(e.status).toBe(400)
    expect(e.code).toBe('content_required')
  })

  test('content of exactly MAX_CONTENT_SIZE passes, one character more is content_too_large', async () => {
    await createUserSkill({ userId: 'alice', name: 'Fits', content: 'x'.repeat(MAX_CONTENT_SIZE) }, ALICE)
    const e = await refusal(createUserSkill({ userId: 'alice', name: 'Too big', content: 'x'.repeat(MAX_CONTENT_SIZE + 1) }, ALICE))
    expect(e.status).toBe(400)
    expect(e.code).toBe('content_too_large')
  })

  test('a description of 500 passes, 501 is description_too_long; blank is stored as null', async () => {
    await createUserSkill({ userId: 'alice', name: 'D500', content: 'x', description: 'd'.repeat(500) }, ALICE)
    const e = await refusal(createUserSkill({ userId: 'alice', name: 'D501', content: 'x', description: 'd'.repeat(501) }, ALICE))
    expect(e.status).toBe(400)
    expect(e.code).toBe('description_too_long')
    await createUserSkill({ userId: 'alice', name: 'Blank', content: 'x', description: '   ' }, ALICE)
    expect(db.rows('userAttackSkill').find((r) => r.name === 'Blank')!.description).toBeNull()
  })

  test('a description that is not a string is description_invalid', async () => {
    expect((await refusal(createUserSkill({ userId: 'alice', name: 'A', content: 'x', description: 5 }, ALICE))).code).toBe('description_invalid')
  })

  test.each([
    ['empty', '   ', 'name_invalid'],
    ['not a string', 7, 'name_invalid'],
    ['missing', undefined, 'name_invalid'],
    ['101 characters', 'n'.repeat(101), 'name_too_long'],
    ['a control character', 'My\u0007flow', 'name_invalid'],
    ['a bidi override', 'My\u202Eflow', 'name_invalid'],
  ])('a name that is %s is refused (%s)', async (_label, name, code) => {
    const e = await refusal(createUserSkill({ userId: 'alice', name, content: 'x' }, ALICE))
    expect(e.status).toBe(400)
    expect(e.code).toBe(code)
    expect(db.rows('userAttackSkill')).toHaveLength(0)
  })

  test('audits user_attack_skill.create with the name and content hash, never the text', async () => {
    const content = 'SECRET-WORKFLOW-BODY: probe http://target.example.invalid/login'
    const out = await createUserSkill({ userId: 'alice', name: 'Audited', content }, ALICE)
    expect(h.audits).toHaveLength(1)
    expect(h.audits[0]).toEqual({
      actorId: 'alice',
      action: 'user_attack_skill.create',
      targetType: 'user_attack_skill',
      targetId: out.id,
      after: { name: 'Audited', contentSha256: sha(content), userId: 'alice' },
      source: 'ui',
    })
    expect(JSON.stringify(h.audits)).not.toContain('SECRET-WORKFLOW-BODY')
  })

  test('an admin writing for the owner is audited with onBehalfOf', async () => {
    await createUserSkill({ userId: 'alice', name: 'By admin', content: 'x' }, auditActorFor('admin1', 'alice'))
    expect(h.audits[0]).toMatchObject({ actorId: 'admin1', after: { onBehalfOf: 'alice', userId: 'alice' } })
  })

  test('two parallel creates of the same name: exactly one succeeds (the per-user lock)', async () => {
    const results = await Promise.allSettled([
      createUserSkill({ userId: 'alice', name: 'Race', content: 'one' }, ALICE),
      createUserSkill({ userId: 'alice', name: 'race', content: 'two' }, ALICE),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    const lost = results.find((r) => r.status === 'rejected') as PromiseRejectedResult
    expect(lost.reason).toBeInstanceOf(UserSkillError)
    expect(lost.reason.code).toBe('name_taken')
    expect(db.rows('userAttackSkill')).toHaveLength(1)
  })

  test('two parallel creates for the last free slot: exactly one succeeds', async () => {
    db.seed('userAttackSkill', Array.from({ length: 999 }, (_, i) => ({ userId: 'alice', name: `S${i}`, content: 'x' })))
    const results = await Promise.allSettled([
      createUserSkill({ userId: 'alice', name: 'Left', content: 'x' }, ALICE),
      createUserSkill({ userId: 'alice', name: 'Right', content: 'x' }, ALICE),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect((results.find((r) => r.status === 'rejected') as PromiseRejectedResult).reason.code).toBe('skill_limit')
    expect(db.rows('userAttackSkill')).toHaveLength(1000)
  })
})

describe('updateUserSkill', () => {
  beforeEach(() => {
    seedSkill({ id: 'mine', name: 'My flow', description: 'Old', lineageRootId: 'root0', version: 2, derivedFromId: 'root0', originPluginId: 'skiller', originPluginVersion: '1.1.0', originChangeSetId: 'cs-origin' })
    seedSkill({ id: 'other', name: 'Other flow' })
    seedSkill({ id: 'bobs', userId: 'bob', name: 'Bob flow' })
  })

  test('an unknown or foreign skill is 404 not_found', async () => {
    expect((await refusal(updateUserSkill({ userId: 'alice', skillId: 'nope', name: 'X' }, ALICE))).status).toBe(404)
    const e = await refusal(updateUserSkill({ userId: 'alice', skillId: 'bobs', name: 'X' }, ALICE))
    expect(e.code).toBe('not_found')
    expect(db.rows('userAttackSkill').find((r) => r.id === 'bobs')!.name).toBe('Bob flow')
  })

  test('a name sent unchanged is not checked again: a duplicate stored before the rules can still be edited', async () => {
    seedSkill({ id: 'dup', name: 'Other flow', content: 'Dup text' })
    const out = await updateUserSkill({ userId: 'alice', skillId: 'dup', name: 'Other flow', description: 'Now described' }, ALICE)
    expect(out).toMatchObject({ name: 'Other flow', description: 'Now described' })
  })

  test('a rename to a taken name is refused with a suggestion; nothing changes', async () => {
    const e = await refusal(updateUserSkill({ userId: 'alice', skillId: 'mine', name: 'other  FLOW', content: 'New text' }, ALICE))
    expect(e.status).toBe(409)
    expect(e.code).toBe('name_taken')
    expect(typeof e.extra.suggestion).toBe('string')
    expect(db.rows('userAttackSkill').find((r) => r.id === 'mine')).toMatchObject({ name: 'My flow', content: 'Original text' })
  })

  test('a rename to its own name with another case is allowed', async () => {
    const out = await updateUserSkill({ userId: 'alice', skillId: 'mine', name: 'MY  FLOW' }, ALICE)
    expect(out.name).toBe('MY FLOW')
  })

  test.each([['empty', ''], ['whitespace', '  \n ']])('%s content is refused (content_required)', async (_label, content) => {
    const e = await refusal(updateUserSkill({ userId: 'alice', skillId: 'mine', content }, ALICE))
    expect(e.code).toBe('content_required')
    expect(db.rows('userAttackSkill').find((r) => r.id === 'mine')!.content).toBe('Original text')
  })

  test('content over MAX_CONTENT_SIZE is refused', async () => {
    expect((await refusal(updateUserSkill({ userId: 'alice', skillId: 'mine', content: 'x'.repeat(MAX_CONTENT_SIZE + 1) }, ALICE))).code)
      .toBe('content_too_large')
  })

  test('an empty description clears it; an absent one leaves it', async () => {
    await updateUserSkill({ userId: 'alice', skillId: 'mine', content: 'New' }, ALICE)
    expect(db.rows('userAttackSkill').find((r) => r.id === 'mine')!.description).toBe('Old')
    await updateUserSkill({ userId: 'alice', skillId: 'mine', description: '' }, ALICE)
    expect(db.rows('userAttackSkill').find((r) => r.id === 'mine')!.description).toBeNull()
  })

  test('lineage, provenance and quarantine are never writable', async () => {
    await updateUserSkill({
      userId: 'alice', skillId: 'mine', name: 'Renamed',
      lineageRootId: 'evil', version: 99, derivedFromId: 'evil', originPluginId: 'evil', originPluginVersion: '9',
      originChangeSetId: 'evil', quarantinedAt: new Date(), quarantineReason: 'x',
    } as never, ALICE)
    expect(db.rows('userAttackSkill').find((r) => r.id === 'mine')).toMatchObject({
      name: 'Renamed', userId: 'alice', lineageRootId: 'root0', version: 2, derivedFromId: 'root0',
      originPluginId: 'skiller', originPluginVersion: '1.1.0', originChangeSetId: 'cs-origin',
      quarantinedAt: null, quarantineReason: null,
    })
  })

  test('audits user_attack_skill.update with before/after hashes and the changed fields', async () => {
    await updateUserSkill({ userId: 'alice', skillId: 'mine', name: 'Renamed', content: 'New text', description: 'Old' }, auditActorFor('admin1', 'alice'))
    expect(h.audits).toEqual([{
      actorId: 'admin1',
      action: 'user_attack_skill.update',
      targetType: 'user_attack_skill',
      targetId: 'mine',
      before: { name: 'My flow', contentSha256: sha('Original text') },
      after: { name: 'Renamed', contentSha256: sha('New text'), changed: ['name', 'content'], onBehalfOf: 'alice' },
      source: 'ui',
    }])
    expect(JSON.stringify(h.audits)).not.toContain('New text')
  })

  test('an update with nothing to change writes nothing and audits changed: []', async () => {
    const before = db.rows('userAttackSkill').find((r) => r.id === 'mine')!
    await updateUserSkill({ userId: 'alice', skillId: 'mine' }, ALICE)
    expect(db.rows('userAttackSkill').find((r) => r.id === 'mine')).toEqual(before)
    expect((h.audits[0].after as Record<string, unknown>).changed).toEqual([])
  })
})

describe('deleteUserSkill', () => {
  const CS = {
    proposed: '11111111-1111-4111-8111-111111111111',
    rejected: '22222222-2222-4222-8222-222222222222',
    adopted: '33333333-3333-4333-8333-333333333333',
    otherSkill: '44444444-4444-4444-8444-444444444444',
    otherUser: '55555555-5555-4555-8555-555555555555',
    builtInPoint: '66666666-6666-4666-8666-666666666666',
  }

  beforeEach(() => {
    seedSkill({ id: 'sk_target', name: 'Target', content: 'Target text' })
    seedSkill({ id: 'sk_keep', name: 'Keep' })
    seedSkill({ id: 'sk_bob', userId: 'bob', name: 'Bob skill' })
    db.seed('project', [
      { id: 'p1', userId: 'alice', attackSkillConfig: { builtIn: { xss: true }, user: { sk_target: true, sk_keep: false } } },
      { id: 'p2', userId: 'alice', attackSkillConfig: { builtIn: { xss: false }, user: { sk_keep: true } } },
      { id: 'p3', userId: 'alice', attackSkillConfig: { builtIn: {} } },
      { id: 'p4', userId: 'alice', attackSkillConfig: { builtIn: {}, user: { sk_target: false } } },
      { id: 'p_bob', userId: 'bob', attackSkillConfig: { builtIn: {}, user: { sk_target: true } } },
    ])
    db.seed('pluginOverride', [
      proposal({ targetGroup: 'sk_target', changeSetId: CS.proposed }),
      proposal({ targetGroup: 'sk_target', changeSetId: CS.rejected, status: 'rejected', pluginId: 'other-plugin' }),
      proposal({ targetGroup: 'sk_target', changeSetId: CS.adopted, status: 'adopted' }),
      proposal({ targetGroup: 'sk_keep', changeSetId: CS.otherSkill }),
      proposal({ targetGroup: 'sk_target', changeSetId: CS.otherUser, scopeId: 'bob', userId: 'bob' }),
      proposal({ targetGroup: 'sk_target', changeSetId: CS.builtInPoint, extensionPoint: 'skill.text' }),
    ])
  })

  test("removes the skill, its toggle in each owner project that names it, and its non-adopted proposals", async () => {
    const writes = instrumentProjects()
    const out = await deleteUserSkill({ userId: 'alice', skillId: 'sk_target' }, ALICE)
    expect(out).toEqual({ deletedProposals: 2, projectsUpdated: 2 })

    expect(db.rows('userAttackSkill').map((r) => r.id).sort()).toEqual(['sk_bob', 'sk_keep'])
    const config = (id: string) => db.rows('project').find((p) => p.id === id)!.attackSkillConfig
    expect(config('p1')).toEqual({ builtIn: { xss: true }, user: { sk_keep: false } })
    expect(config('p4')).toEqual({ builtIn: {}, user: {} })
    expect(config('p2')).toEqual({ builtIn: { xss: false }, user: { sk_keep: true } })
    expect(config('p3')).toEqual({ builtIn: {} })
    expect(config('p_bob')).toEqual({ builtIn: {}, user: { sk_target: true } })
    // update bumps updatedAt, so a form holding the old map is refused as stale.
    expect(writes).toEqual(['update', 'update'])

    expect(db.rows('pluginOverride').map((r) => r.changeSetId).sort())
      .toEqual([CS.adopted, CS.otherSkill, CS.otherUser, CS.builtInPoint].sort())
  })

  test('audits each deleted set as plugin.override.delete (source_deleted), then the skill', async () => {
    await deleteUserSkill({ userId: 'alice', skillId: 'sk_target' }, auditActorFor('admin1', 'alice'))
    const sets = h.audits.filter((a) => a.action === 'plugin.override.delete')
    expect(sets.map((a) => a.targetId).sort()).toEqual([CS.proposed, CS.rejected].sort())
    for (const a of sets) {
      expect(a).toMatchObject({
        actorId: 'admin1',
        targetType: 'plugin_change_set',
        after: { point: 'user_skill.text', targetGroup: 'sk_target', scope: 'user', scopeId: 'alice', reason: 'source_deleted', onBehalfOf: 'alice' },
      })
    }
    expect(sets.find((a) => a.targetId === CS.rejected)!.after).toMatchObject({ pluginId: 'other-plugin' })
    expect(h.audits.at(-1)).toEqual({
      actorId: 'admin1',
      action: 'user_attack_skill.delete',
      targetType: 'user_attack_skill',
      targetId: 'sk_target',
      before: { name: 'Target', contentSha256: sha('Target text') },
      after: { deletedProposals: 2, projectsUpdated: 2, onBehalfOf: 'alice' },
      source: 'ui',
    })
    expect(JSON.stringify(h.audits)).not.toContain('Target text')
  })

  test('takes the per-user lock before the override scope lock', async () => {
    await deleteUserSkill({ userId: 'alice', skillId: 'sk_target' }, ALICE)
    const keys = db.rawCalls.filter((c) => c.sql.includes('pg_advisory_xact_lock')).map((c) => c.values[0])
    const user = keys.indexOf('user_attack_skills:alice')
    const scope = keys.indexOf('override:user_skill.text:user:alice:sk_target')
    expect(user).toBeGreaterThanOrEqual(0)
    expect(scope).toBeGreaterThan(user)
  })

  test('an unknown or foreign skill is 404 and nothing changes', async () => {
    const before = { skills: db.rows('userAttackSkill'), overrides: db.rows('pluginOverride'), projects: db.rows('project') }
    expect((await refusal(deleteUserSkill({ userId: 'alice', skillId: 'sk_bob' }, ALICE))).status).toBe(404)
    expect((await refusal(deleteUserSkill({ userId: 'alice', skillId: 'nope' }, ALICE))).code).toBe('not_found')
    expect({ skills: db.rows('userAttackSkill'), overrides: db.rows('pluginOverride'), projects: db.rows('project') }).toEqual(before)
    expect(h.audits).toEqual([])
  })

  test('one transaction: a failing project write leaves the skill and its proposals in place', async () => {
    instrumentProjects(() => true)
    await expect(deleteUserSkill({ userId: 'alice', skillId: 'sk_target' }, ALICE)).rejects.toThrow('disk full')
    expect(db.rows('userAttackSkill').some((r) => r.id === 'sk_target')).toBe(true)
    expect(db.rows('pluginOverride')).toHaveLength(6)
    expect(h.audits).toEqual([])
  })

  test('a skill with no proposals and no projects naming it', async () => {
    db.seed('userAttackSkill', [{ id: 'sk_lonely', userId: 'alice', name: 'Lonely', content: 'x' }])
    expect(await deleteUserSkill({ userId: 'alice', skillId: 'sk_lonely' }, ALICE)).toEqual({ deletedProposals: 0, projectsUpdated: 0 })
    expect(h.audits.map((a) => a.action)).toEqual(['user_attack_skill.delete'])
  })

  test('a real cuid (the id Prisma assigns) has its proposals deleted too', async () => {
    const created = await createUserSkill({ userId: 'alice', name: 'Fresh', content: 'x' }, ALICE)
    db.seed('pluginOverride', [proposal({ targetGroup: created.id as string, changeSetId: '77777777-7777-4777-8777-777777777777' })])
    expect((await deleteUserSkill({ userId: 'alice', skillId: created.id as string }, ALICE)).deletedProposals).toBe(1)
  })
})

describe('releaseUserSkill', () => {
  test('a skill that is not quarantined is 409 not_quarantined', async () => {
    seedSkill({ id: 'clean', name: 'Clean' })
    const e = await refusal(releaseUserSkill({ userId: 'alice', skillId: 'clean' }, ALICE))
    expect(e.status).toBe(409)
    expect(e.code).toBe('not_quarantined')
    expect(h.audits).toEqual([])
  })

  test('clears the quarantine, records the revocation it is released from, and audits the release', async () => {
    seedSkill({
      id: 'q', name: 'Quarantined', content: 'Q text', quarantinedAt: new Date('2026-10-01T00:00:00Z'),
      quarantineReason: 'plugin_version_revoked', quarantinedFor: 'echo@1.0.0', releasedFor: ['echo@0.9.0'],
    })
    const out = await releaseUserSkill({ userId: 'alice', skillId: 'q' }, ALICE)
    expect(out).toMatchObject({ id: 'q', quarantinedAt: null, quarantineReason: null })
    expect(out).not.toHaveProperty('content')
    expect(db.rows('userAttackSkill')[0]).toMatchObject({
      quarantinedAt: null, quarantineReason: null, quarantinedFor: null, releasedFor: ['echo@0.9.0', 'echo@1.0.0'], content: 'Q text',
    })
    expect(h.audits).toEqual([{
      actorId: 'alice',
      action: 'user_attack_skill.release',
      targetType: 'user_attack_skill',
      targetId: 'q',
      before: { name: 'Quarantined', contentSha256: sha('Q text'), quarantineReason: 'plugin_version_revoked', quarantinedFor: 'echo@1.0.0' },
      after: { name: 'Quarantined', contentSha256: sha('Q text') },
      source: 'ui',
    }])
  })

  test("another user's skill is 404", async () => {
    seedSkill({ id: 'bq', userId: 'bob', name: 'Bob Q', quarantinedAt: new Date() })
    expect((await refusal(releaseUserSkill({ userId: 'alice', skillId: 'bq' }, ALICE))).code).toBe('not_found')
    expect(db.rows('userAttackSkill')[0].quarantinedAt).not.toBeNull()
  })
})

describe('pendingProposalCount', () => {
  test("counts the skill's distinct proposed sets in the owner's scope only", async () => {
    db.seed('pluginOverride', [
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-1' }),
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-1' }),
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-2' }),
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-3', status: 'rejected' }),
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-4', status: 'adopted' }),
      proposal({ targetGroup: 'sk_b', changeSetId: 'cs-5' }),
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-6', scopeId: 'bob', userId: 'bob' }),
      proposal({ targetGroup: 'sk_a', changeSetId: 'cs-7', extensionPoint: 'skill.text' }),
    ])
    expect(await pendingProposalCount('alice', 'sk_a')).toBe(2)
    expect(await pendingProposalCount('alice', 'sk_none')).toBe(0)
  })
})

describe('userSkillErrorResponse', () => {
  test('answers a UserSkillError with its status, code and extra fields', async () => {
    const res = userSkillErrorResponse(new UserSkillError(409, 'name_taken', 'Taken', { suggestion: 'X v2' }))!
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'Taken', code: 'name_taken', suggestion: 'X v2' })
  })

  test('anything else is not its business', () => {
    expect(userSkillErrorResponse(new Error('boom'))).toBeNull()
    expect(userSkillErrorResponse('x')).toBeNull()
  })
})
