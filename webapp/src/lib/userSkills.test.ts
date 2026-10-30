/**
 * The limits and toggle rules of a user's own agent skills (plan Phase 0.B, D10): the shape
 * of `attackSkillConfig`, the owner-aware `user` map every project writer stores, and the
 * forgiving trim a project or preset import gets instead of a refusal.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach } from 'vitest'
import type { Prisma } from '@prisma/client'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import {
  DESCRIPTION_MAX_CHARS,
  MAX_CONTENT_SIZE,
  MAX_ENABLED_USER_SKILLS_PER_PROJECT,
  MAX_SKILLS_PER_USER,
  NAME_MAX_CHARS,
  UserSkillError,
  attackSkillConfigShapeError,
  normalizeUserSkillToggles,
  normalizeUserToggleMap,
  skillToggleWarnings,
  trimImportedSkillToggles,
} from './userSkills'

let db: FakePrisma
// The fake as the client type the module takes (it implements the subset used).
let pg: Prisma.TransactionClient

// Ids sort the same way as names here, so "by name, then id" is readable in assertions.
const id = (i: number) => `sk_${String(i).padStart(2, '0')}`

function seedSkills(owner: string, count: number, extra: Record<string, unknown> = {}) {
  db.seed('userAttackSkill', Array.from({ length: count }, (_, i) => ({
    id: `${owner}_${id(i)}`, userId: owner, name: `Skill ${String(i).padStart(2, '0')}`, content: 'x', ...extra,
  })))
  return Array.from({ length: count }, (_, i) => `${owner}_${id(i)}`)
}

const allOn = (ids: string[]) => Object.fromEntries(ids.map((k) => [k, true]))

async function refusal(p: Promise<unknown>): Promise<UserSkillError> {
  const e = await p.then(() => null, (err) => err)
  expect(e).toBeInstanceOf(UserSkillError)
  return e as UserSkillError
}

beforeEach(() => {
  db = createFakePrisma()
  pg = db as unknown as Prisma.TransactionClient
})

describe('limits', () => {
  test('the bounds the plan fixes (D10, 0.B.1)', () => {
    expect(MAX_SKILLS_PER_USER).toBe(1000)
    expect(MAX_ENABLED_USER_SKILLS_PER_PROJECT).toBe(20)
    expect(MAX_CONTENT_SIZE).toBe(500 * 1024)
    expect(NAME_MAX_CHARS).toBe(100)
    expect(DESCRIPTION_MAX_CHARS).toBe(500)
  })
})

describe('attackSkillConfigShapeError', () => {
  test.each([
    ['null', null],
    ['a string', 'builtIn'],
    ['a number', 1],
    ['an array', [{ builtIn: {} }]],
  ])('refuses %s as the whole config', (_label, value) => {
    expect(attackSkillConfigShapeError(value)).toMatch(/must be an object/)
  })

  test('refuses an unknown top-level key, naming it', () => {
    expect(attackSkillConfigShapeError({ builtIn: {}, user: {}, extra: {} })).toMatch(/unknown key 'extra'/)
  })

  test('refuses a missing builtIn: the agent reads that as "no built-ins"', () => {
    expect(attackSkillConfigShapeError({ user: { a: true } })).toMatch(/builtIn/)
    expect(attackSkillConfigShapeError({})).toMatch(/builtIn/)
  })

  test.each([
    ['builtIn an array', { builtIn: [] }, /builtIn must be an object/],
    ['builtIn null', { builtIn: null }, /builtIn must be an object/],
    ['builtIn present but undefined', { builtIn: undefined }, /builtIn must be an object/],
    ['a builtIn value that is a number', { builtIn: { xss: 1 } }, /builtIn\.xss must be true or false/],
    ['a builtIn value that is the string "true"', { builtIn: { xss: 'true' } }, /builtIn\.xss/],
    ['user an array', { builtIn: {}, user: [] }, /user must be an object/],
    ['user null', { builtIn: {}, user: null }, /user must be an object/],
    ['a user value that is null', { builtIn: {}, user: { sk_a: null } }, /user\.sk_a must be true or false/],
  ])('refuses %s', (_label, value, message) => {
    expect(attackSkillConfigShapeError(value)).toMatch(message)
  })

  test('accepts builtIn alone (user is optional) and both maps of booleans', () => {
    expect(attackSkillConfigShapeError({ builtIn: {} })).toBeNull()
    expect(attackSkillConfigShapeError({ builtIn: { xss: true, rce: false }, user: { sk_a: false, sk_b: true } })).toBeNull()
  })
})

describe('normalizeUserSkillToggles', () => {
  test("drops ids the owner does not have, another user's included", async () => {
    const [mine] = seedSkills('alice', 1)
    const [theirs] = seedSkills('bob', 1)
    const out = await normalizeUserSkillToggles(pg, 'alice', {
      builtIn: { xss: true }, user: { [mine]: true, [theirs]: true, sk_deleted: false },
    })
    expect(out.user).toEqual({ [mine]: true })
  })

  test('refuses more than 20 enabled among the owned skills (409 too_many_enabled_skills)', async () => {
    const ids = seedSkills('alice', 21)
    const e = await refusal(normalizeUserSkillToggles(pg, 'alice', { builtIn: {}, user: allOn(ids) }))
    expect(e.status).toBe(409)
    expect(e.code).toBe('too_many_enabled_skills')
    expect(e.extra).toEqual({ limit: 20, enabled: 21 })
  })

  test('exactly 20 enabled passes, and foreign or off ids do not count toward the bound', async () => {
    const ids = seedSkills('alice', 25)
    const foreign = seedSkills('bob', 5)
    const user = { ...allOn(ids.slice(0, 20)), ...Object.fromEntries(ids.slice(20).map((k) => [k, false])), ...allOn(foreign) }
    const out = await normalizeUserSkillToggles(pg, 'alice', { builtIn: {}, user })
    expect(Object.values(out.user).filter(Boolean)).toHaveLength(20)
    expect(Object.keys(out.user)).toHaveLength(25)
  })

  test('refuses true on a quarantined skill (409 skill_quarantined) but stores false on one', async () => {
    const [ok] = seedSkills('alice', 1)
    db.seed('userAttackSkill', [{
      id: 'q_skill', userId: 'alice', name: 'Revoked', content: 'x',
      quarantinedAt: new Date('2026-10-01T00:00:00Z'), quarantineReason: 'plugin_version_revoked',
    }])
    const e = await refusal(normalizeUserSkillToggles(pg, 'alice', { builtIn: {}, user: { [ok]: true, q_skill: true } }))
    expect(e.status).toBe(409)
    expect(e.code).toBe('skill_quarantined')
    expect(e.extra).toEqual({ skillId: 'q_skill' })

    const out = await normalizeUserSkillToggles(pg, 'alice', { builtIn: {}, user: { [ok]: true, q_skill: false } })
    expect(out.user).toEqual({ [ok]: true, q_skill: false })
  })

  test('a missing builtIn is refused (400 invalid_attack_skill_config), never filled in', async () => {
    const [mine] = seedSkills('alice', 1)
    const e = await refusal(normalizeUserSkillToggles(pg, 'alice', { user: { [mine]: true } }))
    expect(e.status).toBe(400)
    expect(e.code).toBe('invalid_attack_skill_config')
  })

  test('a non-boolean toggle is refused with the same code', async () => {
    const e = await refusal(normalizeUserSkillToggles(pg, 'alice', { builtIn: {}, user: { sk_a: 'on' } }))
    expect(e.code).toBe('invalid_attack_skill_config')
  })

  test('a missing user map becomes {}, with no read', async () => {
    const out = await normalizeUserSkillToggles(
      { userAttackSkill: { findMany: async () => { throw new Error('no read expected') } } } as never,
      'alice', { builtIn: { xss: false } },
    )
    expect(out).toEqual({ builtIn: { xss: false }, user: {} })
  })

  test('builtIn is copied as is (unknown ids and false values kept), not aliased', async () => {
    const builtIn = { xss: false, rce: true, some_future_skill: true }
    const out = await normalizeUserSkillToggles(pg, 'alice', { builtIn })
    expect(out.builtIn).toEqual(builtIn)
    expect(out.builtIn).not.toBe(builtIn)
  })

  test('a project with no owner keeps no user id', async () => {
    const [mine] = seedSkills('alice', 1)
    expect((await normalizeUserSkillToggles(pg, null, { builtIn: {}, user: { [mine]: true } })).user).toEqual({})
    expect((await normalizeUserSkillToggles(pg, undefined, { builtIn: {}, user: { [mine]: true } })).user).toEqual({})
  })
})

describe('normalizeUserToggleMap', () => {
  test('reads only the owner and the requested ids', async () => {
    const calls: unknown[] = []
    const reader = { userAttackSkill: { findMany: async (a: unknown) => { calls.push(a); return [] } } }
    await normalizeUserToggleMap(reader as never, 'alice', { sk_a: true, sk_b: false })
    expect(calls).toEqual([{
      where: { userId: 'alice', id: { in: ['sk_a', 'sk_b'] } },
      select: { id: true, name: true, quarantinedAt: true },
    }])
  })

  test('the 21st enabled skill is refused even when it is the only one turned on now', async () => {
    const ids = seedSkills('alice', 21)
    const e = await refusal(normalizeUserToggleMap(pg, 'alice', allOn(ids)))
    expect(e.code).toBe('too_many_enabled_skills')
  })
})

describe('trimImportedSkillToggles', () => {
  test('an unusable shape yields value undefined and invalid', async () => {
    for (const bad of [null, [], { user: {} }, { builtIn: {}, user: { a: 1 } }, { builtIn: {}, x: 1 }]) {
      expect(await trimImportedSkillToggles(pg, 'alice', bad)).toEqual({ value: undefined, dropped: 0, turnedOff: 0, invalid: true })
    }
  })

  test('drops foreign ids first, then cuts the owned ones to 20 by name, then id', async () => {
    // Two skills share a name so the id decides between them; the seeding order is the
    // reverse of the expected order so a stable sort of the input would not pass.
    const names = Array.from({ length: 24 }, (_, i) => `Skill ${String(23 - i).padStart(2, '0')}`)
    db.seed('userAttackSkill', names.map((name, i) => ({ id: `own_${String(23 - i).padStart(2, '0')}`, userId: 'alice', name, content: 'x' })))
    db.seed('userAttackSkill', [
      { id: 'own_tie_b', userId: 'alice', name: 'Skill 05', content: 'x' },
      { id: 'own_tie_a', userId: 'alice', name: 'Skill 05', content: 'x' },
    ])
    const foreign = seedSkills('bob', 3)
    const owned = [...names.map((_, i) => `own_${String(23 - i).padStart(2, '0')}`), 'own_tie_b', 'own_tie_a']
    const out = await trimImportedSkillToggles(pg, 'alice', { builtIn: { xss: true }, user: { ...allOn(foreign), ...allOn(owned) } })

    expect(out.invalid).toBe(false)
    expect(out.dropped).toBe(3)
    expect(out.turnedOff).toBe(6)
    const user = out.value!.user
    for (const f of foreign) expect(user).not.toHaveProperty(f)
    const on = Object.keys(user).filter((k) => user[k]).sort()
    // By name: Skill 00..05 (the three named "Skill 05" ordered own_05, own_tie_a, own_tie_b), then 06..
    const expected = ['own_00', 'own_01', 'own_02', 'own_03', 'own_04', 'own_05', 'own_tie_a', 'own_tie_b',
      'own_06', 'own_07', 'own_08', 'own_09', 'own_10', 'own_11', 'own_12', 'own_13', 'own_14', 'own_15', 'own_16', 'own_17']
    expect(on).toEqual(expected.sort())
    expect(Object.keys(user)).toHaveLength(26)
    expect(out.value!.builtIn).toEqual({ xss: true })
  })

  test('a quarantined skill is turned off and does not take one of the 20 places', async () => {
    const ids = seedSkills('alice', 20)
    db.seed('userAttackSkill', [{ id: 'aaa_q', userId: 'alice', name: 'AAA revoked', content: 'x', quarantinedAt: new Date() }])
    const out = await trimImportedSkillToggles(pg, 'alice', { builtIn: {}, user: { ...allOn(ids), aaa_q: true } })
    expect(out.turnedOff).toBe(1)
    expect(out.value!.user.aaa_q).toBe(false)
    expect(ids.every((k) => out.value!.user[k] === true)).toBe(true)
  })

  test('off toggles of owned skills are kept as they are; a missing user map is {}', async () => {
    const [a, b] = seedSkills('alice', 2)
    const out = await trimImportedSkillToggles(pg, 'alice', { builtIn: {}, user: { [a]: false, [b]: true } })
    expect(out).toEqual({ value: { builtIn: {}, user: { [a]: false, [b]: true } }, dropped: 0, turnedOff: 0, invalid: false })
    expect(await trimImportedSkillToggles(pg, 'alice', { builtIn: { rce: false } }))
      .toEqual({ value: { builtIn: { rce: false }, user: {} }, dropped: 0, turnedOff: 0, invalid: false })
  })

  test('the warning about foreign ids does not claim the OFF ones were turned on', async () => {
    const out = await trimImportedSkillToggles(pg, 'alice', {
      builtIn: {}, user: { gone_1: true, gone_2: true, gone_3: false, gone_4: false, gone_5: false },
    })
    expect(out.value!.user).toEqual({})
    const text = skillToggleWarnings(out, 'project').join(' ')
    expect(text).not.toMatch(/turned on 5/)
  })
})

describe('skillToggleWarnings', () => {
  test('nothing changed, nothing said', () => {
    expect(skillToggleWarnings({ dropped: 0, turnedOff: 0, invalid: false }, 'project')).toEqual([])
  })

  test('one warning per kind of change, naming what was imported and the counts', () => {
    const [invalid] = skillToggleWarnings({ dropped: 0, turnedOff: 0, invalid: true }, 'preset')
    expect(invalid).toMatch(/preset/)
    expect(invalid).toMatch(/unreadable/)
    const both = skillToggleWarnings({ dropped: 2, turnedOff: 3, invalid: false }, 'project')
    expect(both).toHaveLength(2)
    expect(both[0]).toMatch(/2 user skill/)
    expect(both[1]).toMatch(/\(20\)/)
    expect(both[1]).toMatch(/3 were turned off/)
  })
})
