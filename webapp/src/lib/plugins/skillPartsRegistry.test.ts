/**
 * The webapp's view of the agent's skill-part registry (TD-26): the factory text, hash and
 * limits of every overridable part, fetched from the agent (master key) and cached five
 * minutes, and the agent's validator for proposed text. An agent that cannot be reached
 * and one too old to have the endpoints are told apart, and neither is ever cached.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ calls: [] as { path: string; init?: RequestInit }[], answer: null as unknown as (path: string, init?: RequestInit) => Promise<Response> }))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return {
    AgentUnreachableError,
    agentFetch: (path: string, init?: RequestInit) => {
      h.calls.push({ path, init })
      return h.answer(path, init)
    },
  }
})

import { AgentUnreachableError } from '@/lib/agentFetch'
import { setNowForTests } from './clock'
import {
  SkillPartsRegistryError,
  clearSkillPartsCache,
  registryFailureText,
  registrySkill,
  validateSkillParts,
} from './skillPartsRegistry'

const part = (partId: string, text: string, over: Record<string, unknown> = {}) => ({
  partId,
  constant: `x_prompts.${partId.toUpperCase()}`,
  kind: 'plain',
  placeholders: [],
  sha256: 'a'.repeat(64),
  chars: text.length,
  maxChars: text.length + 20_000,
  order: 1,
  gate: 'always, when the skill renders',
  text,
  ...over,
})
const REGISTRY = {
  skills: [
    { id: 'xxe', maxChars: 30, parts: [part('tools', 'XXE tools')] },
    { id: 'ssrf', maxChars: 60, parts: [part('tools', 'SSRF {x}', { kind: 'template', placeholders: ['x'] }), part('oob_workflow', 'OOB')] },
  ],
}

let t = Date.parse('2026-10-09T10:00:00.000Z')
beforeEach(() => {
  h.calls = []
  h.answer = async () => Response.json(REGISTRY)
  clearSkillPartsCache()
  t = Date.parse('2026-10-09T10:00:00.000Z')
  setNowForTests(() => new Date(t))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setNowForTests(null)
  vi.restoreAllMocks()
})

const failure = async (p: Promise<unknown>) => {
  const e = await p.catch((x: unknown) => x)
  expect(e).toBeInstanceOf(SkillPartsRegistryError)
  return (e as SkillPartsRegistryError).code
}

describe('the registry', () => {
  test('one skill by id, from the full list the agent publishes', async () => {
    const ssrf = await registrySkill('ssrf')
    expect(ssrf).toEqual(REGISTRY.skills[1])
    expect(await registrySkill('nope')).toBeNull()
    expect(h.calls).toEqual([{ path: '/plugins/skill-parts', init: expect.objectContaining({ method: 'GET' }) }])
  })

  test('cached five minutes, then fetched again', async () => {
    await registrySkill('xxe')
    t += 299_000
    await registrySkill('ssrf')
    expect(h.calls).toHaveLength(1)
    t += 2_000
    await registrySkill('ssrf')
    expect(h.calls).toHaveLength(2)
  })

  test('unreachable agent: agent_unreachable, and nothing is cached', async () => {
    h.answer = async () => {
      throw new AgentUnreachableError('down')
    }
    expect(await failure(registrySkill('xxe'))).toBe('agent_unreachable')
    h.answer = async () => Response.json(REGISTRY)
    expect(await registrySkill('xxe')).not.toBeNull()
  })

  test('an agent answering 503 (its master key is weak) is unavailable, not outdated', async () => {
    h.answer = async () => Response.json({ error: 'INTERNAL_API_KEY is not configured' }, { status: 503 })
    expect(await failure(registrySkill('xxe'))).toBe('agent_unreachable')
  })

  test.each<[string, () => Response]>([
    ['the endpoint is missing (404)', () => Response.json({ detail: 'Not Found' }, { status: 404 })],
    ['a part without maxChars (an agent older than the limits)', () =>
      Response.json({ skills: [{ id: 'xxe', maxChars: 30, parts: [{ ...part('tools', 'x'), maxChars: undefined }] }] })],
    ['a skill without maxChars', () => Response.json({ skills: [{ id: 'xxe', parts: [part('tools', 'x')] }] })],
    ['not JSON', () => new Response('<html>', { status: 200 })],
    ['no skill list', () => Response.json({ parts: [] })],
  ])('%s: agent_outdated, not cached', async (_n, answer) => {
    h.answer = async () => answer()
    expect(await failure(registrySkill('xxe'))).toBe('agent_outdated')
    h.answer = async () => Response.json(REGISTRY)
    expect(await registrySkill('xxe')).not.toBeNull()
  })
})

describe('validation', () => {
  const ok = { ok: true, parts: { tools: { errors: [], chars: 9, maxChars: 20_009 } }, skill: { errors: [], chars: 12, maxChars: 60 } }

  test('posts the skill and its parts to the agent and returns its answer', async () => {
    h.answer = async () => Response.json(ok)
    expect(await validateSkillParts('ssrf', { tools: 'SSRF {x}!' })).toEqual(ok)
    expect(h.calls[0].path).toBe('/plugins/skill-parts/validate')
    expect(h.calls[0].init?.method).toBe('POST')
    expect(JSON.parse(String(h.calls[0].init?.body))).toEqual({ skillId: 'ssrf', parts: { tools: 'SSRF {x}!' } })
  })

  test('unreachable: agent_unreachable; route missing: agent_outdated; unknown skill: unknown_skill', async () => {
    h.answer = async () => {
      throw new AgentUnreachableError('down')
    }
    expect(await failure(validateSkillParts('ssrf', {}))).toBe('agent_unreachable')
    h.answer = async () => Response.json({ detail: 'Not Found' }, { status: 404 })
    expect(await failure(validateSkillParts('ssrf', {}))).toBe('agent_outdated')
    h.answer = async () => Response.json({ error: "unknown skill 'ssrf'" }, { status: 404 })
    expect(await failure(validateSkillParts('ssrf', {}))).toBe('unknown_skill')
    h.answer = async () => Response.json({ ok: 'yes' })
    expect(await failure(validateSkillParts('ssrf', {}))).toBe('agent_outdated')
  })
})

describe('why the agent is unavailable: an answer with an error is not "not running"', () => {
  const caught = (p: Promise<unknown>) => p.then(() => null, (e: unknown) => e as SkillPartsRegistryError)

  test('the agent answered 500: its status, and words that do not claim it is down', async () => {
    h.answer = async () => Response.json({ detail: 'boom' }, { status: 500 })
    const e = (await caught(registrySkill('xxe')))!
    expect(e).toMatchObject({ code: 'agent_unreachable', failure: { upstreamStatus: 500 } })
    // The message is what the Gateway hands plugins: unchanged.
    expect(e.message).toBe("The agent service isn't running")
    expect(registryFailureText(e)).toBe('The agent service answered HTTP 500')
  })

  test('no answer: the errno, or that it timed out', async () => {
    h.answer = async () => {
      throw Object.assign(new AgentUnreachableError('down'), { cause_: Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }) })
    }
    const refused = (await caught(registrySkill('xxe')))!
    expect(refused.failure).toEqual({ reason: 'ECONNREFUSED' })
    expect(registryFailureText(refused)).toBe('The agent service could not be reached (ECONNREFUSED)')
    h.answer = async () => {
      throw Object.assign(new AgentUnreachableError('down'), { cause_: new DOMException('timed out', 'TimeoutError') })
    }
    const slow = (await caught(validateSkillParts('ssrf', {})))!
    expect(slow.failure).toEqual({ reason: 'timeout' })
    expect(registryFailureText(slow)).toBe('The agent service did not answer in time')
  })

  test('agent_outdated keeps its own words', async () => {
    h.answer = async () => Response.json({ detail: 'Not Found' }, { status: 404 })
    const e = (await caught(registrySkill('xxe')))!
    expect(registryFailureText(e)).toBe(e.message)
  })
})
