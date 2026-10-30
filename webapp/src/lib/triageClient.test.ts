/**
 * `graphTriage`: what the mute, unmute and Muted Nodes routes hand the browser
 * when the agent fails (G-17).
 *
 * The agent body used to be passed through as is: FastAPI's `{detail}` (a
 * refused key, a rate limit) was dropped by every client, which read `error`
 * only, the status was never shown, and an older agent's catch-all put the raw
 * Neo4j message (which quotes target data) on screen.
 *
 * Run: npx vitest run src/lib/triageClient.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ agentFetch: vi.fn() }))

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: vi.fn() }))
vi.mock('@/lib/session', () => ({ getSession: vi.fn() }))
vi.mock('@/lib/agentAuth', () => ({ internalKeyHeaders: (b: Record<string, string> = {}) => b }))
vi.mock('@/lib/agentFetch', async () => {
  class AgentUnreachableError extends Error {
    readonly cause_: unknown
    constructor(cause: unknown) {
      super('Cannot reach the RedAmon agent service at http://agent:8080: connection refused.')
      this.name = 'AgentUnreachableError'
      this.cause_ = cause
    }
  }
  return { agentFetch: (...a: unknown[]) => h.agentFetch(...a), AgentUnreachableError }
})

import { graphTriage } from './triageClient'
import { AgentUnreachableError } from '@/lib/agentFetch'

const CALLER = { userId: 'u1', projectId: 'p1' }

function answer(body: unknown, status: number) {
  return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status })
}

beforeEach(() => { vi.clearAllMocks() })

describe('graphTriage failures', () => {
  test('FastAPI detail becomes the error, with the agent status', async () => {
    h.agentFetch.mockResolvedValueOnce(answer({ detail: 'Unauthorized' }, 401))
    const out = await graphTriage('list_muted', CALLER)
    expect(out.status).toBe(401)
    expect(out.body).toMatchObject({ error: 'Unauthorized', upstreamStatus: 401 })
  })

  test('a coded 5xx keeps the agent sentence, its code and class', async () => {
    h.agentFetch.mockResolvedValueOnce(answer({
      error: 'The triage operation failed. The details are in the agent log.',
      code: 'internal_error', error_class: 'Neo.TransientError.General.DatabaseUnavailable',
    }, 500))
    const out = await graphTriage('mute', CALLER)
    expect(out.body).toEqual({
      error: 'The triage operation failed. The details are in the agent log.',
      code: 'internal_error',
      errorClass: 'Neo.TransientError.General.DatabaseUnavailable',
      upstreamStatus: 500,
    })
  })

  test('an uncoded 5xx text (an older agent) never reaches the browser', async () => {
    h.agentFetch.mockResolvedValueOnce(answer({ error: "MATCH (n {name: 'secret.example.com'})" }, 500))
    const out = await graphTriage('mute', CALLER)
    expect(JSON.stringify(out.body)).not.toContain('secret.example.com')
    expect(out.body.error).toBe('The findings service answered 500.')
  })

  test('a code that is not a plain code is dropped', async () => {
    h.agentFetch.mockResolvedValueOnce(answer({ error: 'bad', code: 'free text here' }, 400))
    const out = await graphTriage('mute', CALLER)
    expect(out.body.code).toBeUndefined()
  })

  test('a non-JSON answer says so', async () => {
    h.agentFetch.mockResolvedValueOnce(answer('<html>502 Bad Gateway</html>', 502))
    const out = await graphTriage('mute', CALLER)
    expect(out.body).toMatchObject({ code: 'non_json_response', upstreamStatus: 502 })
  })

  test('an unreachable agent is 503 agent_unreachable with the errno', async () => {
    const refused = Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } })
    h.agentFetch.mockRejectedValueOnce(new AgentUnreachableError(refused))
    const out = await graphTriage('mute', CALLER)
    expect(out.status).toBe(503)
    expect(out.body).toMatchObject({ code: 'agent_unreachable', cause: 'ECONNREFUSED' })
    expect(String(out.body.error)).toMatch(/Cannot reach the RedAmon agent/)
  })

  test('any other throw is a fixed sentence and a code, never its message', async () => {
    h.agentFetch.mockRejectedValueOnce(new RangeError('secret detail'))
    const out = await graphTriage('mute', CALLER)
    expect(out.body).toEqual({ error: 'The triage request failed.', code: 'RangeError' })
  })
})
