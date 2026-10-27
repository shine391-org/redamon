import { describe, it, test, expect } from 'vitest'
import { normalizeOrchestratorStartError } from './orchestratorError'

/**
 * Root cause of the reported "Application error: a client-side exception" after
 * starting a partial scan: the memory governor rejects the start with a
 * structured object detail, and the start routes forwarded that OBJECT as
 * `error`. A `toast.error(data.error)` then rendered an object -> React throws
 * "Objects are not valid as a React child" and the page goes down.
 *
 * The invariant these tests lock: normalize ALWAYS returns a string `error`,
 * for every input shape. That is what makes the value safe to render.
 */
describe('normalizeOrchestratorStartError', () => {
  // The exact payload from the crash report (keys: admitted, limitType,
  // resource, current, ceiling, settingName, detail).
  const GOVERNOR_RAM = {
    admitted: false,
    limitType: 'ram',
    resource: 'scan',
    current: 1,
    ceiling: 2,
    settingName: null,
    detail: 'not enough reserved memory budget for another scan',
  }
  const GOVERNOR_HARD = {
    admitted: false,
    limitType: 'hard',
    resource: 'scan',
    current: 12,
    ceiling: 12,
    settingName: 'RECON_MAX_CONCURRENT_GLOBAL',
    detail: 'Maximum concurrent scans reached',
  }

  it('turns a RAM-limit object into a string message and keeps the payload as limit', () => {
    const r = normalizeOrchestratorStartError({ detail: GOVERNOR_RAM }, 'fallback')
    expect(typeof r.error).toBe('string')
    expect(r.error).toContain('not enough reserved memory budget')
    expect(r.error).toContain('RAM limit')
    expect(r.limit).toEqual(GOVERNOR_RAM)
  })

  it('turns a HARD-limit object into a string that names the setting to raise', () => {
    const r = normalizeOrchestratorStartError({ detail: GOVERNOR_HARD }, 'fallback')
    expect(typeof r.error).toBe('string')
    expect(r.error).toContain('Maximum concurrent scans reached')
    expect(r.error).toContain('RECON_MAX_CONCURRENT_GLOBAL')
    expect(r.limit).toEqual(GOVERNOR_HARD)
  })

  it('never returns an object as error, even for an unknown object shape', () => {
    const weird = { detail: { admitted: false, resource: 'scan', unexpected: true } }
    const r = normalizeOrchestratorStartError(weird, 'fallback message')
    expect(typeof r.error).toBe('string')
    // No limitType => falls back (object has no usable detail string).
    expect(r.error).toBe('fallback message')
  })

  it('uses a plain string detail directly', () => {
    const r = normalizeOrchestratorStartError({ detail: 'Full recon is running. Stop it first.' }, 'fallback')
    expect(r.error).toBe('Full recon is running. Stop it first.')
    expect(r.limit).toBeUndefined()
  })

  it('falls back when detail is missing or the body is empty/garbage', () => {
    expect(normalizeOrchestratorStartError({}, 'fb').error).toBe('fb')
    expect(normalizeOrchestratorStartError(undefined, 'fb').error).toBe('fb')
    expect(normalizeOrchestratorStartError(null, 'fb').error).toBe('fb')
    expect(normalizeOrchestratorStartError('a string body', 'fb').error).toBe('fb')
  })

  it('INVARIANT: error is a string for every input shape', () => {
    const inputs: unknown[] = [
      { detail: GOVERNOR_RAM },
      { detail: GOVERNOR_HARD },
      { detail: { admitted: false } },
      { detail: 'plain' },
      { detail: 123 },
      { detail: null },
      {},
      undefined,
      null,
      42,
      'str',
      [],
    ]
    for (const input of inputs) {
      const r = normalizeOrchestratorStartError(input, 'fb')
      expect(typeof r.error, `error must be string for input ${JSON.stringify(input)}`).toBe('string')
    }
  })
})

describe('the orchestrator reason code (plan 12.6, 12.9)', () => {
  test('a detail object naming a code carries it, with its message as the error', () => {
    const n = normalizeOrchestratorStartError(
      { detail: { detail: 'The scan container could not be started: no image', code: 'spawn_failed' } },
      'Failed to start recon',
    )
    expect(n.error).toBe('The scan container could not be started: no image')
    expect(n.code).toBe('spawn_failed')
  })

  test('a plain string detail has no code', () => {
    expect(normalizeOrchestratorStartError({ detail: 'nope' }, 'f').code).toBeUndefined()
  })

  test('a non-string code is ignored', () => {
    expect(normalizeOrchestratorStartError({ detail: { detail: 'x', code: 7 } }, 'f').code).toBeUndefined()
  })
})
