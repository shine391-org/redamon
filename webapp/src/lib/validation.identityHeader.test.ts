/**
 * validateProjectForm judges the engagement identity header with the same
 * identity-only contract the routes enforce at the write, so the form
 * refuses what the server would. Empty/absent is fine; a present
 * null/non-string is refused, matching validateValue.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/validation.identityHeader.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { validateProjectForm } from './validation'

const fields = (data: Record<string, unknown>) =>
  validateProjectForm(data).filter(e => e.field === 'engagementIdentityHeader')

describe('validateProjectForm: engagementIdentityHeader', () => {
  test('a valid line passes', () => {
    expect(fields({ engagementIdentityHeader: 'X-Bug-Bounty: researcher-7f3a' })).toEqual([])
  })

  test('empty string (clearing) and omission pass', () => {
    expect(fields({ engagementIdentityHeader: '' })).toEqual([])
    expect(fields({})).toEqual([])
  })

  test.each([
    'Host: evil', 'Content-Length: 5', 'X-Redamon-Ctx: forged', 'Proxy-Anything: x',
    'X-BB: a;;b', 'X-BB: a\x0bb', 'X-BB: a\x7fb', 'X-BB: a\r\nInjected: 1',
    `X-BB: ${'a'.repeat(4096)}`, `${'X' + 'a'.repeat(256)}: v`,
  ])('%j produces a form error naming the field', (value: string) => {
    const errors = fields({ engagementIdentityHeader: value })
    expect(errors).toHaveLength(1)
    expect(errors[0].message).toMatch(/Invalid engagement identity header/)
  })

  test.each([null, 42, true, ['X-BB: v']])('present non-string %j is refused', (value: unknown) => {
    expect(fields({ engagementIdentityHeader: value })).toHaveLength(1)
  })
})
