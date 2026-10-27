/**
 * Keys that are public by design (plan 05.2): one list for every webapp
 * reader, pinned equal to the Priority Board's (score_model.py), which
 * js_recon's detector list is pinned to in turn.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  PUBLIC_CLIENT_KEY_TYPES,
  isPublicClientKey,
  publicClientKeyCypher,
} from './publicClientKeys'

const SCORE_MODEL = join(__dirname, '../../../../agentic/cypherfix_triage/score_model.py')

function pythonList(): string[] {
  const src = readFileSync(SCORE_MODEL, 'utf8')
  const start = src.indexOf('PUBLIC_CLIENT_KEY_TYPES = frozenset({')
  const end = src.indexOf('})', start)
  return [...src.slice(start, end).matchAll(/^\s*"([^"]+)"/gm)].map(m => m[1])
}

describe('the public client key list', () => {
  test('equals the score model list', () => {
    const python = pythonList()
    expect(python.length).toBeGreaterThanOrEqual(17)
    expect([...PUBLIC_CLIENT_KEY_TYPES].sort()).toEqual([...python].sort())
  })

  test('is lowercased, as the readers compare it', () => {
    for (const name of PUBLIC_CLIENT_KEY_TYPES) expect(name).toBe(name.toLowerCase())
  })
})

describe('isPublicClientKey', () => {
  test('a node carrying the flag', () => {
    expect(isPublicClientKey(true, 'Anything')).toBe(true)
  })

  test('a node written before the flag, by its pattern name', () => {
    expect(isPublicClientKey(null, 'GCP API Key')).toBe(true)
    expect(isPublicClientKey(undefined, 'sentry dsn')).toBe(true)
  })

  test('a secret key of the same vendor is not public', () => {
    expect(isPublicClientKey(false, 'Stripe Secret Key')).toBe(false)
    expect(isPublicClientKey(null, 'GCP Service Account')).toBe(false)
    expect(isPublicClientKey(null, null)).toBe(false)
  })

  test('an explicit false does not override a public name', () => {
    // The flag is false on every non-public js_recon node; the name decides.
    expect(isPublicClientKey(false, 'Mapbox Token')).toBe(true)
  })
})

describe('publicClientKeyCypher', () => {
  test('reads the flag, then the name, with no parameter', () => {
    const cypher = publicClientKeyCypher('s')
    expect(cypher).toContain('coalesce(s.public_client_key, false) = true')
    expect(cypher).toContain("toLower(coalesce(s.secret_type, '')) IN [")
    expect(cypher).not.toContain('$')
    for (const name of PUBLIC_CLIENT_KEY_TYPES) expect(cypher).toContain(`'${name}'`)
  })

  test('refuses an alias that is not an identifier', () => {
    expect(() => publicClientKeyCypher('s) OR (1=1')).toThrow()
  })
})
