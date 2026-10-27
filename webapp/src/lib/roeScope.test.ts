/**
 * The TS RoE excluded-host matcher against the vectors recon's
 * `_is_roe_excluded` also reads (recon/tests/test_roe_exclusion_vectors.py),
 * so the recording scope cannot keep a host a scan refuses (drift-map #20).
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isRoeExcluded, normalizeRoeEntry, normalizeRoeHost } from './roeScope'

const VECTORS = join(process.cwd(), '..', 'recon', 'tests', 'fixtures', 'roe_exclusion_vectors.json')

interface Vector { name: string; host: unknown; excluded: unknown[]; result: boolean }

describe.skipIf(!existsSync(VECTORS))('RoE exclusion: shared vectors', () => {
  const vectors: Vector[] = existsSync(VECTORS) ? JSON.parse(readFileSync(VECTORS, 'utf8')).vectors : []

  test('the table is a real set', () => {
    expect(vectors.length).toBeGreaterThanOrEqual(40)
  })

  test.each(vectors.map(v => [v.name, v] as const))('%s', (_name, v) => {
    expect(isRoeExcluded(v.host, v.excluded)).toBe(v.result)
  })
})

describe('normalisation', () => {
  test('a host loses its scheme, credentials, path, port, brackets, trailing dot and case', () => {
    expect(normalizeRoeHost('https://u:p@API.Example.com:8443/x')).toBe('api.example.com')
    expect(normalizeRoeHost('[2001:DB8::1]:443')).toBe('2001:db8::1')
    expect(normalizeRoeHost('api.example.com.')).toBe('api.example.com')
    expect(normalizeRoeHost('2001:db8::1')).toBe('2001:db8::1')
    expect(normalizeRoeHost(42)).toBe('')
  })

  test('an entry keeps its wildcard and its CIDR shape', () => {
    expect(normalizeRoeEntry('*.Example.COM.')).toBe('*.example.com')
    expect(normalizeRoeEntry('10.0.0.0/8')).toBe('10.0.0.0/8')
    expect(normalizeRoeEntry('2001:DB8::/32')).toBe('2001:db8::/32')
    expect(normalizeRoeEntry('https://example.com/login')).toBe('example.com')
  })
})
