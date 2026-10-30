/**
 * readRoeError: a refusal keeps its own sentence (it names its cause), while a
 * server failure's fixed sentence gains the code and the status, so "Failed to
 * apply the Rules of Engagement." tells a transaction timeout from an outage.
 *
 * Run: npx vitest run --no-file-parallelism src/components/roe/roeClient.test.ts
 */
import { describe, test, expect, vi, afterEach } from 'vitest'

import { downloadRoeFile, readRoeError } from './roeClient'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('readRoeError', () => {
  test('a 500 carries the Prisma code and the status', async () => {
    const err = await readRoeError(json(500, { error: 'Failed to apply the Rules of Engagement.', code: 'P2028' }))
    expect(err).toEqual({
      status: 500, code: 'P2028', error: 'Failed to apply the Rules of Engagement. (P2028 · HTTP 500)',
      keys: undefined, busy: undefined,
    })
  })

  test('a refusal keeps its sentence unchanged', async () => {
    const err = await readRoeError(json(409, { error: 'The project changed.', code: 'roe_stale' }))
    expect(err.error).toBe('The project changed.')
    expect(err.code).toBe('roe_stale')
  })

  test('a proxy page without a body still names the status once', async () => {
    const err = await readRoeError(new Response('<html>Bad Gateway</html>', { status: 502 }))
    expect(err.error).toBe('The request failed (502).')
  })
})

test('a failed download returns the sentence with its code', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json(500, { error: 'Failed to download RoE document', code: 'P2024' })))
  expect(await downloadRoeFile('/api/projects/p1/roe/download', 'roe.pdf'))
    .toBe('Failed to download RoE document (P2024 · HTTP 500)')
})
