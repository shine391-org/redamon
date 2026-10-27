/**
 * @vitest-environment node
 *
 * The fix list follows its findings across a regrouping.
 *
 * When a run produces a group key no row carries (secret groups split per key,
 * a project import, a scan-version restore), the route used to create a fresh
 * pending row and leave the old one behind: a dismissed fix, or one a CodeFix
 * session was working on, was split from a duplicate. It now re-points the old
 * row whose findings overlap most, inside the same transaction.
 *
 * Prisma is an in-memory table. Its transaction rolls back on a throw; the
 * top-level client writes straight through, so a write made outside the
 * transaction would survive a rollback and show here.
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

interface Row {
  id: string
  projectId: string
  groupKey: string | null
  status: string
  agentSessionId: string
  fixBranch: string
  prUrl: string
  title: string
  findingIds: string[]
  liveMemberCount: number
  updatedAt: Date
  [k: string]: unknown
}

const h = vi.hoisted(() => ({
  rows: [] as Row[],
  failOnCreate: false,
  seq: 0,
}))

function table(rows: () => Row[]) {
  return {
    findMany: async ({ where }: { where: { projectId: string } }) =>
      rows().filter((r) => r.projectId === where.projectId).map((r) => ({ ...r })),
    create: async ({ data }: { data: Partial<Row> }) => {
      if (h.failOnCreate) throw new Error('create failed')
      const key = data.groupKey ?? null
      if (rows().some((r) => r.projectId === data.projectId && r.groupKey === key && key !== null)) {
        throw new Error('unique (projectId, groupKey)')
      }
      const row = {
        id: `new-${++h.seq}`, status: 'pending', agentSessionId: '', fixBranch: '', prUrl: '',
        findingIds: [], liveMemberCount: 0, updatedAt: new Date(), ...data,
      } as Row
      rows().push(row)
      return row
    },
    update: async ({ where, data }: { where: { id: string }; data: Partial<Row> }) => {
      const row = rows().find((r) => r.id === where.id)
      if (!row) throw new Error('no row')
      if (data.groupKey !== undefined
          && rows().some((r) => r.id !== row.id && r.projectId === row.projectId && r.groupKey === data.groupKey)) {
        throw new Error('unique (projectId, groupKey)')
      }
      Object.assign(row, data, { updatedAt: new Date() })
      return row
    },
    delete: async ({ where }: { where: { id: string } }) => {
      const i = rows().findIndex((r) => r.id === where.id)
      if (i < 0) throw new Error('no row')
      return rows().splice(i, 1)[0]
    },
  }
}

vi.mock('@/lib/session', () => ({ isInternalRequest: () => true }))
vi.mock('@/lib/prisma', () => ({
  default: {
    triageRun: {
      findUnique: async () => ({ id: 'run-2', projectId: 'p1', status: 'publishing' }),
    },
    remediation: table(() => h.rows),
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
      const snapshot = h.rows.map((r) => ({ ...r, findingIds: [...r.findingIds] }))
      const working = snapshot.map((r) => ({ ...r }))
      try {
        const out = await fn({ remediation: table(() => working) })
        h.rows.length = 0
        h.rows.push(...working)
        return out
      } catch (e) {
        h.rows.length = 0
        h.rows.push(...snapshot)
        throw e
      }
    },
  },
}))

const { POST } = await import('./route')

function existing(over: Partial<Row>): Row {
  return {
    id: 'old', projectId: 'p1', groupKey: 'secret:cloud:https-app.example.com', status: 'pending',
    agentSessionId: '', fixBranch: '', prUrl: '', title: 'Old title',
    findingIds: ['s1', 's2'], liveMemberCount: 2, updatedAt: new Date('2026-10-01T00:00:00Z'),
    ...over,
  }
}

function incoming(groupKey: string, findingIds: string[], title = `Fix ${groupKey}`) {
  return { groupKey, findingIds, title, description: 'd', liveMemberCount: findingIds.length, priority: 1 }
}

async function publish(remediations: unknown[]) {
  const req = { json: async () => ({ projectId: 'p1', remediations }) } as never
  const res = await POST(req, { params: Promise.resolve({ runId: 'run-2' }) })
  return { status: res.status, stats: await res.json() }
}

beforeEach(() => {
  h.rows.length = 0
  h.failOnCreate = false
  h.seq = 0
})

describe('re-pointing a fix item across a regrouping', () => {
  test('a protected row under an old key with >= 50% overlap is re-pointed, not duplicated', async () => {
    h.rows.push(existing({ status: 'in_progress', agentSessionId: 'sess-1', fixBranch: 'fix/aws' }))
    const { stats } = await publish([incoming('secret:abc123', ['s1', 's2', 's3'])])

    expect(h.rows).toHaveLength(1)
    const row = h.rows[0]
    expect(row.id).toBe('old')
    expect(row.groupKey).toBe('secret:abc123')
    // Its words and its CodeFix state are the session's; only the facts follow.
    expect(row.title).toBe('Old title')
    expect(row.agentSessionId).toBe('sess-1')
    expect(row.findingIds).toEqual(['s1', 's2', 's3'])
    expect(stats).toMatchObject({ created: 0, repointed: 1, deleted: 0 })
  })

  test('a dismissed row stays dismissed under its new key and is never recreated', async () => {
    h.rows.push(existing({ status: 'dismissed' }))
    const { stats } = await publish([incoming('secret:abc123', ['s1', 's2'])])
    expect(h.rows.map((r) => [r.id, r.groupKey, r.status])).toEqual([['old', 'secret:abc123', 'dismissed']])
    expect(stats).toMatchObject({ created: 0, repointed: 1 })
  })

  test('an unprotected old row with overlap is re-pointed and refreshed', async () => {
    h.rows.push(existing({}))
    const { stats } = await publish([incoming('secret:abc123', ['s1', 's2'], 'Rotate exposed secret: AWS Access Key ID')])
    expect(h.rows).toHaveLength(1)
    expect(h.rows[0]).toMatchObject({
      id: 'old', groupKey: 'secret:abc123', title: 'Rotate exposed secret: AWS Access Key ID',
    })
    expect(stats).toMatchObject({ created: 0, repointed: 1, updated: 1, deleted: 0 })
  })

  test('no overlap: create as before, and the stale unprotected row goes', async () => {
    h.rows.push(existing({}))
    const { stats } = await publish([incoming('secret:abc123', ['s8', 's9'])])
    expect(h.rows.map((r) => r.groupKey)).toEqual(['secret:abc123'])
    expect(h.rows[0].id).not.toBe('old')
    expect(stats).toMatchObject({ created: 1, repointed: 0, deleted: 1 })
  })

  test('less than half the incoming group overlapping is not enough', async () => {
    h.rows.push(existing({ findingIds: ['s1'] }))
    const { stats } = await publish([incoming('secret:abc123', ['s1', 's2', 's3'])])
    expect(stats).toMatchObject({ created: 1, repointed: 0 })
  })

  test('one old row is never re-pointed to two keys', async () => {
    h.rows.push(existing({ findingIds: ['s1', 's2', 's3', 's4'], status: 'in_progress' }))
    const { stats } = await publish([
      incoming('secret:aaa', ['s1', 's2']),
      incoming('secret:bbb', ['s3', 's4']),
    ])
    expect(h.rows.filter((r) => r.id === 'old').map((r) => r.groupKey)).toEqual(['secret:aaa'])
    expect(h.rows.map((r) => r.groupKey).sort()).toEqual(['secret:aaa', 'secret:bbb'])
    expect(stats).toMatchObject({ created: 1, repointed: 1 })
  })

  test('the largest overlap wins; a tie goes to the protected row, then the newest', async () => {
    h.rows.push(
      existing({ id: 'small', groupKey: 'old:a', findingIds: ['s1', 's2'] }),
      existing({ id: 'big', groupKey: 'old:b', findingIds: ['s1', 's2', 's3'] }),
    )
    await publish([incoming('secret:new', ['s1', 's2', 's3'])])
    expect(h.rows.find((r) => r.id === 'big')?.groupKey).toBe('secret:new')

    h.rows.length = 0
    h.rows.push(
      existing({ id: 'plain-new', groupKey: 'old:a', updatedAt: new Date('2026-10-20T00:00:00Z') }),
      existing({ id: 'owned', groupKey: 'old:b', fixBranch: 'fix/x', updatedAt: new Date('2026-09-01T00:00:00Z') }),
    )
    await publish([incoming('secret:new', ['s1', 's2'])])
    expect(h.rows.find((r) => r.id === 'owned')?.groupKey).toBe('secret:new')

    h.rows.length = 0
    h.rows.push(
      existing({ id: 'older', groupKey: 'old:a', updatedAt: new Date('2026-09-01T00:00:00Z') }),
      existing({ id: 'newer', groupKey: 'old:b', updatedAt: new Date('2026-10-20T00:00:00Z') }),
    )
    await publish([incoming('secret:new', ['s1', 's2'])])
    expect(h.rows.find((r) => r.id === 'newer')?.groupKey).toBe('secret:new')
  })

  test('a row whose key this run still produces is never taken by another group', async () => {
    h.rows.push(existing({ id: 'kept', groupKey: 'secret:kept', findingIds: ['s1', 's2'] }))
    const { stats } = await publish([
      incoming('secret:kept', ['s1']),
      incoming('secret:other', ['s1', 's2']),
    ])
    expect(h.rows.find((r) => r.id === 'kept')?.groupKey).toBe('secret:kept')
    expect(stats).toMatchObject({ created: 1, repointed: 0 })
  })

  test('an existing key still updates in place', async () => {
    h.rows.push(existing({ groupKey: 'secret:abc123' }))
    const { stats } = await publish([incoming('secret:abc123', ['s1', 's2'], 'New title')])
    expect(h.rows).toHaveLength(1)
    expect(h.rows[0]).toMatchObject({ id: 'old', title: 'New title' })
    expect(stats).toMatchObject({ created: 0, repointed: 0, updated: 1 })
  })

  test('the transaction still rolls back as a unit', async () => {
    h.rows.push(existing({ status: 'in_progress', agentSessionId: 'sess-1' }))
    h.failOnCreate = true
    await expect(publish([
      incoming('secret:abc123', ['s1', 's2']),
      incoming('secret:zzz', ['s9']),
    ])).rejects.toThrow('create failed')
    expect(h.rows).toHaveLength(1)
    expect(h.rows[0]).toMatchObject({ id: 'old', groupKey: 'secret:cloud:https-app.example.com' })
  })
})
