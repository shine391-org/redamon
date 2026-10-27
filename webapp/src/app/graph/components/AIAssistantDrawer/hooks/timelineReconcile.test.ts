/**
 * Unit tests for the running-session resync reconciler.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/graph/components/AIAssistantDrawer/hooks/timelineReconcile.test.ts
 *
 * The bug being defended: opening a running session from history reads a DB
 * snapshot that lags the live stream, so the first render is stale/empty. After
 * the socket connects (backend having flushed its persist queue) we re-read and
 * reconcile. reconcileTimeline must (1) adopt the authoritative timeline, (2)
 * drop stale first-restore duplicates, and (3) keep live events that arrived
 * over the socket but aren't persisted yet — with no duplication or loss.
 */

import { describe, test, expect } from 'vitest'
import { reconcileTimeline, timelineItemKey } from './timelineReconcile'
import type { ChatItem } from '../types'

const msg = (role: 'user' | 'assistant', content: string, id = `m-${content}`): ChatItem =>
  ({ type: 'message', id, role, content, timestamp: new Date() } as any)

const thinking = (thought: string, id = `t-${thought}`): ChatItem =>
  ({ type: 'thinking', id, thought, reasoning: '', action: 'thinking', updated_todo_list: [], timestamp: new Date() } as any)

const tool = (tool_name: string, tool_args: any, status: string, id = `x-${tool_name}`): ChatItem =>
  ({ type: 'tool_execution', id, tool_name, tool_args, status, output_chunks: [], timestamp: new Date() } as any)

describe('timelineItemKey', () => {
  test('is content-based and id-independent', () => {
    // Same thought, different id schemes (DB cuid vs live generated) → same key.
    expect(timelineItemKey(thinking('hello', 'cuid_abc')))
      .toBe(timelineItemKey(thinking('hello', 'thinking-123-4')))
  })

  test('a running live tool and its completed DB twin share a key', () => {
    expect(timelineItemKey(tool('nmap', { t: '1' }, 'running', 'live-1')))
      .toBe(timelineItemKey(tool('nmap', { t: '1' }, 'success', 'db-1')))
  })

  test('different tool args produce different keys', () => {
    expect(timelineItemKey(tool('nmap', { t: '1' }, 'running')))
      .not.toBe(timelineItemKey(tool('nmap', { t: '2' }, 'running')))
  })
})

describe('reconcileTimeline', () => {
  test('empty stale restore + complete DB → adopts the full DB timeline', () => {
    const authoritative = [msg('user', 'objective'), thinking('step 1'), tool('nmap', {}, 'success')]
    const current: ChatItem[] = []   // first restore came back empty (queue lag)
    const out = reconcileTimeline(authoritative, current)
    expect(out).toEqual(authoritative)
  })

  test('stale restore items are superseded by their authoritative versions (no dup)', () => {
    // First restore had a running tool; DB now has it completed. Reconcile keeps
    // only the completed one.
    const staleRunning = tool('nmap', { target: 'x' }, 'running', 'live-nmap')
    const dbComplete = tool('nmap', { target: 'x' }, 'success', 'db-nmap')
    const authoritative = [msg('user', 'go'), thinking('t'), dbComplete]
    const current = [msg('user', 'go'), thinking('t'), staleRunning]
    const out = reconcileTimeline(authoritative, current)
    expect(out).toHaveLength(3)
    expect(out).toEqual(authoritative)
    expect(out.filter(i => (i as any).tool_name === 'nmap')).toHaveLength(1)
    expect((out[2] as any).status).toBe('success')
  })

  test('live events not yet persisted survive as a chronological suffix', () => {
    // DB is current up to "thinking B"; two live events arrived over the socket
    // after the flush point and are not in the DB read yet.
    const authoritative = [msg('user', 'go'), thinking('A'), thinking('B')]
    const liveNew1 = tool('curl', { u: '1' }, 'running', 'live-curl')
    const liveNew2 = thinking('C', 'live-C')
    const current = [msg('user', 'go'), thinking('A'), thinking('B'), liveNew1, liveNew2]
    const out = reconcileTimeline(authoritative, current)
    expect(out).toHaveLength(5)
    expect(out.slice(0, 3)).toEqual(authoritative)
    expect(out[3]).toBe(liveNew1)
    expect(out[4]).toBe(liveNew2)
  })

  test('the full bug scenario: stale+partial restore, live continuation, DB catches up', () => {
    // Screen currently: an empty-ish restore (just the objective) + a few live
    // events streamed in. The resync re-read now has the objective + early steps
    // persisted, while the newest live tool isn't in the DB yet.
    const objective = msg('user', 'pentest the target')
    const liveThink = thinking('probing endpoints', 'live-think')
    const liveToolRunning = tool('gobuster', { url: 'http://x' }, 'running', 'live-gob')

    const current = [objective, liveThink, liveToolRunning]

    // Authoritative (post-flush) has the objective + the now-persisted think, but
    // NOT the still-running gobuster.
    const authoritative = [objective, thinking('probing endpoints', 'db-think')]

    const out = reconcileTimeline(authoritative, current)

    // objective (once), think (authoritative version), running gobuster kept.
    expect(out).toHaveLength(3)
    expect(timelineItemKey(out[0])).toBe(timelineItemKey(objective))
    expect((out[1] as any).id).toBe('db-think')          // authoritative wins
    expect(out[2]).toBe(liveToolRunning)                 // live suffix preserved
    // no duplicated think
    expect(out.filter(i => (i as any).type === 'thinking')).toHaveLength(1)
  })

  test('idempotent: reconciling an already-reconciled timeline is a no-op', () => {
    const authoritative = [msg('user', 'go'), thinking('a'), tool('nmap', {}, 'success')]
    const once = reconcileTimeline(authoritative, [])
    const twice = reconcileTimeline(authoritative, once)
    expect(twice).toEqual(authoritative)
  })

  test('de-dupes repeated live items within the suffix', () => {
    const dupA = thinking('same', 'l1')
    const dupB = thinking('same', 'l2')   // same content key as dupA
    const out = reconcileTimeline([msg('user', 'go')], [msg('user', 'go'), dupA, dupB])
    expect(out).toHaveLength(2)           // objective + one 'same'
  })

  test('preserves plan_wave identity by wave_id', () => {
    const dbWave = { type: 'plan_wave', id: 'db-w', wave_id: 'W1', tools: [], status: 'success', timestamp: new Date() } as any
    const liveWave = { type: 'plan_wave', id: 'live-w', wave_id: 'W1', tools: [], status: 'running', timestamp: new Date() } as any
    const out = reconcileTimeline([dbWave], [liveWave])
    expect(out).toHaveLength(1)
    expect((out[0] as any).status).toBe('success')
  })

  test('places a not-yet-persisted MIDDLE live event in its slot, not at the end', () => {
    // current order: X, mid (live, unpersisted), Z. The DB read has only X and Z
    // (mid's persist was still in flight). mid must land between them, not last.
    const X = msg('user', 'x')
    const mid = tool('curl', { u: 'mid' }, 'running', 'live-mid')
    const Z = thinking('z')
    const out = reconcileTimeline([X, Z], [X, mid, Z])
    expect(out.map(i => (i as any).id)).toEqual([X.id, 'live-mid', (Z as any).id])
  })

  test('keeps an authoritative-only item current never saw in backbone order', () => {
    // Y was persisted but never reached this client's live stream. It must stay
    // between X and Z (authoritative is the ordering backbone).
    const X = msg('user', 'x')
    const Y = thinking('y')
    const Z = tool('nmap', {}, 'success')
    const out = reconcileTimeline([X, Y, Z], [X, Z])
    expect(out).toEqual([X, Y, Z])
  })
})

describe('reconcileTimeline - tool cards in a reconnect resync', () => {
  const stepTool = (step_id: string, status: string, extra: any = {}): ChatItem =>
    ({ type: 'tool_execution', id: `x-${step_id}-${status}`, tool_name: 'execute_code', tool_args: { c: 1 },
       status, output_chunks: [], timestamp: new Date(), step_id, ...extra } as any)

  test('cards pair by step_id, so two identical calls stay two cards', () => {
    const auth = [stepTool('S1', 'success'), stepTool('S2', 'running')]
    const current = [stepTool('S1', 'running'), stepTool('S2', 'running')]
    const out = reconcileTimeline(auth, current)
    expect(out).toHaveLength(2)
    expect(out.map((i: any) => i.status)).toEqual(['success', 'running'])
  })

  test('a still-running DB card keeps the output and verdict the socket already showed', () => {
    const auth = [stepTool('S1', 'running')]
    const live = [stepTool('S1', 'running', { output_chunks: ['uid=0'], finished: true, finishedSuccess: true, duration: 1500 })]
    const [card] = reconcileTimeline(auth, live) as any[]
    expect(card.output_chunks).toEqual(['uid=0'])
    expect(card.finished).toBe(true)
    expect(card.duration).toBe(1500)
  })

  test('a completed DB card wins over the live running copy', () => {
    const auth = [stepTool('S1', 'success', { output_chunks: ['final'] })]
    const live = [stepTool('S1', 'running', { output_chunks: ['partial'] })]
    const [card] = reconcileTimeline(auth, live) as any[]
    expect(card.status).toBe('success')
    expect(card.output_chunks).toEqual(['final'])
  })
})

describe('reconcileTimeline - a card the socket closed after the DB read', () => {
  test('a live success/error is never reverted by a staler "running" DB row', () => {
    const auth = [{ type: 'tool_execution', id: 'db', tool_name: 'execute_code', tool_args: {}, status: 'running',
      output_chunks: [], timestamp: new Date(), step_id: 'S1' } as any]
    const live = [{ type: 'tool_execution', id: 'live', tool_name: 'execute_code', tool_args: {}, status: 'success',
      output_chunks: ['out'], final_output: 'analysis', timestamp: new Date(), step_id: 'S1' } as any]
    const [card] = reconcileTimeline(auth, live) as any[]
    expect(card.status).toBe('success')
    expect(card.final_output).toBe('analysis')
  })
})
