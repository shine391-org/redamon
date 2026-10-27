/**
 * WebSocket protocol parity (drift-map #17, section 6 guard #12).
 *
 * The agent's MessageType (agentic/websocket_api.py) and the webapp's
 * (websocket-types.ts) must hold the same values, in the same direction, and
 * every value must be used: a client message is sent by useAgentWebSocket, a
 * server message is handled by the drawer or the socket hook, or it is listed
 * with its reason in IGNORED_SERVER_MESSAGES. `job_update` was the one value the
 * agent sent that the webapp did not know, and nothing failed.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { IGNORED_SERVER_MESSAGES, MessageType } from './websocket-types'

const WS_API_PY = join(__dirname, '../../../agentic/websocket_api.py')
const TYPES_TS = join(__dirname, 'websocket-types.ts')
const SOCKET_HOOK = join(__dirname, '../hooks/useAgentWebSocket.ts')
const DRAWER_HANDLER = join(__dirname, '../app/graph/components/AIAssistantDrawer/hooks/useWebSocketHandler.ts')

type Split = { client: Map<string, string>; server: Map<string, string> }

/**
 * NAME -> value for each direction, from an enum body whose members follow a
 * "Client → Server" and a "Server → Client" comment, as both files are laid out.
 */
function splitByDirection(body: string, comment: string, member: RegExp): Split {
  const out: Split = { client: new Map(), server: new Map() }
  let side: Map<string, string> | null = null
  for (const line of body.split('\n')) {
    const t = line.trim()
    if (t.startsWith(comment) && /Client\s*→\s*Server/.test(t)) side = out.client
    else if (t.startsWith(comment) && /Server\s*→\s*Client/.test(t)) side = out.server
    const m = member.exec(t)
    if (m) {
      expect(side, `${m[1]} appears before any direction comment`).not.toBeNull()
      side!.set(m[1], m[2])
    }
  }
  return out
}

function tsEnum(): Split {
  const src = readFileSync(TYPES_TS, 'utf8')
  const body = /export enum MessageType \{([\s\S]*?)\n\}/.exec(src)
  expect(body, 'enum MessageType not found').toBeTruthy()
  return splitByDirection(body![1], '//', /^([A-Z_]+)\s*=\s*'([^']+)'/)
}

function pythonEnum(): Split {
  const src = readFileSync(WS_API_PY, 'utf8')
  const body = /^class MessageType\(str, Enum\):\n([\s\S]*?)\n(?=\S)/m.exec(src)
  expect(body, 'class MessageType not found in agentic/websocket_api.py').toBeTruthy()
  return splitByDirection(body![1], '#', /^([A-Z_]+)\s*=\s*"([^"]+)"/)
}

const names = (src: string, re: RegExp) => new Set([...src.matchAll(re)].map(m => m[1]))

describe('MessageType parity with the agent', () => {
  const available = existsSync(WS_API_PY)

  test('the parsed TS enum is the runtime enum', () => {
    const { client, server } = tsEnum()
    const parsed = new Map([...client, ...server])
    expect(Object.fromEntries(parsed)).toEqual(Object.fromEntries(Object.entries(MessageType)))
  })

  test.skipIf(!available)('client -> server values are equal on both sides', () => {
    const py = pythonEnum()
    expect(Object.fromEntries(tsEnum().client)).toEqual(Object.fromEntries(py.client))
  })

  test.skipIf(!available)('server -> client values are equal on both sides', () => {
    const py = pythonEnum()
    expect(py.server.size).toBeGreaterThan(30)
    expect(Object.fromEntries(tsEnum().server)).toEqual(Object.fromEntries(py.server))
  })
})

describe('every value is used, or ignored on purpose', () => {
  const socket = readFileSync(SOCKET_HOOK, 'utf8')
  const drawer = readFileSync(DRAWER_HANDLER, 'utf8')
  const sent = names(socket, /sendMessage\(MessageType\.([A-Z_]+)/g)
  const handled = new Set([
    ...names(drawer, /case MessageType\.([A-Z_]+)\s*:/g),
    ...names(socket, /message\.type === MessageType\.([A-Z_]+)/g),
  ])
  const valueToName = new Map(Object.entries(MessageType).map(([k, v]) => [v as string, k]))
  const ignored = new Set(Object.keys(IGNORED_SERVER_MESSAGES).map(v => valueToName.get(v)))

  test('every client message is sent by the socket hook', () => {
    const missing = [...tsEnum().client.keys()].filter(n => !sent.has(n))
    expect(missing).toEqual([])
  })

  test('every server message is handled or listed in IGNORED_SERVER_MESSAGES', () => {
    const missing = [...tsEnum().server.keys()].filter(n => !handled.has(n) && !ignored.has(n))
    expect(missing).toEqual([])
  })

  test('an ignored message is not also handled, and every reason is written', () => {
    expect([...ignored].filter(n => n && handled.has(n))).toEqual([])
    for (const [type, reason] of Object.entries(IGNORED_SERVER_MESSAGES)) {
      expect(valueToName.has(type), `${type} is not a MessageType`).toBe(true)
      expect(reason?.length ?? 0, type).toBeGreaterThan(20)
    }
  })

  test('job_update is known, and ignored because no view lists agent jobs', () => {
    expect(MessageType.JOB_UPDATE).toBe('job_update')
    expect(IGNORED_SERVER_MESSAGES[MessageType.JOB_UPDATE]).toMatch(/background jobs/)
  })
})
