/**
 * useAgentWebSocket Hook
 *
 * Custom React hook for managing WebSocket connection to the RedAmon agent backend.
 * Provides automatic reconnection, message handling, and type-safe communication.
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { buildAgentWsUrl } from './agentWsUrl'
import {
  MessageType,
  ConnectionStatus,
  type ServerMessage,
  type ClientMessage,
  type InitPayload,
  type QueryPayload,
  type ApprovalPayload,
  type AnswerPayload,
  type ConnectedPayload,
  isServerMessage,
} from '@/lib/websocket-types'

/** Client -> server messages that must reach the agent even when the socket is
 *  down at the moment of the click: they wait in an outbox and go out right
 *  after the next CONNECTED. Dropping them silently left Stop doing nothing. */
const OUTBOX_TYPES = new Set<MessageType>([
  MessageType.STOP,
  MessageType.TOOL_STOP,
  MessageType.GUIDANCE,
  MessageType.SKILL_INJECT,
])
const OUTBOX_MAX = 20

export const PING_INTERVAL_MS = 30_000
/** No PONG for this long means the socket is dead even though the browser
 *  still reports it open (half-open TCP): reconnect instead of waiting. */
export const PONG_TIMEOUT_MS = 75_000

// =============================================================================
// HOOK CONFIGURATION
// =============================================================================

interface UseAgentWebSocketConfig {
  userId: string
  projectId: string
  sessionId: string
  graphViewCypher?: string
  enabled?: boolean
  /** A run is in progress: a graph-view change then waits for it to end
   *  instead of reconnecting, which would drop live events mid-run. */
  runActive?: boolean
  onMessage?: (message: ServerMessage) => void
  onError?: (error: Error) => void
  onConnect?: (payload: ConnectedPayload) => void
  onDisconnect?: () => void
  maxReconnectAttempts?: number
  reconnectInterval?: number
}

interface UseAgentWebSocketReturn {
  status: ConnectionStatus
  isConnected: boolean
  reconnectAttempt: number
  error: Error | null
  sendQuery: (question: string) => void
  sendApproval: (decision: 'approve' | 'modify' | 'abort', modification?: string) => void
  sendToolConfirmation: (decision: 'approve' | 'modify' | 'reject', modifications?: Record<string, any>) => void
  sendFireteamMemberConfirmation: (wave_id: string, member_id: string, decision: 'approve' | 'reject', modifications?: Record<string, any>) => void
  sendAnswer: (answer: string) => void
  sendGuidance: (message: string) => void
  sendSkillInject: (payload: { skill_id: string; skill_name: string; content: string }) => void
  sendStop: () => void
  sendResume: () => void
  sendToolStop: (tool_name: string, wave_id?: string, step_index?: number) => void
  disconnect: () => void
  reconnect: () => void
}

// =============================================================================
// WEBSOCKET HOOK
// =============================================================================

export function useAgentWebSocket({
  userId,
  projectId,
  sessionId,
  graphViewCypher,
  enabled = true,
  runActive = false,
  onMessage,
  onError,
  onConnect,
  onDisconnect,
  maxReconnectAttempts = 5,
  reconnectInterval = 3000,
}: UseAgentWebSocketConfig): UseAgentWebSocketReturn {
  const [status, setStatus] = useState<ConnectionStatus>(ConnectionStatus.DISCONNECTED)
  const [reconnectAttempt, setReconnectAttempt] = useState(0)
  const [error, setError] = useState<Error | null>(null)

  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const isIntentionalDisconnect = useRef(false)
  const isAuthenticatedRef = useRef(false)
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  // Set when the ticket mint came back empty, so the agent's 1008 rejection can
  // name the actual cause instead of a generic auth error.
  const ticketMissingRef = useRef(false)
  // Each queued message remembers its session: a Stop clicked while
  // disconnected must never reach another session the page switched to.
  const outboxRef = useRef<{ sessionKey: string; message: ClientMessage }[]>([])
  const sessionKey = `${userId}:${projectId}:${sessionId}`
  const sessionKeyRef = useRef(sessionKey)
  sessionKeyRef.current = sessionKey
  const lastPongAtRef = useRef(0)
  const connectRef = useRef<() => void>(() => {})
  // Read at init time, so a view change does not have to rebuild sendInit.
  const graphViewCypherRef = useRef(graphViewCypher)
  graphViewCypherRef.current = graphViewCypher
  // The view the live connection was opened with (see the view effect below).
  const appliedViewRef = useRef(graphViewCypher)

  // Get WebSocket URL - auto-detect from browser location so it works on any
  // machine. The chat socket authenticates via the init frame (not a URL ticket).
  const getWebSocketUrl = useCallback(() => buildAgentWsUrl('/ws/agent'), [])

  // Send a message to the server
  const sendMessage = useCallback(<T = any>(type: MessageType, payload: T) => {
    const message: ClientMessage<T> = { type, payload }
    const ready = wsRef.current && wsRef.current.readyState === WebSocket.OPEN
      && (isAuthenticatedRef.current || type === MessageType.INIT)
    if (!ready) {
      if (OUTBOX_TYPES.has(type) && outboxRef.current.length < OUTBOX_MAX) {
        outboxRef.current.push({ sessionKey: sessionKeyRef.current, message })
      }
      return
    }
    wsRef.current!.send(JSON.stringify(message))
  }, [])

  const flushOutbox = useCallback(() => {
    const queued = outboxRef.current
    outboxRef.current = []
    for (const { sessionKey: key, message } of queued) {
      if (key === sessionKeyRef.current) sendMessage(message.type, message.payload)
    }
  }, [sendMessage])

  // Send initialization message.
  // STRIDE S6: fetch a short-lived ticket (JWT cookie sent automatically) and
  // include it so the agent can authenticate the socket. A ticketless init is
  // still sent, but the agent FAILS CLOSED and rejects it with close code 1008
  // (see handleClose) - it does not fail open, whatever the mint side says.
  const sendInit = useCallback(async () => {
    if (!wsRef.current || isAuthenticatedRef.current) return

    let ticket: string | undefined
    try {
      const resp = await fetch('/api/agent/ws-ticket', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, sessionId }),
      })
      if (resp.ok) {
        const data = await resp.json()
        if (data?.ticket) ticket = data.ticket as string
      }
    } catch {
      // Non-fatal here: the rejection below is what the user is told about.
    }
    ticketMissingRef.current = !ticket

    const initPayload: InitPayload = {
      user_id: userId,
      project_id: projectId,
      session_id: sessionId,
      ...(ticket && { ticket }),
      ...(graphViewCypherRef.current && { graph_view_cypher: graphViewCypherRef.current }),
    }
    appliedViewRef.current = graphViewCypherRef.current

    sendMessage(MessageType.INIT, initPayload)
  }, [userId, projectId, sessionId, sendMessage])

  // Public API: Send query
  const sendQuery = useCallback((question: string) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const queryPayload: QueryPayload = { question }
    sendMessage(MessageType.QUERY, queryPayload)
  }, [sendMessage])

  // Public API: Send approval
  const sendApproval = useCallback((decision: 'approve' | 'modify' | 'abort', modification?: string) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const approvalPayload: ApprovalPayload = { decision, modification }
    sendMessage(MessageType.APPROVAL, approvalPayload)
  }, [sendMessage])

  // Public API: Send tool confirmation
  const sendToolConfirmation = useCallback((decision: 'approve' | 'modify' | 'reject', modifications?: Record<string, any>) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const payload: any = { decision }
    if (modifications) payload.modifications = modifications
    sendMessage(MessageType.TOOL_CONFIRMATION, payload)
  }, [sendMessage])

  // Public API: Send a single fireteam member's dangerous-tool decision.
  // Unlike sendToolConfirmation, this does NOT pause the parent graph -
  // other members keep running while this one resumes on approve/reject.
  const sendFireteamMemberConfirmation = useCallback((
    wave_id: string,
    member_id: string,
    decision: 'approve' | 'reject',
    modifications?: Record<string, any>,
  ) => {
    if (!isAuthenticatedRef.current) return
    const payload: any = { wave_id, member_id, decision }
    if (modifications) payload.modifications = modifications
    sendMessage(MessageType.FIRETEAM_MEMBER_CONFIRMATION, payload)
  }, [sendMessage])

  // Public API: Send answer
  const sendAnswer = useCallback((answer: string) => {
    if (!isAuthenticatedRef.current) {
      return
    }

    const answerPayload: AnswerPayload = { answer }
    sendMessage(MessageType.ANSWER, answerPayload)
  }, [sendMessage])

  // Public API: Send guidance (steer agent while it's working)
  const sendGuidance = useCallback((message: string) => {
    sendMessage(MessageType.GUIDANCE, { message })
  }, [sendMessage])

  // Public API: Send skill injection (push Chat Skill content into guidance queue)
  const sendSkillInject = useCallback((payload: { skill_id: string; skill_name: string; content: string }) => {
    sendMessage(MessageType.SKILL_INJECT, payload)
  }, [sendMessage])

  // Public API: Stop agent execution
  const sendStop = useCallback(() => {
    sendMessage(MessageType.STOP, {})
  }, [sendMessage])

  // Public API: Resume agent execution from checkpoint
  const sendResume = useCallback(() => {
    if (!isAuthenticatedRef.current) return
    sendMessage(MessageType.RESUME, {})
  }, [sendMessage])

  // Public API: Stop a single tool (same semantics as the global Stop button
  // but scoped to one tool_execution card). Backend cancels just that tool
  // task; the tool completes with success=false and the agent flow proceeds.
  const sendToolStop = useCallback((tool_name: string, wave_id?: string, step_index?: number) => {
    const payload: { tool_name: string; wave_id?: string; step_index?: number } = { tool_name }
    if (wave_id) payload.wave_id = wave_id
    if (step_index !== undefined && step_index !== null) payload.step_index = step_index
    sendMessage(MessageType.TOOL_STOP, payload)
  }, [sendMessage])

  // Start ping interval for keep-alive
  const startPingInterval = useCallback(() => {
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
    }

    lastPongAtRef.current = Date.now()
    pingIntervalRef.current = setInterval(() => {
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return
      if (Date.now() - lastPongAtRef.current > PONG_TIMEOUT_MS) {
        // The agent stopped answering on this socket: a half-open connection
        // never fires onclose, so the page would sit on a stale timeline.
        setStatus(ConnectionStatus.RECONNECTING)
        connectRef.current()
        return
      }
      sendMessage(MessageType.PING, {})
    }, PING_INTERVAL_MS)
  }, [sendMessage])

  // Stop ping interval
  const stopPingInterval = useCallback(() => {
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
  }, [])

  // Handle incoming messages
  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data)

      if (!isServerMessage(data)) {
        return
      }

      const message = data as ServerMessage


      // Handle CONNECTED message
      if (message.type === MessageType.CONNECTED) {
        isAuthenticatedRef.current = true
        setStatus(ConnectionStatus.CONNECTED)
        setReconnectAttempt(0)
        setError(null)
        startPingInterval()
        flushOutbox()
        onConnect?.(message.payload as ConnectedPayload)
      }

      // Handle PONG message
      if (message.type === MessageType.PONG) {
        lastPongAtRef.current = Date.now()
        return // Don't forward pong to message handler
      }

      // Forward message to handler
      onMessage?.(message)

    } catch (err) {
    }
  }, [onMessage, onConnect, startPingInterval, flushOutbox])

  // Handle WebSocket errors
  const handleError = useCallback((event: Event) => {
    const error = new Error('WebSocket error occurred')
    setError(error)
    onError?.(error)
  }, [onError])

  // Handle WebSocket close
  const handleClose = useCallback((event: CloseEvent) => {

    isAuthenticatedRef.current = false
    stopPingInterval()
    wsRef.current = null
    setStatus(ConnectionStatus.DISCONNECTED)
    onDisconnect?.()

    // 1008 = the agent refused the init frame (ws_ticket verification). It is a
    // configuration failure, not a blip: retrying just parks the UI on
    // "Connecting..." forever, which is how a missing AGENT_WS_TICKET_SECRET
    // reached users as a silent hang. Stop and say what is wrong.
    if (event.code === 1008) {
      const authError = new Error(
        ticketMissingRef.current
          ? 'Agent WebSocket authentication failed: no session ticket was issued. Run ./redamon.sh update to generate AGENT_WS_TICKET_SECRET, then restart the webapp and agent.'
          : 'Agent WebSocket authentication failed: the agent rejected the session ticket. Check that AGENT_WS_TICKET_SECRET matches for the webapp and agent containers.'
      )
      setStatus(ConnectionStatus.FAILED)
      setError(authError)
      onError?.(authError)
      return
    }

    // Auto-reconnect if not intentional and enabled
    if (!isIntentionalDisconnect.current && enabled && reconnectAttempt < maxReconnectAttempts) {
      setStatus(ConnectionStatus.RECONNECTING)
      setReconnectAttempt(prev => prev + 1)

      reconnectTimeoutRef.current = setTimeout(() => {
        connect()
      }, reconnectInterval)
    } else if (reconnectAttempt >= maxReconnectAttempts) {
      setStatus(ConnectionStatus.FAILED)
      const maxRetriesError = new Error('Max reconnection attempts reached')
      setError(maxRetriesError)
      onError?.(maxRetriesError)
    }
  }, [enabled, reconnectAttempt, maxReconnectAttempts, reconnectInterval, stopPingInterval, onDisconnect, onError])

  // Connect to WebSocket
  const connect = useCallback(() => {
    // Close existing connection - detach handlers first to prevent
    // the old close event from clobbering the new connection
    if (wsRef.current) {
      wsRef.current.onopen = null
      wsRef.current.onmessage = null
      wsRef.current.onerror = null
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }

    // Clear reconnect timeout
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    // Reset authentication state for new connection
    isAuthenticatedRef.current = false

    try {
      const wsUrl = getWebSocketUrl()

      setStatus(ConnectionStatus.CONNECTING)
      setError(null)

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        sendInit()
      }

      ws.onmessage = handleMessage
      ws.onerror = handleError
      ws.onclose = handleClose

    } catch (err) {
      const connectionError = err instanceof Error ? err : new Error('Failed to create WebSocket')
      setError(connectionError)
      setStatus(ConnectionStatus.FAILED)
      onError?.(connectionError)
    }
  }, [getWebSocketUrl, sendInit, handleMessage, handleError, handleClose, onError])
  connectRef.current = connect

  // Public API: Disconnect
  const disconnect = useCallback(() => {
    isIntentionalDisconnect.current = true
    stopPingInterval()

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (wsRef.current) {
      wsRef.current.onopen = null
      wsRef.current.onmessage = null
      wsRef.current.onerror = null
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }

    isAuthenticatedRef.current = false
    setStatus(ConnectionStatus.DISCONNECTED)
    setReconnectAttempt(0)
  }, [stopPingInterval])

  // Public API: Reconnect
  const reconnect = useCallback(() => {
    isIntentionalDisconnect.current = false
    setReconnectAttempt(0)
    connect()
  }, [connect])

  // Connect when enabled
  useEffect(() => {
    if (enabled) {
      isIntentionalDisconnect.current = false
      connect()
    } else {
      disconnect()
    }

    // Cleanup on unmount
    return () => {
      isIntentionalDisconnect.current = true
      stopPingInterval()

      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }

      if (wsRef.current) {
        wsRef.current.onopen = null
        wsRef.current.onmessage = null
        wsRef.current.onerror = null
        wsRef.current.onclose = null
        wsRef.current.close()
      }
    }
  }, [enabled, userId, projectId, sessionId]) // Reconnect if the session changes

  // The graph view is sent in INIT, so a new view needs a new connection, but
  // not in the middle of a run: that reconnect drops the live stream exactly
  // when it matters. A change made during a run applies once the run ends.
  useEffect(() => {
    if (!enabled || runActive || appliedViewRef.current === graphViewCypher) return
    connectRef.current()
  }, [enabled, runActive, graphViewCypher])

  return {
    status,
    isConnected: status === ConnectionStatus.CONNECTED,
    reconnectAttempt,
    error,
    sendQuery,
    sendApproval,
    sendToolConfirmation,
    sendFireteamMemberConfirmation,
    sendAnswer,
    sendGuidance,
    sendSkillInject,
    sendStop,
    sendResume,
    sendToolStop,
    disconnect,
    reconnect,
  }
}
