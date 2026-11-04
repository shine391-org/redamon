'use client'

import { useState, useCallback, useRef, useEffect } from 'react'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'

export interface Conversation {
  id: string
  sessionId: string
  title: string
  status: string
  agentRunning: boolean
  currentPhase: string
  iterationCount: number
  activeSkillId: string
  createdAt: string
  updatedAt: string
  _count?: { messages: number }
}

export interface ConversationWithMessages extends Conversation {
  messages: Array<{
    id: string
    sequenceNum: number
    type: string
    data: any
    createdAt: string
  }>
}

export type ConversationAction = 'list' | 'create' | 'delete' | 'load' | 'update'

/** A cleanup step the delete route could not do (the agent may still run, chain nodes may remain). */
export interface ConversationDeleteWarning {
  step: 'agent_stop' | 'graph_cleanup'
  code: string
  status?: number
}

export interface UseConversationsOptions {
  /** A failed call, read into an ApiError whose message carries the code and HTTP status. */
  onError?: (action: ConversationAction, error: ApiError) => void
  /** A delete that went through with steps that did not. */
  onDeleteWarnings?: (warnings: ConversationDeleteWarning[]) => void
}

const FAILED: Record<ConversationAction, string> = {
  list: 'Failed to fetch conversations',
  create: 'Failed to create conversation',
  delete: 'Failed to delete conversation',
  load: 'Failed to load conversation',
  update: 'Failed to update conversation',
}

export function useConversations(projectId: string, userId: string, options: UseConversationsOptions = {}) {
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [loading, setLoading] = useState(false)
  // The list's last failure, shown in the history panel; an action's failure
  // goes to onError instead, so it is not read as "the list did not load".
  const [error, setError] = useState<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const optionsRef = useRef(options)
  optionsRef.current = options

  const fail = useCallback((action: ConversationAction, err: unknown): ApiError => {
    const apiError = toApiError(err, FAILED[action])
    if (action === 'list') setError(apiError.message)
    optionsRef.current.onError?.(action, apiError)
    return apiError
  }, [])

  // Drop the previous project's list the instant the project changes, so the
  // history panel shows a loading spinner (not stale rows) until the new
  // project's conversations arrive.
  useEffect(() => {
    setConversations([])
    setError(null)
  }, [projectId])

  // Answers the ApiError on failure (undefined when superseded), so a caller
  // restoring a session can say why it could not.
  const fetchConversations = useCallback(async (): Promise<Conversation[] | ApiError | undefined> => {
    if (!projectId || !userId) return

    // Abort any in-flight request
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    try {
      setLoading(true)
      const res = await fetch(
        `/api/conversations?projectId=${projectId}&userId=${userId}`,
        { signal: controller.signal }
      )
      if (!res.ok) throw await readApiError(res, FAILED.list)
      const data = await res.json()
      setConversations(data)
      setError(null)
      return data as Conversation[]
    } catch (err: any) {
      if (err?.name !== 'AbortError') {
        return fail('list', err)
      }
    } finally {
      // Only the most-recent fetch owns the loading flag; a superseded/aborted
      // fetch must not flip the spinner off while the newer one is still running
      // (which would flash "No sessions yet" during a project switch).
      if (abortRef.current === controller) setLoading(false)
    }
  }, [projectId, userId, fail])

  const createConversation = useCallback(async (sessionId: string): Promise<Conversation | null> => {
    if (!projectId || !userId) return null

    try {
      const res = await fetch('/api/conversations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, userId, sessionId }),
      })
      if (!res.ok) throw await readApiError(res, FAILED.create)
      const conversation = await res.json()
      // Prepend to list
      setConversations(prev => [{ ...conversation, _count: { messages: 0 } }, ...prev])
      return conversation
    } catch (err: any) {
      fail('create', err)
      return null
    }
  }, [projectId, userId, fail])

  /** True when the conversation is gone; the caller keeps its chat otherwise. */
  const deleteConversation = useCallback(async (id: string): Promise<boolean> => {
    try {
      const res = await fetch(`/api/conversations/${id}`, { method: 'DELETE' })
      if (!res.ok) throw await readApiError(res, FAILED.delete)
      const body = await res.json().catch(() => null)
      setConversations(prev => prev.filter(c => c.id !== id))
      if (Array.isArray(body?.warnings) && body.warnings.length > 0) {
        optionsRef.current.onDeleteWarnings?.(body.warnings as ConversationDeleteWarning[])
      }
      return true
    } catch (err: any) {
      fail('delete', err)
      return false
    }
  }, [fail])

  const loadConversation = useCallback(async (id: string): Promise<ConversationWithMessages | null> => {
    try {
      const res = await fetch(`/api/conversations/${id}`)
      if (!res.ok) throw await readApiError(res, FAILED.load)
      return await res.json()
    } catch (err: any) {
      fail('load', err)
      return null
    }
  }, [fail])

  const updateConversation = useCallback(async (id: string, updates: Partial<Conversation>) => {
    try {
      const res = await fetch(`/api/conversations/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      })
      if (!res.ok) throw await readApiError(res, FAILED.update)
      const updated = await res.json()
      setConversations(prev => prev.map(c => c.id === id ? { ...c, ...updated } : c))
    } catch (err: any) {
      fail('update', err)
    }
  }, [fail])

  return {
    conversations,
    loading,
    error,
    fetchConversations,
    createConversation,
    deleteConversation,
    loadConversation,
    updateConversation,
  }
}
