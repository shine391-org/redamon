'use client'

import { useState, useEffect, useRef } from 'react'
import { ArrowLeft, Plus, Trash2, MessageSquare, Loader2, AlertCircle } from 'lucide-react'
import type { Conversation } from '@/hooks/useConversations'
import styles from './ConversationHistory.module.css'

const PHASE_COLORS: Record<string, { color: string; bg: string }> = {
  informational: { color: '#059669', bg: 'rgba(5, 150, 105, 0.1)' },
  exploitation: { color: 'var(--status-warning)', bg: 'rgba(245, 158, 11, 0.1)' },
  post_exploitation: { color: 'var(--status-error)', bg: 'rgba(239, 68, 68, 0.1)' },
}

function formatRelativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime()
  const minutes = Math.floor(diff / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`
  return new Date(dateStr).toLocaleDateString()
}

interface ConversationHistoryProps {
  conversations: Conversation[]
  currentSessionId: string
  onBack: () => void
  onSelect: (conversation: Conversation) => void
  onDelete: (id: string) => void
  onNewChat: () => void
  loading?: boolean
  /** The list could not be loaded: shown instead of "No sessions yet", or above a stale list. */
  error?: string | null
}

export function ConversationHistory({
  conversations,
  currentSessionId,
  onBack,
  onSelect,
  onDelete,
  onNewChat,
  loading = false,
  error = null,
}: ConversationHistoryProps) {
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)
  const confirmTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Auto-dismiss delete confirmation after 5s
  useEffect(() => {
    if (deleteConfirmId) {
      confirmTimerRef.current = setTimeout(() => setDeleteConfirmId(null), 5000)
      return () => {
        if (confirmTimerRef.current) clearTimeout(confirmTimerRef.current)
      }
    }
  }, [deleteConfirmId])

  const handleDeleteClick = (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    setDeleteConfirmId(id)
  }

  const handleConfirmDelete = (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    onDelete(id)
    setDeleteConfirmId(null)
  }

  const handleCancelDelete = (e: React.MouseEvent) => {
    e.stopPropagation()
    setDeleteConfirmId(null)
  }

  return (
    <div className={styles.overlay}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={onBack} title="Back to chat">
          <ArrowLeft size={14} />
        </button>
        <span className={styles.headerTitle}>Sessions</span>
        <button className={styles.newChatButton} onClick={onNewChat}>
          <Plus size={12} />
          New Session
        </button>
      </div>

      <div className={styles.list}>
        {error && conversations.length > 0 && (
          <div className={styles.listError} role="alert">
            <AlertCircle size={12} />
            <span>{error}</span>
          </div>
        )}
        {error && conversations.length === 0 ? (
          <div className={styles.empty} role="alert">
            <AlertCircle size={22} style={{ marginBottom: 8, opacity: 0.7 }} />
            <span>Could not load the sessions</span>
            <span className={styles.emptyDetail}>{error}</span>
          </div>
        ) : loading && conversations.length === 0 ? (
          <div className={styles.empty}>
            <Loader2 size={22} className={styles.spinner} />
            <span>Loading sessions…</span>
          </div>
        ) : conversations.length === 0 ? (
          <div className={styles.empty}>
            <MessageSquare size={24} style={{ marginBottom: 8, opacity: 0.5 }} />
            <span>No sessions yet</span>
          </div>
        ) : (
          conversations.map((conv) => {
            const phaseStyle = PHASE_COLORS[conv.currentPhase] || PHASE_COLORS.informational
            const isActive = conv.sessionId === currentSessionId

            return (
              <div key={conv.id}>
                <div
                  className={`${styles.item} ${isActive ? styles.itemActive : ''}`}
                  onClick={() => {
                    if (!isActive) onSelect(conv)
                  }}
                >
                  <div className={styles.itemContent}>
                    <div className={styles.itemTitle}>
                      {conv.title || 'New session'}
                    </div>
                    <div className={styles.itemMeta}>
                      <span className={styles.itemTime} title={conv.sessionId}>
                        {conv.sessionId.slice(-8)}
                      </span>
                      <span className={styles.itemTime}>
                        {formatRelativeTime(conv.updatedAt)}
                      </span>
                      <span
                        className={styles.phaseBadge}
                        style={{
                          color: phaseStyle.color,
                          backgroundColor: phaseStyle.bg,
                          borderColor: phaseStyle.color,
                        }}
                      >
                        {conv.currentPhase.replace('_', ' ')}
                      </span>
                      {conv.iterationCount > 0 && (
                        <span className={styles.itemTime}>
                          Step {conv.iterationCount}
                        </span>
                      )}
                      {conv.agentRunning && <span className={styles.runningDot} title="Agent running" />}
                    </div>
                  </div>
                  <button
                    className={styles.deleteButton}
                    onClick={(e) => handleDeleteClick(e, conv.id)}
                    title="Delete session"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>

                {deleteConfirmId === conv.id && (
                  <div className={styles.confirmDelete}>
                    <span>Delete this session?</span>
                    <button
                      className={styles.confirmYes}
                      onClick={(e) => handleConfirmDelete(e, conv.id)}
                    >
                      Delete
                    </button>
                    <button
                      className={styles.confirmNo}
                      onClick={handleCancelDelete}
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
