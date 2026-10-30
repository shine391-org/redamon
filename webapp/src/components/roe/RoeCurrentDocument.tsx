'use client'

/**
 * The project's current RoE document: what it is, when it applied, and the
 * documents it superseded.
 */
import { useState } from 'react'
import { Download, FileText, History, Trash2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { downloadRoeFile } from './roeClient'
import { readApiError, toApiError } from '@/lib/apiError'

interface Revision {
  id: string
  documentName: string
  appliedAt: string | null
  supersededAt: string
  reason: string
}

export interface RoeCurrentDocumentProps {
  projectId: string
  documentName: string
  appliedAt: string | null
  onRemove: () => void
  removing?: boolean
}

export function RoeCurrentDocument({ projectId, documentName, appliedAt, onRemove, removing }: RoeCurrentDocumentProps) {
  const [error, setError] = useState<string | null>(null)
  const [revisions, setRevisions] = useState<Revision[] | null>(null)
  const [historyOpen, setHistoryOpen] = useState(false)
  const [historyError, setHistoryError] = useState<string | null>(null)

  const openHistory = async () => {
    setHistoryOpen(true)
    setRevisions(null)
    setHistoryError(null)
    try {
      const res = await fetch(`/api/projects/${projectId}/roe/revisions`)
      if (!res.ok) throw await readApiError(res, 'Could not load the RoE history')
      const body = await res.json()
      setRevisions(Array.isArray(body.revisions) ? body.revisions : [])
    } catch (e) {
      // An unread history must not read as "no earlier document".
      setHistoryError(toApiError(e, 'Could not load the RoE history').message)
      setRevisions([])
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap',
        padding: '10px 12px', background: 'var(--form-field-bg)',
        border: '1px solid var(--form-field-border)', borderRadius: 'var(--radius-default)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flexWrap: 'wrap' }}>
          <FileText size={15} style={{ flexShrink: 0, color: 'var(--form-info)' }} />
          <strong style={{ overflowWrap: 'anywhere', color: 'var(--form-ink)' }}>{documentName}</strong>
          {appliedAt && (
            <span style={{ fontSize: 11, color: 'var(--form-ink-muted)' }}>
              applied {new Date(appliedAt).toLocaleString()}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            type="button"
            className="secondaryButton"
            onClick={async () => setError(await downloadRoeFile(`/api/projects/${projectId}/roe/download`, documentName))}
          >
            <Download size={14} /> Download
          </button>
          <button type="button" className="secondaryButton" onClick={openHistory}>
            <History size={14} /> History
          </button>
          <button type="button" className="secondaryButton" onClick={onRemove} disabled={removing}>
            <Trash2 size={14} /> {removing ? 'Preparing…' : 'Remove RoE'}
          </button>
        </div>
      </div>
      {error && <span role="alert" style={{ fontSize: 11, color: 'var(--form-danger)' }}>{error}</span>}

      <Modal isOpen={historyOpen} onClose={() => setHistoryOpen(false)} title="Superseded RoE documents" size="default">
        {error && <p role="alert" style={{ fontSize: 11, color: 'var(--form-danger)' }}>{error}</p>}
        {revisions === null ? (
          <p>Loading…</p>
        ) : historyError ? (
          <p role="alert" style={{ color: 'var(--form-danger)' }}>{historyError}</p>
        ) : revisions.length === 0 ? (
          <p>No earlier document. A replaced or removed document is kept here (the newest ten).</p>
        ) : (
          <ul style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {revisions.map(r => (
              <li key={r.id}>
                <strong>{r.documentName}</strong>{' '}
                <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  {r.reason} {new Date(r.supersededAt).toLocaleString()}
                  {r.appliedAt ? ` · applied ${new Date(r.appliedAt).toLocaleString()}` : ''}
                </span>{' '}
                <button
                  type="button"
                  className="secondaryButton"
                  style={{ padding: '2px 8px' }}
                  onClick={async () => setError(await downloadRoeFile(
                    `/api/projects/${projectId}/roe/revisions/${r.id}/download`, r.documentName))}
                >
                  <Download size={12} /> Download
                </button>
              </li>
            ))}
          </ul>
        )}
      </Modal>
    </div>
  )
}
