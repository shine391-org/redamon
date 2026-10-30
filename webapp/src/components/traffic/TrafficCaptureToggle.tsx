'use client'

import { useEffect, useState } from 'react'
import { Toggle, useToast } from '@/components/ui'
import { errorMessage, readApiError } from '@/lib/apiError'

/**
 * Per-project TrafficMind capture-routing toggle.
 *
 * Reads and writes the project's `captureProxyEnabled` flag directly (PUT
 * /api/projects/[id]) - the change applies immediately and takes effect on the
 * project's next session. Shows the current project name next to the switch so
 * the operator always knows which project they are toggling.
 *
 * `initialEnabled` lets a parent that already knows the value (e.g. the settings
 * matrix) skip the self-fetch; when omitted the component fetches it once.
 */
export function TrafficCaptureToggle({
  projectId,
  projectName,
  initialEnabled,
  showName = true,
  size = 'default',
}: {
  projectId: string
  projectName?: string | null
  initialEnabled?: boolean
  showName?: boolean
  size?: 'small' | 'default' | 'large'
}) {
  const [enabled, setEnabled] = useState<boolean | null>(
    initialEnabled === undefined ? null : initialEnabled
  )
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  useEffect(() => {
    if (initialEnabled !== undefined) { setEnabled(initialEnabled); return }
    let cancelled = false
    setEnabled(null)
    if (!projectId) return
    fetch(`/api/projects/${projectId}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((p) => { if (!cancelled && p) setEnabled(!!p.captureProxyEnabled) })
      .catch(() => { if (!cancelled) setEnabled(false) })
    return () => { cancelled = true }
  }, [projectId, initialEnabled])

  async function onToggle(next: boolean) {
    if (saving || !projectId) return
    const prev = enabled
    setEnabled(next)
    setSaving(true)
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ captureProxyEnabled: next }),
      })
      if (!res.ok) throw await readApiError(res, 'Failed to update traffic capture setting')
      toast.success(`Traffic capture ${next ? 'enabled' : 'disabled'}${projectName ? ` for ${projectName}` : ''}`)
    } catch (err) {
      setEnabled(prev ?? false)
      toast.error(errorMessage(err, 'Failed to update traffic capture setting'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      {showName && (
        <span style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
          Enable traffic capture for{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{projectName || 'this project'}</strong>
        </span>
      )}
      <Toggle
        checked={!!enabled}
        onChange={onToggle}
        disabled={enabled === null || saving}
        size={size}
        aria-label={`Toggle traffic capture${projectName ? ` for ${projectName}` : ''}`}
      />
    </div>
  )
}
