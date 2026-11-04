'use client'

import { useCallback, useEffect, useState } from 'react'
import { Check, FolderOpen, Loader2, Pencil, Trash2, X } from 'lucide-react'
import { Modal, useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { PRESET_LIMITS, type MuteRulesPresetSummary } from '@/lib/nodeFilters/presets'
import { fetchJson, formatApiError, readApiError, toApiError } from '@/lib/apiError'
import styles from './NodeFilters.module.css'

export type PresetListMode = 'load' | 'manage'

interface PresetListModalProps {
  isOpen: boolean
  mode: PresetListMode
  onClose: () => void
  /** Confirms, then loads and saves. Resolves true once the preset is on screen. */
  onLoad: (preset: MuteRulesPresetSummary) => Promise<boolean>
}

function fmtDate(value: string | Date): string {
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })
}

function describe(p: MuteRulesPresetSummary): string {
  const { rules, kinds } = p.counts
  return `${p.mode} · ${rules} active rule${rules === 1 ? '' : 's'} in ${kinds} kind${kinds === 1 ? '' : 's'}`
}

export function PresetListModal({ isOpen, mode, onClose, onLoad }: PresetListModalProps) {
  const toast = useToast()
  const { dangerConfirm } = useAlertModal()
  const [presets, setPresets] = useState<MuteRulesPresetSummary[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ id: string; name: string; description: string; error?: string } | null>(null)

  const fetchPresets = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setPresets(await fetchJson<MuteRulesPresetSummary[]>('/api/mute-rule-presets', undefined, 'Could not load the presets'))
    } catch (e) {
      setError(toApiError(e, 'Could not load the presets').message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!isOpen) return
    setEditing(null)
    void fetchPresets()
  }, [isOpen, fetchPresets])

  const load = async (preset: MuteRulesPresetSummary) => {
    setBusyId(preset.id)
    try {
      if (await onLoad(preset)) onClose()
    } finally {
      setBusyId(null)
    }
  }

  const rename = async () => {
    if (!editing || !editing.name.trim()) return
    setBusyId(editing.id)
    try {
      const res = await fetch(`/api/mute-rule-presets/${encodeURIComponent(editing.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: editing.name, description: editing.description }),
      })
      if (!res.ok) {
        const err = await readApiError(res, 'Rename failed')
        setEditing(prev => (prev ? { ...prev, error: err.message } : prev))
        return
      }
      const body = await res.json()
      setPresets(prev => prev.map(p => (p.id === editing.id ? body : p)))
      setEditing(null)
      toast.success(`Preset "${body.name}" updated.`, 'Mute rules')
    } catch (e) {
      const message = toApiError(e, 'Rename failed').message
      setEditing(prev => (prev ? { ...prev, error: message } : prev))
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (preset: MuteRulesPresetSummary) => {
    const ok = await dangerConfirm(
      `Delete the preset "${preset.name}"? Projects keep the rules they loaded from it.`,
      'Delete preset',
      { confirmLabel: 'Delete' },
    )
    if (!ok) return
    setBusyId(preset.id)
    try {
      const res = await fetch(`/api/mute-rule-presets/${encodeURIComponent(preset.id)}`, { method: 'DELETE' })
      if (!res.ok) throw await readApiError(res, 'could not be deleted')
      setPresets(prev => prev.filter(p => p.id !== preset.id))
      toast.success(`Preset "${preset.name}" deleted.`, 'Mute rules')
    } catch (e) {
      const err = toApiError(e, 'could not be deleted')
      toast.error(`${formatApiError({ ...err, reason: `Preset "${preset.name}" could not be deleted` })}.`, 'Mute rules')
    } finally {
      setBusyId(null)
    }
  }

  const busy = busyId !== null

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={mode === 'load' ? 'Load preset' : 'Manage presets'}
      closeOnOverlayClick={!busy}
      closeOnEscape={!busy && !editing}
      headerActions={<WikiInfoButton target="NodeFilters" />}
    >
      {loading ? (
        <div className={styles.presetEmpty}><Loader2 size={18} className={styles.spin} /></div>
      ) : error ? (
        <div className={styles.presetEmpty}>
          <p>{error}</p>
          <button type="button" className={styles.button} onClick={() => void fetchPresets()}>Retry</button>
        </div>
      ) : presets.length === 0 ? (
        <div className={styles.presetEmpty}>
          <FolderOpen size={28} />
          <p>No saved presets yet.</p>
          <p>Use Presets → Save as preset to keep the rules on screen.</p>
        </div>
      ) : (
        <ul className={styles.presetList}>
          {presets.map(p => (
            <li key={p.id} className={styles.presetRow}>
              {editing?.id === p.id ? (
                <div className={styles.presetEdit}>
                  <input
                    type="text"
                    className="textInput"
                    aria-label="Preset name"
                    value={editing.name}
                    maxLength={PRESET_LIMITS.name}
                    onChange={e => setEditing({ ...editing, name: e.target.value, error: undefined })}
                    onKeyDown={e => {
                      if (e.key === 'Enter') void rename()
                      if (e.key === 'Escape') setEditing(null)
                    }}
                    autoFocus
                  />
                  <textarea
                    className="textarea"
                    aria-label="Preset description"
                    value={editing.description}
                    maxLength={PRESET_LIMITS.description}
                    onChange={e => setEditing({ ...editing, description: e.target.value, error: undefined })}
                    rows={2}
                  />
                  {editing.error && <p className={styles.ruleError}>{editing.error}</p>}
                  <div className={styles.presetRowActions}>
                    <button type="button" className={styles.button} onClick={() => setEditing(null)} disabled={busy}>
                      <X size={12} /> Cancel
                    </button>
                    <button
                      type="button"
                      className={`${styles.button} ${styles.primary}`}
                      onClick={() => void rename()}
                      disabled={busy || !editing.name.trim()}
                    >
                      {busyId === p.id ? <Loader2 size={12} className={styles.spin} /> : <Check size={12} />} Save
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div className={styles.presetRowMain}>
                    <span className={styles.presetRowName}>{p.name}</span>
                    {p.description && <span className={styles.presetRowDesc}>{p.description}</span>}
                    <span className={styles.presetRowMeta}>{describe(p)} · updated {fmtDate(p.updatedAt)}</span>
                  </div>
                  <div className={styles.presetRowActions}>
                    {mode === 'load' ? (
                      <button
                        type="button"
                        className={`${styles.button} ${styles.primary}`}
                        onClick={() => void load(p)}
                        disabled={busy}
                      >
                        {busyId === p.id && <Loader2 size={12} className={styles.spin} />} Load
                      </button>
                    ) : (
                      <>
                        <button
                          type="button"
                          className={styles.iconButton}
                          onClick={() => setEditing({ id: p.id, name: p.name, description: p.description })}
                          disabled={busy || !!editing}
                          aria-label={`Rename ${p.name}`}
                          title="Rename"
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          type="button"
                          className={styles.iconButton}
                          onClick={() => void remove(p)}
                          disabled={busy || !!editing}
                          aria-label={`Delete ${p.name}`}
                          title="Delete"
                        >
                          {busyId === p.id ? <Loader2 size={12} className={styles.spin} /> : <Trash2 size={12} />}
                        </button>
                      </>
                    )}
                  </div>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </Modal>
  )
}
