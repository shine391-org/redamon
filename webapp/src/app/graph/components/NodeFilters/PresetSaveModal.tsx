'use client'

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal, useToast, WikiInfoButton } from '@/components/ui'
import type { NodeFilterDoc, NodeFilterMode } from '@/lib/nodeFilters/model'
import { PRESET_LIMITS } from '@/lib/nodeFilters/presets'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './NodeFilters.module.css'

interface PresetSaveModalProps {
  isOpen: boolean
  onClose: () => void
  mode: NodeFilterMode
  rules: NodeFilterDoc
  counts: { rules: number; kinds: number }
}

export function PresetSaveModal({ isOpen, onClose, mode, rules, counts }: PresetSaveModalProps) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [errors, setErrors] = useState<string[]>([])

  useEffect(() => {
    if (!isOpen) return
    setName('')
    setDescription('')
    setErrors([])
  }, [isOpen])

  const save = async () => {
    if (!name.trim()) return
    setSaving(true)
    setErrors([])
    try {
      const res = await fetch('/api/mute-rule-presets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, description, mode, rules }),
      })
      if (!res.ok) {
        const err = await readApiError(res, 'Save failed')
        // Every rule error, as before: ApiError.details keeps only the first ten.
        const ruleErrors = Array.isArray(err.body?.errors) ? err.body.errors as string[] : []
        setErrors([err.message, ...ruleErrors])
        return
      }
      toast.success(`Preset "${name.trim()}" saved.`, 'Mute rules')
      onClose()
    } catch (e) {
      setErrors([toApiError(e, 'Save failed').message])
    } finally {
      setSaving(false)
    }
  }

  const ruleWord = counts.rules === 1 ? 'rule' : 'rules'
  const kindWord = counts.kinds === 1 ? 'kind' : 'kinds'

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Save as preset"
      // As the recon Save as Preset dialog: a stray click must not lose what was typed.
      closeOnOverlayClick={false}
      closeOnEscape={false}
      headerActions={<WikiInfoButton target="NodeFilters" />}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={onClose} disabled={saving}>Cancel</button>
          <button type="button" className="primaryButton" onClick={() => void save()} disabled={saving || !name.trim()}>
            {saving ? <><Loader2 size={14} className={styles.spin} /> Saving…</> : 'Save preset'}
          </button>
        </>
      }
    >
      <div className={styles.presetForm}>
        <p className={styles.presetSummary}>
          Saves the rules on screen: <strong>{mode}</strong> mode, {counts.rules} active {ruleWord} in{' '}
          {counts.kinds} {kindWord}, plus every rule and kind that is switched off. Not included: whether the
          rules run on new scans, and the findings an operator exempted. Those stay with the project.
        </p>
        <label className={styles.presetField}>
          <span className={styles.presetFieldLabel}>Name</span>
          <input
            type="text"
            className="textInput"
            value={name}
            maxLength={PRESET_LIMITS.name}
            onChange={e => setName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && name.trim() && !saving) void save() }}
            placeholder="e.g. Quiet external perimeter"
            autoFocus
          />
        </label>
        <label className={styles.presetField}>
          <span className={styles.presetFieldLabel}>Description</span>
          <textarea
            className="textarea"
            value={description}
            maxLength={PRESET_LIMITS.description}
            onChange={e => setDescription(e.target.value)}
            placeholder="Optional: what this preset mutes and when to use it"
            rows={3}
          />
        </label>
        {errors.length > 0 && (
          <div className={`${styles.banner} ${styles.bannerWarn}`} role="alert">
            <ul className={styles.errorList}>{errors.map(e => <li key={e}>{e}</li>)}</ul>
          </div>
        )}
      </div>
    </Modal>
  )
}
