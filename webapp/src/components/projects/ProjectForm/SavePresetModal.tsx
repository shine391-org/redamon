'use client'

import { useState, useEffect } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { extractPresetSettings, PRESET_FIELD_KEYS } from '@/lib/project-preset-utils'
import { useToast, WikiInfoButton } from '@/components/ui'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './ProjectForm.module.css'

interface SavePresetModalProps {
  isOpen: boolean
  onClose: () => void
  formData: Record<string, unknown>
  userId: string | null | undefined
}

export function SavePresetModal({ isOpen, onClose, formData, userId }: SavePresetModalProps) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  // Reset fields when modal opens
  useEffect(() => {
    if (isOpen) {
      setName('')
      setDescription('')
    }
  }, [isOpen])

  const handleSave = async () => {
    if (!name.trim()) return
    if (!userId) {
      toast.error('User not found')
      return
    }

    setIsSaving(true)
    try {
      const settings = extractPresetSettings(formData)

      const res = await fetch('/api/presets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, name, description, settings }),
      })

      if (!res.ok) throw await readApiError(res, 'Failed to save preset')

      toast.success(`Preset "${name.trim()}" saved`, 'Preset Saved')
      onClose()
    } catch (error) {
      toast.error(toApiError(error, 'Failed to save preset').message)
    } finally {
      setIsSaving(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Save as Preset"
      closeOnOverlayClick={false}
      closeOnEscape={false}
      headerActions={<WikiInfoButton target="ReconPreset" title="Open Recon Presets wiki page" />}
      footer={
        <>
          <button
            type="button"
            className="secondaryButton"
            onClick={onClose}
            disabled={isSaving}
          >
            Cancel
          </button>
          <button
            type="button"
            className="primaryButton"
            onClick={handleSave}
            disabled={isSaving || !name.trim()}
          >
            {isSaving ? (
              <>
                <Loader2 size={14} className={styles.spinner} />
                Saving...
              </>
            ) : (
              'Save Preset'
            )}
          </button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          Saves all {PRESET_FIELD_KEYS.length} project settings. Not included: the name and
          description, the target and scope, the Rules of Engagement, uploaded files and credentials.
        </p>
        <div>
          <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
            Name
          </label>
          <input
            type="text"
            className="textInput"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. My aggressive scan config"
            autoFocus
          />
        </div>
        <div>
          <label className={styles.fieldLabel}>
            Description
          </label>
          <textarea
            className="textarea"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional description for this preset"
            rows={3}
          />
        </div>
      </div>
    </Modal>
  )
}
