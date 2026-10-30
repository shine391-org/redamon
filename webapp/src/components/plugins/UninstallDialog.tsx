'use client'

import { useState } from 'react'
import { Modal } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { downloadPluginExport } from './exportDownload'
import styles from './plugins.module.css'

interface UninstallDialogProps {
  isOpen: boolean
  pluginId: string
  pluginName: string
  busy?: boolean
  /** The plugin is already uninstalled: only its kept data can be deleted. */
  keptOnly?: boolean
  onConfirm: (mode: 'keep' | 'purge') => void
  onCancel: () => void
}

/**
 * Uninstall (README.PLUGINS.md §9.6): keeping the data is the default; deleting it is
 * instance-wide, so the export must be downloaded first and the plugin id typed. The same
 * gates guard deleting the data an earlier "keep data" left (`keptOnly`).
 */
export function UninstallDialog({ isOpen, pluginId, pluginName, busy = false, keptOnly = false, onConfirm, onCancel }: UninstallDialogProps) {
  // Mounted when it opens, so "keep" is selected and nothing is typed each time.
  const [mode, setMode] = useState<'keep' | 'purge'>(keptOnly ? 'purge' : 'keep')
  const [exported, setExported] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [typed, setTyped] = useState('')

  // Only an export that really downloaded counts: the server refuses a purge without one.
  const exportData = async () => {
    setExporting(true)
    setExportError(null)
    try {
      await downloadPluginExport(pluginId)
      setExported(true)
    } catch (e) {
      setExportError(errorMessage(e, 'The export could not be downloaded'))
    } finally {
      setExporting(false)
    }
  }

  const ready = mode === 'keep' || (exported && typed === pluginId)
  return (
    <Modal
      isOpen={isOpen}
      onClose={onCancel}
      title={keptOnly ? `Delete the kept data of ${pluginName}` : `Uninstall ${pluginName}`}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={mode === 'purge' ? `secondaryButton ${styles.danger}` : 'primaryButton'}
            disabled={!ready || busy}
            onClick={() => onConfirm(mode)}
          >
            {keptOnly ? 'Delete kept data' : mode === 'purge' ? 'Delete everything and uninstall' : 'Uninstall'}
          </button>
        </>
      }
    >
      {keptOnly ? (
        <p>
          {pluginName} is not installed. The data, approved skill versions and proposals waiting for review kept when it
          was uninstalled are deleted for every user and project. Skills people saved from its proposals as their own
          are not affected. This cannot be undone.
        </p>
      ) : (
        <p>The plugin&apos;s code is removed from this host. Its contributions disappear for everyone.</p>
      )}
      {!keptOnly && (
        <div className={styles.choice} role="radiogroup" aria-label="Plugin data">
          <label>
            <input type="radio" name="uninstall-mode" checked={mode === 'keep'} onChange={() => setMode('keep')} />
            <span>
              Keep its data: the plugin&apos;s data and approved skill versions stay, unused, and come back if it is installed
              again. Skills people saved from its proposals as their own are not affected.
            </span>
          </label>
          <label>
            <input type="radio" name="uninstall-mode" checked={mode === 'purge'} onChange={() => setMode('purge')} />
            <span>
              Delete all data for every user and project, including approved skill versions and proposals waiting for
              review. Skills people saved from its proposals as their own are not affected. This cannot be undone.
            </span>
          </label>
        </div>
      )}
      {mode === 'purge' && (
        <div className={styles.choice}>
          <button type="button" className="textButton" onClick={() => void exportData()} disabled={exporting}>
            {exported ? 'Export downloaded; download it again' : 'Download the export of its data first'}
          </button>
          {exportError && (
            <span className={styles.error} role="alert">
              {exportError}
            </span>
          )}
          <span className="formHint">Text that plugins proposed for people&apos;s own skills is not included.</span>
          <label className="formLabel" htmlFor="uninstall-confirm">
            Type {pluginId} to confirm
          </label>
          <input
            id="uninstall-confirm"
            className="formInput"
            aria-label={`Type ${pluginId} to confirm`}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
          />
        </div>
      )}
    </Modal>
  )
}
