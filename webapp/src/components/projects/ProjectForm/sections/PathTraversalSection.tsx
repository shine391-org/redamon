'use client'

import type { Project } from '@prisma/client'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface PathTraversalSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onOpenRoe?: () => void
}

export function PathTraversalSection({ data, updateField, onOpenRoe }: PathTraversalSectionProps) {
  return (
    <div className={styles.skillSettings}>
      <div className={styles.skillSettingsHead}>
        <p className={styles.sectionDescription}>
          Configure which Path Traversal / LFI / RFI sub-workflows to inject into the agent
          prompt and tune probe parameters. Disable sub-sections you don&apos;t want for this engagement.
        </p>
        <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills" title="Open Agent Skills wiki page" />
      </div>

      <h3 className={styles.subSectionTitle}>Sub-workflow injection</h3>

      <div>
        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>OOB callback workflow (interactsh)</span>
            <p className={styles.toggleDescription}>
              Adds the RFI / blind-LFI sub-prompt. Sends DNS and HTTP probes to the configured OOB provider.
              Disable when external callbacks are forbidden.
            </p>
          </div>
          <Toggle
            checked={data.pathTraversalOobCallbackEnabled ?? true}
            onChange={(checked) => updateField('pathTraversalOobCallbackEnabled', checked)}
            aria-label="OOB callback workflow (interactsh)"
          />
        </div>

        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>PHP wrappers + log poisoning sub-section</span>
            <p className={styles.toggleDescription}>
              Adds php://filter, data://, expect://, zip:// payloads and the log-poisoning chain.
              Disable for non-PHP targets to reduce prompt bloat.
            </p>
          </div>
          <Toggle
            checked={data.pathTraversalPhpWrappersEnabled ?? true}
            onChange={(checked) => updateField('pathTraversalPhpWrappersEnabled', checked)}
            aria-label="PHP wrappers + log poisoning sub-section"
          />
        </div>

        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>Archive extraction (Zip Slip) write tests</span>
            <p className={styles.toggleDescription}>
              Allows the agent to upload crafted ZIP / TAR archives whose entries escape the destination
              directory. WRITES files to the target filesystem -- enable only with explicit RoE permission.
            </p>
          </div>
          <Toggle
            checked={data.pathTraversalArchiveExtractionEnabled ?? false}
            onChange={(checked) => updateField('pathTraversalArchiveExtractionEnabled', checked)}
            aria-label="Archive extraction (Zip Slip) write tests"
          />
        </div>

        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>Bypass + encoding payload reference table</span>
            <p className={styles.toggleDescription}>
              Injects the encoding / dot-trick / wrapper / parser-mismatch payload reference and the
              real-world precedents table (~3 KB extra). Disable for a leaner prompt.
            </p>
          </div>
          <Toggle
            checked={data.pathTraversalPayloadReferenceEnabled ?? true}
            onChange={(checked) => updateField('pathTraversalPayloadReferenceEnabled', checked)}
            aria-label="Bypass + encoding payload reference table"
          />
        </div>
      </div>

      <h3 className={styles.subSectionTitle}>Probe parameters</h3>

      <div className={styles.fieldRow}>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>Request Timeout (seconds)</label>
          <input
            type="number"
            className="textInput"
            value={data.pathTraversalRequestTimeout ?? 10}
            onChange={(e) => updateField('pathTraversalRequestTimeout', parseInt(e.target.value) || 10)}
            min={1}
            max={120}
          />
          <span className={styles.fieldHint}>
            curl --max-time / --connect-timeout for each traversal probe. Lower values speed up
            fuzzing loops but may miss slow file-read sinks.
          </span>
        </div>
        <div className={styles.fieldGroup}>
          <label className={styles.fieldLabel}>OOB Provider</label>
          <input
            type="text"
            className="textInput"
            value={data.pathTraversalOobProvider ?? 'oast.fun'}
            onChange={(e) => updateField('pathTraversalOobProvider', e.target.value)}
            placeholder="oast.fun"
          />
          <span className={styles.fieldHint}>
            interactsh-client server. Use a self-hosted instance if oast.fun is blocked. Only used
            when the OOB callback workflow is enabled.
          </span>
        </div>
      </div>

      <h3 className={styles.subSectionTitle}>Route exposure findings</h3>
      {data.routeExposureEnabled ? (
        <div>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Reconstruct exposed .git repositories</span>
              <p className={styles.toggleDescription}>
                Rebuilds a repository from an exposed .git the Route Exposure scan found, counts the secrets in it
                and deletes it. Off by default.
              </p>
              <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
                Needs data exfiltration allowed in{' '}
                {onOpenRoe ? (
                  <button
                    type="button"
                    onClick={onOpenRoe}
                    style={{ background: 'none', border: 0, padding: 0, color: 'var(--accent-primary)',
                             fontWeight: 500, cursor: 'pointer' }}
                  >
                    Rules of Engagement
                  </button>
                ) : (
                  <>Rules of Engagement</>
                )}
                .
              </p>
            </div>
            <Toggle
              checked={data.pathTraversalGitReconstructEnabled ?? false}
              onChange={(checked) => updateField('pathTraversalGitReconstructEnabled', checked)}
              aria-label="Reconstruct exposed .git repositories"
            />
          </div>
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Validate secrets found in exposed files</span>
              <p className={styles.toggleDescription}>
                Checks each secret with one identity-only call to its provider, which sees the call. Off by default.
              </p>
            </div>
            <Toggle
              checked={data.pathTraversalValidateSecretsEnabled ?? false}
              onChange={(checked) => updateField('pathTraversalValidateSecretsEnabled', checked)}
              aria-label="Validate secrets found in exposed files"
            />
          </div>
        </div>
      ) : (
        <p className={styles.fieldHint}>
          These apply to files the Route Exposure scan finds. Enable it in Vulnerability Scanning.
        </p>
      )}
    </div>
  )
}
