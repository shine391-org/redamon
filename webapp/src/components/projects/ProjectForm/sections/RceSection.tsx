'use client'

import type { Project } from '@prisma/client'
import { Toggle } from '@/components/ui/Toggle/Toggle'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface RceSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onOpenRoe?: () => void
}

export function RceSection({ data, updateField, onOpenRoe }: RceSectionProps) {
  return (
    <div className={styles.skillSettings}>
      <div className={styles.skillSettingsHead}>
        <p className={styles.sectionDescription}>
          Configure how the agent tests for RCE / command injection. Disable sub-workflows you don&apos;t want
          injected into the prompt and gate destructive payloads behind the explicit aggressive toggle.
        </p>
        <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Agent-Skills" title="Open Agent Skills wiki page" />
      </div>

      <h3 className={styles.subSectionTitle}>Sub-workflow injection</h3>

      <div>
        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>OOB callback workflow (interactsh)</span>
            <p className={styles.toggleDescription}>
              Adds the blind-RCE / OOB sub-prompt. The agent registers an oast.fun domain and uses DNS or HTTP
              callbacks as a quiet oracle for command execution. Disable when external OOB providers are off-limits.
            </p>
          </div>
          <Toggle
            checked={data.rceOobCallbackEnabled ?? true}
            onChange={(checked) => updateField('rceOobCallbackEnabled', checked)}
            aria-label="OOB callback workflow (interactsh)"
          />
        </div>

        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>Deserialization gadget workflow (ysoserial)</span>
            <p className={styles.toggleDescription}>
              Adds the Java / PHP / Python / Ruby / .NET deserialization sub-prompt with ysoserial gadget-chain
              guidance (URLDNS, CommonsCollections, Spring, etc.). Disable when the target stack does not deserialize
              untrusted input or when you want a leaner prompt.
            </p>
          </div>
          <Toggle
            checked={data.rceDeserializationEnabled ?? true}
            onChange={(checked) => updateField('rceDeserializationEnabled', checked)}
            aria-label="Deserialization gadget workflow (ysoserial)"
          />
        </div>

        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>Aggressive payloads (file write, web shells, container escape)</span>
            <p className={styles.toggleDescription}>
              <strong>Default OFF.</strong> When enabled, Step 7 of the workflow permits file writes outside /tmp,
              persistent web shells / cron / systemd hooks, reverse-shell handlers, and container / Kubernetes escape
              probes. Leave OFF for read-only proofs (id, whoami, /etc/passwd) which already produce a Level 3 finding.
              Only enable for engagements where critical-impact (Level 4) demonstration is explicitly authorised.
            </p>
          </div>
          <Toggle
            checked={data.rceAggressivePayloads ?? false}
            onChange={(checked) => updateField('rceAggressivePayloads', checked)}
            aria-label="Aggressive payloads (file write, web shells, container escape)"
          />
        </div>
      </div>

      <h3 className={styles.subSectionTitle}>Route exposure findings</h3>
      {data.routeExposureEnabled ? (
        <div className={styles.toggleRow}>
          <div>
            <span className={styles.toggleLabel}>Analyse exposed heap dumps</span>
            <p className={styles.toggleDescription}>
              Downloads an exposed heap dump the Route Exposure scan found once, counts the credential shapes in it
              and deletes it. Off by default.
            </p>
            <p className={`${styles.fieldHint} ${styles.fieldHintCaution}`}>
              Needs data exfiltration allowed and sensitive data handling above &quot;no access&quot; in{' '}
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
            checked={data.rceHeapdumpAnalysisEnabled ?? false}
            onChange={(checked) => updateField('rceHeapdumpAnalysisEnabled', checked)}
            aria-label="Analyse exposed heap dumps"
          />
        </div>
      ) : (
        <p className={styles.fieldHint}>
          These apply to the consoles the Route Exposure scan finds. Enable it in Vulnerability Scanning.
        </p>
      )}
    </div>
  )
}
