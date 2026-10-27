'use client'

import { useState } from 'react'
import { ChevronDown, Network, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface IpAttributionSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  onRun?: () => void
}

const DEFAULT_TLS_MAX_PROBES = 500

/**
 * IP attribution: after the HTTP probe, every IP of the run is tagged
 * shared_edge, dedicated or unknown, and vhost/SNI, origin discovery, the
 * passive CVE writers and the Priority Board read that one tag.
 */
export function IpAttributionSection({ data, updateField, onRun }: IpAttributionSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const enabled = data.ipAttributionEnabled ?? true

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Network size={16} />
          IP Attribution
          <NodeInfoTooltip section="IpAttribution" />
          <WikiInfoButton target="IpAttribution" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && enabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              className={styles.runPartialButton}
              title="Run IP Attribution"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={enabled}
              onChange={(checked) => updateField('ipAttributionEnabled', checked)}
              aria-label="Enable IP Attribution"
            />
          </div>
          <ChevronDown size={16} className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`} />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Tags every IP of the scan as a <strong>shared edge</strong> (a CDN edge serving many companies),
            <strong> dedicated</strong> (the certificate it presents without SNI covers a target domain) or
            <strong> unknown</strong>. It never says an IP is not the target&apos;s: a real server on a cloud
            provider looks generic from the outside. Vhost/SNI skips its wordlist on a shared edge, origin
            discovery never reports one as an origin, Shodan and Netlas write no CVE on one, and the Priority
            Board caps the reach of findings on one. The CDN signals come from data the scan already holds;
            the only traffic is one TLS handshake per IP with port 443 open.
          </p>

          {enabled && (
            <div className={styles.fieldRow}>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Max TLS handshakes per scan</label>
                <input
                  type="number"
                  className="textInput"
                  value={data.ipAttributionTlsMaxProbes ?? DEFAULT_TLS_MAX_PROBES}
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10)
                    updateField('ipAttributionTlsMaxProbes', Number.isNaN(n) ? DEFAULT_TLS_MAX_PROBES : n)
                  }}
                  min={0}
                  max={5000}
                />
                <span className={styles.fieldHint}>
                  One handshake without SNI per IP with port 443 open, paced at the engagement rate ceiling
                  and never to an RoE-excluded host. 0 turns the handshake off; stealth mode does the same.
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
